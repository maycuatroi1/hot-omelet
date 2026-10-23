import json
import time
import re
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

CENSYS_STATE_DIR = Path.home() / ".hot-omelet" / "censys"
CENSYS_STATE_DIR.mkdir(parents=True, exist_ok=True)
STORAGE_STATE_FILE = CENSYS_STATE_DIR / "browser_state.json"
RESULTS_DIR = CENSYS_STATE_DIR / "results"
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

COUNTRY_CODES = {
    "VN": "Vietnam", "TH": "Thailand", "ID": "Indonesia", "SG": "Singapore",
    "MY": "Malaysia", "PH": "Philippines", "JP": "Japan", "KR": "South Korea",
    "CN": "China", "TW": "Taiwan", "IN": "India", "US": "United States",
}


def with_country(query, country_code):
    if country_code:
        return f'{query} and location.country_code: "{country_code.upper()}"'
    return query


ATTACK_QUERIES = {
    "redis-noauth": {
        "query": 'services.service_name=REDIS and services.redis.ping_response="PONG"',
        "desc": "Redis servers without authentication (direct RCE possible)",
    },
    "redis-open": {
        "query": "services.service_name=REDIS",
        "desc": "All exposed Redis servers",
    },
    "mongodb-noauth": {
        "query": "services.service_name=MONGODB and services.mongodb.ismaster.ismaster=true",
        "desc": "MongoDB without authentication",
    },
    "elastic-open": {
        "query": 'services.service_name=ELASTICSEARCH and services.http.response.status_code=200',
        "desc": "Elasticsearch without auth",
    },
    "mysql-open": {
        "query": "services.service_name=MYSQL and services.port=3306",
        "desc": "Exposed MySQL servers",
    },
    "postgres-open": {
        "query": "services.service_name=POSTGRESQL and services.port=5432",
        "desc": "Exposed PostgreSQL servers",
    },
    "memcached-open": {
        "query": "services.service_name=MEMCACHED and services.port=11211",
        "desc": "Exposed Memcached (DDoS amplification + data leak)",
    },
    "docker-api": {
        "query": 'services.port=2375 and services.http.response.body: "Docker"',
        "desc": "Docker API exposed without TLS (full host takeover)",
    },
    "kubernetes-api": {
        "query": 'services.port=10250 and services.http.response.status_code=200',
        "desc": "Kubelet API exposed (container escape)",
    },
    "jenkins-open": {
        "query": 'services.http.response.body: "Dashboard [Jenkins]" and services.http.response.status_code=200',
        "desc": "Jenkins without auth (RCE via script console)",
    },
    "airflow-open": {
        "query": 'services.http.response.body: "Airflow" and services.http.response.body: "DAGs"',
        "desc": "Apache Airflow exposed (RCE via DAG)",
    },
    "airflow-vn": {
        "query": 'services.http.response.html_title: "Airflow" and location.country_code: "VN"',
        "desc": "Apache Airflow in Vietnam (RCE via DAG upload)",
    },
    "airflow-title": {
        "query": 'services.http.response.html_title: "Airflow"',
        "desc": "Airflow by HTML title (more precise than body match)",
    },
    "airflow-api": {
        "query": 'services.http.response.body: "airflow" and services.http.response.body: "api/v1"',
        "desc": "Airflow with REST API exposed",
    },
    "minio-default": {
        "query": 'services.http.response.body: "MinIO" and services.port=9000',
        "desc": "MinIO S3 exposed (try minioadmin:minioadmin)",
    },
    "kafka-open": {
        "query": "services.service_name=KAFKA and services.port=9092",
        "desc": "Apache Kafka exposed without auth",
    },
    "couchdb-open": {
        "query": 'services.http.response.body: "couchdb" and services.http.response.status_code=200',
        "desc": "CouchDB without auth",
    },
    "rabbitmq-mgmt": {
        "query": 'services.http.response.body: "RabbitMQ Management" and services.port=15672',
        "desc": "RabbitMQ management console (try guest:guest)",
    },
    "etcd-open": {
        "query": "services.port=2379 and services.http.response.status_code=200",
        "desc": "etcd exposed (k8s secrets leak)",
    },
    "prometheus-open": {
        "query": 'services.http.response.body: "Prometheus" and services.port=9090',
        "desc": "Prometheus metrics exposed (info disclosure)",
    },
    "grafana-open": {
        "query": 'services.http.response.body: "Grafana" and services.http.response.status_code=200',
        "desc": "Grafana dashboards (try admin:admin)",
    },
    "ssh-weak": {
        "query": "services.service_name=SSH and services.port=22",
        "desc": "SSH servers (for credential spray)",
    },
    "ftp-anon": {
        "query": 'services.service_name=FTP and services.banner: "Anonymous"',
        "desc": "FTP with anonymous login enabled",
    },
    "spring-actuator": {
        "query": 'services.http.response.body: "actuator" and services.http.response.body: "beans"',
        "desc": "Spring Boot Actuator exposed (env leak, possible RCE)",
    },
    "hadoop-namenode": {
        "query": 'services.http.response.body: "Namenode" and services.port=50070',
        "desc": "Hadoop NameNode UI exposed",
    },
    "spark-master": {
        "query": 'services.http.response.body: "Spark Master" and services.port=8080',
        "desc": "Apache Spark Master UI (RCE possible)",
    },
    "solr-open": {
        "query": 'services.http.response.body: "Solr Admin" and services.http.response.status_code=200',
        "desc": "Apache Solr Admin exposed (RCE via SSRF/deserialization)",
    },
    "jupyter-open": {
        "query": 'services.http.response.body: "Jupyter" and services.port=8888',
        "desc": "Jupyter Notebook exposed (direct code execution)",
    },
    "phpmyadmin-open": {
        "query": 'services.http.response.body: "phpMyAdmin" and services.http.response.status_code=200',
        "desc": "phpMyAdmin exposed",
    },
    "consul-open": {
        "query": 'services.http.response.body: "consul" and services.port=8500',
        "desc": "HashiCorp Consul exposed (service mesh takeover)",
    },
    "vault-open": {
        "query": 'services.http.response.body: "Vault" and services.port=8200',
        "desc": "HashiCorp Vault exposed (secrets management)",
    },
}


class CensysSearch:
    def __init__(self, headless=True, slow_mo=0, proxy=None):
        self.headless = headless
        self.slow_mo = slow_mo
        self.proxy = proxy
        self._browser = None
        self._context = None
        self._page = None
        self._playwright = None
        self._pw_cm = None
        self._query_count = 0

    def _launch(self):
        from playwright.sync_api import sync_playwright
        from playwright_stealth import Stealth

        self._pw_cm = sync_playwright()
        self._playwright = self._pw_cm.__enter__()

        launch_args = [
            "--disable-blink-features=AutomationControlled",
            "--no-sandbox",
        ]

        browser_opts = {
            "headless": self.headless,
            "args": launch_args,
        }
        if self.proxy:
            browser_opts["proxy"] = {"server": self.proxy}

        self._browser = self._playwright.chromium.launch(**browser_opts)

        context_opts = {
            "viewport": {"width": 1920, "height": 1080},
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        }
        if STORAGE_STATE_FILE.exists():
            try:
                context_opts["storage_state"] = str(STORAGE_STATE_FILE)
            except Exception:
                pass

        self._context = self._browser.new_context(**context_opts)
        self._page = self._context.new_page()
        Stealth().apply_stealth_sync(self._page)

    def _save_state(self):
        try:
            self._context.storage_state(path=str(STORAGE_STATE_FILE))
        except Exception:
            pass

    def _wait_for_cf(self, timeout=30):
        start = time.time()
        while time.time() - start < timeout:
            title = self._page.title()
            if "just a moment" not in title.lower():
                return True
            time.sleep(1)
        return False

    def _navigate_search(self, query, resource="hosts", page_num=1):
        import urllib.parse
        encoded_q = urllib.parse.quote(query)
        url = f"https://search.censys.io/search?resource={resource}&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q={encoded_q}"
        if page_num > 1:
            url += f"&cursor=eyJBZnRlciI6WyIiLCIiXSwiUmV2ZXJzZSI6ZmFsc2V9&page={page_num}"

        self._page.goto(url, wait_until="domcontentloaded", timeout=60000)
        if not self._wait_for_cf(timeout=45):
            console.print("[red]Cloudflare challenge timeout[/red]")
            return False

        for _ in range(15):
            time.sleep(2)
            cur_url = self._page.url
            title = self._page.title()
            if "accounts.censys.io" in cur_url:
                return True
            if "legacy-redirect" not in cur_url and "Redirecting" not in title:
                break

        try:
            self._page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            pass
        self._page.wait_for_timeout(2000)
        return True

    def _is_redirected(self):
        url = self._page.url
        return "platform.censys.io" in url or "accounts.censys.io" in url

    def _check_rate_limit(self):
        url = self._page.url
        if "accounts.censys.io" in url:
            return True
        content = self._page.content()
        rate_indicators = [
            "you've reached your daily search limit",
            "search limit reached",
            "daily query limit",
            "low-on-quotas=true",
        ]
        lower = content.lower()
        for indicator in rate_indicators:
            if indicator in lower:
                return True
        return False

    def _parse_platform_results(self):
        results = []
        try:
            body = self._page.inner_text("body")
        except Exception:
            return results

        result_count_match = re.search(r'RESULTS:\s*([\d,]+)', body)
        self._last_result_count = result_count_match.group(1) if result_count_match else "unknown"

        blocks = re.split(r'\n(?=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\nHOST)', body)

        for block in blocks:
            ip_match = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\nHOST', block.strip())
            if not ip_match:
                continue
            ip = ip_match.group(1)

            labels = []
            label_match = re.search(r'HOST\n(.*?)(?:Network|OS|Location|Services|Software|MATCHED)', block, re.DOTALL)
            if label_match:
                raw = label_match.group(1).strip()
                labels = [line.strip() for line in raw.split('\n') if line.strip() and len(line.strip()) < 30]

            network = ""
            net_match = re.search(r'Network \(AS\)\s*(.+?)(?:\n|Location|Services|Software|OS)', block)
            if net_match:
                network = net_match.group(1).strip()

            location = ""
            loc_match = re.search(r'Location\s*\n(.+?)(?:\n|Services|Software|OS|MATCHED)', block)
            if loc_match:
                location = loc_match.group(1).strip()

            os_info = ""
            os_match = re.search(r'OS\s*\n(.+?)(?:\n|Network|Location|Services|Software|MATCHED)', block)
            if os_match:
                os_info = os_match.group(1).strip()

            services = []
            svc_match = re.search(r'Services \((\d+)\)\n(.*?)(?:Software|MATCHED|$)', block, re.DOTALL)
            if svc_match:
                svc_text = svc_match.group(2).strip()
                services = [s.strip() for s in svc_text.split('\n') if re.match(r'\d+\s*/\s*\w+', s.strip())]

            software = []
            sw_match = re.search(r'Software \((\d+)\)\n(.*?)(?:MATCHED|$)', block, re.DOTALL)
            if sw_match:
                sw_text = sw_match.group(2).strip()
                software = [s.strip() for s in sw_text.split('\n') if s.strip() and not s.strip().startswith('MATCHED')]

            results.append({
                "ip": ip,
                "labels": labels,
                "services": services,
                "software": software,
                "network": network,
                "location": location,
                "os": os_info,
                "url": f"https://search.censys.io/hosts/{ip}",
            })

        return results

    def _parse_result_count(self):
        if hasattr(self, '_last_result_count'):
            return self._last_result_count
        try:
            body = self._page.inner_text("body")
            match = re.search(r'RESULTS:\s*([\d,]+)', body)
            if match:
                return match.group(1)
            match = re.search(r'([\d,]+)\s+(?:hosts?|results?)', body, re.IGNORECASE)
            if match:
                return match.group(1)
        except Exception:
            pass
        return "unknown"

    def search(self, query, resource="hosts", max_pages=1, delay=3):
        if not self._browser:
            self._launch()

        all_results = []
        result_count = ""
        self._last_result_count = "unknown"

        for page_num in range(1, max_pages + 1):
            console.print(f"[cyan]Searching page {page_num}: {query}[/cyan]")

            if not self._navigate_search(query, resource, page_num):
                console.print("[red]Navigation failed[/red]")
                break

            if self._check_rate_limit():
                console.print("[red]Rate limit hit! Rotate VPN then search again.[/red]")
                console.print(f"[yellow]Queries used this session: {self._query_count}[/yellow]")
                self._save_state()
                return {"error": "rate_limited", "results": all_results, "query_count": self._query_count}

            page_results = self._parse_platform_results()
            result_count = self._last_result_count

            if page_num == 1:
                console.print(f"[green]Found: {result_count} hosts[/green]")

            if not page_results:
                break

            all_results.extend(page_results)
            self._query_count += 1

            if page_num < max_pages:
                time.sleep(delay)

        self._save_state()

        return {
            "query": query,
            "resource": resource,
            "result_count": result_count,
            "results": all_results,
            "pages_scraped": page_num if all_results else 0,
        }

    def search_and_save(self, query, resource="hosts", max_pages=1, output=None):
        data = self.search(query, resource, max_pages)
        if not output:
            safe_q = re.sub(r'[^\w\-]', '_', query)[:50]
            output = str(RESULTS_DIR / f"censys_{safe_q}_{int(time.time())}.json")

        with open(output, "w") as f:
            json.dump(data, f, indent=2)
        console.print(f"[green]Saved: {output}[/green]")
        return data

    def get_host_details(self, ip):
        if not self._browser:
            self._launch()

        url = f"https://search.censys.io/hosts/{ip}"
        self._page.goto(url, wait_until="domcontentloaded", timeout=60000)
        if not self._wait_for_cf():
            return None

        self._page.wait_for_timeout(3000)
        self._save_state()

        details = {"ip": ip, "raw_text": ""}
        try:
            body = self._page.query_selector("main") or self._page.query_selector("body")
            if body:
                details["raw_text"] = body.inner_text()[:5000]
        except Exception:
            pass

        return details

    def login(self, email=None, password=None):
        if not self._browser:
            self._launch()

        self._page.goto("https://accounts.censys.io/login", wait_until="domcontentloaded", timeout=60000)
        if not self._wait_for_cf():
            console.print("[red]CF challenge failed on login page[/red]")
            return False

        self._page.wait_for_timeout(2000)

        if email and password:
            try:
                self._page.fill('input[name="email"], input[type="email"]', email)
                self._page.fill('input[name="password"], input[type="password"]', password)
                self._page.click('button[type="submit"]')
                self._page.wait_for_timeout(5000)
                self._save_state()
                console.print("[green]Login attempted, state saved[/green]")
                return True
            except Exception as e:
                console.print(f"[red]Login failed: {e}[/red]")
                return False
        else:
            console.print("[yellow]Manual login - open browser with --no-headless, login, then press Enter[/yellow]")
            input()
            self._save_state()
            console.print("[green]State saved[/green]")
            return True

    def rotate_ip(self):
        console.print("[yellow]Clearing browser state for IP rotation...[/yellow]")
        self.close()
        if STORAGE_STATE_FILE.exists():
            STORAGE_STATE_FILE.unlink()
        console.print("[green]State cleared. Switch VPN, then search again.[/green]")

    def close(self):
        try:
            self._save_state()
        except Exception:
            pass
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        try:
            if hasattr(self, '_pw_cm') and self._pw_cm:
                self._pw_cm.__exit__(None, None, None)
        except Exception:
            pass
        self._browser = None
        self._context = None
        self._page = None
        self._playwright = None
        self._pw_cm = None

    def interactive(self):
        console.print(Panel(
            "[bold cyan]Censys Interactive Search[/bold cyan]\n"
            "Commands:\n"
            "  search <query>     - Custom Censys query\n"
            "  attack <preset>    - Use preset attack query\n"
            "  list               - List all attack presets\n"
            "  detail <ip>        - Get host details\n"
            "  rotate             - Clear state for VPN rotation\n"
            "  login              - Login to Censys\n"
            "  quit               - Exit",
            expand=False
        ))

        try:
            while True:
                cmd = input("\ncensys> ").strip()
                if not cmd:
                    continue

                if cmd.lower() in ("quit", "exit", "q"):
                    break
                elif cmd.lower() == "list":
                    self._list_presets()
                elif cmd.lower() == "login":
                    self.login()
                elif cmd.lower() == "rotate":
                    self.rotate_ip()
                    input("[Press Enter after VPN switch]")
                    self._launch()
                elif cmd.lower().startswith("detail "):
                    ip = cmd.split(" ", 1)[1].strip()
                    details = self.get_host_details(ip)
                    if details:
                        console.print(details.get("raw_text", "No data")[:3000])
                elif cmd.lower().startswith("attack "):
                    parts = cmd.split(" ", 1)[1].strip().split(" ")
                    preset = parts[0]
                    country = parts[1].upper() if len(parts) > 1 else None
                    if preset in ATTACK_QUERIES:
                        q = ATTACK_QUERIES[preset]
                        query = with_country(q["query"], country) if country else q["query"]
                        console.print(f"[yellow]{q['desc']}{f' [{country}]' if country else ''}[/yellow]")
                        data = self.search(query)
                        self._print_results(data)
                    else:
                        console.print(f"[red]Unknown preset: {preset}[/red]")
                        self._list_presets()
                elif cmd.lower().startswith("search "):
                    query = cmd.split(" ", 1)[1].strip()
                    data = self.search(query)
                    self._print_results(data)
                else:
                    if cmd in ATTACK_QUERIES:
                        q = ATTACK_QUERIES[cmd]
                        console.print(f"[yellow]{q['desc']}[/yellow]")
                        data = self.search(q["query"])
                        self._print_results(data)
                    else:
                        data = self.search(cmd)
                        self._print_results(data)
        finally:
            self.close()

    def _list_presets(self):
        table = Table(title="Attack Presets")
        table.add_column("Name", style="red")
        table.add_column("Description", style="yellow")
        table.add_column("Query", style="dim", max_width=60)

        for name, info in ATTACK_QUERIES.items():
            table.add_row(name, info["desc"], info["query"][:60])
        console.print(table)

    def _print_results(self, data):
        if data.get("error") == "rate_limited":
            console.print("[red]Rate limited! Use 'rotate' to switch IP[/red]")
            return

        results = data.get("results", [])
        if not results:
            console.print("[yellow]No results[/yellow]")
            return

        table = Table(title=f"Censys Results ({data.get('result_count', '?')} total)")
        table.add_column("#", style="dim", width=4)
        table.add_column("IP", style="green")
        table.add_column("Labels", style="red", max_width=25)
        table.add_column("Services", style="cyan", max_width=40)
        table.add_column("Location", style="yellow", max_width=25)

        for i, r in enumerate(results, 1):
            labels = ", ".join(r.get("labels", []))
            svcs = ", ".join(r.get("services", []))
            loc = r.get("location", "")
            table.add_row(str(i), r["ip"], labels, svcs, loc)

        console.print(table)
        console.print(f"[dim]Showing {len(results)} hosts. IPs saved to results file.[/dim]")

    def extract_ips(self, data):
        return [r["ip"] for r in data.get("results", [])]


def censys_search_cli(query, resource="hosts", max_pages=1, headless=True, proxy=None, output=None, interactive=False, attack=None):
    searcher = CensysSearch(headless=headless, proxy=proxy)
    try:
        if interactive:
            searcher.interactive()
        elif attack:
            if attack in ATTACK_QUERIES:
                q = ATTACK_QUERIES[attack]
                console.print(f"[yellow]{q['desc']}[/yellow]")
                data = searcher.search_and_save(q["query"], resource, max_pages, output)
                searcher._print_results(data)
                return data
            else:
                console.print(f"[red]Unknown preset: {attack}[/red]")
                searcher._list_presets()
        elif query:
            data = searcher.search_and_save(query, resource, max_pages, output)
            searcher._print_results(data)
            return data
    finally:
        searcher.close()
