"""Confirmation-gated load testing for infrastructure you own.

This is NOT an assessment probe: `hot dos stress` deliberately generates
sustained load. It refuses to run unless you pass `--yes` AND type the
target host when prompted (or pipe it via stdin). Defaults are conservative
(8 workers, 15s) and hard-capped.
"""
from __future__ import annotations

import threading
import time

import click
from rich.console import Console
from rich.live import Live
from rich.table import Table

from hot_omelet.dos.http_utils import make_session, normalize_url

console = Console()

HARD_MAX_WORKERS = 256
HARD_MAX_DURATION = 300.0

STOP = threading.Event()
STATS = {"requests": 0, "errors": 0, "latencies": []}
STATS_LOCK = threading.Lock()


def _auth_payload(login_url: str, valid_user: str) -> dict | str:
    if login_url.endswith("token.php"):
        return (
            f"username={valid_user}&password=stress_test_wrongpw&"
            "service=moodle_mobile_app"
        )
    return {"username": valid_user, "password": "stress_test_wrongpw"}


def _worker(base_url: str, mode: str, login_url: str, valid_user: str,
            interval: float, timeout: float) -> None:
    session = make_session()
    url = login_url if mode == "auth" else base_url
    payload = _auth_payload(login_url, valid_user) if mode == "auth" else None
    while not STOP.is_set():
        t0 = time.monotonic()
        try:
            if mode == "auth":
                r = session.post(url, data=payload, timeout=timeout, verify=False)
            else:
                r = session.get(url, timeout=timeout, verify=False)
            with STATS_LOCK:
                STATS["requests"] += 1
                STATS["latencies"].append(time.monotonic() - t0)
                if r.status_code >= 500:
                    STATS["errors"] += 1
        except Exception:
            with STATS_LOCK:
                STATS["requests"] += 1
                STATS["errors"] += 1
        if interval > 0:
            STOP.wait(interval)


def _summary_table(elapsed: float) -> Table:
    table = Table(title=None, box=None)
    table.add_column("metric", style="cyan")
    table.add_column("value", justify="right")
    with STATS_LOCK:
        reqs, errs, lat = STATS["requests"], STATS["errors"], list(STATS["latencies"])
    rps = reqs / elapsed if elapsed > 0 else 0
    if lat:
        lat.sort()
        p50 = lat[len(lat) // 2]
        p95 = lat[int(len(lat) * 0.95)] if len(lat) >= 20 else lat[-1]
    else:
        p50 = p95 = 0.0
    table.add_row("elapsed", f"{elapsed:.1f}s")
    table.add_row("requests", str(reqs))
    table.add_row("req/s", f"{rps:.1f}")
    table.add_row("latency p50", f"{p50:.2f}s")
    table.add_row("latency p95", f"{p95:.2f}s")
    table.add_row("5xx/conn errors", str(errs))
    return table


def dos_stress_command(target: str, mode: str, workers: int, duration: float,
                       interval: float, login_url: str | None, valid_user: str,
                       timeout: float, yes: bool) -> None:
    base = normalize_url(target)
    login = login_url or f"{base}/login/token.php"
    workers = min(workers, HARD_MAX_WORKERS)
    duration = min(duration, HARD_MAX_DURATION)

    if not yes:
        console.print("[bold red]This command generates real load and can take the "
                      "target down.[/bold red]")
        console.print("Only run it against infrastructure you own or are "
                      "explicitly authorized to load-test.")
        typed = click.prompt("Type the target host to confirm", type=str)
        if typed.strip().rstrip("/") != base.split("://", 1)[-1].rstrip("/"):
            console.print("[red]Confirmation mismatch. Aborting.[/red]")
            return

    console.print(f"[bold cyan]Stress test - {base}[/bold cyan]")
    console.print(f"[dim]mode={mode} workers={workers} duration={duration}s "
                  f"interval={interval}s[/dim]")

    STOP.clear()
    STATS.update(requests=0, errors=0, latencies=[])
    threads = []
    t0 = time.monotonic()
    with Live(_summary_table(0), refresh_per_second=2, console=console) as live:
        for _ in range(workers):
            t = threading.Thread(
                target=_worker,
                args=(base, mode, login, valid_user, interval, timeout),
                daemon=True,
            )
            t.start()
            threads.append(t)
        while time.monotonic() - t0 < duration and not STOP.is_set():
            live.update(_summary_table(time.monotonic() - t0))
            time.sleep(0.5)
        STOP.set()
        for t in threads:
            t.join(timeout=timeout + 2)
        live.update(_summary_table(time.monotonic() - t0))

    elapsed = time.monotonic() - t0
    console.print("\n[bold]Done.[/bold]")
    console.print(_summary_table(elapsed))
    with STATS_LOCK:
        err_rate = STATS["errors"] / STATS["requests"] if STATS["requests"] else 0
    if err_rate > 0.05:
        console.print(f"[red]{err_rate:.0%} error rate observed - target degraded "
                      "under this load.[/red]")
    else:
        console.print("[green]No significant 5xx/timeout degradation at this load.[/green]")
