"""Orchestration for `hot dos assess`."""
from __future__ import annotations

import time

from rich.console import Console

from hot_omelet.dos.http_utils import normalize_url
from hot_omelet.dos.probes import PROBES, findings_from_probes, run_probes
from hot_omelet.dos.report import render_report

console = Console()


def build_context(target: str, login_url: str | None, reset_url: str | None,
                  valid_user: str | None, timeout: float, slow_deadline: float,
                  rate_requests: int, burst: int, lockout_requests: int,
                  send_reset: bool) -> dict:
    base = normalize_url(target)
    return {
        "base_url": base,
        "login_url": login_url or f"{base}/login/token.php",
        "reset_url": reset_url or f"{base}/login/forgot_password.php",
        "valid_user": valid_user,
        "timeout": timeout,
        "slow_deadline": slow_deadline,
        "rate_requests": rate_requests,
        "burst": burst,
        "lockout_requests": lockout_requests,
        "send_reset": send_reset,
    }


def dos_assess_command(target: str, probes: str | None, login_url: str | None,
                       reset_url: str | None, valid_user: str | None,
                       timeout: float, slow_deadline: float, rate_requests: int,
                       burst: int, lockout_requests: int, send_reset: bool,
                       json_out: str | None) -> None:
    """Run bounded DoS-exposure probes against an authorized target."""
    ctx = build_context(target, login_url, reset_url, valid_user, timeout,
                        slow_deadline, rate_requests, burst, lockout_requests,
                        send_reset)
    names = [p.strip() for p in probes.split(",")] if probes else list(PROBES)
    unknown = [n for n in names if n not in PROBES]
    if unknown:
        console.print(f"[red]Unknown probes: {', '.join(unknown)}. "
                      f"Available: {', '.join(PROBES)}[/red]")
        return

    console.print(f"[bold cyan]DoS exposure assessment - {ctx['base_url']}[/bold cyan]")
    console.print("[dim]Authorized targets only. Bounded probes: 1 connection for slow "
                  f"vectors, <= {max(rate_requests, burst, lockout_requests)} requests for "
                  "request vectors.[/dim]")
    console.print(f"[dim]Probes: {', '.join(names)}[/dim]\n")

    results = []
    for name in names:
        console.print(f"[dim]>[/dim] [bold]{name}[/bold]", end=" ")
        t0 = time.monotonic()
        res = run_probes([name], ctx)[0]
        secs = time.monotonic() - t0
        status = "ok" if res["ok"] else "error"
        err = res.get("result", {}).get("error", "")
        if err == "no valid user":
            status = "skipped (needs --valid-user)"
        console.print(f"[{'green' if res['ok'] else 'red'}]{status}[/] ({secs:.1f}s)")
        results.append(res)

    findings = findings_from_probes(results)
    render_report(ctx["base_url"], results, findings, json_out)
