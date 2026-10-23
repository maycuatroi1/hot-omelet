"""Rendering for `hot dos` results (CLAUDE.md [LEVEL] [SERVICE] [VECTOR] format)."""
from __future__ import annotations

import json

from rich.console import Console

console = Console()

_LEVEL_COLOR = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                "LOW": "cyan", "INFO": "green"}

_LEVEL_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def print_finding(f: dict) -> None:
    color = _LEVEL_COLOR.get(f["level"], "white")
    console.print(f"  [bold {color}]\\[{f['level']}] \\[{f['service']}] \\[{f['vector']}][/]")
    console.print(f"    - Finding: {f['finding']}", markup=False)
    console.print(f"    - Evidence: {f['evidence']}", markup=False)
    console.print(f"    - Impact: {f['impact']}", markup=False)
    console.print(f"    - Fix: {f['fix']}", markup=False)


def print_summary(findings: list[dict]) -> None:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["level"]] = counts.get(f["level"], 0) + 1
    ordered = sorted(counts.items(), key=lambda kv: _LEVEL_ORDER.get(kv[0], 9))
    parts = [f"[{color}]{lvl}: {n}[/]" for lvl, n in ordered
             for color in [_LEVEL_COLOR.get(lvl, "white")]]
    console.print("\n[bold]Summary:[/bold] " + "  ".join(parts))


def render_report(target: str, probes: list[dict], findings: list[dict],
                  json_out: str | None) -> None:
    console.print(f"\n[bold cyan]DoS exposure report - {target}[/bold cyan]")
    if not findings:
        console.print("[green]No DoS-relevant signals from the selected probes.[/green]")
    for f in sorted(findings, key=lambda x: _LEVEL_ORDER.get(x["level"], 9)):
        print_finding(f)
    print_summary(findings)
    if json_out:
        payload = {"target": target, "probes": probes, "findings": findings}
        with open(json_out, "w") as fh:
            json.dump(payload, fh, indent=2, default=str)
        console.print(f"[green]Report written to {json_out}[/green]")
