"""`hot airflow ...` - Apache Airflow enumeration and exploitation."""
import json
from pathlib import Path

import click

from hot_omelet.commands._common import output_option, timeout_option, workers_option


@click.group("airflow")
def airflow():
    """Apache Airflow enumeration and exploitation."""


@airflow.command("scan")
@click.option("--host", required=False, help="Single Airflow hostname/IP")
@click.option("--file", "target_file", required=False, help="File with target IPs (one per line)")
@click.option("--port", default=None, type=int, help="Port (default: auto-detect from common ports)")
@workers_option(20)
@timeout_option(8)
@click.option("--ssl", is_flag=True, help="Force HTTPS")
@output_option()
def airflow_scan(host, target_file, port, workers, timeout, ssl, output):
    """Scan Apache Airflow for default credentials, unauth access, and leaked secrets."""
    from hot_omelet.default_creds.airflow import (
        _print_summary,
        scan_single_target,
        scan_targets_from_file,
    )
    ports = [port] if port else None
    if target_file:
        scan_targets_from_file(target_file, ports=ports, timeout=timeout, max_workers=workers, output=output)
        return
    if host:
        result = scan_single_target(host, ports=ports, timeout=timeout)
        _print_summary([result], [result] if result.get("status") in ("critical_creds", "critical_unauth") else [])
        if output:
            with open(output, "w") as f:
                json.dump(result, f, indent=2, default=str)
        return
    target = click.prompt("Enter Airflow hostname/IP, or path to IP list file")
    if Path(target).is_file():
        scan_targets_from_file(target, timeout=timeout, max_workers=workers, output=output)
    else:
        result = scan_single_target(target, timeout=timeout)
        _print_summary([result], [result] if result.get("status") in ("critical_creds", "critical_unauth") else [])


# `hot airflow shell` is provided by hot_omelet.airflow_shell:airflow_shell_cmd
from hot_omelet.airflow_shell import airflow_shell_cmd as _airflow_shell_cmd  # noqa: E402

_airflow_shell_cmd.name = "shell"
airflow.add_command(_airflow_shell_cmd)
