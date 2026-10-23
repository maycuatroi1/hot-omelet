"""`hot pgsql ...` - PostgreSQL enumeration."""
import click

from hot_omelet.commands._common import host_port_options, prompt_host


@click.group("pgsql")
def pgsql():
    """PostgreSQL enumeration."""


@pgsql.command("scan")
@host_port_options(5432)
def pgsql_scan(host, port):
    """Scan PostgreSQL for default credentials."""
    from hot_omelet.data_extraction import pgsql_scan_command
    host = prompt_host(host, "PostgreSQL hostname or IP")
    pgsql_scan_command(host, port)
