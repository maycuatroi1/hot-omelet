"""`hot redis ...` - Redis enumeration and exploitation."""
import click

from hot_omelet.commands._common import (
    host_port_options,
    output_option,
    prompt_host,
    timeout_option,
    workers_option,
)


@click.group("redis")
def redis():
    """Redis enumeration and exploitation."""


@redis.command("scan")
@host_port_options(6379)
@workers_option()
@timeout_option()
@output_option()
def redis_scan(host, port, workers, timeout, output):
    """Scan Redis for default credentials."""
    from hot_omelet.default_creds.redis import scan_redis
    host = prompt_host(host, "Redis hostname or IP")
    scan_redis(host=host, port=port, max_workers=workers, timeout=timeout, output_file=output)


@redis.command("dump")
@host_port_options(6379)
def redis_dump(host, port):
    """Extract data from a Redis server."""
    from hot_omelet.data_extraction import redis_dump_command
    host = prompt_host(host, "Redis hostname or IP")
    redis_dump_command(host, port)


@redis.command("cve")
@host_port_options(6379)
@click.option("--password", default=None, help="Redis password (if required)")
@timeout_option()
def redis_cve(host, port, password, timeout):
    """Scan Redis for known CVEs and misconfigurations."""
    from hot_omelet.hot_redis.redis_cve_scanner import scan_redis_cves
    host = prompt_host(host, "Redis hostname or IP")
    scan_redis_cves(host=host, port=port, password=password, timeout=timeout)


@redis.command("attack")
@host_port_options(6379)
@click.option("--password", default=None, help="Redis password (if required)")
@output_option("Output file for attack results (JSON)")
def redis_attack(host, port, password, output):
    """Comprehensive Redis attack toolkit - test multiple exploitation vectors."""
    from hot_omelet.data_extraction import redis_attack_command
    host = prompt_host(host, "Redis hostname or IP")
    redis_attack_command(host, port, password, output)


@redis.command("rce")
@host_port_options(6379)
@click.option("--password", default=None, help="Redis password")
@click.option("--callback-ip", default=None, help="Callback IP for reverse shell")
@click.option("--callback-port", default=4444, show_default=True, type=int)
@click.option("--tunnel", type=click.Choice(["ngrok", "cloudflared"]), default="ngrok")
@output_option()
def redis_rce(host, port, password, callback_ip, callback_port, tunnel, output):
    """Redis RCE exploiter - tries SSH key, webshell, crontab, module replication."""
    from hot_omelet.hot_redis.rce_exploiter import redis_rce as _redis_rce
    host = prompt_host(host, "Redis hostname or IP")
    _redis_rce(host, port, password, callback_ip, callback_port, tunnel, output)
