"""`hot minio ...` - MinIO enumeration."""
import click

from hot_omelet.commands._common import (
    host_port_options,
    output_option,
    prompt_host,
    timeout_option,
    workers_option,
)


@click.group("minio")
def minio():
    """MinIO enumeration."""


@minio.command("scan")
@host_port_options(9000)
@workers_option()
@timeout_option()
@click.option("--ssl", is_flag=True, help="Use HTTPS instead of HTTP")
@output_option()
def minio_scan(host, port, workers, timeout, ssl, output):
    """Scan MinIO for default credentials."""
    from hot_omelet.default_creds.minio import scan_minio
    host = prompt_host(host, "MinIO hostname or IP")
    scan_minio(host=host, port=port, max_workers=workers, timeout=timeout, use_ssl=ssl, output_file=output)
