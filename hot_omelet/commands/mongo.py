"""`hot mongo ...` - MongoDB enumeration and PII extraction."""
import click

from hot_omelet.commands._common import (
    host_port_options,
    output_option,
    prompt_host,
    timeout_option,
    workers_option,
)


@click.group("mongo")
def mongo():
    """MongoDB enumeration and PII extraction."""


@mongo.command("scan")
@host_port_options(27017)
@workers_option()
@timeout_option()
@click.option("--database", default="admin", show_default=True, help="Database to authenticate against")
@output_option()
def mongo_scan(host, port, workers, timeout, database, output):
    """Scan MongoDB for default credentials."""
    from hot_omelet.default_creds.mongodb import scan_mongodb
    host = prompt_host(host, "MongoDB hostname or IP")
    scan_mongodb(host=host, port=port, max_workers=workers, timeout=timeout, database=database, output_file=output)


@mongo.command("dump")
@host_port_options(27017)
@click.option("--username", default="", help="Username for authentication")
@click.option("--password", default="", help="Password for authentication")
@click.option("--database", default="admin", show_default=True, help="Authentication database")
@click.option("--sample-limit", default=100, show_default=True, type=int,
              help="Number of documents to sample per collection")
@click.option("--skip-system-dbs/--include-system-dbs", default=True, help="Skip system databases")
@click.option("--no-schemas", is_flag=True, help="Don't analyze collection schemas")
def mongo_dump(host, port, username, password, database, sample_limit, skip_system_dbs, no_schemas):
    """Extract data from a MongoDB server."""
    from hot_omelet.data_extraction import mongodb_dump_command
    host = prompt_host(host, "MongoDB hostname or IP")
    mongodb_dump_command(host, port, username, password, database, sample_limit, skip_system_dbs, not no_schemas)


@mongo.command("pii")
@host_port_options(27017)
@click.option("--username", default="", help="Username")
@click.option("--password", default="", help="Password")
@click.option("--limit", default=200, show_default=True, type=int, help="Max PII records to extract")
@click.option("--output", default="pii_evidence.xlsx", show_default=True, help="Output file")
@click.option("--format", "fmt", type=click.Choice(["excel", "json", "all"]), default="excel")
@click.option("--target-name", default="", help="Target name for report header")
def mongo_pii(host, port, username, password, limit, output, fmt, target_name):
    """Extract PII from MongoDB and export to Excel/JSON evidence."""
    from hot_omelet.mongo_explorer.pii_extractor import mongo_pii as _mongo_pii
    host = prompt_host(host, "MongoDB hostname or IP")
    _mongo_pii(host, port, username, password, "admin", limit, output, fmt, target_name)
