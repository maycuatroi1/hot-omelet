"""
Data extraction commands module.
Handles database dumps and data extraction for various services.
"""

import click
from typing import Optional

from hot_omelet.hot_redis.redis_extractor import extract_redis_data
from hot_omelet.hot_redis.redis_attacker import attack_redis
from hot_omelet.pgsql.extract_pg_data import extract_pg_data
from hot_omelet.mongo_explorer.mongodb_extractor import extract_mongodb_data


def redis_dump_command(host: str, port: int, username: Optional[str]=None, password: Optional[str]=None):
    """Extract data from a Redis server."""
    data = extract_redis_data(ip=host, port=port, username=username, password=password)
    if data is None:
        raise click.ClickException("Failed to extract data")


def redis_attack_command(
    host: str, port: int, password: Optional[str], output: Optional[str]
):
    """Comprehensive Redis attack toolkit."""
    attack_redis(host=host, port=port, password=password, output_file=output)


def pgsql_scan_command(host: str, port: int):
    """Scan PostgreSQL for default credentials and extract data."""
    extract_pg_data(ip=host, port=port)


def mongodb_dump_command(
    host: str,
    port: int,
    username: str,
    password: str,
    database: str,
    sample_limit: int,
    skip_system_dbs: bool,
    analyze_schemas: bool,
):
    """Extract data from a MongoDB server."""
    result = extract_mongodb_data(
        host=host,
        port=port,
        username=username,
        password=password,
        database=database,
        sample_limit=sample_limit,
        skip_system_dbs=skip_system_dbs,
        analyze_schemas=analyze_schemas,
    )

    if "error" in result:
        raise click.ClickException(f"Failed to extract data: {result['error']}")
