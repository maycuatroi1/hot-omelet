"""
Unified credential scanner module for various services.
Simplifies and centralizes default credential scanning logic.
"""

from typing import Dict, Any, Optional
import click

from hot_omelet.default_creds.airflow import scan_airflow
from hot_omelet.default_creds.minio import scan_minio
from hot_omelet.default_creds.mongodb import scan_mongodb
from hot_omelet.default_creds.redis import scan_redis
from hot_omelet.mongo_explorer.mongodb_extractor import extract_mongodb_data
from hot_omelet.pgsql.extract_pg_data import extract_pg_data


class CredentialScanner:
    """Unified scanner for default credentials across different services."""

    def __init__(self):
        self.scanners = {
            "airflow": self._scan_airflow,
            "minio": self._scan_minio,
            "mongodb": self._scan_mongodb,
            "redis": self._scan_redis,
            "postgresql": self._scan_postgresql,
        }

    def scan_service(
        self, host: str, port: str, service: str
    ) -> Dict[str, Any]:
        """Scan a service for default credentials."""
        result = {
            "service": service,
            "port": port,
            "host": host,
            "vulnerable": False,
            "credentials": [],
            "info": {},
            "error": None,
        }

        scanner = self.scanners.get(service)
        if not scanner:
            result["error"] = f"Unknown service: {service}"
            return result

        try:
            scanner(host, port, result)
        except Exception as e:
            result["error"] = str(e)
            click.echo(f"Error scanning {service}: {str(e)}")

        return result

    def _scan_airflow(
        self, host: str, port: str, protocol: Optional[str], result: Dict[str, Any]
    ):
        """Scan Apache Airflow."""
        use_ssl = protocol == "https" if protocol else False
        scan_result = scan_airflow(
            host=host,
            port=int(port),
            max_workers=5,
            timeout=5,
            use_ssl=use_ssl,
            output_file=None,
            verbose=False,
        )
        self._process_scan_result(scan_result, result)

    def _scan_minio(
        self, host: str, port: str, result: Dict[str, Any]
    ):
        """Scan MinIO."""
        scan_result = scan_minio(
            host=host,
            port=int(port),
            max_workers=5,
            timeout=5,
            use_ssl=False,
            output_file=None,
            verbose=False,
        )
        self._process_scan_result(scan_result, result)

    def _scan_mongodb(
        self, host: str, port: str, result: Dict[str, Any]
    ):
        """Scan MongoDB and optionally extract data."""
        scan_result = scan_mongodb(
            host=host,
            port=int(port),
            max_workers=5,
            timeout=5,
            database="admin",
            output_file=None,
            verbose=False,
        )
        self._process_scan_result(scan_result, result)

        # Auto-extract MongoDB data if credentials found
        if result["vulnerable"] and result["credentials"]:
            self._extract_mongodb_data(host, port, result)

    def _scan_redis(
        self, host: str, port: str, result: Dict[str, Any]
    ):
        """Scan Redis."""
        scan_result = scan_redis(
            host=host, port=int(port), max_workers=5, timeout=5, verbose=False
        )        
        self._process_scan_result(scan_result, result)

    def _scan_postgresql(
        self, host: str, port: str, result: Dict[str, Any]
    ):
        """Scan PostgreSQL."""
        click.echo("Scanning PostgreSQL for default credentials...")
        pg_result = extract_pg_data(ip=host, port=int(port))
        if pg_result:
            result["info"]["scan_completed"] = True

    def _process_scan_result(self, scan_result: Dict[str, Any], result: Dict[str, Any]):
        """Process scan results in a unified way."""
        if not scan_result or not scan_result.get("valid_credentials"):
            return

        result["vulnerable"] = True

        # Handle results with additional info
        if "results" in scan_result:
            for cred in scan_result["results"]:
                if cred.get("success"):
                    result["credentials"].append(self._extract_credential(cred))
        else:
            # Handle tuple format
            for cred in scan_result["valid_credentials"]:
                result["credentials"].append(self._extract_credential(cred))

    def _extract_credential(self, cred) -> Dict[str, str]:
        """Extract credential info from various formats."""
        if isinstance(cred, tuple):
            return {
                "username": cred[0] if len(cred) > 0 else "",
                "password": cred[1] if len(cred) > 1 else "",
                "info": "",
            }
        return {
            "username": cred.get("username", ""),
            "password": cred.get("password", ""),
            "info": cred.get("info", ""),
        }

    def _extract_mongodb_data(self, host: str, port: str, result: Dict[str, Any]):
        """Extract MongoDB data when valid credentials are found."""
        click.echo("\n--- Exploring MongoDB data ---")
        first_cred = result["credentials"][0]

        try:
            extract_result = extract_mongodb_data(
                host=host,
                port=int(port),
                username=first_cred.get("username", ""),
                password=first_cred.get("password", ""),
                database="admin",
                sample_limit=50,
                skip_system_dbs=True,
                analyze_schemas=True,
            )

            if "export_paths" in extract_result:
                result["info"]["mongodb_exports"] = extract_result["export_paths"]
                result["info"]["databases_found"] = extract_result.get(
                    "extraction_stats", {}
                ).get("databases_count", 0)
                result["info"]["collections_found"] = extract_result.get(
                    "extraction_stats", {}
                ).get("collections_count", 0)
        except Exception as e:
            click.echo(f"Error exploring MongoDB: {str(e)}")
            result["info"]["extraction_error"] = str(e)
