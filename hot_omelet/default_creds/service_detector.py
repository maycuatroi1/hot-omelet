"""Service detection module for identifying web applications."""

import re
from typing import Optional, List
import requests
from bs4 import BeautifulSoup
import urllib3

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ServiceDetector:
    """Detect web applications based on HTTP responses."""

    # Service detection patterns
    SERVICES = {
        "airflow": {
            "title_patterns": [r"airflow", r"apache airflow"],
            "url_patterns": [r"/admin/airflow/", r"/login/", r"/home"],
            "header_patterns": {"Server": r"airflow"},
            "body_patterns": [r"airflow", r"dag_id", r"task_id"],
            "default_ports": [8080, 8081, 8082],
        },
        "minio": {
            "title_patterns": [r"minio"],
            "url_patterns": [r"/minio/", r"/login"],
            "header_patterns": {"Server": r"minio"},
            "body_patterns": [r"minio", r"bucket", r"object storage"],
            "default_ports": [9000, 9001],
        },
        "mongodb": {
            "title_patterns": [r"mongodb", r"mongo express"],
            "url_patterns": [r"/mongo/", r"/db/"],
            "header_patterns": {},
            "body_patterns": [r"mongodb", r"mongo express", r"collections"],
            "default_ports": [27017, 28017],
        },
        "redis": {
            "title_patterns": [r"redis"],
            "url_patterns": [r"/redis/"],
            "header_patterns": {},
            "body_patterns": [r"redis", r"key-value"],
            "default_ports": [6379],
        },
        "postgresql": {
            "title_patterns": [r"postgresql", r"pgadmin"],
            "url_patterns": [r"/pgadmin/", r"/postgres/"],
            "header_patterns": {},
            "body_patterns": [r"postgresql", r"pgadmin"],
            "default_ports": [5432, 5433],
        },
    }

    @classmethod
    def detect_service(
        cls, host: str, port: int, protocol: str = "http"
    ) -> Optional[str]:
        """
        Detect which service is running on the given host:port.

        Returns:
            Service name if detected, None otherwise
        """
        url = f"{protocol}://{host}:{port}"

        try:
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            response.raise_for_status()

            # Parse HTML
            soup = BeautifulSoup(response.text, "html.parser")
            title = soup.find("title")
            title_text = title.string.strip().lower() if title and title.string else ""

            # Check each service
            for service_name, patterns in cls.SERVICES.items():
                # For common ports (80, 443), require stronger evidence
                if int(port) in [80, 443]:
                    # Must have at least 2 different pattern matches for common ports
                    match_count = 0
                    if cls._check_title_patterns(
                        title_text, patterns.get("title_patterns", [])
                    ):
                        match_count += 1
                    if cls._check_url_patterns(
                        response.url, patterns.get("url_patterns", [])
                    ):
                        match_count += 1
                    if cls._check_header_patterns(
                        response.headers, patterns.get("header_patterns", {})
                    ):
                        match_count += 1
                    if cls._check_body_patterns(
                        response.text.lower(), patterns.get("body_patterns", [])
                    ):
                        match_count += 1

                    if match_count >= 2:
                        return service_name
                else:
                    # For non-common ports, use normal detection
                    if cls._check_patterns(response, soup, title_text, patterns):
                        return service_name

            return None

        except Exception:
            return None

    @classmethod
    def _check_patterns(cls, response, soup, title_text: str, patterns: dict) -> bool:
        """Check if response matches service patterns."""
        # Check title patterns
        if title_text:
            for pattern in patterns["title_patterns"]:
                if re.search(pattern, title_text, re.IGNORECASE):
                    return True

        # Check URL patterns
        for pattern in patterns["url_patterns"]:
            if re.search(pattern, response.url, re.IGNORECASE):
                return True

        # Check header patterns
        for header, pattern in patterns["header_patterns"].items():
            header_value = response.headers.get(header, "")
            if re.search(pattern, header_value, re.IGNORECASE):
                return True

        # Check body patterns
        body_text = response.text.lower()
        for pattern in patterns["body_patterns"]:
            if re.search(pattern, body_text, re.IGNORECASE):
                return True

        return False

    @classmethod
    def _check_title_patterns(cls, title_text: str, patterns: List[str]) -> bool:
        """Check if title matches any patterns."""
        if not title_text or not patterns:
            return False
        for pattern in patterns:
            if re.search(pattern, title_text, re.IGNORECASE):
                return True
        return False

    @classmethod
    def _check_url_patterns(cls, url: str, patterns: List[str]) -> bool:
        """Check if URL matches any patterns."""
        if not patterns:
            return False
        for pattern in patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    @classmethod
    def _check_header_patterns(cls, headers: dict, patterns: dict) -> bool:
        """Check if headers match any patterns."""
        if not patterns:
            return False
        for header, pattern in patterns.items():
            header_value = headers.get(header, "")
            if re.search(pattern, header_value, re.IGNORECASE):
                return True
        return False

    @classmethod
    def _check_body_patterns(cls, body_text: str, patterns: List[str]) -> bool:
        """Check if body matches any patterns."""
        if not patterns:
            return False
        for pattern in patterns:
            if re.search(pattern, body_text, re.IGNORECASE):
                return True
        return False

    @classmethod
    def get_scanner_for_service(cls, service: str):
        """Get the appropriate scanner function for a service."""
        scanner_map = {
            "airflow": ("src.default_creds.airflow", "scan_airflow"),
            "minio": ("src.default_creds.minio", "scan_minio"),
            "mongodb": ("src.default_creds.mongodb", "scan_mongodb"),
            "redis": ("src.default_creds.redis", "scan_redis"),
            "postgresql": ("src.pgsql.extract_pg_data", "extract_pg_data"),
        }

        if service in scanner_map:
            module_name, function_name = scanner_map[service]
            try:
                import importlib

                module = importlib.import_module(module_name)
                return getattr(module, function_name)
            except (ImportError, AttributeError):
                return None

        return None
