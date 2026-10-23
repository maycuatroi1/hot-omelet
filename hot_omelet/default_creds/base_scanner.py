"""Base class for default credential scanners."""

import json
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


class BaseDefaultCredsScanner(ABC):
    """Base class for service-specific default credential scanners."""

    def __init__(
        self,
        host: str,
        port: int,
        credentials: Optional[List[Tuple[str, str]]] = None,
        max_workers: int = 10,
        timeout: int = 5,
        verbose: bool = True,
    ):
        self.host = host
        self.port = port
        self.credentials = credentials or self.get_default_credentials()
        self.max_workers = max_workers
        self.timeout = timeout
        self.verbose = verbose
        self.results: List[Dict[str, Any]] = []

    @abstractmethod
    def get_default_credentials(self) -> List[Tuple[str, str]]:
        """Return list of default username/password pairs for this service."""
        pass

    @abstractmethod
    def test_connection(self, username: str, password: str) -> Dict[str, Any]:
        """Test a single credential pair against the service."""
        pass

    @abstractmethod
    def get_service_name(self) -> str:
        """Return the name of the service being scanned."""
        pass

    def scan(self) -> List[Dict[str, Any]]:
        """Scan the target with all configured credentials."""
        if self.verbose:
            print(
                f"[INFO] Starting {self.get_service_name()} scan on {self.host}:{self.port}"
            )
            print(
                f"[INFO] Testing {len(self.credentials)} credential pairs with {self.max_workers} threads"
            )

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []
            for username, password in self.credentials:
                future = executor.submit(self.test_connection, username, password)
                futures.append((future, username, password))

            for future, username, password in futures:
                try:
                    result = future.result(timeout=self.timeout)
                    if result["success"]:
                        if self.verbose:
                            print(
                                f"[SUCCESS] Valid credentials found: {username}:{password}"
                            )
                        self.results.append(result)
                    elif self.verbose and result.get("error"):
                        print(f"[ERROR] {username}:{password} - {result['error']}")
                except Exception as e:
                    if self.verbose:
                        print(f"[ERROR] {username}:{password} - {str(e)}")

        if self.verbose:
            print(
                f"[INFO] Scan completed. Found {len(self.results)} valid credential(s)"
            )

        return self.results

    def save_results(self, output_file: Optional[str] = None) -> str:
        """Save scan results to a JSON file."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = (
                f"{self.get_service_name().lower()}_scan_{self.host}_{timestamp}.json"
            )

        data = {
            "service": self.get_service_name(),
            "host": self.host,
            "port": self.port,
            "scan_time": datetime.now().isoformat(),
            "total_tested": len(self.credentials),
            "valid_found": len(self.results),
            "results": self.results,
        }

        with open(output_file, "w") as f:
            json.dump(data, f, indent=2)

        if self.verbose:
            print(f"[INFO] Results saved to {output_file}")

        return output_file

    def print_summary(self):
        """Print a summary of the scan results."""
        print(f"\n{self.get_service_name()} Scan Summary")
        print("=" * 50)
        print(f"Target: {self.host}:{self.port}")
        print(f"Credentials tested: {len(self.credentials)}")
        print(f"Valid credentials found: {len(self.results)}")

        if self.results:
            print("\nValid Credentials:")
            for result in self.results:
                print(
                    f"  - {result.get('username', 'N/A')}:{result.get('password', 'N/A')}"
                )
                if "info" in result:
                    print(f"    Additional info: {result['info']}")
        else:
            print("\nNo valid credentials found.")

    def get_valid_credentials(self) -> List[Tuple[str, str]]:
        """Return list of valid credential pairs found during scan."""
        return [
            (r["username"], r["password"]) for r in self.results if r.get("success")
        ]
