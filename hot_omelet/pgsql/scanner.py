import json
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any, Optional

try:
    import psycopg2
except ImportError:  # optional; `hot install` / pip install .[full] provides it
    psycopg2 = None

# Common default PostgreSQL credentials
DEFAULT_CREDENTIALS = [
    {"username": "postgres", "password": "postgres"},
    {"username": "postgres", "password": ""},
    {"username": "postgres", "password": "admin"},
    {"username": "postgres", "password": "password"},
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "root", "password": "root"},
    {"username": "root", "password": "password"},
    {"username": "postgres", "password": "postgresql"},
    {"username": "postgres", "password": "123456"},
    {"username": "airflow", "password": "airflow"},
    {"username": "innovature_analytic", "password": "innovature_analytic"},
    {"username": "postgres", "password": "qai@2025"},
    {"username": "postgres", "password": "qai@2024"},
    {"username": "postgres", "password": "qai@12345"},
    {"username": "postgres", "password": "qai@123456"},
]


class PostgreSQLScanner:
    """Class for scanning PostgreSQL servers for default credentials"""

    def __init__(
        self,
        host: str,
        port: int = 5432,
        credentials: Optional[List[Dict[str, str]]] = None,
        max_workers: int = 5,
        timeout: int = 3,
        database: str = "postgres",
    ):
        """
        Initialize the PostgreSQL scanner

        Args:
            host: Target PostgreSQL server IP or hostname
            port: PostgreSQL server port (default: 5432)
            credentials: List of credential dictionaries with username and password keys
            max_workers: Maximum number of concurrent connection attempts
            timeout: Connection timeout in seconds
            database: Default database to connect to
        """
        self.host = host
        self.port = port
        self.credentials = (
            credentials if credentials is not None else DEFAULT_CREDENTIALS
        )
        self.max_workers = max_workers
        self.timeout = timeout
        self.database = database
        self.results = []

    def test_connection(self, username: str, password: str) -> Dict[str, Any]:
        """Test if a connection can be established with the given credentials"""
        if psycopg2 is None:
            return {
                "status": "failed",
                "username": username,
                "password": password,
                "error": "psycopg2 not installed (pip install psycopg2-binary)",
            }
        try:
            conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                user=username,
                password=password,
                database=self.database,
                connect_timeout=self.timeout,
            )

            # Connection successful
            cur = conn.cursor()

            # Get PostgreSQL version
            cur.execute("SELECT version();")
            version = cur.fetchone()[0]

            # Get database list
            cur.execute("SELECT datname FROM pg_database WHERE datistemplate = false;")
            databases = [row[0] for row in cur.fetchall()]

            # Close connection
            cur.close()
            conn.close()

            return {
                "status": "success",
                "username": username,
                "password": password,
                "version": version,
                "databases": databases,
            }

        except psycopg2.OperationalError as e:
            # Connection failed
            return {
                "status": "failed",
                "username": username,
                "password": password,
                "error": str(e),
            }
        except Exception as e:
            return {
                "status": "error",
                "username": username,
                "password": password,
                "error": str(e),
            }

    def scan(self, verbose: bool = True) -> List[Dict[str, Any]]:
        """
        Scan a PostgreSQL server for default credentials

        Args:
            verbose: Whether to print progress and results to console

        Returns:
            List of result dictionaries with connection test outcomes
        """
        if verbose:
            print(
                f"[INFO] Starting scan of PostgreSQL server at {self.host}:{self.port}"
            )
            print(f"[INFO] Testing {len(self.credentials)} credential combinations")

        self.results = []
        successful_attempts = 0

        # Use ThreadPoolExecutor for parallel attempts
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_cred = {
                executor.submit(
                    self.test_connection, cred["username"], cred["password"]
                ): cred
                for cred in self.credentials
            }

            for future in future_to_cred:
                result = future.result()
                self.results.append(result)

                if result["status"] == "success" and verbose:
                    successful_attempts += 1
                    print(
                        f"[SUCCESS] Found valid credentials: {result['username']}/{result['password']}"
                    )
                    print(f"  - PostgreSQL version: {result['version']}")
                    print(f"  - Databases: {', '.join(result['databases'])}")

        if verbose:
            print(
                f"[INFO] Scan completed. Found {successful_attempts} valid credential combinations."
            )

        return self.results

    def save_results(self, filename: Optional[str] = None) -> str:
        """
        Save scan results to a file

        Args:
            filename: Optional filename, defaults to pgsql_scan_{host}_{port}.json

        Returns:
            Path to the saved file
        """
        if not self.results:
            raise ValueError("No scan results to save. Run scan() method first.")
        is_success = any(r["status"] == "success" for r in self.results)
        if not is_success:
            print(f"[INFO] No valid credentials found for {self.host}:{self.port}")
            return None
        if filename is None:
            filename = f"pgsql_scan_{self.host}_{self.port}.json"

        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)

        return filename

    def print_summary(self) -> None:
        """Print a summary of scan results"""
        if not self.results:
            print("[INFO] No scan results available. Run scan() method first.")
            return

        success_count = sum(1 for r in self.results if r["status"] == "success")

        print("\nScan Summary:")
        print(f"  - Tested combinations: {len(self.results)}")
        print(f"  - Successful logins: {success_count}")
        print(f"  - Failed logins: {len(self.results) - success_count}")

        if success_count > 0:
            print("\nSuccessful logins:")
            for result in self.results:
                if result["status"] == "success":
                    print(f"  - {result['username']}/{result['password']}")
