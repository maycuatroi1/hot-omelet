"""Redis default credential scanner."""

import redis
from typing import Dict, Any, List, Tuple
from .base_scanner import BaseDefaultCredsScanner

# Import data extraction modules
try:
    from src.hot_redis.redis_client import RedisClient
    from src.hot_redis.data_exporter import DataExporter
except ImportError:
    # Fallback if modules can't be imported
    RedisClient = None
    DataExporter = None


DEFAULT_REDIS_CREDENTIALS = [
    ("", ""),  # No authentication
    ("", "redis"),
    ("", "password"),
    ("", "admin"),
    ("", "123456"),
    ("", "redis123"),
    ("", "Redis123"),
    ("", "redis@123"),
    ("", "Redis@123"),
    ("", "default"),
    ("", "secret"),
    ("", "changeme"),
    ("", "redispass"),
    ("", "redisadmin"),
    ("", "redis1234"),
    ("", "redis12345"),
    ("", "redis123456"),
]


class RedisScanner(BaseDefaultCredsScanner):
    """Scanner for Redis default credentials."""

    def __init__(
        self,
        host: str,
        port: int = 6379,
        credentials: List[Tuple[str, str]] = None,
        max_workers: int = 10,
        timeout: int = 5,
        verbose: bool = True,
    ):
        super().__init__(host, port, credentials, max_workers, timeout, verbose)

    def get_default_credentials(self) -> List[Tuple[str, str]]:
        """Return default Redis credentials."""
        return DEFAULT_REDIS_CREDENTIALS

    def get_service_name(self) -> str:
        """Return service name."""
        return "Redis"

    def test_connection(self, username: str, password: str) -> Dict[str, Any]:
        """Test credentials against Redis server."""
        result = {
            "username": username,
            "password": password,
            "success": False,
            "service": "redis",
            "host": self.host,
            "port": self.port,
        }

        try:
            # Redis doesn't use username, only password
            client = redis.Redis(
                host=self.host,
                port=self.port,
                password=password if password else None,
                socket_timeout=self.timeout,
                socket_connect_timeout=self.timeout,
                decode_responses=True,
            )

            # Try to ping the server
            client.ping()
            result["success"] = True

            # Try to get server info
            try:
                info = client.info()
                version = info.get("redis_version", "Unknown")
                mode = info.get("redis_mode", "Unknown")

                # Get database info
                databases = []
                for i in range(16):  # Redis default has 16 databases
                    db_key = f"db{i}"
                    if db_key in info:
                        db_info = info[db_key]
                        keys = db_info.get("keys", 0)
                        if keys > 0:
                            databases.append(f"db{i}:{keys} keys")

                result["info"] = f"Version: {version}, Mode: {mode}"
                if databases:
                    result["info"] += f", Active DBs: {', '.join(databases[:3])}"
                    if len(databases) > 3:
                        result["info"] += f" (+{len(databases) - 3} more)"

                # Get total key count
                try:
                    total_keys = sum(
                        client.dbsize()
                        for _ in range(
                            client.execute_command("CONFIG GET databases")[1]
                        )
                    )
                    if total_keys > 0:
                        result["info"] += f", Total keys: {total_keys}"
                except:  # noqa: E722
                    pass

            except Exception:
                # If we can't get info, at least we know connection works
                result["info"] = "Connection successful"

            # Close connection
            client.close()

        except redis.exceptions.AuthenticationError:
            result["error"] = "Authentication failed"
        except redis.exceptions.ConnectionError:
            result["error"] = "Connection failed"
        except redis.exceptions.TimeoutError:
            result["error"] = "Connection timeout"
        except Exception as e:
            result["error"] = str(e)

        return result


def scan_redis(
    host: str,
    port: int = 6379,
    credentials: List[Tuple[str, str]] = None,
    max_workers: int = 10,
    timeout: int = 5,
    verbose: bool = True,
    output_file: str = None,
    auto_export: bool = False,
) -> Dict[str, Any]:
    """Scan Redis instance for default credentials.

    Args:
        host: Target Redis host
        port: Target Redis port
        credentials: List of (username, password) tuples to test
        max_workers: Maximum number of parallel workers
        timeout: Connection timeout in seconds
        verbose: Print verbose output
        output_file: File to save scan results
        auto_export: Automatically export data when valid credentials are found

    Returns:
        Dictionary containing scan results and extracted data (if auto_export is True)
    """
    scanner = RedisScanner(
        host=host,
        port=port,
        credentials=credentials,
        max_workers=max_workers,
        timeout=timeout,
        verbose=verbose,
    )

    results = scanner.scan()
    scanner.print_summary()

    if output_file:
        scanner.save_results(output_file)

    # Get valid credentials
    valid_creds = scanner.get_valid_credentials()

    # Auto-export data if requested and valid credentials found
    extracted_data = None
    if auto_export and valid_creds and RedisClient and DataExporter:
        print(
            f"\n[INFO] Found {len(valid_creds)} valid credential(s). Attempting to extract data..."
        )

        # Use the first valid credential to extract data
        first_cred = valid_creds[0]
        password = first_cred.get("password", None)

        try:
            # Create Redis client with valid credentials
            redis_client = RedisClient(
                host=host,
                port=port,
                password=password if password else None,
                socket_timeout=timeout,
            )

            # Connect and extract data
            if redis_client.connect():
                print("[INFO] Extracting data from Redis...")
                extracted_data = redis_client.extract_data()

                # Export to JSON and display rich table
                # Note: DataExporter.export_to_json now handles all display
                _ = DataExporter.export_to_json(extracted_data, host, port)
            else:
                print("[ERROR] Failed to connect with valid credentials")

        except Exception as e:
            print(f"[ERROR] Failed to extract data: {str(e)}")
    elif auto_export and not valid_creds:
        print("[INFO] No valid credentials found, skipping data export")
    elif auto_export and not RedisClient:
        print("[WARNING] Data export modules not available, skipping export")

    return {
        "host": host,
        "port": port,
        "service": "redis",
        "valid_credentials": valid_creds,
        "total_tested": len(scanner.credentials),
        "results": results,
        "extracted_data": extracted_data if auto_export else None,
    }
