"""MongoDB default credential scanner."""

from typing import Dict, Any, List, Tuple
from .base_scanner import BaseDefaultCredsScanner


from pymongo import MongoClient
from pymongo.errors import (
    ConnectionFailure,
    OperationFailure,
    ServerSelectionTimeoutError,
)


DEFAULT_MONGODB_CREDENTIALS = [
    ("admin", "admin"),
    ("root", "root"),
    ("admin", "password"),
    ("root", "password"),
    ("admin", "admin123"),
    ("root", "root123"),
    ("admin", "123456"),
    ("root", "123456"),
    ("mongodb", "mongodb"),
    ("mongo", "mongo"),
    ("admin", "mongodb"),
    ("root", "mongodb"),
    ("admin", "mongo"),
    ("root", "mongo"),
    ("test", "test"),
    ("user", "password"),
    ("admin", ""),  # Empty password
    ("root", ""),  # Empty password
    ("", ""),  # No auth
]


class MongoDBScanner(BaseDefaultCredsScanner):
    """Scanner for MongoDB default credentials."""

    def __init__(
        self,
        host: str,
        port: int = 27017,
        credentials: List[Tuple[str, str]] = None,
        max_workers: int = 10,
        timeout: int = 5,
        verbose: bool = True,
        database: str = "admin",
    ):
        self.database = database
        super().__init__(host, port, credentials, max_workers, timeout, verbose)

    def get_default_credentials(self) -> List[Tuple[str, str]]:
        """Return default MongoDB credentials."""
        return DEFAULT_MONGODB_CREDENTIALS

    def get_service_name(self) -> str:
        """Return service name."""
        return "MongoDB"

    def test_connection(self, username: str, password: str) -> Dict[str, Any]:
        """Test credentials against MongoDB."""
        result = {
            "username": username,
            "password": password,
            "success": False,
            "service": "mongodb",
            "host": self.host,
            "port": self.port,
        }

        try:
            # Build connection string
            if username and password:
                connection_string = f"mongodb://{username}:{password}@{self.host}:{self.port}/{self.database}?authSource={self.database}"
            elif username:  # Username but no password
                connection_string = f"mongodb://{username}@{self.host}:{self.port}/{self.database}?authSource={self.database}"
            else:  # No authentication
                connection_string = f"mongodb://{self.host}:{self.port}/"

            # Attempt connection
            client = MongoClient(
                connection_string,
                serverSelectionTimeoutMS=self.timeout * 1000,
                connectTimeoutMS=self.timeout * 1000,
                socketTimeoutMS=self.timeout * 1000,
            )

            # Test connection by getting server info
            server_info = client.server_info()
            result["success"] = True

            # Get additional information
            info_parts = []

            # MongoDB version
            if "version" in server_info:
                info_parts.append(f"Version: {server_info['version']}")

            # Try to list databases
            try:
                db_list = client.list_database_names()
                info_parts.append(f"Databases: {len(db_list)}")

                # Get sample database names (excluding system dbs)
                user_dbs = [
                    db for db in db_list if db not in ["admin", "config", "local"]
                ]
                if user_dbs:
                    sample_dbs = user_dbs[:3]
                    info_parts.append(f"Sample DBs: {', '.join(sample_dbs)}")
            except:  # noqa: E722
                pass

            # Try to get replica set info
            try:
                admin_db = client.admin
                repl_status = admin_db.command("replSetGetStatus")
                if "set" in repl_status:
                    info_parts.append(f"Replica Set: {repl_status['set']}")
            except:  # noqa: E722
                pass

            result["info"] = (
                ", ".join(info_parts) if info_parts else "Connected successfully"
            )

            # Close connection
            client.close()

        except ServerSelectionTimeoutError:
            result["error"] = "Connection timeout"
        except ConnectionFailure as e:
            result["error"] = f"Connection failed: {str(e)}"
        except OperationFailure as e:
            if "Authentication failed" in str(e):
                result["error"] = "Invalid credentials"
            else:
                result["error"] = f"Operation failed: {str(e)}"
        except Exception as e:
            result["error"] = str(e)

        return result


def scan_mongodb(
    host: str,
    port: int = 27017,
    credentials: List[Tuple[str, str]] = None,
    max_workers: int = 10,
    timeout: int = 5,
    verbose: bool = True,
    database: str = "admin",
    output_file: str = None,
) -> Dict[str, Any]:
    """Scan MongoDB instance for default credentials."""
    scanner = MongoDBScanner(
        host=host,
        port=port,
        credentials=credentials,
        max_workers=max_workers,
        timeout=timeout,
        verbose=verbose,
        database=database,
    )

    results = scanner.scan()
    scanner.print_summary()

    if output_file:
        scanner.save_results(output_file)

    return {
        "host": host,
        "port": port,
        "service": "mongodb",
        "valid_credentials": scanner.get_valid_credentials(),
        "total_tested": len(scanner.credentials),
        "results": results,
    }
