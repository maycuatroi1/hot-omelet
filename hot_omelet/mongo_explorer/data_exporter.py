"""MongoDB data exporter module."""

import json
import os
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class MongoDBDataExporter:
    """Export MongoDB data to various formats."""

    def __init__(self, output_dir: str = "mongodb_exports"):
        """Initialize exporter with output directory."""
        self.output_dir = output_dir
        self._ensure_output_dir()

    def _ensure_output_dir(self):
        """Ensure output directory exists."""
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            logger.info(f"Created output directory: {self.output_dir}")

    def export_to_json(
        self, data: Dict[str, Any], host: str, port: int
    ) -> Optional[str]:
        """Export MongoDB data to JSON file."""
        if not data:
            logger.warning("No data to export")
            return None

        # Generate filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mongodb_data_{host}_{port}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        try:
            # Write data to JSON file
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)

            logger.info(f"Data exported to: {filepath}")

            # Calculate file size
            file_size = os.path.getsize(filepath)
            logger.info(f"Export file size: {self._format_size(file_size)}")

            return filepath

        except Exception as e:
            logger.error(f"Error exporting data to JSON: {str(e)}")
            return None

    def export_summary(
        self, data: Dict[str, Any], host: str, port: int
    ) -> Optional[str]:
        """Export a summary of MongoDB data."""
        if not data:
            logger.warning("No data to export")
            return None

        # Generate summary
        summary = {
            "scan_info": {
                "host": host,
                "port": port,
                "timestamp": datetime.now().isoformat(),
                "server_version": data.get("server_info", {}).get("version", "Unknown"),
            },
            "statistics": {
                "total_databases": len(data.get("databases", [])),
                "total_collections": sum(
                    len(db.get("collections", [])) for db in data.get("databases", [])
                ),
                "total_documents_sampled": sum(
                    len(coll.get("sample_data", []))
                    for db in data.get("databases", [])
                    for coll in db.get("collections", [])
                ),
                "total_users": len(data.get("users", [])),
            },
            "databases": [],
        }

        # Add database summaries
        for db in data.get("databases", []):
            db_summary = {
                "name": db.get("name"),
                "size_on_disk": db.get("sizeOnDisk", 0),
                "collections_count": db.get("collections_count", 0),
                "objects_count": db.get("objects", 0),
                "collections": [],
            }

            # Add collection summaries
            for coll in db.get("collections", []):
                coll_summary = {
                    "name": coll.get("name"),
                    "document_count": coll.get("count", 0),
                    "size": coll.get("size", 0),
                    "indexes_count": coll.get("nindexes", 0),
                    "sample_size": len(coll.get("sample_data", [])),
                }

                # Add schema info if available
                if "schema" in coll:
                    coll_summary["fields_detected"] = len(
                        coll["schema"].get("fields", {})
                    )

                db_summary["collections"].append(coll_summary)

            summary["databases"].append(db_summary)

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mongodb_summary_{host}_{port}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)

            logger.info(f"Summary exported to: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error exporting summary: {str(e)}")
            return None

    def export_schemas(
        self, data: Dict[str, Any], host: str, port: int
    ) -> Optional[str]:
        """Export collection schemas to a separate file."""
        schemas = {}

        # Extract schemas from data
        for db in data.get("databases", []):
            db_name = db.get("name")
            schemas[db_name] = {}

            for coll in db.get("collections", []):
                if "schema" in coll:
                    schemas[db_name][coll["name"]] = coll["schema"]

        if not any(schemas.values()):
            logger.warning("No schemas to export")
            return None

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mongodb_schemas_{host}_{port}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(schemas, f, indent=2)

            logger.info(f"Schemas exported to: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error exporting schemas: {str(e)}")
            return None

    def export_users(
        self, users: List[Dict[str, Any]], host: str, port: int
    ) -> Optional[str]:
        """Export MongoDB users information."""
        if not users:
            logger.warning("No users to export")
            return None

        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"mongodb_users_{host}_{port}_{timestamp}.json"
        filepath = os.path.join(self.output_dir, filename)

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump({"users": users}, f, indent=2)

            logger.info(f"Users exported to: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error exporting users: {str(e)}")
            return None

    def print_summary(self, data: Dict[str, Any]):
        """Print a summary of extracted data to console."""
        print("\n" + "=" * 50)
        print("MongoDB Data Extraction Summary")
        print("=" * 50)

        # Server info
        if "server_info" in data:
            print(f"\nServer Version: {data['server_info'].get('version', 'Unknown')}")
            if "hostInfo" in data["server_info"]:
                host_info = data["server_info"]["hostInfo"]
                print(f"OS: {host_info.get('os', {}).get('name', 'Unknown')}")
                print(
                    f"CPU Cores: {host_info.get('system', {}).get('numCores', 'Unknown')}"
                )
                print(
                    f"Memory: {host_info.get('system', {}).get('memSizeMB', 'Unknown')} MB"
                )

        # Database summary
        databases = data.get("databases", [])
        print(f"\nTotal Databases: {len(databases)}")

        for db in databases:
            print(f"\n  Database: {db.get('name', 'Unknown')}")
            print(f"    Size on Disk: {self._format_size(db.get('sizeOnDisk', 0))}")
            print(f"    Collections: {db.get('collections_count', 0)}")
            print(f"    Total Objects: {db.get('objects', 0)}")

            # Collection details
            collections = db.get("collections", [])
            if collections:
                print("    Collections:")
                for coll in collections[:5]:  # Show first 5 collections
                    print(
                        f"      - {coll.get('name')}: {coll.get('count', 0)} documents"
                    )
                if len(collections) > 5:
                    print(f"      ... and {len(collections) - 5} more collections")

        # User summary
        users = data.get("users", [])
        if users:
            print(f"\nTotal Users: {len(users)}")
            for user in users[:5]:  # Show first 5 users
                print(
                    f"  - {user.get('user')}@{user.get('db')} (Roles: {len(user.get('roles', []))})"
                )
            if len(users) > 5:
                print(f"  ... and {len(users) - 5} more users")

        print("\n" + "=" * 50)

    def _format_size(self, size_bytes: int) -> str:
        """Format size in bytes to human readable format."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"
