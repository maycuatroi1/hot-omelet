"""MongoDB data extractor - high-level orchestration."""

import logging
from typing import Dict, Any, Optional
from .mongodb_client import MongoDBClient
from .data_exporter import MongoDBDataExporter

logger = logging.getLogger(__name__)


class MongoDBExtractor:
    """High-level MongoDB data extraction orchestrator."""

    def __init__(
        self,
        host: str,
        port: int = 27017,
        username: str = "",
        password: str = "",
        database: str = "admin",
        timeout: int = 5,
    ):
        """Initialize MongoDB extractor."""
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.database = database
        self.timeout = timeout
        self.client = None
        self.exporter = MongoDBDataExporter()

    def extract_all(
        self,
        sample_limit: int = 100,
        skip_system_dbs: bool = True,
        analyze_schemas: bool = True,
        export_format: str = "json",
    ) -> Dict[str, Any]:
        """Extract comprehensive MongoDB data."""
        logger.info(f"Starting MongoDB extraction from {self.host}:{self.port}")

        # Initialize client
        self.client = MongoDBClient(
            self.host,
            self.port,
            self.username,
            self.password,
            self.database,
            self.timeout,
        )

        # Connect to MongoDB
        if not self.client.connect():
            logger.error("Failed to connect to MongoDB")
            return {"error": "Connection failed"}

        try:
            # Extract all data
            extracted_data = {
                "host": self.host,
                "port": self.port,
                "extraction_timestamp": self._get_timestamp(),
                "server_info": {},
                "databases": [],
                "users": [],
                "extraction_stats": {},
            }

            # Get server information
            logger.info("Extracting server information...")
            extracted_data["server_info"] = self.client.get_server_info()

            # Get users
            logger.info("Extracting user information...")
            extracted_data["users"] = self.client.get_users()

            # Get databases
            logger.info("Extracting database information...")
            databases = self.client.list_databases()

            # Filter system databases if requested
            if skip_system_dbs:
                databases = [
                    db
                    for db in databases
                    if db.get("name") not in ["admin", "config", "local"]
                ]

            # Extract data from each database
            total_collections = 0
            total_documents = 0

            for db_info in databases:
                db_name = db_info.get("name")
                if not db_name:
                    continue

                logger.info(f"Processing database: {db_name}")

                # Get collections
                collections = self.client.list_collections(db_name)
                db_data = {
                    "name": db_name,
                    "info": db_info,
                    "collections": [],
                    "collections_count": len(collections),
                    "sizeOnDisk": db_info.get("sizeOnDisk", 0),
                    "objects": db_info.get("objects", 0),
                }

                # Process each collection
                for coll_info in collections:
                    coll_name = coll_info.get("name")
                    if not coll_name:
                        continue

                    logger.info(f"  Processing collection: {db_name}.{coll_name}")

                    coll_data = {
                        "name": coll_name,
                        "info": coll_info,
                        "count": coll_info.get("count", 0),
                        "size": coll_info.get("size", 0),
                        "nindexes": coll_info.get("nindexes", 0),
                    }

                    # Extract sample data
                    if sample_limit > 0:
                        logger.info(
                            f"    Extracting sample data (limit: {sample_limit})..."
                        )
                        sample_data = self.client.extract_sample_data(
                            db_name, coll_name, limit=sample_limit
                        )
                        coll_data["sample_data"] = sample_data
                        coll_data["sample_count"] = len(sample_data)
                        total_documents += len(sample_data)

                    # Analyze schema if requested
                    if analyze_schemas and coll_info.get("count", 0) > 0:
                        logger.info("    Analyzing collection schema...")
                        schema = self.client.get_collection_schema(
                            db_name, coll_name, sample_size=min(sample_limit, 100)
                        )
                        coll_data["schema"] = schema

                    db_data["collections"].append(coll_data)
                    total_collections += 1

                extracted_data["databases"].append(db_data)

            # Update extraction statistics
            extracted_data["extraction_stats"] = {
                "databases_count": len(extracted_data["databases"]),
                "collections_count": total_collections,
                "documents_sampled": total_documents,
                "users_count": len(extracted_data["users"]),
            }

            # Export data
            logger.info("Exporting extracted data...")
            export_paths = self._export_data(extracted_data, export_format)
            extracted_data["export_paths"] = export_paths

            # Print summary
            self.exporter.print_summary(extracted_data)

            return extracted_data

        except Exception as e:
            logger.error(f"Error during extraction: {str(e)}")
            return {"error": str(e)}

        finally:
            # Disconnect
            if self.client:
                self.client.disconnect()

    def extract_database(
        self, database_name: str, sample_limit: int = 100, analyze_schemas: bool = True
    ) -> Dict[str, Any]:
        """Extract data from a specific database."""
        logger.info(f"Extracting database: {database_name}")

        # Initialize client
        self.client = MongoDBClient(
            self.host,
            self.port,
            self.username,
            self.password,
            self.database,
            self.timeout,
        )

        # Connect to MongoDB
        if not self.client.connect():
            logger.error("Failed to connect to MongoDB")
            return {"error": "Connection failed"}

        try:
            # Get database info
            databases = self.client.list_databases()
            db_info = next(
                (db for db in databases if db.get("name") == database_name), None
            )

            if not db_info:
                return {"error": f"Database '{database_name}' not found"}

            # Extract database data
            result = {
                "database": database_name,
                "info": db_info,
                "collections": [],
                "extraction_timestamp": self._get_timestamp(),
            }

            # Get collections
            collections = self.client.list_collections(database_name)

            for coll_info in collections:
                coll_name = coll_info.get("name")
                if not coll_name:
                    continue

                logger.info(f"Processing collection: {coll_name}")

                coll_data = {
                    "name": coll_name,
                    "info": coll_info,
                }

                # Extract sample data
                if sample_limit > 0:
                    sample_data = self.client.extract_sample_data(
                        database_name, coll_name, limit=sample_limit
                    )
                    coll_data["sample_data"] = sample_data

                # Analyze schema
                if analyze_schemas and coll_info.get("count", 0) > 0:
                    schema = self.client.get_collection_schema(
                        database_name, coll_name, sample_size=min(sample_limit, 100)
                    )
                    coll_data["schema"] = schema

                result["collections"].append(coll_data)

            return result

        except Exception as e:
            logger.error(f"Error extracting database: {str(e)}")
            return {"error": str(e)}

        finally:
            if self.client:
                self.client.disconnect()

    def extract_collection(
        self,
        database_name: str,
        collection_name: str,
        sample_limit: int = 100,
        filter_query: Optional[Dict] = None,
        analyze_schema: bool = True,
    ) -> Dict[str, Any]:
        """Extract data from a specific collection."""
        logger.info(f"Extracting collection: {database_name}.{collection_name}")

        # Initialize client
        self.client = MongoDBClient(
            self.host,
            self.port,
            self.username,
            self.password,
            self.database,
            self.timeout,
        )

        # Connect to MongoDB
        if not self.client.connect():
            logger.error("Failed to connect to MongoDB")
            return {"error": "Connection failed"}

        try:
            # Get collection info
            collections = self.client.list_collections(database_name)
            coll_info = next(
                (c for c in collections if c.get("name") == collection_name), None
            )

            if not coll_info:
                return {
                    "error": f"Collection '{collection_name}' not found in '{database_name}'"
                }

            # Extract collection data
            result = {
                "database": database_name,
                "collection": collection_name,
                "info": coll_info,
                "extraction_timestamp": self._get_timestamp(),
            }

            # Extract sample data
            if sample_limit > 0:
                sample_data = self.client.extract_sample_data(
                    database_name,
                    collection_name,
                    limit=sample_limit,
                    filter_query=filter_query,
                )
                result["sample_data"] = sample_data
                result["sample_count"] = len(sample_data)

            # Analyze schema
            if analyze_schema and coll_info.get("count", 0) > 0:
                schema = self.client.get_collection_schema(
                    database_name, collection_name, sample_size=min(sample_limit, 100)
                )
                result["schema"] = schema

            return result

        except Exception as e:
            logger.error(f"Error extracting collection: {str(e)}")
            return {"error": str(e)}

        finally:
            if self.client:
                self.client.disconnect()

    def _export_data(
        self, data: Dict[str, Any], format: str = "json"
    ) -> Dict[str, str]:
        """Export extracted data in various formats."""
        export_paths = {}

        if format == "json" or format == "all":
            # Export full data
            path = self.exporter.export_to_json(data, self.host, self.port)
            if path:
                export_paths["full_data"] = path

            # Export summary
            path = self.exporter.export_summary(data, self.host, self.port)
            if path:
                export_paths["summary"] = path

            # Export schemas
            path = self.exporter.export_schemas(data, self.host, self.port)
            if path:
                export_paths["schemas"] = path

            # Export users
            if data.get("users"):
                path = self.exporter.export_users(data["users"], self.host, self.port)
                if path:
                    export_paths["users"] = path

        return export_paths

    def _get_timestamp(self) -> str:
        """Get current timestamp in ISO format."""
        from datetime import datetime

        return datetime.now().isoformat()


def extract_mongodb_data(
    host: str,
    port: int = 27017,
    username: str = "",
    password: str = "",
    database: str = "admin",
    sample_limit: int = 100,
    skip_system_dbs: bool = True,
    analyze_schemas: bool = True,
) -> Dict[str, Any]:
    """
    Extract MongoDB data using provided credentials.

    Args:
        host: MongoDB host
        port: MongoDB port (default: 27017)
        username: Username for authentication
        password: Password for authentication
        database: Authentication database (default: admin)
        sample_limit: Number of documents to sample per collection
        skip_system_dbs: Skip system databases (admin, config, local)
        analyze_schemas: Analyze collection schemas

    Returns:
        Dictionary containing extracted data
    """
    extractor = MongoDBExtractor(
        host=host, port=port, username=username, password=password, database=database
    )

    return extractor.extract_all(
        sample_limit=sample_limit,
        skip_system_dbs=skip_system_dbs,
        analyze_schemas=analyze_schemas,
    )
