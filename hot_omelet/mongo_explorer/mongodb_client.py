"""MongoDB client for data exploration and extraction."""

import base64
from typing import Dict, Any, List, Optional
from datetime import datetime
from bson import ObjectId, Binary, Timestamp
from pymongo import MongoClient
from pymongo.errors import (
    ConnectionFailure,
    ServerSelectionTimeoutError,
)
import logging


class MongoDBClient:
    """MongoDB client with data exploration capabilities."""

    def __init__(
        self,
        host: str,
        port: int = 27017,
        username: str = "",
        password: str = "",
        database: str = "admin",
        timeout: int = 5,
    ):
        """Initialize MongoDB client."""
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.database = database
        self.timeout = timeout
        self.client = None
        self.connected = False

    def connect(self) -> bool:
        """Establish connection to MongoDB."""
        try:
            # Build connection string
            if self.username and self.password:
                connection_string = f"mongodb://{self.username}:{self.password}@{self.host}:{self.port}/{self.database}?authSource={self.database}"
            elif self.username:
                connection_string = f"mongodb://{self.username}@{self.host}:{self.port}/{self.database}?authSource={self.database}"
            else:
                connection_string = f"mongodb://{self.host}:{self.port}/"

            # Attempt connection
            self.client = MongoClient(
                connection_string,
                serverSelectionTimeoutMS=self.timeout * 1000,
                connectTimeoutMS=self.timeout * 1000,
                socketTimeoutMS=self.timeout * 1000,
            )

            # Test connection
            self.client.server_info()
            self.connected = True
            logging.info(
                f"Successfully connected to MongoDB at {self.host}:{self.port}"
            )
            return True

        except ServerSelectionTimeoutError:
            logging.error(f"Connection timeout to {self.host}:{self.port}")
            self.connected = False
            return False
        except ConnectionFailure as e:
            logging.error(f"Connection failed to {self.host}:{self.port}: {str(e)}")
            self.connected = False
            return False
        except Exception as e:
            logging.error(
                f"Unexpected error connecting to {self.host}:{self.port}: {str(e)}"
            )
            self.connected = False
            return False

    def disconnect(self):
        """Close MongoDB connection."""
        if self.client:
            self.client.close()
            self.connected = False
            logging.info("Disconnected from MongoDB")

    def get_server_info(self) -> Dict[str, Any]:
        """Get MongoDB server information."""
        if not self.connected:
            return {}

        try:
            info = self.client.server_info()
            admin_db = self.client.admin

            # Extract relevant information
            server_data = {
                "version": info.get("version", "Unknown"),
                "gitVersion": info.get("gitVersion", "Unknown"),
                "modules": info.get("modules", []),
                "allocator": info.get("allocator", "Unknown"),
                "javascriptEngine": info.get("javascriptEngine", "Unknown"),
                "storageEngines": info.get("storageEngines", []),
            }

            # Try to get build info
            try:
                build_info = admin_db.command("buildInfo")
                server_data["buildInfo"] = {
                    "version": build_info.get("version"),
                    "gitVersion": build_info.get("gitVersion"),
                    "openSSLVersion": build_info.get("openSSLVersion"),
                    "allocator": build_info.get("allocator"),
                    "javascriptEngine": build_info.get("javascriptEngine"),
                }
            except:  # noqa: E722
                pass

            # Try to get host info
            try:
                host_info = admin_db.command("hostInfo")
                server_data["hostInfo"] = {
                    "os": {
                        "type": host_info.get("os", {}).get("type"),
                        "name": host_info.get("os", {}).get("name"),
                        "version": host_info.get("os", {}).get("version"),
                    },
                    "system": {
                        "cpuArch": host_info.get("system", {}).get("cpuArch"),
                        "numCores": host_info.get("system", {}).get("numCores"),
                        "memSizeMB": host_info.get("system", {}).get("memSizeMB"),
                    },
                }
            except:  # noqa: E722
                pass

            return server_data

        except Exception as e:
            logging.error(f"Error getting server info: {str(e)}")
            return {}

    def list_databases(self) -> List[Dict[str, Any]]:
        """List all databases with their sizes."""
        if not self.connected:
            return []

        try:
            # Get database list
            db_list = []

            # Try to list databases
            try:
                database_names = self.client.list_database_names()

                for db_name in database_names:
                    try:
                        db = self.client[db_name]
                        stats = db.command("dbStats")

                        db_info = {
                            "name": db_name,
                            "sizeOnDisk": stats.get("dataSize", 0),
                            "storageSize": stats.get("storageSize", 0),
                            "collections": stats.get("collections", 0),
                            "objects": stats.get("objects", 0),
                            "avgObjSize": stats.get("avgObjSize", 0),
                            "indexes": stats.get("indexes", 0),
                            "indexSize": stats.get("indexSize", 0),
                        }
                        db_list.append(db_info)

                    except Exception as e:
                        # If we can't get stats, just add the name
                        db_list.append({"name": db_name, "error": str(e)})

            except Exception as e:
                logging.error(f"Error listing databases: {str(e)}")

            return db_list

        except Exception as e:
            logging.error(f"Error in list_databases: {str(e)}")
            return []

    def list_collections(self, database_name: str) -> List[Dict[str, Any]]:
        """List all collections in a database."""
        if not self.connected:
            return []

        try:
            db = self.client[database_name]
            collections = []

            for collection_name in db.list_collection_names():
                try:
                    stats = db.command("collStats", collection_name)

                    collection_info = {
                        "name": collection_name,
                        "count": stats.get("count", 0),
                        "size": stats.get("size", 0),
                        "storageSize": stats.get("storageSize", 0),
                        "totalIndexSize": stats.get("totalIndexSize", 0),
                        "nindexes": stats.get("nindexes", 0),
                        "capped": stats.get("capped", False),
                    }
                    collections.append(collection_info)

                except Exception as e:
                    collections.append({"name": collection_name, "error": str(e)})

            return collections

        except Exception as e:
            logging.error(f"Error listing collections: {str(e)}")
            return []

    def _convert_value(self, value: Any) -> Any:
        """Convert MongoDB types to JSON serializable format."""
        if isinstance(value, ObjectId):
            return {"$oid": str(value)}
        elif isinstance(value, Binary):
            return {"$binary": base64.b64encode(value).decode("utf-8")}
        elif isinstance(value, datetime):
            return {"$date": value.isoformat()}
        elif isinstance(value, Timestamp):
            return {"$timestamp": {"t": value.time, "i": value.inc}}
        elif isinstance(value, dict):
            return {k: self._convert_value(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [self._convert_value(item) for item in value]
        else:
            return value

    def extract_sample_data(
        self,
        database_name: str,
        collection_name: str,
        limit: int = 100,
        filter_query: Optional[Dict] = None,
    ) -> List[Dict[str, Any]]:
        """Extract sample documents from a collection."""
        if not self.connected:
            return []

        try:
            db = self.client[database_name]
            collection = db[collection_name]

            # Build query
            query = filter_query or {}

            # Extract documents
            documents = []
            cursor = collection.find(query).limit(limit)

            for doc in cursor:
                # Convert MongoDB types to JSON serializable format
                converted_doc = self._convert_value(doc)
                documents.append(converted_doc)

            return documents

        except Exception as e:
            logging.error(
                f"Error extracting data from {database_name}.{collection_name}: {str(e)}"
            )
            return []

    def get_collection_schema(
        self, database_name: str, collection_name: str, sample_size: int = 100
    ) -> Dict[str, Any]:
        """Analyze collection schema by sampling documents."""
        if not self.connected:
            return {}

        try:
            db = self.client[database_name]
            collection = db[collection_name]

            # Sample documents to analyze schema
            sample_docs = list(collection.find().limit(sample_size))

            if not sample_docs:
                return {"fields": {}, "document_count": 0}

            # Analyze field types
            field_info = {}

            def analyze_value(value, path=""):
                """Recursively analyze value types."""
                type_name = type(value).__name__

                if isinstance(value, dict):
                    for key, val in value.items():
                        field_path = f"{path}.{key}" if path else key
                        analyze_value(val, field_path)
                elif isinstance(value, list) and value:
                    # Analyze first element of list
                    analyze_value(value[0], f"{path}[]")
                else:
                    if path not in field_info:
                        field_info[path] = {
                            "types": set(),
                            "count": 0,
                            "sample_values": [],
                        }

                    field_info[path]["types"].add(type_name)
                    field_info[path]["count"] += 1

                    # Store sample values (limit to 5)
                    if len(field_info[path]["sample_values"]) < 5:
                        if (
                            isinstance(value, (str, int, float, bool))
                            and len(str(value)) < 100
                        ):
                            field_info[path]["sample_values"].append(value)

            # Analyze all sampled documents
            for doc in sample_docs:
                for key, value in doc.items():
                    analyze_value(value, key)

            # Convert sets to lists for JSON serialization
            schema_info = {
                "fields": {},
                "document_count": collection.count_documents({}),
                "sample_size": len(sample_docs),
            }

            for field, info in field_info.items():
                schema_info["fields"][field] = {
                    "types": list(info["types"]),
                    "occurrence_count": info["count"],
                    "occurrence_percentage": (info["count"] / len(sample_docs)) * 100,
                    "sample_values": info["sample_values"],
                }

            return schema_info

        except Exception as e:
            logging.error(
                f"Error analyzing schema for {database_name}.{collection_name}: {str(e)}"
            )
            return {}

    def execute_command(self, command: str, database: str = "admin") -> Dict[str, Any]:
        """Execute a MongoDB command."""
        if not self.connected:
            return {"error": "Not connected"}

        try:
            db = self.client[database]
            result = db.command(command)
            return self._convert_value(result)
        except Exception as e:
            return {"error": str(e)}

    def get_users(self) -> List[Dict[str, Any]]:
        """Get list of MongoDB users."""
        if not self.connected:
            return []

        try:
            admin_db = self.client.admin
            users_info = admin_db.command("usersInfo", 1)

            users = []
            for user in users_info.get("users", []):
                user_data = {
                    "user": user.get("user"),
                    "db": user.get("db"),
                    "roles": user.get("roles", []),
                    "mechanisms": user.get("mechanisms", []),
                }
                users.append(user_data)

            return users

        except Exception as e:
            logging.error(f"Error getting users: {str(e)}")
            return []
