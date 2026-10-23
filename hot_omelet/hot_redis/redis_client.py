import base64
import redis
from redis.exceptions import AuthenticationError, ConnectionError


class RedisClient:
    def __init__(self, host="localhost", port=6379, username=None, password=None, socket_timeout=5):
        """Initialize the Redis client with connection parameters."""
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.socket_timeout = socket_timeout
        self.client = None

    def connect(self):
        """Establish connection to the Redis server."""
        try:
            self.client: redis.Redis = redis.Redis(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                socket_timeout=self.socket_timeout,
            )
            self.client.ping()  # Test connection
            print(f"[SUCCESS] Connected to Redis at {self.host}:{self.port}")
            return True
        except AuthenticationError:
            print(
                "[ERROR] Authentication failed. Password required or incorrect password provided."
            )
            return False
        except ConnectionError:
            print(
                f"[ERROR] Could not connect to Redis server at {self.host}:{self.port}"
            )
            raise
            return False

    def safe_decode(self, data):
        """Try to decode as UTF-8, if it fails, encode as base64."""
        if data is None:
            return None
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            with open("redis_data.dt", "wb") as f:
                f.write(data)
            return f"__binary__{base64.b64encode(data).decode('ascii')}"

    def extract_data(self):
        """Extract all data from Redis server and return it as a dictionary."""
        if not self.client:
            print("[ERROR] Not connected to Redis server")
            return None

        # Try to get keys using various methods
        keys = self._get_keys()

        if not keys:
            print("[INFO] No keys found")
            return {}

        print(f"[INFO] Successfully found {len(keys)} keys to extract")

        # Extract data for each key
        data = {}
        for key in keys:
            try:
                key_str = self.safe_decode(key)
                key_type = self.client.type(key).decode("utf-8")

                if key_type == "string":
                    data[key_str] = self.safe_decode(self.client.get(key))

                elif key_type == "list":
                    data[key_str] = [
                        self.safe_decode(item)
                        for item in self.client.lrange(key, 0, -1)
                    ]

                elif key_type == "set":
                    data[key_str] = [
                        self.safe_decode(item) for item in self.client.smembers(key)
                    ]

                elif key_type == "hash":
                    hash_data = self.client.hgetall(key)
                    data[key_str] = {
                        self.safe_decode(k): self.safe_decode(v)
                        for k, v in hash_data.items()
                    }

                elif key_type == "zset":
                    data[key_str] = {
                        self.safe_decode(item[0]): item[1]
                        for item in self.client.zrange(key, 0, -1, withscores=True)
                    }

                else:
                    data[key_str] = f"[Unsupported data type: {key_type}]"
            except Exception as e:
                print(f"[WARNING] Error processing key {key}: {e}")
                continue

        return data

    def _get_keys(self):
        """Try different methods to get Redis keys."""
        keys = []

        # First try RANDOMKEY approach
        try:
            seen_keys = set()
            # Try to get up to 100 random keys
            for _ in range(100):
                try:
                    key = self.client.randomkey()
                    if not key:
                        # No more keys or empty database
                        break

                    key_str = self.safe_decode(key)
                    if key_str not in seen_keys:
                        keys.append(key)
                        seen_keys.add(key_str)
                except Exception as e:
                    print(f"[WARNING] Error getting random key: {e}")
                    break

            print(f"[INFO] Found {len(keys)} keys using RANDOMKEY")

        except Exception as e:
            print(f"[WARNING] RANDOMKEY approach failed: {e}")

        # If RANDOMKEY failed or found no keys, try common keys
        if not keys:
            print("[INFO] Trying common Redis keys...")
            common_keys = [
                "user",
                "users",
                "session",
                "sessions",
                "config",
                "settings",
                "cache",
                "data",
                "auth",
                "key",
                "token",
                "secret",
                "password",
                "admin",
                "info",
                "flag",
            ]

            for key_name in common_keys:
                try:
                    if self.client.exists(key_name):
                        keys.append(key_name.encode())
                except Exception:
                    continue

        return keys
