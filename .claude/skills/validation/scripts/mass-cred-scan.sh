#!/bin/bash
# Mass credential scanner - tests default creds across multiple services
# Usage: ./mass-cred-scan.sh <target>

TARGET=${1:?"Usage: $0 <target>"}

echo "=== Mass Credential Scan ==="
echo "Target: $TARGET"
echo "=========================="

declare -A SCANNERS
SCANNERS[redis]=6379
SCANNERS[pgsql]=5432
SCANNERS[mongodb]=27017
SCANNERS[airflow]=8080
SCANNERS[minio]=9000

for service in "${!SCANNERS[@]}"; do
    port=${SCANNERS[$service]}
    echo ""
    echo "[*] Scanning $service on port $port..."
    timeout 15 red "${service}-scan" --host "$TARGET" --port "$port" --timeout 3 2>&1 || echo "  [-] $service scan failed or timed out"
done

echo ""
echo "[*] Mass credential scan complete."
