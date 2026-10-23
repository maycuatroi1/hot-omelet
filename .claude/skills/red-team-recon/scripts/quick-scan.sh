#!/bin/bash
# Quick scan helper - runs recon chain on a target
# Usage: ./quick-scan.sh <target>

TARGET=${1:?"Usage: $0 <target>"}

echo "=== Hot Omelet Quick Scan ==="
echo "Target: $TARGET"
echo "Time: $(date)"
echo "=========================="

echo ""
echo "[*] Phase 1: Port Scan"
hot scan "$TARGET" --no-report 2>&1

echo ""
echo "[*] Phase 2: Credential Scan"
for scanner in redis-scan pgsql-scan mongodb-scan airflow-scan minio-scan; do
    echo "  [+] Running $scanner..."
    red "$scanner" --host "$TARGET" --timeout 3 2>&1 || true
done

echo ""
echo "[*] Scan complete. Check results above."
