---
name: red-team-recon
description: Network reconnaissance and target enumeration for authorized penetration testing, CTF competitions, and attack/defend games. Use when asked to "scan a target", "enumerate services", "find open ports", "discover hosts on network", "bypass cloudflare", "find real IP", "map attack surface", "fingerprint services", "subdomain enumeration", or any reconnaissance task in authorized security testing.
---

# Red Team Reconnaissance

Systematic target discovery and enumeration for authorized security assessments.

## Tools

The `hot` CLI tool (from hot-omelet) provides reconnaissance capabilities. Install: `pip install -e .` from the hot-omelet project root.

### Port Scanning & Service Detection
```bash
hot scan <TARGET>
```
Runs RustScan for fast port discovery, then nmap for service detection. Auto-runs credential scanners on discovered services. Generates HTML report in `./reports/`.

### Network Discovery
```bash
hot net hosts --network <CIDR>          # Find active hosts
hot net mac --network <CIDR>          # MAC fingerprinting + vendor ID
```

### CDN/Cloudflare Bypass
```bash
hot cf bypass <DOMAIN>                 # All bypass techniques
hot cf subdomain <DOMAIN>              # Subdomain enumeration
hot cf mx <DOMAIN>                     # MX record analysis
hot cf check <IP>                      # Check if Cloudflare IP
```

Bypass techniques: subdomain enum, MX records, SPF records, SSL cert search (crt.sh/Censys), historical DNS (ViewDNS/SecurityTrails), DNS brute force.

## Reconnaissance Methodology

### Phase 1: Initial Scan
Run `hot scan TARGET` to discover open ports and identify services. Parse output for port numbers, service names, and versions.

### Phase 2: Service Mapping
For each discovered service, note:
- Port number and protocol
- Service name and version
- Whether default credentials were found (auto-checked)
- Known CVEs for that version

### Phase 3: Network Mapping
If on the same network, run `hot net hosts` and `hot net mac` to discover additional hosts and identify device vendors.

### Phase 4: CDN Analysis
If target is a domain behind CDN, use `hot cf bypass` to find origin IP. Check subdomains, MX records, SPF records, and certificate transparency logs.

### Phase 5: Attack Surface Report
Compile findings into structured report:
- Open ports and services (table format)
- Identified vulnerabilities
- Recommended attack vectors (prioritized by success likelihood)
- Network topology
- CDN/WAF detection results

## Common Service Ports Reference

| Port | Service | Scanner Command |
|------|---------|----------------|
| 22 | SSH | Check CVE-2024-6387 |
| 80/443 | HTTP/HTTPS | Web tech analysis |
| 5432 | PostgreSQL | `hot pgsql scan` |
| 6379 | Redis | `hot redis scan` |
| 8080 | Airflow/Web | `hot airflow scan` |
| 9000 | MinIO | `hot minio scan` |
| 27017 | MongoDB | `hot mongo scan` |
