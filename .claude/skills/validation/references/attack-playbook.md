# Service Validation Playbook - Hot Omelet

## Service-Specific Validation Workflows

### Redis (Port 6379)

**Detection**: `hot scan` identifies redis service
**Validation flow**:
1. Check auth: `hot redis scan --host TARGET`
2. If no auth or weak password found:
   - Extract a minimal sample: `hot redis dump --host TARGET`
   - Run validation workflow: `hot redis attack --host TARGET`
3. Validation vectors (tested by redis-attack):
   - configuration exposure
   - risky command availability
   - high-impact code paths requiring explicit confirmation
4. Data review: Search for passwords, API keys, tokens in Redis samples

Note: if risky Redis code paths are confirmed, document them and stop after sufficient proof.

### PostgreSQL (Port 5432)

**Detection**: `hot scan` identifies postgresql
**Validation flow**:
1. Credential scan: `hot pgsql scan --host TARGET`
2. If credentials found:
   - Extract data via `extract_pg_data()`
   - Check for CVE-2025-1094 (input validation via encoding)
   - Check for CVE-2025-4207 (availability concern via GB18030)
3. Impact review:
   - minimal file/database evidence only
   - search for credentials in database tables

### MongoDB (Port 27017)

**Detection**: `hot scan` identifies mongodb
**Validation flow**:
1. Credential scan: `hot mongo scan --host TARGET`
2. Many MongoDB instances have no auth by default
3. Data extraction: `hot mongo dump --host TARGET`
4. Look for:
   - User credentials in collections
   - API keys and tokens
   - Configuration data with secrets
   - Other service connection strings

### Apache Airflow (Port 8080)

**Detection**: `hot scan` identifies web service on 8080
**Validation flow**:
1. Credential scan: `hot airflow scan --host TARGET`
2. Default creds: `airflow:airflow`
3. If access gained:
   - controlled DAG/config validation
   - Variable/Connection secrets extraction
   - review of connected systems (databases, cloud providers)

### MinIO / S3 (Port 9000)

**Detection**: `hot scan` identifies S3 API
**Validation flow**:
1. Credential scan: `hot minio scan --host TARGET`
2. Default creds: `minioadmin:minioadmin`
3. If access gained:
   - list buckets and review minimal samples
   - search for secrets, backups, configs

### SSH (Port 22)

**Validation flow**:
1. Check version for CVE-2024-6387 (regreSSHion)
2. Run check: `python3 cve/CVE-2024-6387/CVE-2024-6387.py TARGET`
3. Review auth posture and key-based auth misconfigs

### HTTP/HTTPS (Port 80/443)

**Assessment flow**:
1. Fetch title and technology stack
2. Check for known CVEs in web framework
3. Directory enumeration
4. Check for HTTP/2 Rapid Reset applicability
5. Look for exposed admin panels, API docs

## Network-Level Checks

### ARP Inspection (Traffic Analysis)
```bash
hot net arp-poison --target VICTIM_IP --gateway GATEWAY_IP
```
- Inspect traffic between victim and gateway
- Identify credentials sent in plaintext
- Analyze traffic patterns

### ARP Availability Validation
```bash
hot net arp-denial --victim1 IP1 --victim2 IP2
hot net arp-denial --all --network CIDR
```
- Validate communication resilience between specific hosts
- Network-wide availability check in isolated lab only

### Origin Exposure Assessment
```bash
hot cf bypass DOMAIN
```
Techniques used:
- Subdomain enumeration (direct, ftp, mail, cpanel, etc.)
- MX record analysis
- SPF record IP extraction
- SSL certificate search (crt.sh, Censys)
- Historical DNS records (ViewDNS, SecurityTrails)
- DNS enumeration

## Multi-Service Validation Paths

### Path 1: Redis -> Follow-on Exposure
1. Find Redis with no auth
2. Extract data for other service credentials
3. Document risky code paths and trust implications
4. Stop after sufficient proof

### Path 2: Web -> Database -> Trust Review
1. Find web app with default creds
2. Access database through web app
3. Extract credentials from database
4. Use found creds on other services

### Path 3: MongoDB -> Cloud Configuration Review
1. Find MongoDB with no auth
2. Extract connection strings from configs
3. Access cloud services (AWS, GCP) with found keys
4. Review other infrastructure

## CTF Scoring Tips

- Document every step with timestamps
- Save all extracted data to `./reports/`
- Generate HTML reports: `hot scan TARGET --report`
- Keep track of services confirmed vs total
- Prioritize high-value targets (databases, admin panels)
- Check for flags in common locations: /root/flag.txt, environment variables, database entries
