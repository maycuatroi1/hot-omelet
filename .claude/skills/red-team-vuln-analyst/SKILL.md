---
name: red-team-vuln-analyst
description: Vulnerability research, CVE analysis, and exploit development for authorized security testing, CTF competitions, and attack/defend games. Use when asked to "research a CVE", "is this version vulnerable", "write an exploit", "find vulnerabilities for this service", "check for CVEs", "develop POC", "analyze vulnerability", or any vulnerability research task.
---

# Vulnerability Analysis & Exploit Development

Research vulnerabilities, assess exploitability, and develop proof-of-concept exploits for authorized security testing.

## CVE Research Process

### Step 1: Identify Service Version
From reconnaissance output, extract exact service name and version string.

### Step 2: Search for CVEs
Search NVD, exploit-db, and GitHub advisories for the specific version. Use web search with queries like:
- `"<service> <version>" CVE exploit`
- `"<service>" site:nvd.nist.gov`
- `"<service>" site:exploit-db.com`

### Step 3: Assess Exploitability
For each CVE found, evaluate:
- **Attack Vector**: Network (remote) vs Local
- **Authentication Required**: None vs Low vs High
- **Complexity**: Low vs High
- **Impact**: RCE > Data Leak > DoS
- **Public Exploit Available**: Yes/No

Prioritize: Remote + No Auth + Low Complexity + RCE + Public Exploit = exploit first.

### Step 4: Check Local Exploit Inventory
Available POCs in `./cve/` directory:

```
cve/
├── CVE-2024-6387/           # SSH regreSSHion (OpenSSH < 9.8p1)
│   ├── CVE-2024-6387.py     # Python POC
│   └── 7etsuo-regreSSHion.c # C exploit
├── postgresql/
│   ├── CVE-2025-1094.py     # SQL Injection via encoding
│   └── CVE-2025-4207.py     # GB18030 DoS
├── redis/
│   └── CVE-2024-31449.py    # Redis memory corruption
├── cve_2023_38408_poc.py    # SSH Agent exploit
└── http2_rapid_reset_poc.py # HTTP/2 Rapid Reset DoS
```

### Step 5: Develop New POC (if needed)
Follow existing patterns in `./cve/`:
- Python 3 with standard libraries + requests/socket
- Defanged mode by default (POC only, no destructive payload)
- Clear usage instructions
- Error handling for network failures
- Save to `./cve/<service>/CVE-XXXX-YYYY.py`

## Vulnerability Quick Reference

### Redis Vulnerabilities
- **No auth**: CRITICAL - full data access + RCE via CONFIG SET / MODULE LOAD
- **CVE-2024-31449**: Memory corruption in Lua scripting
- **Lua sandbox escape**: RCE via `package.loadlib` (older versions)
- **CONFIG SET**: Write arbitrary files (crontab, SSH keys)
- **MODULE LOAD**: Load malicious .so for direct RCE

### PostgreSQL Vulnerabilities
- **CVE-2025-1094**: SQL injection via GB18030 encoding handling
- **CVE-2025-4207**: DoS via malformed GB18030 input
- **Default creds**: postgres:postgres
- **COPY command**: File read/write if accessible
- **CREATE EXTENSION**: Code execution potential

### SSH Vulnerabilities
- **CVE-2024-6387**: regreSSHion - race condition RCE (OpenSSH < 9.8p1)
- **CVE-2023-38408**: SSH agent forwarding exploitation
- **Weak passwords**: Brute force with common wordlists

### HTTP/2 Vulnerabilities
- **CVE-2023-44487**: Rapid Reset DoS (affects most HTTP/2 implementations)

### MongoDB Vulnerabilities
- **No auth by default**: Many instances accessible without credentials
- **SSRF via MongoDB**: Internal network scanning through MongoDB queries

### Apache Airflow Vulnerabilities
- **Default credentials**: airflow:airflow
- **DAG injection**: Code execution through workflow definitions
- **API access**: Unauthenticated API in older versions

### MinIO Vulnerabilities
- **Default credentials**: minioadmin:minioadmin
- **Bucket policies**: Misconfigured public access
