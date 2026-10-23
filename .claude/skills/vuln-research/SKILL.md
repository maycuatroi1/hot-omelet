---
name: vuln-research
description: CVE research and validation check development. Use when asked to "research a CVE", "is this version vulnerable", "write a check", "find issues for this service", "check for CVEs", "develop validation logic", or any CVE research task.
---

# CVE Research & Validation Development

Research CVEs, assess applicability, develop validation checks. Provides methodology for the vuln-analyst-agent.

## Research Decision Tree

```
1. IDENTIFY service and exact version
   -> From recon output, banner grab, or HTTP headers

2. SEARCH for CVEs:
   -> WebSearch: "{service} {version} CVE vulnerability"
   -> WebSearch: "site:nvd.nist.gov {service}"
   -> WebSearch: "site:github.com advisories {service}"
   -> Check local: grep -r "{service}" ./cve/ ./docs/cve/

3. ASSESS each CVE:
   IF version in affected range:
     -> Check: remote exploitable? (CVSS AV:N)
     -> Check: auth required? (CVSS PR:N = no auth = best)
     -> Check: complexity? (CVSS AC:L = low = best)
     -> Priority score: Remote + NoAuth + LowComplexity = P1
   IF version NOT in affected range:
     -> Skip, note as "patched"

4. CHECK local inventory:
   IF POC exists in ./cve/:
     -> Read code, verify target version match
     -> Run: python3 cve/<path>/<CVE>.py <TARGET> [PORT]
   IF no local POC:
     -> Search GitHub for public POCs
     -> IF found and trustworthy: adapt and save to ./cve/
     -> IF not found: develop minimal check

5. VALIDATE against target
   -> Run check with minimal impact
   -> Capture output as evidence

6. RETURN structured results
```

## Local CVE Inventory

| CVE | Service | Type | File | Affected |
|-----|---------|------|------|----------|
| CVE-2024-6387 | OpenSSH | Race condition | `cve/CVE-2024-6387/CVE-2024-6387.py` | < 9.8p1 |
| CVE-2025-1094 | PostgreSQL | Input validation | `cve/postgresql/CVE-2025-1094.py` | < 17.3, 16.7, 15.11 |
| CVE-2025-4207 | PostgreSQL | Availability | `cve/postgresql/CVE-2025-4207.py` | Various |
| CVE-2024-31449 | Redis | Memory safety | `cve/redis/CVE-2024-31449.py` | < 7.2.6, 7.4.1 |
| CVE-2023-38408 | SSH Agent | Forwarding | `cve/cve_2023_38408_poc.py` | Various |
| CVE-2023-44487 | HTTP/2 | Rapid Reset | `cve/http2_rapid_reset_poc.py` | Various |

## Version -> CVE Quick Map

```
OpenSSH < 9.8p1        -> CVE-2024-6387 (regreSSHion, Critical, CVSS 8.1)
Redis < 7.2.6/7.4.1    -> CVE-2024-31449 (memory safety, High)
PostgreSQL < 17.3       -> CVE-2025-1094 (input validation, High)
Airflow < 2.6.0         -> Multiple auth bypass CVEs
Apache < 2.4.56         -> CVE-2023-43622 (HTTP/2 DoS)
nginx < 1.25.3          -> Various HTTP/2 issues
```

## POC Development Template

```python
#!/usr/bin/env python3
"""
CVE-YYYY-NNNNN: {title}
Service: {service} | Affected: {version range}
Type: {vuln type} | CVSS: {score}
References: https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNNN

Usage: python3 {filename}.py <target> [port]
"""
import sys, socket, requests

DEFAULT_PORT = NNNN

def check_version(target: str, port: int) -> dict:
    """Check if target version is in the affected range."""
    # ... banner grab or version detection ...
    return {"vulnerable": bool, "version": str, "detail": str}

def validate(target: str, port: int) -> dict:
    """Minimal non-destructive validation check."""
    # ... smallest check that proves the issue ...
    return {"confirmed": bool, "evidence": str}

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <target> [port]")
        sys.exit(1)
    target = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_PORT
    result = check_version(target, port)
    if result["vulnerable"]:
        validation = validate(target, port)
        print(f"[{'CONFIRMED' if validation['confirmed'] else 'NOT CONFIRMED'}] {result['detail']}")
    else:
        print(f"[SAFE] {target}:{port} - {result['detail']}")
```

Save to: `./cve/{service}/CVE-YYYY-NNNNN.py`
Document: `./docs/cve/{SERVICE}_CVE_ANALYSIS.md`

## Applicability Assessment Matrix

| Factor | P1 (Critical) | P2 (High) | P3 (Medium) | P4 (Low) |
|--------|---------------|-----------|-------------|----------|
| Network | Remote (AV:N) | Remote | Local network | Physical |
| Auth | None (PR:N) | Low (PR:L) | High (PR:H) | Admin only |
| Complexity | Low (AC:L) | Low | High (AC:H) | Very high |
| Impact | RCE/Data leak | Data read | DoS | Info disclosure |
| Public POC | Available | Available | Not available | Theoretical |

## Error Recovery

| Error | Recovery |
|-------|----------|
| CVE not in local inventory | WebSearch for public POCs |
| POC fails to run | Check deps, read code for required args |
| Version detection fails | Try: banner grab, HTTP headers, error pages |
| False positive suspected | Verify with second method before confirming |
| New CVE, no POC exists | Write minimal check following template above |
