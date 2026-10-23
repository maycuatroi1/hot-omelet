---
name: recon
description: Run full reconnaissance against a target. Usage /recon <target>
---

# Reconnaissance

Target: `$ARGUMENTS`

Launch the **recon-agent** for comprehensive service discovery and enumeration.

## What the recon-agent does:
1. Port scan with `hot scan` (rustscan-based)
2. Service version identification
3. CDN/WAF detection and origin bypass (if domain)
4. Subdomain enumeration (if domain)
5. Network host discovery (if CIDR)
6. Initial credential hygiene check (auto with hot scan)

## Execution

Use the **Agent tool** to spawn:
- Agent type: `recon-agent`
- Pass the full target: `$ARGUMENTS`

## Output
Structured report with:
- Open services table (port, service, version, auth status)
- CDN/WAF detection
- CVE candidates by version
- Recommended validation paths (priority-ordered)
