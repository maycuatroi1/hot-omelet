---
name: cred-scan
description: Validate whether discovered services still use default or weak credentials. Usage /cred-scan <target>
---

# Credential Hygiene Scan

Target: `$ARGUMENTS`

Launch the **validation-agent** in credential-scan mode.

## What it does:
1. Runs ALL credential scanners against the target in parallel:
   - `hot redis scan` (6379)
   - `hot pgsql scan` (5432)
   - `hot mongo scan` (27017)
   - `hot airflow scan` (8080)
   - `hot minio scan` (9000)
2. For any service with confirmed access, immediately validates data exposure
3. Chains discovered credentials across services

## Execution

Use the **Agent tool** to spawn:
- Agent type: `validation-agent`
- Prompt: "Run credential hygiene scan on {target}. Test ALL services: Redis, PostgreSQL, MongoDB, Airflow, MinIO. Chain any found credentials. Return structured results."

## Output
- Credential report table (service, port, status, username, password, access level)
- Follow-on validation recommendations
