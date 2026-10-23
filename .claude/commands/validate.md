---
name: validate
description: Validate a specific service weakness on a target. Usage /validate <service> <target> [port]
---

# Service Validation

Arguments: `$ARGUMENTS`

Parse arguments to identify: **service type**, **target IP/host**, and optional **port**.

Launch the **validation-agent** for service-specific configuration review.

## What the validation-agent does:
1. Runs credential hygiene check for the service
2. Follows per-service decision tree (Redis/PostgreSQL/MongoDB/Airflow/MinIO/SSH/HTTP)
3. Chains discovered credentials across other services
4. Checks applicable CVEs for the service version
5. Collects minimal evidence for confirmed findings

## Execution

Use the **Agent tool** to spawn:
- Agent type: `validation-agent`
- Prompt: "Validate {service} on {target}:{port}. Follow the per-service decision tree."

## Output
- Confirmation status (CONFIRMED / NOT VULNERABLE / INCONCLUSIVE)
- Credentials found
- Data exposure summary
- Recommended next steps
