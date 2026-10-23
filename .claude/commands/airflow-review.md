---
name: airflow-review
description: Airflow exposure discovery and validation workflow. Usage /airflow-review <target-or-country>
---

# Airflow Review

Arguments: `$ARGUMENTS`

Launch the **orchestrator agent** for Airflow-specific assessment workflow.

## What the orchestrator does:
1. IF country code given: discovery via `hot censys` for Airflow instances
2. IF IP/domain given: direct Airflow validation
3. Mass credential scan with `hot airflow scan`
4. Post-auth enumeration (connections, variables, config, users, DAG sources)
5. Connected-service validation for extracted credentials
6. Report generation

## Execution

Use the **Agent tool** to spawn:
- Agent type: `orchestrator`
- Prompt: "Airflow assessment workflow. Target: {$ARGUMENTS}. Follow the airflow-review skill methodology."

The orchestrator will use the airflow-review skill as its knowledge base and coordinate specialist agents as needed.
