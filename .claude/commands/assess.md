---
name: assess
description: End-to-end security assessment workflow for an authorized target. Usage /assess <target>
---

# End-to-End Assessment

Target: `$ARGUMENTS`

Launch the **orchestrator agent** to plan and execute a full assessment autonomously.

## What the orchestrator does:
1. Analyzes target type (IP / domain / CIDR / mobile app / GitHub URL)
2. Spawns **recon-agent** to discover services
3. Based on recon results, spawns **validation-agent(s)** in parallel for each service
4. Spawns **vuln-analyst-agent** for CVE research on discovered versions
5. Spawns **impact-agent** for confirmed findings
6. Chains credentials across services automatically
7. Produces a consolidated final report in `./reports/{target}/`

## Execution

Use the **Agent tool** to spawn the orchestrator:
- Agent type: `orchestrator` (defined in `.claude/agents/orchestrator-agent.md`)
- Pass the full target string: `$ARGUMENTS`
- The orchestrator will handle all planning, delegation, and reporting

## Rules
- Do NOT execute the assessment yourself -- delegate to the orchestrator
- Do NOT stop to ask intermediate questions
- Only pause if the target is ambiguous or missing
