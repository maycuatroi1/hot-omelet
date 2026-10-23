---
name: attack
description: End-to-end security assessment workflow for an authorized target. Usage /attack <target>
---

# Full Assessment Chain (alias for /assess)

Target: `$ARGUMENTS`

This is an alias for `/assess`. Launch the **orchestrator agent** to plan and execute a full autonomous assessment.

## What the orchestrator does:
1. Analyzes target type (IP / domain / CIDR / mobile app / GitHub URL)
2. Spawns **recon-agent** to discover services
3. Based on recon results, spawns **validation-agent(s)** in parallel for each service
4. Spawns **vuln-analyst-agent** for CVE research on discovered versions
5. Spawns **impact-agent** for confirmed findings
6. Chains credentials across services automatically
7. Produces a consolidated final report in `./reports/{target}/`

## CRITICAL: Autonomous Execution

- **DO NOT** stop after recon to ask "should I continue?" -- always continue
- **DO NOT** list findings and wait -- immediately act on each finding
- **When you find credentials** -> immediately use them on the next service
- **When you confirm a misconfiguration** -> immediately check follow-on impact
- **When multiple services are open** -> process ALL of them, not just the first
- **Only produce a comprehensive final report** when the full chain is exhausted

## Execution

Use the **Agent tool** to spawn the orchestrator:
- Agent type: `orchestrator`
- Pass the full target string: `$ARGUMENTS`
- The orchestrator handles all planning, delegation, and reporting

## Constraints
- Use rustscan not nmap
- No brute force -- focus on misconfigurations and known CVEs
- Skip designed features (sentry DSN, firebase API keys) -- use key-analyze skill
- If you need a domain for upload, ask the user (this is the ONLY valid reason to pause)
