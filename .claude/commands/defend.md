---
name: defend
description: Analyze a target from defensive perspective and suggest hardening. Usage /defend <target>
---

# Defense Analysis

Target: `$ARGUMENTS`

Analyze the target from a **blue team perspective**. Discover exposure surface, then provide hardening recommendations with specific commands.

## Execution

1. Run `hot scan $ARGUMENTS` to discover exposed services
2. Run credential hygiene checks on all discovered services
3. For each service, apply the defense skill's hardening playbooks
4. Prioritize findings: Critical -> High -> Medium

## Output
- Risk summary (critical/high/medium counts)
- Per-service hardening commands (copy-paste ready)
- Priority-ordered remediation steps
- Incident detection checklist
- Monitoring recommendations
