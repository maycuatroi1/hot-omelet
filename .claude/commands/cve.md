---
name: cve
description: Research and validate whether a CVE applies to a target. Usage /cve <CVE-ID or service> <target>
---

# CVE Research & Validation

Arguments: `$ARGUMENTS`

Parse arguments to identify: **CVE ID or service name**, and **target**.

Launch the **vuln-analyst-agent** for CVE research and validation.

## What the vuln-analyst-agent does:
1. Searches for CVEs matching the service/version (WebSearch + local ./cve/ inventory)
2. Assesses applicability (version range, preconditions, complexity)
3. Runs existing POC from `./cve/` if available
4. Develops new validation check if needed
5. Reports results with evidence and remediation

## Execution

Use the **Agent tool** to spawn:
- Agent type: `vuln-analyst-agent`
- Prompt: "Research and validate {CVE/service} against {target}. Check local ./cve/ inventory first."

## Output
- CVE assessment table (CVE, severity, applicable, confirmed)
- Validation results with evidence
- POC details (file path, command)
- Remediation recommendations
