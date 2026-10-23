---
name: command-validation
description: Controlled command-path validation in authorized labs. Use when a finding suggests a service allows running commands and you need to confirm with a benign check.
---

# Command-Path Validation

Confirm whether a command-path exists using harmless, deterministic commands and capture output as evidence.

## Principles

- Use one-shot benign commands such as `id`, `whoami`, `hostname`, or `echo marker`.
- Avoid persistence.
- Capture only the output needed to prove the code path.
- Move repeated transport/auth/parsing logic into `./workers/{target}/connect.py`.

## Workflow

### 1. Build a wrapper
Create `workers/{target}/connect.py` with target URL, auth, request helper, output parsing, timeout handling.

### 2. Use a benign validation command
Examples: `id`, `whoami`, `uname -a`, `echo hot-omelet-check`

### 3. Record evidence
Save: request parameters, response metadata, parsed output, timestamps.

### 4. Stop after confirmation
Summarize: preconditions, payload shape, observed output, confidence level, remediation guidance.

## Tips

- Base64 encoding may help normalize log output when the platform alters formatting.
- Prefer ephemeral validation over interactive sessions.
- If the same path is used twice, factor it into the wrapper immediately.
