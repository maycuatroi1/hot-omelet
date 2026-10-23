---
name: burpsuite-scan
description: Automated web application scanning using Burp Suite Professional headless mode via REST API. Use when asked to "burp scan", "scan web app", "web scan", "burpsuite scan", "audit web application", or any Burp Suite-related task.
---

# Burp Suite Professional - Headless Web Scanning

Automated web application scanning via Burp Suite REST API in headless mode.

## Prerequisites

- Burp Suite Professional installed: `hot install --burpsuite`
- License activated (one-time GUI step): `DISPLAY=:0 burpsuite`
- Java 17+ and xvfb installed

## Paths

| Item | Path |
|------|------|
| JAR | `~/tools/burpsuite/burpsuite_pro.jar` |
| Launcher | `~/bin/burpsuite` |

## Workflow

### Step 1: Start Burp Headless with REST API

Create user config for REST API on port 1337, then launch:

```bash
xvfb-run --auto-servernum java -jar ~/tools/burpsuite/burpsuite_pro.jar \
  --project-file=/tmp/burp_project.burp \
  --user-config-file=/tmp/burp_api_config.json \
  --unpause-spider-and-scanner \
  1>/tmp/burp_out.log 2>/tmp/burp_err.log &
```

Wait ~30s for startup.

### Step 2: Create Scan via REST API

```bash
curl -s -X POST "http://127.0.0.1:1337/v0.1/scan" \
  -H "Content-Type: application/json" \
  -d '{"urls": ["https://TARGET"], "scope": {"include": [{"rule": "https://TARGET/"}]}}'
```

### Step 3: Monitor Progress

Poll `GET /v0.1/scan/<task_id>` for status, progress, and issue counts.

### Step 4: Extract Results

Parse issues by severity from the scan results JSON.

### Step 5: Cleanup

```bash
kill $(pgrep -f burpsuite_pro) 2>/dev/null
```

## REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v0.1/scan` | Create new scan |
| GET | `/v0.1/scan/<id>` | Get scan progress + issues |
| GET | `/v0.1/issue_definitions` | List all issue types |

## Troubleshooting

- License not activated: Run GUI once with `DISPLAY=:0 burpsuite`
- Missing xvfb: `sudo apt install xvfb`
- Use `--user-config-file` (NOT `--config-file`) for API settings
- Wait 30s+ for JVM startup
- Startup takes ~30s due to JVM + Burp initialization
