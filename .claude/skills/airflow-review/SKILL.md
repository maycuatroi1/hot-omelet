---
name: airflow-review
description: Apache Airflow configuration review workflow. Use when asked to "scan airflow", "airflow assessment", "find airflow instances", "airflow credentials", "airflow config review", or any Airflow-related review task.
---

# Apache Airflow Configuration Review

Review methodology for exposed Apache Airflow instances. Covers discovery, credential hygiene, post-auth enumeration, configuration analysis, and connected-service mapping.

## Phase 1: Discovery

```bash
hot censys 'services.http.response.html_title: "Airflow" and location.country_code: "VN"'
```

Save results to target file for batch processing.

## Phase 2: Credential Hygiene Review

```bash
hot airflow scan --host <IP> --port 8080
hot airflow scan --file airflow_targets.txt --workers 20 --timeout 8 --output results.json
```

The scanner auto-detects ports, SSL config, unauthenticated API access, and default credentials.

## Phase 3: Post-Auth Enumeration

After gaining access, enumerate via Airflow REST API v1:

1. **Connections** - review connection configurations
2. **Variables** - review stored variables
3. **Users** - review user accounts and roles
4. **Config** - review Airflow configuration
5. **DAG source** - review DAG definitions for hardcoded values
6. **XCom data** - review processed results

## Phase 4: Connected-Service Review

Use extracted connection details to review connected services. Collect minimal evidence for each:
- Database services (PostgreSQL, MySQL, MongoDB)
- Messaging services (Telegram bots, Lark/Feishu)
- Generic API endpoints

## Phase 5: Configuration Path Verification

If write access is available, verify the configuration path via DAG creation using benign commands.

## Phase 6: Report Generation

Generate HTML report with:
1. Summary - total targets, misconfigured count, findings
2. Validation flow
3. Affected targets table
4. Configuration issues found
5. Connected-service analysis
6. Recommendations

## Unauth API Endpoints to Check

```
/api/v1/health
/api/v1/version
/api/v1/dags
/api/v1/connections
/api/v1/variables
/api/v1/config
/api/v1/users
/api/v1/providers
/api/v1/plugins
/api/v1/eventLogs
```

## Prior Misconfiguration Detection

Look for evidence of previous unauthorized changes:
- Unusual values in variables
- Suspicious DAGs
- Unknown admin users created recently
- Unusual audit log entries
