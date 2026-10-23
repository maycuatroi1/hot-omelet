---
name: impact-analysis
description: Post-validation impact analysis. Use when asked to "review sample data", "analyze follow-on exposure", "search for secrets", "map trust relationships", or any impact-analysis task.
---

# Post-Validation Impact Analysis

Measure impact from confirmed findings through sample data review, secret discovery, trust-path mapping, and PII classification. Provides methodology for the impact-agent.

## Workflow Decision Tree

```
1. EXTRACT minimal data sample from accessible service
   -> Use hot CLI tools (redis-dump, mongodb-dump)
   -> Limit to smallest useful sample (50 keys, 5 rows, 2 docs)

2. SEARCH sample for secrets:
   -> Credential patterns (password, token, api_key, secret)
   -> Cloud keys (AWS AKIA*, GCP AIza*, Azure client IDs)
   -> API tokens (GitHub ghp_*, Slack xox*, Telegram bot tokens)
   -> Connection strings (postgres://, mongodb://, redis://)

3. For EACH secret found:
   IF it's a connection string:
     -> Extract host, port, credentials
     -> This is a trust-path to another service
     -> Report as new validation target
   IF it's a cloud key:
     -> Classify provider (AWS/GCP/Azure)
     -> Report for scope validation
   IF it's an API token:
     -> Identify service (Telegram, Slack, GitHub)
     -> Validate read-only (getMe, users.info)
     -> Do NOT send messages or modify

4. MAP trust relationships:
   -> Build graph: service A -> credential -> service B
   -> Calculate chain depth
   -> Identify highest-impact path

5. CLASSIFY data:
   -> Count records by PII type
   -> Apply severity matrix
   -> Report top-level statistics only
```

## Secret Discovery Patterns

### High-Priority Patterns
```regex
# Credentials
password|passwd|pwd|secret|token|api_key|apikey|auth_token
connection_string|conn_str|database_url|db_url|dsn

# Cloud Keys
AKIA[0-9A-Z]{16}                              # AWS access key
AIza[0-9A-Za-z_-]{35}                         # GCP API key
"type":\s*"service_account"                    # GCP service account

# API Tokens
ghp_[A-Za-z0-9_]{36,}                         # GitHub PAT
glpat-[A-Za-z0-9_-]{20,}                      # GitLab PAT
xox[bporas]-[0-9]+-[0-9]+-[a-zA-Z0-9]+        # Slack token
[0-9]+:[A-Za-z0-9_-]{35,}                     # Telegram bot
sk_live_[A-Za-z0-9]{24,}                      # Stripe secret
SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}      # SendGrid

# Connection Strings
postgres(ql)?://[^\s"']+                       # PostgreSQL
mongodb(\+srv)?://[^\s"']+                     # MongoDB
redis://[^\s"']+                               # Redis
mysql://[^\s"']+                               # MySQL
amqp://[^\s"']+                                # RabbitMQ
```

## PII Classification Matrix

| Type | Severity | Column Patterns | Action |
|------|----------|-----------------|--------|
| Identity | CRITICAL | name, full_name, dob, birth, cccd, cmnd, ssn, passport | Count + report |
| Contact | CRITICAL | email, phone, mobile, address, city | Count + report |
| Financial | CRITICAL | bank, account, salary, tax, transaction, credit_card | Count + report |
| Credentials | CRITICAL | password, hash, token, secret, api_key | Validate + chain |
| Health | CRITICAL | medical, diagnosis, insurance, health | Count + report |
| Business | HIGH | customer, contract, invoice, order, revenue | Note scope |
| Technical | HIGH | ip, hostname, internal_url, config | Note for trust-path |
| Behavioral | MEDIUM | login, session, access_log, activity | Note if large scale |

## Trust-Path Mapping Format

```
{Source} ({access method})
  └→ {credential type} -> {Destination} ({access level})
       └→ {data type}: {record count} ({sensitivity})

Example:
Redis:6379 (no auth)
  └→ db_url -> PostgreSQL:5432 (admin)
       └→ users: 50,000 records (Critical PII)
       └→ transactions: 200,000 records (Financial)
  └→ telegram_token -> Telegram Bot
       └→ org internal channel (Business comms)
  └→ aws_key -> AWS S3 (read/write)
       └→ database-backups/ (Full DB dumps)
```

## Per-Service Analysis Guide

### Redis
- `DBSIZE` for scale
- `INFO keyspace` for database distribution
- Sample 50 random keys across databases
- Look for: session:*, user:*, config:*, conn:*, token:*

### PostgreSQL/MySQL
- List databases and table sizes
- Find PII columns: `column_name ~* '(email|phone|password|name|address)'`
- Count records per PII table
- Extract 3-5 sample rows, redact in report

### MongoDB
- List databases and collections with doc counts
- Check first document schema for PII fields
- Count documents per collection
- Sample 1-2 documents per collection

### Airflow
- Connections contain: host, port, login, password, extra JSON
- Variables may contain: tokens, API keys, config values
- Config may contain: fernet_key, sql_alchemy_conn, broker_url
- Each connection is a trust-path to validate

## Error Recovery

| Error | Recovery |
|-------|----------|
| Data too large | Sample first 100 entries, grep for patterns |
| Binary/encoded data | Skip, note "binary data present" |
| Access revoked mid-analysis | Report what was found before revocation |
| No secrets found | Report "clean" - still valuable scope information |
| Encrypted values (Fernet) | Note as "encrypted, key needed to decrypt" |

## CTF Flag Locations

```
/root/flag.txt, /home/*/flag.txt
Environment variables: env | grep -i flag
Database tables: SELECT * FROM flags
Redis keys: redis-cli keys "*flag*"
Config files: /etc/*, /opt/*/config*
Hidden files: find / -name "*.flag" -o -name ".flag*"
```
