---
name: red-team-defense
description: Blue team defense analysis and hardening for attack/defend games, CTF competitions, and security assessments. Use when asked to "defend a service", "harden the server", "fix vulnerabilities", "blue team", "incident response", "detect attacks", "secure redis", "patch vulnerabilities", "security audit", or any defensive security task.
---

# Blue Team Defense & Hardening

Analyze targets from a defensive perspective, identify exposures, and apply hardening measures for attack/defend game challenges.

## Quick Defense Audit

Run `hot scan TARGET` to see what an attacker sees, then harden each exposed service.

## Service Hardening Playbooks

### Redis (Port 6379)
```bash
# Set strong password
redis-cli CONFIG SET requirepass "$(openssl rand -base64 32)"
# Enable protected mode
redis-cli CONFIG SET protected-mode yes
# Disable dangerous commands
redis-cli CONFIG SET rename-command FLUSHALL ""
redis-cli CONFIG SET rename-command CONFIG ""
redis-cli CONFIG SET rename-command MODULE ""
# Bind to localhost only
redis-cli CONFIG SET bind 127.0.0.1
# Remove backdoor users
redis-cli ACL DELUSER backdoor
redis-cli ACL LIST  # Audit all users
```

### PostgreSQL (Port 5432)
- Change default `postgres` password
- Edit `pg_hba.conf`: replace `trust` with `scram-sha-256`
- Enable SSL: `ssl = on` in `postgresql.conf`
- Restrict network: `listen_addresses = 'localhost'`
- Patch CVE-2025-1094 and CVE-2025-4207

### MongoDB (Port 27017)
- Enable auth: add `--auth` flag or `security.authorization: enabled`
- Create admin user with strong password
- Bind to localhost: `bindIp: 127.0.0.1`
- Enable TLS

### SSH (Port 22)
- Disable password auth: `PasswordAuthentication no`
- Disable root login: `PermitRootLogin no`
- Patch CVE-2024-6387 (update OpenSSH)
- Install fail2ban
- Audit `authorized_keys` files

### Web Services (80/443/8080/9000)
- Change all default credentials immediately
- Enable HTTPS/TLS
- Restrict admin panel access by IP
- Enable rate limiting

## Incident Detection

### Signs of Redis Compromise
- Unknown ACL users: `redis-cli ACL LIST`
- Modified config: check `dir` and `dbfilename` values
- Suspicious keys: `redis-cli KEYS "*backup*" "*cron*" "*shell*"`
- Unexpected data: look for crontab entries or SSH keys in values

### Signs of SSH Compromise
- Unknown authorized_keys: `cat ~/.ssh/authorized_keys`
- Suspicious crontab entries: `crontab -l`
- Unknown processes: `ps aux | grep -E "(nc|bash|sh|python)"`
- Reverse shells: `ss -tlnp | grep -v LISTEN`

### Signs of Database Compromise
- Unknown users/roles
- Recent bulk SELECT queries in logs
- New databases or collections
- Modified data or schemas

## Quick Response Actions
1. Rotate all passwords immediately
2. Kill suspicious processes
3. Remove unauthorized SSH keys and crontab entries
4. Restart compromised services with hardened config
5. Enable firewall rules: block unnecessary ports
6. Start monitoring logs for continued access attempts

## Scoring Defense Points
- Patch known CVEs before exploitation
- Change ALL default credentials (even obscure services)
- Enable authentication on every service
- Restrict network binding to localhost where possible
- Monitor and alert on login failures
- Document all defensive actions with timestamps
