---
name: defense
description: Blue team defense analysis and hardening recommendations. Use when asked to "defend a service", "harden the server", "fix misconfigurations", "blue team", "incident response", "secure redis", "security audit", or any defensive task.
---

# Defense Analysis & Hardening

Analyze targets from defensive perspective, identify exposures, recommend hardening with specific commands and configurations.

## Analysis Decision Tree

```
1. SCAN: hot scan TARGET -> identify exposed services
2. For EACH service:
   IF no authentication:
     -> CRITICAL: enable auth immediately
     -> Provide exact config commands
   IF default credentials:
     -> CRITICAL: change passwords immediately
     -> Provide password policy guidance
   IF outdated version with known CVEs:
     -> HIGH: upgrade to patched version
     -> Provide upgrade commands
   IF bound to 0.0.0.0 (all interfaces):
     -> HIGH: bind to localhost or specific IP
   IF missing TLS/encryption:
     -> HIGH: enable TLS
   IF dangerous commands enabled:
     -> MEDIUM: disable or rename
   IF no monitoring:
     -> MEDIUM: enable logging and alerting
```

## Service Hardening Playbooks

### Redis
```bash
# Enable auth
echo "requirepass $(openssl rand -base64 32)" >> /etc/redis/redis.conf

# Bind to localhost only
sed -i 's/^bind .*/bind 127.0.0.1 ::1/' /etc/redis/redis.conf

# Enable protected mode
sed -i 's/^protected-mode .*/protected-mode yes/' /etc/redis/redis.conf

# Disable dangerous commands
cat >> /etc/redis/redis.conf << 'EOF'
rename-command FLUSHALL ""
rename-command FLUSHDB ""
rename-command CONFIG ""
rename-command DEBUG ""
rename-command SLAVEOF ""
rename-command REPLICAOF ""
rename-command MODULE ""
rename-command SAVE ""
rename-command BGSAVE ""
EOF

# Enable TLS (Redis 6+)
# redis-server --tls-port 6379 --port 0 --tls-cert-file /path/cert.pem --tls-key-file /path/key.pem

systemctl restart redis
```

### PostgreSQL
```bash
# Change default password
sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '$(openssl rand -base64 32)';"

# Enforce auth in pg_hba.conf
# Replace 'trust' with 'scram-sha-256'
sed -i 's/trust$/scram-sha-256/' /etc/postgresql/*/main/pg_hba.conf

# Bind to localhost
sed -i "s/#listen_addresses = 'localhost'/listen_addresses = 'localhost'/" /etc/postgresql/*/main/postgresql.conf

# Enable SSL
sed -i 's/#ssl = off/ssl = on/' /etc/postgresql/*/main/postgresql.conf

# Apply
systemctl restart postgresql
```

### MongoDB
```bash
# Enable auth
cat >> /etc/mongod.conf << 'EOF'
security:
  authorization: enabled
net:
  bindIp: 127.0.0.1
  tls:
    mode: requireTLS
    certificateKeyFile: /path/to/server.pem
EOF

# Create admin user first
mongosh --eval '
  use admin
  db.createUser({
    user: "admin",
    pwd: passwordPrompt(),
    roles: ["userAdminAnyDatabase", "dbAdminAnyDatabase", "readWriteAnyDatabase"]
  })
'

systemctl restart mongod
```

### SSH
```bash
# Harden sshd_config
cat >> /etc/ssh/sshd_config.d/hardening.conf << 'EOF'
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
AllowAgentForwarding no
X11Forwarding no
Protocol 2
EOF

# Install fail2ban
apt install -y fail2ban
systemctl enable --now fail2ban

# Audit authorized_keys
find /home -name authorized_keys -exec ls -la {} \;

systemctl restart sshd
```

### Airflow
```bash
# Change default password
airflow users create --username admin --password "$(openssl rand -base64 32)" --role Admin --firstname Admin --lastname User --email admin@example.com

# Disable public API
# Set in airflow.cfg:
# [api]
# auth_backends = airflow.api.auth.backend.session

# Enable RBAC
# [webserver]
# rbac = True
```

## Priority Framework

| Priority | Criteria | SLA |
|----------|----------|-----|
| P1 CRITICAL | No auth, default creds, known RCE CVE, 0.0.0.0 bind | Fix NOW |
| P2 HIGH | Weak passwords, no TLS, dangerous commands enabled | Fix within hours |
| P3 MEDIUM | No monitoring, no rate limiting, verbose errors | Fix within days |
| P4 LOW | Missing security headers, info disclosure | Fix when possible |

## Incident Detection Checklist

```
CHECK for signs of prior compromise:
  -> Unknown users/roles in services
  -> Modified config values (especially auth settings)
  -> Unexpected scheduled tasks or cron jobs
  -> Unknown processes or connections
  -> Recent bulk data access in logs
  -> New or modified SSH authorized_keys
  -> Unusual outbound network connections
```

## Quick Response Actions

1. **Rotate all passwords** - every exposed service
2. **Remove unauthorized access** - delete unknown users, revoke tokens
3. **Bind to localhost** - all services that don't need external access
4. **Enable firewall** - allow only necessary ports
5. **Enable logging** - all access logs to centralized system
6. **Patch** - upgrade all services to latest stable versions
7. **Document** - all defensive actions with timestamps
