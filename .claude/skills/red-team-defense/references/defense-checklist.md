# Defense Checklist - Blue Team Reference

Use this checklist to analyze targets from a defensive perspective and identify what the opposing team might exploit.

## Service Hardening

### Redis
- [ ] Authentication enabled (`requirepass` set)
- [ ] Strong password (not in common wordlists)
- [ ] Protected mode enabled
- [ ] Bind to localhost only (not 0.0.0.0)
- [ ] CONFIG command renamed or disabled
- [ ] MODULE LOAD disabled
- [ ] ACL configured with least privilege
- [ ] Lua scripting restricted
- [ ] Network firewall restricting port 6379

### PostgreSQL
- [ ] No default credentials (postgres:postgres)
- [ ] pg_hba.conf properly configured
- [ ] SSL/TLS enabled
- [ ] No `trust` authentication method
- [ ] Extension loading restricted
- [ ] COPY command restricted
- [ ] Network access limited
- [ ] Updated to patch CVE-2025-1094, CVE-2025-4207

### MongoDB
- [ ] Authentication enabled (not default)
- [ ] No anonymous access
- [ ] Role-based access control
- [ ] Network binding restricted
- [ ] TLS enabled
- [ ] Audit logging enabled

### Apache Airflow
- [ ] Default admin password changed
- [ ] RBAC enabled
- [ ] Fernet key rotated
- [ ] Web UI access restricted
- [ ] API authentication enforced
- [ ] DAG folder permissions locked

### MinIO / S3
- [ ] Default credentials changed
- [ ] Bucket policies configured
- [ ] No public bucket access
- [ ] TLS enabled
- [ ] Audit logging enabled

### SSH
- [ ] Key-based auth only (password auth disabled)
- [ ] Root login disabled
- [ ] Updated to patch CVE-2024-6387
- [ ] Fail2ban or similar rate limiting
- [ ] Non-standard port (optional)
- [ ] AllowUsers/AllowGroups configured

## Network Defense

- [ ] ARP spoofing detection (arpwatch, dynamic ARP inspection)
- [ ] Network segmentation
- [ ] Firewall rules (only necessary ports exposed)
- [ ] IDS/IPS active (Snort, Suricata)
- [ ] DNS monitoring
- [ ] Cloudflare/CDN properly configured
  - [ ] Origin IP not leaked via subdomains
  - [ ] MX records not exposing origin
  - [ ] Historical DNS records cleaned

## Monitoring

- [ ] Log aggregation active
- [ ] Failed login monitoring
- [ ] New connection alerts
- [ ] File integrity monitoring
- [ ] Process monitoring for suspicious activity
- [ ] Crontab change detection
- [ ] SSH authorized_keys monitoring

## Incident Response Quick Actions

### Redis Compromise Detected
1. `CONFIG SET requirepass <strong_password>`
2. `ACL DELUSER backdoor` (remove unauthorized users)
3. Check crontab: `crontab -l` and `/var/spool/cron/`
4. Check SSH keys: `cat /root/.ssh/authorized_keys`
5. Review Redis logs for suspicious commands
6. `FLUSHALL` if data integrity compromised (if acceptable)

### SSH Key Injection Detected
1. Remove unauthorized keys from `authorized_keys`
2. Restart sshd
3. Check running processes: `ps aux`
4. Check for reverse shells: `netstat -tlnp`
5. Rotate all credentials

### ARP Poisoning Detected
1. Set static ARP entries for critical hosts
2. Enable dynamic ARP inspection on switches
3. Monitor MAC address changes
4. Restart network interfaces

### Database Compromise Detected
1. Rotate all passwords
2. Review recent queries in logs
3. Check for new users or elevated privileges
4. Backup and restore from known-good state
5. Restrict network access immediately

## Scoring Defense Points

- Patch known CVEs before they're exploited
- Change all default credentials
- Enable authentication everywhere
- Restrict network access
- Monitor and alert on suspicious activity
- Document defensive actions with timestamps
