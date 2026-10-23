"""
MITM constants: regex patterns, port maps, and display dispatch tables.
"""

import re
import json
from typing import Dict, Tuple, List

# Sensitive field patterns for JSON/form body detection
SENSITIVE_FIELDS = re.compile(
    r"(?:password|passwd|pass|pwd|secret|token|api[_-]?key|access[_-]?key|"
    r"auth|credential|session|cookie|jwt|bearer|pin|otp|mfa|totp|"
    r"credit[_-]?card|cc[_-]?num|cvv|cccd|cmnd|so_cmnd|"
    r"ssn|social[_-]?security|tax[_-]?id|"
    r"private[_-]?key|signing[_-]?key|encryption[_-]?key|"
    r"account[_-]?number|routing[_-]?number|iban|swift|"
    r"trading[_-]?pin|stock[_-]?pin|"
    r"phone|mobile|email|address|dob|birth)",
    re.IGNORECASE,
)

# Common cleartext protocol ports
PROTOCOL_PORTS = {
    21: "FTP", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 139: "NetBIOS",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 554: "RTSP",
    587: "SMTP-TLS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
    8888: "HTTP-Alt", 8000: "HTTP-Alt", 9200: "Elasticsearch",
    27017: "MongoDB",
}

# Port sets used in packet handler routing
ENCRYPTED_PORTS = frozenset({443, 8443, 993, 995, 465, 636, 989, 990, 992})
HTTP_PORTS = frozenset({80, 8080, 8888, 8000, 8081, 8082, 3000, 5000, 9090, 83})
MAIL_PORTS = frozenset({25, 110, 143, 587})
DB_PORTS = frozenset({3306, 5432, 6379, 27017, 1433, 1521})

# ── Display dispatch tables ──────────────────────────────

# Credential display fields: type -> [(label, key, color, bold, max_len)]
# max_len=0 means no truncation
CRED_DISPLAY: Dict[str, List[Tuple]] = {
    "cred_digest": [
        ("User", "username", "green", True, 0),
        ("Realm", "realm", "green", False, 0),
        ("Response", "response", "cyan", False, 0),
    ],
    "cred_basic": [("Creds", "credentials", "green", True, 0)],
    "cred_bearer": [("Token", "token", "green", True, 80)],
    "cred_ntlm": [("NTLM", "hash", "green", False, 80)],
    "cred_form_post": [
        ("URL", "url", "cyan", False, 0),
        ("User", "username", "green", True, 0),
        ("Pass", "password", "green", True, 0),
    ],
    "cred_api_token": [
        ("Header", "header", "cyan", False, 0),
        ("Value", "value", "green", True, 0),
    ],
    "cred_hikvision": [
        ("User", "username", "green", True, 0),
        ("Hash", "password_hash", "cyan", False, 64),
    ],
    "cred_mail": [
        ("Proto", "protocol", "cyan", False, 0),
        ("User", "username", "green", True, 0),
        ("Pass", "password", "green", True, 0),
    ],
    "session_cookie": [
        ("Host", "host", "cyan", False, 0),
        ("Cookie", "cookie", "green", False, 80),
    ],
}

# Event color mapping: (prefix, fg_color, bold)
EVENT_COLORS = (
    ("cred_", "red", True),
    ("sensitive_", "red", False),
    ("http_request", "cyan", False),
    ("http_response", "blue", False),
    ("dns_", "green", False),
    ("tls_sni", "yellow", False),
    ("ftp_", "magenta", False),
    ("mail_", "magenta", False),
    ("telnet_", "magenta", False),
    ("db_", "yellow", False),
    ("session_cookie", "red", True),
    ("auth_challenge", "yellow", False),
    ("mdns_", "green", False),
    ("llmnr_", "green", False),
    ("netbios_", "green", False),
)

# One-liner detail formatters by event type
DETAIL_FMT = {
    "http_request": lambda ev: f"{ev['method']} {ev['url'][:100]}",
    "http_response": lambda ev: f"{ev['status']} {ev.get('server', '')}",
    "dns_query": lambda ev: f"{ev['qtype']} {ev['query']}",
    "dns_response": lambda ev: f"{ev['query']} \u2192 {', '.join(ev.get('answers', [])[:3])}",
    "tls_sni": lambda ev: f"\u2192 {ev['sni']}",
    "ftp_user": lambda ev: f"USER {ev.get('username', '')}",
    "ftp_pass": lambda ev: "PASS ***",
    "mail_envelope": lambda ev: f"{ev.get('protocol', '')} {ev.get('address', '')}",
    "mail_auth": lambda ev: f"{ev.get('protocol', '')} {ev.get('method', '')}",
    "mdns_query": lambda ev: ev.get("query", ""),
    "llmnr_query": lambda ev: ev.get("query", ""),
    "auth_challenge": lambda ev: ev.get("challenge", "")[:80],
}


def get_event_detail(ev: dict) -> str:
    """Get one-liner detail string for an event."""
    etype = ev["type"]
    fmt = DETAIL_FMT.get(etype)
    if fmt:
        return fmt(ev)
    if etype.startswith("db_"):
        return str(ev.get("version", ev.get("command", ev.get("username", ""))))[:80]
    return json.dumps(
        {k: v for k, v in ev.items() if k not in ("time", "type", "src", "dst")}
    )[:100]
