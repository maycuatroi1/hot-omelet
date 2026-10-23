"""
Protocol extractors — stateless functions that parse packets into event dicts.

Each extractor takes a scapy packet + timestamp and returns event dict(s) or None.
DNS/SNI extractors also take dedup state dicts for semantic deduplication.
"""

import re
import json
import time
import base64
import struct
from typing import Optional, Dict, List
from urllib.parse import unquote_plus

from scapy.all import IP, TCP, UDP, DNS, Raw

from .constants import SENSITIVE_FIELDS


def extract_dns(pkt, ts: str, seen_dns: Dict[str, float], dedup_window: float) -> Optional[dict]:
    """Extract DNS query/response events."""
    if not pkt.haslayer(DNS):
        return None

    if pkt.haslayer(UDP) and pkt[UDP].dport in (5353, 5355):
        return None

    dns = pkt[DNS]
    src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "?"
    now = time.time()

    # DNS Query
    if dns.qr == 0 and dns.qd:
        qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
        qtype_map = {1: "A", 28: "AAAA", 5: "CNAME", 15: "MX", 16: "TXT", 33: "SRV", 12: "PTR"}
        qtype = qtype_map.get(dns.qd.qtype, str(dns.qd.qtype))

        key = f"{src_ip}|{qname}"
        if key in seen_dns and (now - seen_dns[key]) < dedup_window:
            return None
        seen_dns[key] = now

        return {
            "time": ts, "type": "dns_query",
            "src": src_ip, "dst": dst_ip,
            "query": qname, "qtype": qtype,
        }

    # DNS Response
    if dns.qr == 1 and dns.an:
        answers = []
        for i in range(dns.ancount):
            try:
                rr = dns.an[i]
                rdata = rr.rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode(errors="ignore")
                answers.append(str(rdata))
            except Exception:
                pass
        if answers:
            qname = dns.qd.qname.decode(errors="ignore").rstrip(".") if dns.qd else "?"
            key = f"R|{src_ip}|{qname}"
            if key in seen_dns and (now - seen_dns[key]) < dedup_window:
                return None
            seen_dns[key] = now
            return {
                "time": ts, "type": "dns_response",
                "src": src_ip, "dst": dst_ip,
                "query": qname, "answers": answers,
            }

    return None


def extract_tls_sni(pkt, ts: str, seen_sni: Dict[str, float], dedup_window: float) -> Optional[dict]:
    """Extract Server Name Indication from TLS ClientHello."""
    if not pkt.haslayer(Raw):
        return None

    raw = bytes(pkt[Raw].load)
    if len(raw) < 11 or raw[0] != 0x16 or raw[5] != 0x01:
        return None

    try:
        # Skip: record header (5) + handshake header (4) + version (2) + random (32) = 43
        pos = 43
        if pos >= len(raw):
            return None

        # Session ID
        sid_len = raw[pos]
        pos += 1 + sid_len

        # Cipher suites
        if pos + 2 > len(raw):
            return None
        cs_len = struct.unpack("!H", raw[pos:pos + 2])[0]
        pos += 2 + cs_len

        # Compression methods
        if pos >= len(raw):
            return None
        cm_len = raw[pos]
        pos += 1 + cm_len

        # Extensions
        if pos + 2 > len(raw):
            return None
        ext_len = struct.unpack("!H", raw[pos:pos + 2])[0]
        pos += 2
        ext_end = pos + ext_len

        while pos + 4 <= ext_end and pos + 4 <= len(raw):
            ext_type = struct.unpack("!H", raw[pos:pos + 2])[0]
            ext_data_len = struct.unpack("!H", raw[pos + 2:pos + 4])[0]
            pos += 4

            if ext_type == 0x0000:  # SNI extension
                if pos + 5 <= len(raw):
                    name_len = struct.unpack("!H", raw[pos + 3:pos + 5])[0]
                    if pos + 5 + name_len <= len(raw):
                        sni = raw[pos + 5:pos + 5 + name_len].decode(errors="ignore")
                        src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
                        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "?"
                        dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else 443

                        now = time.time()
                        key = f"{src_ip}|{sni}"
                        if key in seen_sni and (now - seen_sni[key]) < dedup_window:
                            return None
                        seen_sni[key] = now

                        return {
                            "time": ts, "type": "tls_sni",
                            "src": src_ip,
                            "dst": f"{dst_ip}:{dst_port}",
                            "sni": sni,
                        }
                break

            pos += ext_data_len

    except Exception:
        pass

    return None


def extract_http(pkt, ts: str, stats: dict) -> List[dict]:
    """Extract ALL HTTP information: requests, responses, credentials, tokens, sensitive data."""
    if not pkt.haslayer(Raw):
        return []

    try:
        payload = pkt[Raw].load.decode("utf-8", errors="ignore")
    except Exception:
        return []

    src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "?"
    dst_port = pkt[TCP].dport if pkt.haslayer(TCP) else 0
    src_port = pkt[TCP].sport if pkt.haslayer(TCP) else 0
    results = []

    header_body = payload.split("\r\n\r\n", 1)
    headers_raw = header_body[0]
    body = header_body[1] if len(header_body) > 1 else ""

    # ── HTTP Request ──
    req_match = re.match(r"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|CONNECT)\s+(\S+)\s+HTTP/", payload)
    if req_match:
        method = req_match.group(1)
        url = req_match.group(2)

        host_match = re.search(r"Host:\s*(\S+)", headers_raw, re.IGNORECASE)
        host = host_match.group(1) if host_match else dst_ip
        full_url = f"http://{host}{url}"

        parsed_headers = {}
        for hdr in re.finditer(r"^([^:\r\n]+):\s*(.+?)$", headers_raw, re.MULTILINE):
            parsed_headers[hdr.group(1)] = hdr.group(2).strip()

        event = {
            "time": ts, "type": "http_request",
            "src": f"{src_ip}:{src_port}", "dst": f"{dst_ip}:{dst_port}",
            "method": method, "url": full_url,
            "host": host,
            "user_agent": parsed_headers.get("User-Agent", "")[:200],
            "content_type": parsed_headers.get("Content-Type", ""),
        }

        if method in ("POST", "PUT", "PATCH") and body:
            event["body"] = body[:2000]

        results.append(event)
        stats["http"] += 1

        # ── Credential Extraction ──
        _extract_http_creds(
            payload, headers_raw, body, ts,
            src_ip, src_port, dst_ip, dst_port,
            host, full_url, method, event, results, stats,
        )

    # ── HTTP Response ──
    resp_match = re.match(r"HTTP/\d\.\d\s+(\d{3})\s*(.*?)(?:\r\n|\n)", payload)
    if resp_match:
        status = resp_match.group(1)
        reason = resp_match.group(2)

        parsed_headers = {}
        for hdr in re.finditer(r"^([^:\r\n]+):\s*(.+?)$", headers_raw, re.MULTILINE):
            parsed_headers[hdr.group(1)] = hdr.group(2).strip()

        event = {
            "time": ts, "type": "http_response",
            "src": f"{src_ip}:{src_port}", "dst": f"{dst_ip}:{dst_port}",
            "status": status, "reason": reason,
            "server": parsed_headers.get("Server", ""),
            "content_type": parsed_headers.get("Content-Type", ""),
            "content_length": parsed_headers.get("Content-Length", ""),
        }

        set_cookies = re.findall(r"Set-Cookie:\s*(.*?)(?:\r\n|\n)", payload, re.IGNORECASE)
        if set_cookies:
            event["set_cookies"] = [c[:300] for c in set_cookies]

        results.append(event)

        # WWW-Authenticate challenge
        m = re.search(
            r"WWW-Authenticate:\s*((?:Digest|Basic|NTLM|Negotiate)\s+.*?)(?:\r\n|\n)",
            payload, re.IGNORECASE,
        )
        if m:
            results.append({
                "time": ts, "type": "auth_challenge",
                "src": f"{src_ip}:{src_port}", "dst": f"{dst_ip}:{dst_port}",
                "challenge": m.group(1)[:500],
            })

        # Response body sensitive JSON
        if body and "json" in parsed_headers.get("Content-Type", "").lower():
            sensitive = _extract_sensitive_json(body)
            if sensitive:
                results.append({
                    "time": ts, "type": "sensitive_json_response",
                    "src": f"{src_ip}:{src_port}", "dst": f"{dst_ip}:{dst_port}",
                    "fields": sensitive,
                })
                stats["sensitive_data"] += 1

    return results


def _extract_http_creds(
    payload, headers_raw, body, ts,
    src_ip, src_port, dst_ip, dst_port,
    host, full_url, method, event, results, stats,
):
    """Extract credentials from an HTTP request (called by extract_http)."""
    src = f"{src_ip}:{src_port}"
    dst = f"{dst_ip}:{dst_port}"

    # Digest Auth
    m = re.search(r"Authorization:\s*Digest\s+(.*?)(?:\r\n|\n)", payload, re.IGNORECASE)
    if m:
        params = {}
        for kv in re.finditer(r'(\w+)="?([^",\s]+)"?', m.group(1)):
            params[kv.group(1)] = kv.group(2)
        results.append({
            "time": ts, "type": "cred_digest", "src": src, "dst": dst,
            "username": params.get("username", ""),
            "realm": params.get("realm", ""),
            "nonce": params.get("nonce", ""),
            "uri": params.get("uri", ""),
            "response": params.get("response", ""),
            "qop": params.get("qop", ""),
            "nc": params.get("nc", ""),
            "cnonce": params.get("cnonce", ""),
            "raw": m.group(1)[:500],
        })
        stats["credentials"] += 1

    # Basic Auth
    m = re.search(r"Authorization:\s*Basic\s+(\S+)", payload, re.IGNORECASE)
    if m:
        try:
            decoded = base64.b64decode(m.group(1)).decode()
        except Exception:
            decoded = m.group(1)
        results.append({
            "time": ts, "type": "cred_basic", "src": src, "dst": dst,
            "credentials": decoded,
        })
        stats["credentials"] += 1

    # Bearer / API Token
    m = re.search(r"Authorization:\s*Bearer\s+(\S+)", payload, re.IGNORECASE)
    if m:
        results.append({
            "time": ts, "type": "cred_bearer", "src": src, "dst": dst,
            "token": m.group(1)[:500],
        })
        stats["credentials"] += 1

    # NTLM Auth
    m = re.search(r"Authorization:\s*NTLM\s+(\S+)", payload, re.IGNORECASE)
    if m:
        results.append({
            "time": ts, "type": "cred_ntlm", "src": src, "dst": dst,
            "hash": m.group(1)[:200],
        })
        stats["credentials"] += 1

    # X-API-Key / custom token headers
    for token_hdr in ["X-API-Key", "X-Auth-Token", "X-Access-Token", "X-CSRF-Token",
                      "X-Session-Token", "Api-Key", "API-KEY"]:
        m = re.search(rf"{re.escape(token_hdr)}:\s*(\S+)", headers_raw, re.IGNORECASE)
        if m:
            results.append({
                "time": ts, "type": "cred_api_token", "src": src, "dst": dst,
                "header": token_hdr, "value": m.group(1)[:200],
            })
            stats["credentials"] += 1

    # Session cookies
    m = re.search(r"Cookie:\s*(.*?)(?:\r\n|\n)", payload, re.IGNORECASE)
    if m:
        cookie_val = m.group(1)
        if any(kw in cookie_val.lower() for kw in
               ["session", "token", "auth", "jwt", "sid", "phpsessid",
                "jsessionid", "asp.net", "_identity", "access"]):
            results.append({
                "time": ts, "type": "session_cookie", "src": src, "dst": dst,
                "host": host, "cookie": cookie_val[:500],
            })
            stats["credentials"] += 1

    # Form POST credentials
    if method == "POST" and body:
        pw_match = re.search(
            r"(?:password|passwd|pass|pwd|pin|otp|trading_pin|stock_pin)=([^&\s]+)",
            body, re.IGNORECASE,
        )
        if pw_match:
            user_match = re.search(
                r"(?:user(?:name)?|login|email|account|phone|mobile)=([^&\s]+)",
                body, re.IGNORECASE,
            )
            results.append({
                "time": ts, "type": "cred_form_post", "src": src, "dst": dst,
                "host": host, "url": full_url,
                "username": unquote_plus(user_match.group(1)) if user_match else "",
                "password": unquote_plus(pw_match.group(1)),
                "full_body": body[:1000],
            })
            stats["credentials"] += 1

    # JSON body sensitive fields
    if body and ("application/json" in event.get("content_type", "").lower() or
                 body.strip().startswith("{")):
        sensitive = _extract_sensitive_json(body)
        if sensitive:
            results.append({
                "time": ts, "type": "sensitive_json", "src": src, "dst": dst,
                "host": host, "url": full_url,
                "fields": sensitive,
            })
            stats["sensitive_data"] += 1

    # Hikvision SessionLogin XML
    m = re.search(
        r"<userName>([^<]+)</userName>.*?<password>([^<]+)</password>",
        payload, re.DOTALL,
    )
    if m:
        results.append({
            "time": ts, "type": "cred_hikvision", "src": src, "dst": dst,
            "username": m.group(1),
            "password_hash": m.group(2),
        })
        stats["credentials"] += 1


def _extract_sensitive_json(body: str) -> dict:
    """Extract sensitive fields from JSON body."""
    sensitive = {}
    try:
        data = json.loads(body)
        _walk_json(data, sensitive, "")
    except (json.JSONDecodeError, RecursionError):
        for m in re.finditer(r'"(\w+)"\s*:\s*"([^"]+)"', body):
            key = m.group(1)
            if SENSITIVE_FIELDS.search(key):
                sensitive[key] = m.group(2)[:100]
    return sensitive


def _walk_json(obj, result: dict, prefix: str, depth: int = 0):
    """Recursively walk JSON and extract sensitive fields."""
    if depth > 5:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            path = f"{prefix}.{k}" if prefix else k
            if SENSITIVE_FIELDS.search(k) and isinstance(v, (str, int, float)):
                result[path] = str(v)[:200]
            elif isinstance(v, (dict, list)):
                _walk_json(v, result, path, depth + 1)
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:5]):
            _walk_json(item, result, f"{prefix}[{i}]", depth + 1)


def extract_ftp(pkt, ts: str) -> Optional[dict]:
    """Extract FTP USER/PASS commands."""
    if not pkt.haslayer(Raw) or not pkt.haslayer(TCP):
        return None
    if pkt[TCP].dport != 21 and pkt[TCP].sport != 21:
        return None

    try:
        payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None

    src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
    if payload.upper().startswith("USER "):
        return {"time": ts, "type": "ftp_user", "src": src_ip, "username": payload[5:].strip()}
    elif payload.upper().startswith("PASS "):
        return {"time": ts, "type": "ftp_pass", "src": src_ip, "password": payload[5:].strip()}
    return None


def extract_mail(pkt, ts: str) -> Optional[dict]:
    """Extract SMTP/POP3/IMAP credentials and envelope data."""
    if not pkt.haslayer(Raw) or not pkt.haslayer(TCP):
        return None

    port = pkt[TCP].dport
    sport = pkt[TCP].sport
    mail_ports = {25, 110, 143, 587, 993, 995}
    if port not in mail_ports and sport not in mail_ports:
        return None

    try:
        payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None

    src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "?"
    proto = ("SMTP" if port in (25, 587) or sport in (25, 587) else
             "POP3" if port in (110, 995) or sport in (110, 995) else "IMAP")

    # AUTH LOGIN
    if payload.upper().startswith("AUTH LOGIN"):
        return {
            "time": ts, "type": "mail_auth",
            "src": src_ip, "dst": dst_ip,
            "protocol": proto, "method": "AUTH LOGIN",
        }

    # AUTH PLAIN
    m = re.match(r"AUTH PLAIN\s+(\S+)", payload, re.IGNORECASE)
    if m:
        try:
            decoded = base64.b64decode(m.group(1)).decode(errors="ignore")
            parts = decoded.split("\x00")
            return {
                "time": ts, "type": "cred_mail",
                "src": src_ip, "dst": dst_ip,
                "protocol": proto,
                "username": parts[1] if len(parts) > 1 else "",
                "password": parts[2] if len(parts) > 2 else "",
            }
        except Exception:
            pass

    # POP3 USER/PASS
    if payload.upper().startswith("USER ") and proto == "POP3":
        return {
            "time": ts, "type": "mail_user",
            "src": src_ip, "protocol": "POP3",
            "username": payload[5:].strip(),
        }
    if payload.upper().startswith("PASS ") and proto == "POP3":
        return {
            "time": ts, "type": "cred_mail",
            "src": src_ip, "protocol": "POP3",
            "password": payload[5:].strip(),
        }

    # IMAP LOGIN
    m = re.match(r"\S+\s+LOGIN\s+\"?(\S+?)\"?\s+\"?(\S+?)\"?\s*$", payload, re.IGNORECASE)
    if m:
        return {
            "time": ts, "type": "cred_mail",
            "src": src_ip, "dst": dst_ip,
            "protocol": "IMAP",
            "username": m.group(1),
            "password": m.group(2),
        }

    # MAIL FROM / RCPT TO
    m = re.match(r"(?:MAIL FROM|RCPT TO):\s*<([^>]+)>", payload, re.IGNORECASE)
    if m:
        return {
            "time": ts, "type": "mail_envelope",
            "src": src_ip, "dst": dst_ip,
            "protocol": proto, "address": m.group(1),
        }

    return None


def extract_telnet(pkt, ts: str) -> Optional[dict]:
    """Extract telnet cleartext data."""
    if not pkt.haslayer(Raw) or not pkt.haslayer(TCP):
        return None
    if pkt[TCP].dport != 23 and pkt[TCP].sport != 23:
        return None

    try:
        payload = pkt[Raw].load.decode("utf-8", errors="ignore").strip()
    except Exception:
        return None

    if not payload or len(payload) > 200:
        return None

    src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
    return {"time": ts, "type": "telnet_data", "src": src_ip, "data": payload[:200]}


def extract_db_proto(pkt, ts: str) -> Optional[dict]:
    """Detect database protocol connections and auth attempts."""
    if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
        return None

    dport = pkt[TCP].dport
    raw = bytes(pkt[Raw].load)
    src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
    dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "?"

    # MySQL greeting (protocol 10)
    if dport == 3306 or pkt[TCP].sport == 3306:
        if len(raw) > 4 and raw[4] == 0x0a:
            try:
                version_end = raw.index(0x00, 5)
                version = raw[5:version_end].decode(errors="ignore")
                return {
                    "time": ts, "type": "db_mysql_greeting",
                    "src": src_ip, "dst": f"{dst_ip}:3306",
                    "version": version,
                }
            except Exception:
                pass

    # PostgreSQL startup
    if dport == 5432:
        try:
            payload = raw.decode("utf-8", errors="ignore")
            if "user" in payload:
                parts = payload.split("\x00")
                user = ""
                db = ""
                for i, p in enumerate(parts):
                    if p == "user" and i + 1 < len(parts):
                        user = parts[i + 1]
                    if p == "database" and i + 1 < len(parts):
                        db = parts[i + 1]
                if user:
                    return {
                        "time": ts, "type": "db_pgsql_connect",
                        "src": src_ip, "dst": f"{dst_ip}:5432",
                        "username": user, "database": db,
                    }
        except Exception:
            pass

    # Redis commands
    if dport == 6379 or pkt[TCP].sport == 6379:
        try:
            payload = raw.decode("utf-8", errors="ignore")
            if payload.startswith("*") or "AUTH" in payload.upper():
                return {
                    "time": ts, "type": "db_redis_cmd",
                    "src": src_ip, "dst": dst_ip,
                    "command": payload.strip()[:200],
                }
        except Exception:
            pass

    # MongoDB wire protocol
    if dport == 27017 or pkt[TCP].sport == 27017:
        return {
            "time": ts, "type": "db_mongodb_traffic",
            "src": src_ip, "dst": dst_ip,
            "size": len(raw),
        }

    return None


def extract_netbios_mdns(
    pkt, ts: str, seen_dns: Dict[str, float], dedup_window: float,
) -> Optional[dict]:
    """Extract mDNS / LLMNR / NetBIOS Name Service events."""
    if not pkt.haslayer(UDP):
        return None

    sport = pkt[UDP].sport
    dport = pkt[UDP].dport
    src_ip = pkt[IP].src if pkt.haslayer(IP) else "?"
    now = time.time()

    # mDNS (port 5353)
    if dport == 5353 and pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qd:
            qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
            key = f"mdns|{src_ip}|{qname}"
            if key in seen_dns and (now - seen_dns[key]) < dedup_window:
                return None
            seen_dns[key] = now
            return {"time": ts, "type": "mdns_query", "src": src_ip, "query": qname}

    # LLMNR (port 5355)
    if dport == 5355 and pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qd:
            qname = dns.qd.qname.decode(errors="ignore").rstrip(".")
            key = f"llmnr|{src_ip}|{qname}"
            if key in seen_dns and (now - seen_dns[key]) < dedup_window:
                return None
            seen_dns[key] = now
            return {"time": ts, "type": "llmnr_query", "src": src_ip, "query": qname}

    # NetBIOS Name Service (port 137)
    if dport == 137 or sport == 137:
        return {
            "time": ts, "type": "netbios_ns",
            "src": src_ip, "size": len(bytes(pkt[UDP].payload)),
        }

    return None
