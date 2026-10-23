"""Shared HTTP/socket helpers for DoS probes."""
from __future__ import annotations

import socket
import ssl
import time
import urllib.parse

import requests

try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

USER_AGENT = "hot-omelet-dos-assess/1.0 (+authorized use only)"


def normalize_url(target: str, default_scheme: str = "https") -> str:
    """Accept bare hosts, add scheme when missing."""
    if "://" not in target:
        target = f"{default_scheme}://{target}"
    return target.rstrip("/")


def split_url(url: str):
    """Return (host, port, use_tls, path) for raw-socket probes."""
    p = urllib.parse.urlparse(url)
    use_tls = p.scheme == "https"
    port = p.port or (443 if use_tls else 80)
    path = p.path or "/"
    if p.query:
        path += "?" + p.query
    return p.hostname, port, use_tls, path


def make_session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    return s


def open_raw_socket(host: str, port: int, use_tls: bool, timeout: float) -> ssl.SSLSocket | socket.socket:
    """Open a TCP (optionally TLS) connection with ALPN offered for h2."""
    raw = socket.create_connection((host, port), timeout=timeout)
    if use_tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            pass
        return ctx.wrap_socket(raw, server_hostname=host)
    return raw


def read_until_close(sock, deadline: float) -> tuple[bytes, float]:
    """Read until EOF/deadline; return (data, seconds until EOF)."""
    start = time.monotonic()
    data = b""
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        data += chunk
    return data, time.monotonic() - start
