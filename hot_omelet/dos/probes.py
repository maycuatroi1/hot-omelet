"""Low-volume DoS exposure probes.

Each probe returns a dict:
    {"probe": str, "ok": bool, "result": {...measurements...}}

Every probe is bounded: a single connection for slow probes, `n` requests
(tens, not thousands) for request-based probes. None of them can take a
server down on their own.
"""
from __future__ import annotations

import concurrent.futures
import statistics
import time

from hot_omelet.dos.http_utils import (
    make_session, open_raw_socket, read_until_close, split_url,
)


def probe_http2(base_url: str, timeout: float = 10.0) -> dict:
    """Negotiate ALPN: does the server offer h2? (CONTINUATION/Rapid-Reset class exposure)."""
    host, port, use_tls, _ = split_url(base_url)
    if not use_tls:
        return {"probe": "http2", "ok": True, "result": {"h2": False, "note": "plaintext target"}}
    try:
        sock = open_raw_socket(host, port, use_tls, timeout)
        proto = sock.selected_alpn_protocol()
        sock.close()
    except Exception as e:
        return {"probe": "http2", "ok": False, "result": {"error": str(e)}}
    return {"probe": "http2", "ok": True, "result": {"h2": proto == "h2", "alpn": proto}}


def probe_slowloris(base_url: str, timeout: float = 40.0) -> dict:
    """One deliberately slow incomplete request; measures server patience.

    A server that closes quickly (or answers 408) has mod_reqtimeout-class
    protection. A server that holds the connection to our deadline is
    Slowloris-susceptible: each held socket occupies a worker.
    """
    host, port, use_tls, path = split_url(base_url)
    start = time.monotonic()
    try:
        sock = open_raw_socket(host, port, use_tls, timeout)
        sock.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nX-Slow: ".encode())
        data, held = read_until_close(sock, start + timeout)
        sock.close()
    except Exception as e:
        return {"probe": "slowloris", "ok": False, "result": {"error": str(e)}}
    closed = len(data) > 0 or held < timeout - 1.0
    status = data.split(b"\r\n", 1)[0].decode("latin1", "replace") if data else ""
    return {
        "probe": "slowloris", "ok": True,
        "result": {
            "held_seconds": round(held, 1),
            "server_closed": closed,
            "first_line": status.strip(),
            "patient_to_deadline": not closed,
        },
    }


def probe_rudy(base_url: str, timeout: float = 40.0) -> dict:
    """One slow-body POST (declared large length, trickled body)."""
    host, port, use_tls, _ = split_url(base_url)
    start = time.monotonic()
    try:
        sock = open_raw_socket(host, port, use_tls, timeout)
        sock.sendall(
            f"POST / HTTP/1.1\r\nHost: {host}\r\n"
            "Content-Type: application/x-www-form-urlencoded\r\n"
            "Content-Length: 1024\r\n\r\na=1".encode()
        )
        data, held = read_until_close(sock, start + timeout)
        sock.close()
    except Exception as e:
        return {"probe": "rudy", "ok": False, "result": {"error": str(e)}}
    closed = len(data) > 0 or held < timeout - 1.0
    status = data.split(b"\r\n", 1)[0].decode("latin1", "replace") if data else ""
    return {
        "probe": "rudy", "ok": True,
        "result": {
            "held_seconds": round(held, 1),
            "server_closed": closed,
            "first_line": status.strip(),
        },
    }


def _timed_post(session, url, data, timeout: float) -> tuple[float, int, str]:
    t0 = time.monotonic()
    r = session.post(url, data=data, timeout=timeout, verify=False)
    return time.monotonic() - t0, r.status_code, r.text[:300]


def probe_auth_cost(login_url: str, valid_user: str | None, timeout: float = 15.0) -> dict:
    """Measure per-request server CPU on the auth endpoint.

    Compares an unknown-username request (cheap) against a valid username
    with a wrong password (forces password-hash verification). A large
    timing delta means each ~100-byte unauthenticated request buys the
    attacker a CPU-heavy hash computation.
    """
    session = make_session()
    payload = "username=red_dos_probe_nobody&password=x&service=moodle_mobile_app"
    try:
        cheap, code_cheap, body_cheap = _timed_post(session, login_url, payload, timeout)
        delta_probe = {"cheap_seconds": round(cheap, 3), "cheap_status": code_cheap}
        if not valid_user:
            return {"probe": "auth_cost", "ok": True, "result": {**delta_probe, "valid_user": None}}
        payload = (
            f"username={valid_user}&password=red_dos_probe_wrongpw&service=moodle_mobile_app"
        )
        costly, code_costly, body_costly = _timed_post(session, login_url, payload, timeout)
        return {
            "probe": "auth_cost", "ok": True,
            "result": {
                **delta_probe,
                "valid_user": valid_user,
                "hash_seconds": round(costly, 3),
                "hash_status": code_costly,
                "cpu_delta_seconds": round(costly - cheap, 3),
                "response_snippet": body_costly[:120],
            },
        }
    except Exception as e:
        return {"probe": "auth_cost", "ok": False, "result": {"error": str(e)}}


def probe_rate_limit(login_url: str, valid_user: str | None, n: int = 10,
                     timeout: float = 15.0) -> dict:
    """Fire n rapid auth failures; detect throttling (429/403/delay/captcha)."""
    session = make_session()
    times, statuses, bodies = [], [], []
    payload = (
        f"username={valid_user or 'red_dos_probe_nobody'}&"
        "password=red_dos_probe_wrongpw&service=moodle_mobile_app"
    )
    try:
        for _ in range(n):
            t, code, body = _timed_post(session, login_url, payload, timeout)
            times.append(t)
            statuses.append(code)
            bodies.append(body)
        throttled = (
            any(s in (429, 403, 503) for s in statuses)
            or "captcha" in "".join(bodies).lower()
            or (len(times) > 2 and statistics.median(times[4:]) > 2 * statistics.median(times[:2] + [0.001]))
        )
        return {
            "probe": "rate_limit", "ok": True,
            "result": {
                "requests": n,
                "statuses": sorted(set(statuses)),
                "median_seconds": round(statistics.median(times), 3),
                "max_seconds": round(max(times), 3),
                "throttled": throttled,
            },
        }
    except Exception as e:
        return {"probe": "rate_limit", "ok": False, "result": {"error": str(e)}}


def probe_concurrency(login_url: str, valid_user: str | None, n: int = 20,
                      timeout: float = 30.0) -> dict:
    """Small parallel burst to estimate worker-pool saturation.

    If n parallel requests complete in about the same wall time as one
    request, the pool is at least n deep and saturation needs n/latency RPS.
    """
    payload = (
        f"username={valid_user or 'red_dos_probe_nobody'}&"
        "password=red_dos_probe_wrongpw&service=moodle_mobile_app"
    )

    def one(_):
        s = make_session()
        t, code, _ = _timed_post(s, login_url, payload, timeout)
        return t, code

    try:
        t0 = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=n) as pool:
            results = list(pool.map(one, range(n)))
        wall = time.monotonic() - t0
        per = [t for t, _ in results]
        slowest_user_time = max(per)
        saturation_rps = round(n / wall, 1) if wall > 0 else None
        return {
            "probe": "concurrency", "ok": True,
            "result": {
                "burst": n,
                "wall_seconds": round(wall, 2),
                "slowest_request_seconds": round(slowest_user_time, 2),
                "all_parallel": wall < slowest_user_time * 2,
                "min_rps_to_saturate_pool_estimate": saturation_rps,
            },
        }
    except Exception as e:
        return {"probe": "concurrency", "ok": False, "result": {"error": str(e)}}


def probe_account_lockout(login_url: str, valid_user: str, n: int = 5,
                          timeout: float = 15.0) -> dict:
    """Check whether repeated failures lock the account (message oracle)."""
    session = make_session()
    payload = (
        f"username={valid_user}&password=red_dos_probe_wrongpw&service=moodle_mobile_app"
    )
    try:
        last_body = ""
        for _ in range(n):
            _, _, last_body = _timed_post(session, login_url, payload, timeout)
        lowered = last_body.lower()
        locked = "lock" in lowered
        return {
            "probe": "lockout", "ok": True,
            "result": {
                "failures_sent": n,
                "lockout_message": locked,
                "response_snippet": last_body[:120],
            },
        }
    except Exception as e:
        return {"probe": "lockout", "ok": False, "result": {"error": str(e)}}


def probe_password_reset(reset_url: str, valid_user: str, send: bool = False,
                         timeout: float = 15.0) -> dict:
    """Measure the password-reset endpoint.

    send=False (default): only a GET to confirm the form exists. send=True
    sends exactly one reset request and measures the cost - one email is
    queued to the target user, nothing more.
    """
    session = make_session()
    try:
        r = session.get(reset_url, timeout=timeout, verify=False)
        exists = r.status_code == 200
        result = {"form_status": r.status_code, "form_exists": exists}
        if send and exists:
            t, code, body = _timed_post(
                session, reset_url, {"username": valid_user}, timeout
            )
            result.update(
                post_seconds=round(t, 3),
                post_status=code,
                accepted=code == 200 and "error" not in body.lower()[:80],
            )
        return {"probe": "password_reset", "ok": True, "result": result}
    except Exception as e:
        return {"probe": "password_reset", "ok": False, "result": {"error": str(e)}}


PROBES = {
    "http2": lambda ctx: probe_http2(ctx["base_url"], ctx["timeout"]),
    "slowloris": lambda ctx: probe_slowloris(ctx["base_url"], ctx["slow_deadline"]),
    "rudy": lambda ctx: probe_rudy(ctx["base_url"], ctx["slow_deadline"]),
    "auth": lambda ctx: probe_auth_cost(ctx["login_url"], ctx["valid_user"], ctx["timeout"]),
    "ratelimit": lambda ctx: probe_rate_limit(
        ctx["login_url"], ctx["valid_user"], ctx["rate_requests"], ctx["timeout"]),
    "workers": lambda ctx: probe_concurrency(
        ctx["login_url"], ctx["valid_user"], ctx["burst"], ctx["timeout"] * 2),
    "lockout": lambda ctx: (
        probe_account_lockout(ctx["login_url"], ctx["valid_user"], ctx["lockout_requests"], ctx["timeout"])
        if ctx["valid_user"] else {"probe": "lockout", "ok": False, "result": {"error": "no valid user"}}),
    "reset": lambda ctx: (
        probe_password_reset(ctx["reset_url"], ctx["valid_user"], ctx["send_reset"], ctx["timeout"])
        if ctx["valid_user"] else {"probe": "reset", "ok": False, "result": {"error": "no valid user"}}),
}


def run_probes(names: list[str], ctx: dict) -> list[dict]:
    out = []
    for name in names:
        fn = PROBES.get(name)
        if fn is None:
            out.append({"probe": name, "ok": False, "result": {"error": "unknown probe"}})
            continue
        out.append(fn(ctx))
    return out


def findings_from_probes(probe_results: list[dict]) -> list[dict]:
    """Convert raw probe measurements into risk findings."""
    findings = []
    by_name = {p["probe"]: p.get("result", {}) for p in probe_results}

    r = by_name.get("http2", {})
    if r.get("h2"):
        findings.append({
            "level": "HIGH", "service": "HTTP/2", "vector": "CONTINUATION / Rapid Reset",
            "finding": "HTTP/2 negotiated via ALPN - protocol-level flood class applies",
            "evidence": f"ALPN selected: {r.get('alpn')}",
            "impact": "Cheap protocol frames can exhaust worker/memory with tiny bandwidth",
            "fix": "Terminate h2 at a hardened proxy (rate/frame limits) or disable h2",
        })
    elif r.get("alpn"):
        findings.append({
            "level": "INFO", "service": "HTTP/2", "vector": "exposure",
            "finding": "HTTP/1.1 only - HTTP/2 flood class not applicable",
            "evidence": f"ALPN selected: {r.get('alpn')}", "impact": "None from this vector",
            "fix": "-",
        })

    r = by_name.get("slowloris", {})
    if r.get("patient_to_deadline"):
        findings.append({
            "level": "HIGH", "service": "HTTP", "vector": "Slowloris (slow headers)",
            "finding": "Server held an incomplete-header connection to the probe deadline",
            "evidence": f"held {r.get('held_seconds')}s without closing",
            "impact": "Each held socket pins a worker; a few hundred sockets starve the pool",
            "fix": "Enable mod_reqtimeout (header timeout 20-30s) or front with a proxy",
        })
    elif r.get("server_closed"):
        findings.append({
            "level": "INFO", "service": "HTTP", "vector": "Slowloris (slow headers)",
            "finding": "Server closed/reset the slow connection",
            "evidence": f"closed after {r.get('held_seconds')}s: {r.get('first_line') or 'EOF'}",
            "impact": "Protected for single-connection trickle",
            "fix": "-",
        })

    r = by_name.get("rudy", {})
    if r.get("server_closed"):
        findings.append({
            "level": "INFO", "service": "HTTP", "vector": "RUDY (slow body)",
            "finding": "Server did not wait for the declared body",
            "evidence": f"closed after {r.get('held_seconds')}s",
            "impact": "Protected against slow-body trickle", "fix": "-",
        })
    elif r:
        findings.append({
            "level": "MEDIUM", "service": "HTTP", "vector": "RUDY (slow body)",
            "finding": "Server waits for the full declared body",
            "evidence": f"held {r.get('held_seconds')}s", "impact": "Slow-body sockets hold workers",
            "fix": "mod_reqtimeout body-timeout, or limit request body size",
        })

    r = by_name.get("auth_cost", {})
    delta = r.get("cpu_delta_seconds")
    if delta is not None and delta >= 0.1:
        findings.append({
            "level": "HIGH", "service": "Auth endpoint", "vector": "CPU asymmetry (bcrypt)",
            "finding": "Valid-username failures cost significantly more CPU than unknown users",
            "evidence": f"unknown-user {r.get('cheap_seconds')}s vs valid-user {r.get('hash_seconds')}s (delta {delta}s)",
            "impact": "~100-byte unauthenticated request buys a CPU-heavy hash; 64-128 RPS from one VPS saturates the pool",
            "fix": "Rate-limit auth endpoints per IP; captcha after N failures; keep hash cost (do not lower)",
        })
    elif delta is not None:
        findings.append({
            "level": "INFO", "service": "Auth endpoint", "vector": "CPU asymmetry (bcrypt)",
            "finding": "No meaningful CPU delta between unknown and valid usernames",
            "evidence": f"delta {delta}s", "impact": "Low amplification", "fix": "-",
        })

    r = by_name.get("rate_limit", {})
    if r.get("throttled") is False:
        findings.append({
            "level": "HIGH", "service": "Auth endpoint", "vector": "No rate limiting",
            "finding": f"{r.get('requests')} rapid failures: no 429/403/captcha/delay observed",
            "evidence": f"statuses {r.get('statuses')}, median {r.get('median_seconds')}s",
            "impact": "Unlimited brute-force and DoS throughput from any single IP",
            "fix": "limit_req/fail2ban in front of /login and token endpoints",
        })
    elif r.get("throttled"):
        findings.append({
            "level": "INFO", "service": "Auth endpoint", "vector": "No rate limiting",
            "finding": "Throttling detected (status change, captcha or added delay)",
            "evidence": f"statuses {r.get('statuses')}, max {r.get('max_seconds')}s",
            "impact": "Mitigated", "fix": "-",
        })

    r = by_name.get("concurrency", {})
    if r.get("all_parallel"):
        findings.append({
            "level": "MEDIUM", "service": "Worker pool", "vector": "Saturation",
            "finding": f"Burst of {r.get('burst')} parallel requests served simultaneously",
            "evidence": f"wall {r.get('wall_seconds')}s vs slowest single {r.get('slowest_request_seconds')}s",
            "impact": f"Pool >= {r.get('burst')} deep; est. {r.get('min_rps_to_saturate_pool_estimate')} RPS at probe cost begins queueing",
            "fix": "Front the app with connection/rate limits; autoscale or queue at proxy",
        })
    elif r.get("wall_seconds") is not None:
        findings.append({
            "level": "INFO", "service": "Worker pool", "vector": "Saturation",
            "finding": f"Burst of {r.get('burst')} serialized significantly (small pool or queueing)",
            "evidence": f"wall {r.get('wall_seconds')}s vs slowest single {r.get('slowest_request_seconds')}s",
            "impact": "Pool shallower than burst - saturates faster", "fix": "-",
        })

    r = by_name.get("lockout", {})
    if r.get("lockout_message"):
        findings.append({
            "level": "MEDIUM", "service": "Auth endpoint", "vector": "Account lockout DoS",
            "finding": "Account lockout engages after repeated failures",
            "evidence": r.get("response_snippet", ""),
            "impact": "Unauthenticated attacker can lock arbitrary accounts (admin included)",
            "fix": "Lock by IP+account, exponential backoff, or alert-only lockout mode",
        })
    elif r.get("failures_sent"):
        findings.append({
            "level": "MEDIUM", "service": "Auth endpoint", "vector": "No lockout",
            "finding": f"{r.get('failures_sent')} failures: no lockout message",
            "evidence": r.get("response_snippet", ""),
            "impact": "No lockout-DoS risk, but unlimited brute force pairs with the CPU vector",
            "fix": "Rely on rate limiting + monitoring rather than account lockout",
        })

    r = by_name.get("password_reset", {})
    if r.get("accepted"):
        findings.append({
            "level": "MEDIUM", "service": "Password reset", "vector": "Email amplification",
            "finding": "Reset endpoint accepts unauthenticated submissions",
            "evidence": f"POST status {r.get('post_status')} in {r.get('post_seconds')}s",
            "impact": "Each request queues a real email - mail-bomb + DB write amplification",
            "fix": "Per-IP throttle + captcha + per-account cooldown on reset requests",
        })
    elif r.get("form_exists"):
        findings.append({
            "level": "LOW", "service": "Password reset", "vector": "Email amplification",
            "finding": "Reset form exists (no submission sent in assess mode)",
            "evidence": f"form status {r.get('form_status')}",
            "impact": "Unknown until tested with --send-reset",
            "fix": "-",
        })
    return findings
