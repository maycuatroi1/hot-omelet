from scapy.all import ARP, Ether, srp, conf
import ipaddress
import socket
import requests
from typing import List, Dict, Optional, Any
import click
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import json


class MACAddressScanner:
    """Scanner for discovering MAC addresses and fingerprinting devices on the network."""

    def __init__(self):
        self.oui_database = {}
        self.device_patterns = {
            "apple": {
                "oui_prefixes": [
                    "00:03:93",
                    "00:05:02",
                    "00:0A:27",
                    "00:0A:95",
                    "00:0D:93",
                    "84:2f:57",
                ],
                "hostname_patterns": [
                    r"iPhone",
                    r"iPad",
                    r"MacBook",
                    r"iMac",
                    r"Apple",
                ],
            },
            "samsung": {
                "oui_prefixes": ["00:00:F0", "00:02:78", "00:07:AB", "00:09:18"],
                "hostname_patterns": [r"Galaxy", r"Samsung", r"android"],
            },
            "cisco": {
                "oui_prefixes": ["00:00:0C", "00:01:42", "00:01:43", "00:01:63"],
                "hostname_patterns": [r"cisco", r"router", r"switch"],
            },
            "hp": {
                "oui_prefixes": ["00:01:E6", "00:04:EA", "00:08:02", "00:0B:CD"],
                "hostname_patterns": [r"HP", r"printer", r"laserjet"],
            },
            "dell": {
                "oui_prefixes": ["00:06:5B", "00:08:74", "00:0B:DB", "00:0D:56"],
                "hostname_patterns": [r"Dell", r"OptiPlex", r"Latitude"],
            },
            "intel": {
                "oui_prefixes": ["00:02:B3", "00:03:47", "00:04:23", "00:07:E9"],
                "hostname_patterns": [r"Intel", r"NUC"],
            },
            "raspberry_pi": {
                "oui_prefixes": ["B8:27:EB", "DC:A6:32", "E4:5F:01"],
                "hostname_patterns": [r"raspberrypi", r"raspberry"],
            },
            "router": {
                "oui_prefixes": [],
                "hostname_patterns": [r"router", r"gateway", r"modem"],
                "ip_patterns": [r"\.1$", r"\.254$"],
            },
        }

    def load_oui_database(self, online: bool = True) -> None:
        """Load OUI database for vendor identification."""
        if online:
            try:
                click.echo(click.style("Downloading OUI database...", fg="yellow"))
                response = requests.get(
                    "https://www.wireshark.org/download/automated/data/manuf",
                    timeout=10,
                    verify=False,
                )
                if response.status_code == 200:
                    self._parse_oui_data(response.text)
                    click.echo(
                        click.style("OUI database loaded successfully", fg="green")
                    )
            except Exception as e:
                click.echo(
                    click.style(f"Failed to download OUI database: {e}", fg="red")
                )
                self._load_basic_oui()
        else:
            self._load_basic_oui()

    def _parse_oui_data(self, data: str) -> None:
        """Parse OUI data from Wireshark manuf file."""
        for line in data.split("\n"):
            if line and not line.startswith("#"):
                parts = line.split("\t")
                if len(parts) >= 2:
                    mac_prefix = parts[0].strip()
                    vendor = parts[1].strip()
                    if len(mac_prefix) == 8:  # XX:XX:XX format
                        self.oui_database[mac_prefix.upper()] = vendor

    def _load_basic_oui(self) -> None:
        """Load basic OUI database for common vendors."""
        basic_oui = {
            "00:00:0C": "Cisco Systems",
            "00:01:42": "Cisco Systems",
            "00:03:93": "Apple",
            "00:05:02": "Apple",
            "00:00:F0": "Samsung Electronics",
            "00:01:E6": "Hewlett-Packard",
            "00:06:5B": "Dell",
            "00:02:B3": "Intel",
            "B8:27:EB": "Raspberry Pi Foundation",
            "DC:A6:32": "Raspberry Pi Trading",
            "00:50:56": "VMware",
            "00:0C:29": "VMware",
            "00:05:69": "VMware",
            "08:00:27": "Oracle VirtualBox",
            "52:54:00": "QEMU/KVM",
        }
        self.oui_database.update(basic_oui)

    def scan_network_with_mac(
        self, network: str | None = None, timeout: int = 3
    ) -> List[Dict[str, Any]]:
        """Scan network and return detailed information including MAC addresses."""
        if network is None:
            network = self._get_default_network()

        click.echo(click.style(f"\nScanning network: {network}", fg="cyan"))

        # Send ARP requests
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(broadcast / arp_request, timeout=timeout, verbose=False)[0]

        devices = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []

            for _, received in result:
                future = executor.submit(
                    self._analyze_device, received.psrc, received.hwsrc
                )
                futures.append(future)

            for future in as_completed(futures):
                try:
                    device_info = future.result()
                    if device_info:
                        devices.append(device_info)
                except Exception as e:
                    click.echo(click.style(f"Error analyzing device: {e}", fg="red"))

        # Sort by IP address
        devices.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))
        return devices

    def _analyze_device(self, ip: str, mac: str) -> Dict[str, Any]:
        """Analyze a single device and gather information."""
        device_info = {
            "ip": ip,
            "mac": mac.upper(),
            "vendor": self._get_vendor(mac),
            "hostname": self._get_hostname(ip),
            "device_type": "Unknown",
            "open_ports": [],
            "fingerprint": {},
        }

        # Device type identification
        device_info["device_type"] = self._identify_device_type(
            device_info["vendor"], device_info["hostname"], ip
        )

        # Quick port scan for common services
        device_info["open_ports"] = self._quick_port_scan(ip)

        # Additional fingerprinting
        device_info["fingerprint"] = self._fingerprint_device(
            ip, device_info["open_ports"]
        )

        return device_info

    def _get_vendor(self, mac: str) -> str:
        """Get vendor name from MAC address."""
        mac_prefix = mac.upper()[:8]
        return self.oui_database.get(mac_prefix, "Unknown")

    def _get_hostname(self, ip: str) -> Optional[str]:
        """Get hostname for IP address."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:  # noqa: E722
            return None

    def _identify_device_type(
        self, vendor: str, hostname: Optional[str], ip: str
    ) -> str:
        """Identify device type based on various indicators."""
        # Check vendor-based patterns
        vendor_lower = vendor.lower() if vendor else ""
        hostname_lower = hostname.lower() if hostname else ""

        for device_type, patterns in self.device_patterns.items():
            # Check OUI prefixes
            for prefix in patterns["oui_prefixes"]:
                if vendor and prefix in vendor:
                    return device_type.replace("_", " ").title()

            # Check hostname patterns
            for pattern in patterns["hostname_patterns"]:
                if hostname and re.search(pattern, hostname_lower):
                    return device_type.replace("_", " ").title()

            # Check IP patterns
            if "ip_patterns" in patterns:
                for pattern in patterns["ip_patterns"]:
                    if re.search(pattern, ip):
                        return device_type.replace("_", " ").title()

        # Generic identification based on vendor
        if "cisco" in vendor_lower:
            return "Network Device"
        elif "apple" in vendor_lower:
            return "Apple Device"
        elif "samsung" in vendor_lower:
            return "Mobile Device"
        elif any(vm in vendor_lower for vm in ["vmware", "virtualbox", "qemu"]):
            return "Virtual Machine"

        return "Unknown"

    def _quick_port_scan(self, ip: str, ports: List[int] = None) -> List[int]:
        """Perform quick port scan on common ports."""
        if ports is None:
            ports = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]

        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()

            if result == 0:
                open_ports.append(port)

        return open_ports

    def _fingerprint_device(self, ip: str, open_ports: List[int]) -> Dict[str, Any]:
        """Fingerprint device based on open ports and services."""
        fingerprint = {"services": [], "os_guess": "Unknown"}

        # Service identification
        port_services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            80: "HTTP",
            443: "HTTPS",
            445: "SMB",
            3389: "RDP",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
        }

        for port in open_ports:
            service = port_services.get(port, f"Port {port}")
            fingerprint["services"].append(service)

        # OS guessing based on open ports
        if 445 in open_ports or 3389 in open_ports:
            fingerprint["os_guess"] = "Windows"
        elif 22 in open_ports and 445 not in open_ports:
            fingerprint["os_guess"] = "Linux/Unix"
        elif 22 in open_ports and 80 in open_ports:
            fingerprint["os_guess"] = "Linux/Network Device"

        return fingerprint

    def _get_default_network(self) -> str:
        """Get default network to scan."""
        gw = conf.route.route("0.0.0.0")[2]
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((gw, 80))
        local_ip = s.getsockname()[0]
        s.close()
        network = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
        return network

    def display_results(self, devices: List[Dict[str, Any]]) -> None:
        """Display scan results in a formatted table."""
        click.echo(click.style(f"\n{'=' * 80}", fg="cyan"))
        click.echo(click.style("MAC Address Scanner Results", fg="cyan", bold=True))
        click.echo(click.style(f"{'=' * 80}", fg="cyan"))
        click.echo(click.style(f"Found {len(devices)} devices", fg="green"))
        click.echo()

        # Table header
        headers = [
            "IP Address",
            "MAC Address",
            "Vendor",
            "Device Type",
            "Hostname",
            "Services",
        ]
        col_widths = [15, 17, 20, 15, 20, 20]

        # Print header
        header_line = ""
        for header, width in zip(headers, col_widths):
            header_line += f"{header:<{width}} "
        click.echo(click.style(header_line, fg="yellow", bold=True))
        click.echo(
            click.style(
                "-" * sum(col_widths) + "-" * (len(col_widths) - 1), fg="yellow"
            )
        )

        # Print devices
        for device in devices:
            services = ", ".join(device["fingerprint"].get("services", []))[:20]
            hostname = (device["hostname"] or "N/A")[:20]

            row = f"{device['ip']:<15} "
            row += f"{device['mac']:<17} "
            row += f"{device['vendor'][:20]:<20} "
            row += f"{device['device_type'][:15]:<15} "
            row += f"{hostname:<20} "
            row += f"{services:<20}"

            click.echo(row)

        click.echo()

    def export_results(self, devices: List[Dict[str, Any]], filename: str) -> None:
        """Export scan results to JSON file."""
        with open(filename, "w") as f:
            json.dump(devices, f, indent=2)
        click.echo(click.style(f"Results exported to {filename}", fg="green"))
