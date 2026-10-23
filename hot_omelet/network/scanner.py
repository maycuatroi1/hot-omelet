from scapy.all import ARP, Ether, sendp, sniff, conf
import ipaddress
import netifaces
import socket
import threading
from typing import List
import click


def _get_interface_cidr(iface: str) -> str | None:
    """Get the CIDR network from the actual interface config."""
    try:
        addrs = netifaces.ifaddresses(iface)
        ipv4 = addrs.get(netifaces.AF_INET, [{}])[0]
        ip = ipv4.get("addr")
        netmask = ipv4.get("netmask")
        if ip and netmask:
            return str(ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False))
    except Exception:
        pass
    return None


def scan_network(network: str | None = None) -> List[str]:
    """Return a list of active IP addresses in the given network."""
    iface = conf.iface
    if network is None:
        gw = conf.route.route("0.0.0.0")[2]
        click.echo(f"Gateway: {gw}")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((gw, 80))
        local_ip = s.getsockname()[0]
        click.echo(f"Local IP: {local_ip}")
        s.close()
        # Use actual interface netmask instead of assuming /24
        network = _get_interface_cidr(str(iface))
        if not network:
            network = str(ipaddress.IPv4Network(f"{local_ip}/24", strict=False))
        click.echo(f"Network: {network}")

    net = ipaddress.IPv4Network(network, strict=False)
    num_hosts = net.num_addresses
    timeout = 4 if num_hosts > 256 else 2

    # Use sendp + sniff instead of srp (srp fails to match replies on macOS)
    seen = set()

    def _send():
        import time
        time.sleep(0.5)
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net))
        sendp(pkt, iface=str(iface), verbose=False)

    sender = threading.Thread(target=_send, daemon=True)
    sender.start()
    pkts = sniff(filter="arp", iface=str(iface), timeout=timeout + 1)
    sender.join()

    for p in pkts:
        if p.haslayer(ARP) and p[ARP].op == 2:
            ip = p[ARP].psrc
            if ipaddress.IPv4Address(ip) in net:
                seen.add(ip)

    return sorted(seen, key=lambda ip: ipaddress.IPv4Address(ip))
