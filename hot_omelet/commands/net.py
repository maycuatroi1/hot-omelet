"""`hot net ...` - LAN reconnaissance and attacks."""
import click

from hot_omelet.commands._common import output_option, timeout_option


@click.group("net")
def net():
    """LAN reconnaissance and attacks."""


@net.command("hosts")
@click.option("--network", required=False, help="CIDR range to scan, e.g. 192.168.1.0/24")
def net_hosts(network):
    """Scan the local network for active hosts."""
    from hot_omelet.network_commands import network_scan_command
    network_scan_command(network)


@net.command("mac")
@click.option("--network", required=False, help="CIDR range to scan, e.g. 192.168.1.0/24")
@timeout_option(3)
@click.option("--online-oui/--offline-oui", default=True, help="Download OUI database online")
@output_option()
def net_mac(network, timeout, online_oui, output):
    """Scan network for MAC addresses and fingerprint devices."""
    from hot_omelet.network_commands import mac_scan_command
    mac_scan_command(network, timeout, online_oui, output)


@net.command("arp-poison")
@click.option("--target", help="Target IP address to poison (default: all devices)")
@click.option("--gateway", help="Gateway IP address (auto-detected if not provided)")
@click.option("--analyze/--no-analyze", default=True, help="Analyze intercepted packets")
@click.option("--show-all/--no-show-all", default=False, help="Show all packet details")
def net_arp_poison(target, gateway, analyze, show_all):
    """ARP poisoning for Man-in-the-Middle attacks."""
    from hot_omelet.network_commands import arp_poison_command
    arp_poison_command(target, gateway, analyze, show_all)


@net.command("arp-denial")
@click.option("--victim1", help="First victim IP address")
@click.option("--victim2", help="Second victim IP address")
@click.option("--all", "all_devices", is_flag=True, help="Deny all devices on the network")
@click.option("--bidirectional/--unidirectional", default=True, help="Block both directions")
@click.option("--network", help="CIDR range for --all option (auto-detected if not provided)")
def net_arp_denial(victim1, victim2, all_devices, bidirectional, network):
    """ARP denial - block communication between hosts."""
    from hot_omelet.network_commands import arp_denial_command
    arp_denial_command(victim1, victim2, all_devices, bidirectional, network)


@net.command("mitm")
@click.option("--target", "-t", help="Target IP (default: all devices on network)")
@click.option("--gateway", "-g", help="Gateway IP (auto-detected if not provided)")
@click.option("--gateway-mac", help="Gateway MAC address (auto-detected if not provided)")
@click.option("--interface", "-i", default="en0", help="Network interface")
@click.option("--output", "-o", default="./reports/mitm", help="Log output directory")
@click.option("--filter", "bpf_filter", help="Custom BPF filter (advanced)")
@click.option("--network", "-n", help="CIDR range (auto-detected if not provided)")
@click.option("--ssl-intercept", "-S", is_flag=True, help="SSL intercept: ARP + DNS spoof + mitmproxy")
@click.option("--proxy-port", "-p", default=443, type=int, help="mitmproxy listen port")
@click.option("--domains", "-d", help="Comma-separated domains to intercept (default: ALL)")
@click.option("--stealth", is_flag=True, help="Stealth mode: randomized timing + batched ARP")
def net_mitm(target, gateway, gateway_mac, interface, output, bpf_filter, network,
             ssl_intercept, proxy_port, domains, stealth):
    """Universal MITM interceptor.

    \b
    Examples:
      hot net mitm                          # Passive sniff mode
      hot net mitm --stealth -t 10.1.0.5    # Stealth against single target
      hot net mitm -S                       # Intercept ALL HTTPS
      hot net mitm -S -d example.com       # Only intercept matching domains
      hot net mitm -S -t 10.1.0.13 -d ssi   # Target specific device + domain
    """
    from hot_omelet.mitm import mitm_command
    mitm_command(target, gateway, gateway_mac, interface, output, bpf_filter, network,
                 ssl_intercept, proxy_port, domains, stealth)


@net.command("evil-twin")
@click.argument("ssid")
@click.option("--password", "-p", default="highlands", help="WPA3 password for evil AP")
@click.option("--channel", "-c", default=36, type=int, help="WiFi channel (default: 36, 5GHz)")
@click.option("--bssid", "-b", help="Target AP BSSID for deauth attack")
@click.option("--ap-iface", default="ap1", help="AP interface")
@click.option("--inet-iface", "-i", default="en0", help="Internet interface")
@click.option("--subnet", "-s", default="192.168.44", help="Evil network subnet")
@click.option("--no-deauth", is_flag=True, help="Disable deauth attack")
@click.option("--no-captive", is_flag=True, help="Disable captive portal")
def net_evil_twin(ssid, password, channel, bssid, ap_iface, inet_iface, subnet, no_deauth, no_captive):
    """Evil Twin AP attack - bypass AP isolation completely.

    \b
    Examples:
      hot net evil-twin "CoffeeWiFi"
      hot net evil-twin "CoffeeWiFi" -b 14:49:bc:6d:62:b0
      hot net evil-twin "CoffeeWiFi" -p "coffee123" -c 36
    """
    from hot_omelet.evil_twin import evil_twin_command
    evil_twin_command(ssid, channel, bssid, ap_iface, inet_iface, subnet, no_deauth, not no_captive, password)


@net.command("link-check")
@click.argument("mac")
@click.option("--iface", help="Wired interface (default: auto-detect)")
@click.option("--timeout", default=3, show_default=True, type=int, help="ARP timeout seconds")
@click.option("--count", default=3, show_default=True, type=int, help="Ping count")
def net_link_check(mac, iface, timeout, count):
    """Check L2/L3 connectivity to a device by MAC over a wired Ethernet link."""
    from hot_omelet.link_discovery import link_check_command
    link_check_command(mac, iface, timeout, count)


@net.command("link-setup")
@click.option("--iface", default="en8", show_default=True, help="Wired Ethernet interface")
@click.option("--net", default="192.168.1", show_default=True, help="First 3 octets of the /24")
@click.option("--myip", default="192.168.1.250", show_default=True, help="Static IP for this host")
@click.option("--cleanup", is_flag=True, help="Remove static IP and exit")
def net_link_setup(iface, net, myip, cleanup):
    """Bring up a direct host<->device Ethernet link (static IP + ARP sweep + SSH probe)."""
    from hot_omelet.link_discovery import link_setup_command
    link_setup_command(iface, net, myip, cleanup)


@net.command("link-discover")
@click.option("--iface", default="en6", show_default=True, help="Interface to listen on")
@click.option("--duration", default=12, show_default=True, type=int, help="Seconds to sniff")
def net_link_discover(iface, duration):
    """Passively discover devices on a direct/wired link (ARP/DHCP/mDNS sniff)."""
    from hot_omelet.link_discovery import link_discover_command
    link_discover_command(iface, duration)


@net.command("link-sweep")
@click.option("--iface", default="en6", show_default=True, help="Interface to sweep on")
@click.option("--range", "ranges", multiple=True, help="Extra CIDR range(s) to sweep (repeatable)")
def net_link_sweep(iface, ranges):
    """ARP-sweep common private ranges on a link to find a silent device."""
    from hot_omelet.link_discovery import link_sweep_command
    link_sweep_command(iface, list(ranges) or None)
