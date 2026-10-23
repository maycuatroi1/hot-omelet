"""Direct Ethernet link device discovery.

Consolidates the former root scripts (check_mac_connection, connect_pi,
discover_link, sweep_link) into reusable command backends. All scapy imports
are deferred into the functions that need them so `hot --help` works without
the `full` extra installed.
"""
from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import sys
from collections import defaultdict
from typing import Optional

import click


def _require_scapy():
    try:
        from scapy.all import ARP, Ether, IP, conf, get_if_hwaddr, sniff, srp  # noqa: F401
        return ARP, Ether, IP, conf, get_if_hwaddr, sniff, srp
    except ImportError:
        click.echo(
            click.style(
                "scapy is required for link discovery. Install with:",
                fg="red", bold=True,
            )
        )
        click.echo("    pip install -e .[full]")
        raise


def normalize_mac(mac: str) -> str:
    hexd = re.sub(r"[^0-9a-fA-F]", "", mac)
    if len(hexd) != 12:
        raise ValueError(f"Invalid MAC address: {mac!r}")
    return ":".join(hexd[i:i + 2] for i in range(0, 12, 2)).lower()


def detect_wired_iface() -> Optional[str]:
    if platform.system() == "Darwin":
        try:
            out = subprocess.check_output(
                ["networksetup", "-listallhardwareports"], text=True
            )
        except Exception:
            return None
        candidates = []
        for b in out.split("Hardware Port:"):
            name = b.strip().splitlines()[0] if b.strip() else ""
            m = re.search(r"Device:\s*(\w+)", b)
            if not m:
                continue
            dev = m.group(1)
            low = name.lower()
            if "wi-fi" in low or "bridge" in low or "thunderbolt 1" in low:
                continue
            if "lan" in low or "ethernet" in low or "usb" in low:
                candidates.append(dev)
        for dev in candidates:
            return dev
        return candidates[0] if candidates else None
    else:
        try:
            out = subprocess.check_output(["ip", "-o", "link"], text=True)
        except Exception:
            return None
        for line in out.splitlines():
            m = re.search(r"\d+:\s*(e[a-z0-9]+):", line)
            if m:
                return m.group(1)
        return None


def _iface_link_status(iface: str) -> str:
    try:
        out = subprocess.check_output(["ifconfig", iface], text=True)
    except Exception:
        return "unknown"
    m = re.search(r"status:\s*(\w+)", out)
    return m.group(1) if m else "unknown"


def _iface_subnet(iface: str) -> Optional[str]:
    try:
        out = subprocess.check_output(["ifconfig", iface], text=True)
    except Exception:
        return None
    ipm = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
    maskm = re.search(r"netmask (0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)", out)
    if not ipm:
        return None
    ip = ipm.group(1)
    if maskm:
        mask = maskm.group(1)
        if mask.startswith("0x"):
            bits = bin(int(mask, 16)).count("1")
        else:
            bits = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    else:
        bits = 24
    return str(ipaddress.IPv4Network(f"{ip}/{bits}", strict=False))


def _arp_resolve(iface, subnet, target_mac, timeout, ARP, Ether, conf, srp):
    conf.verb = 0
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    try:
        ans, _ = srp(pkt, iface=iface, timeout=timeout, verbose=False)
    except PermissionError:
        click.echo("  ! Need root for raw ARP. Re-run with sudo.", err=True)
        return None
    for _, rcv in ans:
        if rcv.hwsrc.lower() == target_mac:
            return rcv.psrc
    return None


def _read_arp_table(target_mac: str) -> Optional[str]:
    try:
        out = subprocess.check_output(["arp", "-a"], text=True)
    except Exception:
        return None
    for line in out.splitlines():
        m = re.search(r"\(([\d.]+)\) at ([0-9a-fA-F:]+)", line)
        if m:
            ip, mac = m.group(1), m.group(2)
            norm = ":".join(f"{int(o, 16):02x}" for o in mac.split(":") if o != "")
            if len(norm.split(":")) == 6 and norm == target_mac:
                return ip
    return None


def _ping(ip: str, count: int):
    try:
        out = subprocess.run(
            ["ping", "-c", str(count), "-W", "1000", ip],
            capture_output=True, text=True, timeout=count * 2 + 3,
        )
    except Exception as e:
        return False, str(e)
    txt = out.stdout
    m = re.search(r"(\d+(?:\.\d+)?)% packet loss", txt)
    avg = re.search(r"= [\d.]+/([\d.]+)/", txt)
    loss = m.group(1) if m else "?"
    summary = f"{loss}% loss" + (f", avg {avg.group(1)} ms" if avg else "")
    return out.returncode == 0, summary


def link_check_command(mac: str, iface: Optional[str], timeout: int, count: int):
    ARP, Ether, _IP, conf, _ghw, _sniff, srp = _require_scapy()
    try:
        target = normalize_mac(mac)
    except ValueError as e:
        click.echo(f"[ERROR] {e}")
        sys.exit(2)

    iface = iface or detect_wired_iface()
    if not iface:
        click.echo("[ERROR] Could not detect a wired Ethernet interface. Use --iface.")
        sys.exit(2)

    click.echo(f"Target MAC : {target}")
    click.echo(f"Interface  : {iface}")

    status = _iface_link_status(iface)
    click.echo(f"Link status: {status}")
    if status == "inactive":
        click.echo(
            f"  ! {iface} has no link (cable unplugged or device off). "
            "Plug in the Ethernet cable, then re-run."
        )

    ip = None
    subnet = _iface_subnet(iface)
    if subnet:
        click.echo(f"Subnet     : {subnet}  -> sending ARP who-has ...")
        ip = _arp_resolve(iface, subnet, target, timeout, ARP, Ether, conf, srp)

    if not ip:
        ip = _read_arp_table(target)
        if ip:
            click.echo("  (resolved from system ARP cache)")

    if not ip:
        click.echo("\nRESULT: device NOT reachable on this wired link.")
        click.echo("  - MAC did not answer ARP and is not in the neighbor table.")
        click.echo("  - Check: cable, link light, and that both ends share a subnet.")
        sys.exit(1)

    click.echo(f"Resolved IP: {ip}  (device is L2-reachable)")
    ok, summary = _ping(ip, count)
    click.echo(f"Ping       : {summary}")
    state = "CONNECTED" if ok else "L2-only (ping blocked?)"
    click.echo(f"\nRESULT: device {state} -> {ip}")


_PI_OUIS = ("dc:a6:32", "b8:27:eb", "e4:5f:01", "28:cd:c1", "d8:3a:dd", "2c:cf:67")


def _run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def _configure_iface(iface, myip, mask="255.255.255.0"):
    click.echo(f"[*] Assign {myip}/{mask} to {iface} and bring it up ...")
    r = _run(["ifconfig", iface, "inet", myip, "netmask", mask, "up"])
    if r.returncode != 0:
        click.echo(f"[!] Config error on {iface}: {r.stderr.strip()}")
        click.echo("    -> Re-run with sudo.")
        sys.exit(1)
    info = _run(["ifconfig", iface]).stdout
    for key in ("inet ", "media:", "status:"):
        for line in info.splitlines():
            if key in line:
                click.echo(f"    {line.strip()}")
                break


def _sweep_subnet(iface, net, timeout, ARP, Ether, conf, srp):
    conf.verb = 0
    subnet = f"{net}.0/24"
    click.echo(f"[*] ARP sweep {subnet} on {iface} ...")
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
        iface=iface, timeout=timeout, retry=2, verbose=False,
    )
    hosts = [(r.psrc, r.hwsrc.lower()) for _, r in ans]
    return sorted(set(hosts), key=lambda x: tuple(int(o) for o in x[0].split(".")))


def _check_port(ip, port, t=1.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(t)
    ok = s.connect_ex((ip, port)) == 0
    s.close()
    return ok


def _rev_dns(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def link_setup_command(iface: str, net: str, myip: str, cleanup: bool):
    _ARP, Ether, _IP, conf, _ghw, _sniff, srp = _require_scapy()
    if cleanup:
        click.echo(f"[*] Remove IP from {iface} ...")
        _run(["ifconfig", iface, "inet", myip, "delete"])
        _run(["ifconfig", iface, "down"])
        click.echo("[+] Cleaned up.")
        return

    _configure_iface(iface, myip)
    hosts = _sweep_subnet(iface, net, 2, _ARP, Ether, conf, srp)

    if not hosts:
        click.echo(f"\n[!] No device answered ARP on {net}.0/24.")
        click.echo("    Device may be powered off, eth0 down, or using a different subnet.")
        sys.exit(1)

    click.echo(f"\n[+] Found {len(hosts)} device(s):")
    for ip, mac in hosts:
        if ip == myip:
            continue
        name = _rev_dns(ip) or "?"
        alive, _ = _ping(ip, 2)
        ssh = _check_port(ip, 22)
        oui = mac[:8]
        is_pi = oui in _PI_OUIS
        tag = "  <-- Raspberry Pi (OUI)" if is_pi else ""
        click.echo(
            f"    IP {ip:<15} MAC {mac}  ping={'OK' if alive else 'x'} "
            f"ssh22={'OPEN' if ssh else 'closed'}  host={name}{tag}"
        )
        if ssh:
            click.echo(f"        => SSH:  ssh pi@{ip}")

    click.echo("\n[i] Link established. When done, clean up with:")
    click.echo(f"    hot net link-setup --iface {iface} --myip {myip} --cleanup")


def link_discover_command(iface: str, duration: int):
    _ARP, Ether, IP, conf, get_if_hwaddr, sniff, srp = _require_scapy()
    try:
        my_mac = get_if_hwaddr(iface).lower()
    except Exception:
        my_mac = ""

    seen = defaultdict(lambda: {"ips": set(), "kinds": set()})
    click.echo(f"[*] Listening on {iface} for {duration}s (my MAC {my_mac}) ...")

    def handle(pkt):
        src_mac = None
        src_ip = None
        kind = None
        if pkt.haslayer(_ARP):
            a = pkt[_ARP]
            src_mac = a.hwsrc.lower()
            src_ip = a.psrc
            kind = "ARP-request" if a.op == 1 else "ARP-reply"
        elif pkt.haslayer(Ether) and pkt.haslayer(IP):
            src_mac = pkt[Ether].src.lower()
            src_ip = pkt[IP].src
            kind = "IPv4"
        if not src_mac or src_mac == my_mac or src_mac == "ff:ff:ff:ff:ff:ff":
            return
        rec = seen[src_mac]
        if src_ip and src_ip != "0.0.0.0":
            rec["ips"].add(src_ip)
        if kind:
            rec["kinds"].add(kind)

    sniff(iface=iface, prn=handle, store=False, timeout=duration)

    if not seen:
        click.echo("\n[!] No packets heard from any device (silent / no IP yet).")
        click.echo("    -> Try assigning a static IP then ARP-sweep common ranges.")
        sys.exit(1)

    click.echo(f"\n[+] Detected {len(seen)} device(s) on {iface}:")
    subnets = set()
    for mac, rec in seen.items():
        ips = ", ".join(sorted(rec["ips"])) or "(no IP yet)"
        kinds = ", ".join(sorted(rec["kinds"]))
        click.echo(f"    MAC {mac}  IP {ips}  [{kinds}]")
        for ip in rec["ips"]:
            try:
                subnets.add(str(ipaddress.IPv4Network(f"{ip}/24", strict=False)))
            except Exception:
                pass

    conf.verb = 0
    for sn in subnets:
        click.echo(f"\n[*] Confirm ARP sweep on {sn} ...")
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / _ARP(pdst=sn),
                iface=iface, timeout=3, verbose=False,
            )
            for _, r in ans:
                click.echo(f"    ALIVE  {r.psrc:<15}  {r.hwsrc.lower()}")
        except PermissionError:
            click.echo("    ! need raw socket (sudo) to sweep")


_COMMON_RANGES = [
    "192.168.1.0/24",
    "192.168.0.0/24",
    "192.168.8.0/24",
    "192.168.100.0/24",
    "192.168.2.0/24",
    "10.0.0.0/24",
    "10.0.1.0/24",
    "10.10.10.0/24",
    "169.254.0.0/24",
]


def link_sweep_command(iface: str, ranges: Optional[list[str]]):
    _ARP, Ether, _IP, conf, _ghw, _sniff, srp = _require_scapy()
    conf.verb = 0
    targets = ranges or _COMMON_RANGES
    found = []
    click.echo(f"[*] ARP sweep on {iface} across {len(targets)} common range(s) ...")
    for sn in targets:
        try:
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / _ARP(pdst=sn),
                iface=iface, timeout=2, verbose=False, retry=1,
            )
        except PermissionError:
            click.echo("[!] need raw socket (sudo)")
            sys.exit(2)
        for _, r in ans:
            found.append((r.psrc, r.hwsrc.lower()))
            click.echo(f"    [+] ALIVE  {r.psrc:<15}  MAC {r.hwsrc.lower()}  (range {sn})")

    if not found:
        click.echo("\n[!] No device answered ARP on these ranges.")
        click.echo("    Device may use a different subnet, or assign a static IP first.")
        sys.exit(1)
    else:
        click.echo(f"\n[+] Total {len(found)} device(s) responded on {iface}.")
