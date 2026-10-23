"""
Host discovery + device fingerprinting for camera assessment.

ARP-based discovery (cameras frequently drop ICMP but always answer ARP),
TCP port probing, HTTP banner grab, and vendor classification.
"""
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Ports worth checking on camera / DVR / NVR gear.
#   80/443 web, 554 RTSP, 8000 Hikvision SDK, 8200, 34567 XiongMai DVRIP, 23 telnet
CAMERA_PORTS = [80, 443, 554, 8000, 8200, 34567, 23]


def discover_hosts(target):
    """
    Resolve `target` to a list of host IPs.

    A CIDR ("192.168.1.0/24") triggers an ARP sweep of the subnet; anything
    else is treated as a single host.
    """
    if "/" in target:
        from hot_omelet.network import scan_network
        return scan_network(target)
    return [target]


def tcp_open(ip, port, timeout=1.5):
    """Return True if a TCP connection to ip:port succeeds."""
    try:
        with socket.create_connection((ip, port), timeout):
            return True
    except Exception:
        return False


def scan_ports(ip, ports=None, timeout=1.5):
    """Return the sorted list of open TCP ports from `ports` on `ip`."""
    ports = ports or CAMERA_PORTS
    open_ports = []
    with ThreadPoolExecutor(max_workers=len(ports)) as ex:
        futures = {ex.submit(tcp_open, ip, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            if fut.result():
                open_ports.append(futures[fut])
    return sorted(open_ports)


def http_banner(ip, timeout=4):
    """
    Grab an HTTP banner. Returns scheme, Server header, auth realm and the
    HTML <title> - the body identifies the firmware.
    """
    out = {"scheme": None, "server": None, "realm": None, "title": None}
    for scheme, port in (("http", 80), ("https", 443)):
        try:
            resp = requests.get(f"{scheme}://{ip}:{port}/", timeout=timeout,
                                verify=False, allow_redirects=False)
        except Exception:
            continue
        out["scheme"] = scheme
        out["server"] = resp.headers.get("Server")
        auth = resp.headers.get("WWW-Authenticate", "")
        m = re.search(r'realm="?([^",]+)"?', auth)
        if m:
            out["realm"] = m.group(1).strip()
        m = re.search(r"<title>(.*?)</title>", resp.text or "", re.I | re.S)
        if m:
            out["title"] = m.group(1).strip()
        break
    return out


def classify(open_ports, banner):
    """
    Classify a host into a camera vendor bucket from its open ports and
    HTTP banner. Returns one of: xiongmai, hikvision, generic, unknown.
    """
    title = (banner.get("title") or "").lower()
    server = (banner.get("server") or "").lower()
    realm = (banner.get("realm") or "").lower()

    # XiongMai / NETSurveillance / Sofia firmware - the jackpot.
    if "netsurveillance" in title or 34567 in open_ports:
        return "xiongmai"

    # Hikvision (or OEM rebrand).
    if "hikvision" in realm or "hikvision" in server:
        return "hikvision"
    if "ip camera" in realm:
        return "hikvision"
    if server == "webserver" and 8000 in open_ports:
        return "hikvision"

    # Camera-ish but vendor unclear (RTSP present).
    if 554 in open_ports:
        return "generic"

    return "unknown"
