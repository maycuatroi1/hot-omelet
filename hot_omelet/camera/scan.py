"""
IP camera / DVR / NVR assessment orchestration.

Pipeline: discover hosts -> port + HTTP-banner fingerprint -> dispatch by
vendor (XiongMai DVRIP, Hikvision default creds + CVE detection) -> RTSP
open-stream check -> print findings in the CLAUDE.md [LEVEL] [SERVICE]
[VECTOR] format.
"""
import json

from rich.console import Console

from hot_omelet.camera import dvrip
from hot_omelet.camera.fingerprint import (
    discover_hosts, scan_ports, http_banner, classify,
)
from hot_omelet.camera.hikvision import assess_hikvision
from hot_omelet.camera.rtsp import check_rtsp

console = Console()

# Vendor-specific RTSP request paths for the DESCRIBE probe.
RTSP_PATHS = {
    "xiongmai": "/user=admin&password=&channel=1&stream=1.sdp",
    "hikvision": "/Streaming/Channels/101",
    "generic": "/",
    "unknown": "/",
}

_LEVEL_COLOR = {"CRITICAL": "red", "HIGH": "yellow", "INFO": "cyan"}


def print_finding(level, service, vector, finding, evidence, impact, nxt):
    """Print a finding block in the CLAUDE.md reporting format."""
    color = _LEVEL_COLOR.get(level, "white")
    # \[ renders a literal '[' in rich markup; body lines disable markup so
    # paths and brackets print verbatim.
    console.print(f"  [bold {color}]\\[{level}] \\[{service}] \\[{vector}][/]")
    console.print(f"    - Finding: {finding}", markup=False)
    console.print(f"    - Evidence: {evidence}", markup=False)
    console.print(f"    - Impact: {impact}", markup=False)
    console.print(f"    - Next: {nxt}", markup=False)


def _assess_xiongmai(ip, finding, creds):
    res = dvrip.assess(ip, test_creds=creds)
    finding["dvrip"] = res
    if res.get("login"):
        cred = res["login"]
        empty = res.get("empty_admin")
        print_finding(
            "CRITICAL", "XiongMai DVRIP",
            "Empty Admin Password" if empty else "Default Credentials",
            finding=("admin account has NO password set" if empty else
                     f"default credentials {cred['user']}:{cred['password']!r} valid"),
            evidence=f"DVRIP login {ip}:34567 -> Ret:100, session {cred['session']}",
            impact=("Full device access: live video/audio, account list with "
                    "Sofia password hashes, system configuration"),
            next=("Set a strong unique password; enable ONVIF password check; "
                  "isolate the camera on its own VLAN with no inbound Internet"),
        )
        for acct in res.get("accounts", []):
            tag = "  <-- EMPTY PASSWORD" if acct.get("empty_password") else ""
            console.print(
                f"      account: {acct.get('name')}  "
                f"hash={acct.get('password_hash')}{tag}", markup=False)
    elif res.get("reachable"):
        console.print("    [green]DVRIP: no default credentials worked[/green]")
    elif res.get("error"):
        console.print(f"    [dim]DVRIP unreachable: {res['error']}[/dim]")


def _assess_hikvision(ip, finding, creds):
    res = assess_hikvision(ip, test_creds=creds)
    finding["hikvision"] = res

    dc = res.get("default_creds")
    if dc:
        print_finding(
            "CRITICAL", "Hikvision", "Default Credentials",
            finding=f"default credentials {dc['user']}:{dc['password']} valid",
            evidence=f"digest auth -> 200 on http://{ip}/ISAPI/System/deviceInfo",
            impact="Full camera access: live stream, configuration, user management",
            next="Change the admin password; update firmware to the latest release",
        )

    c79 = res.get("cve_2017_7921") or {}
    if c79.get("vulnerable"):
        print_finding(
            "CRITICAL", "Hikvision", "CVE-2017-7921 Auth Bypass",
            finding="?auth=YWRtaW46MTEK exposes /Security/users without auth",
            evidence=f"GET http://{ip}/Security/users?auth=... -> 200 + UserList",
            impact=("Unauthenticated user/config disclosure - credentials can be "
                    "extracted and the live snapshot pulled without login"),
            next="Update firmware (5.4.5+); there is no configuration-only fix",
        )

    c36 = res.get("cve_2021_36260") or {}
    if c36.get("endpoint_exposed"):
        print_finding(
            "HIGH", "Hikvision", "CVE-2021-36260 Endpoint Exposed",
            finding=("/SDK/webLanguage reachable unauthenticated (RCE "
                     "precondition) - RCE NOT auto-confirmed"),
            evidence=(f"PUT http://{ip}/SDK/webLanguage -> "
                      f"{c36.get('status')} + statusString OK"),
            impact=("If firmware is unpatched this is unauthenticated command "
                    "injection as root - confirm separately before claiming RCE"),
            next=("Update firmware; manually confirm RCE with a time-based "
                  "probe before reporting it as exploitable"),
        )


def _assess_rtsp(ip, finding, vendor):
    path = RTSP_PATHS.get(vendor, RTSP_PATHS["unknown"])
    res = check_rtsp(ip, path=path)
    finding["rtsp"] = res
    if res.get("open_stream"):
        print_finding(
            "CRITICAL", "RTSP", "Open Video Stream",
            finding="RTSP DESCRIBE succeeds without credentials",
            evidence=f"{res['uri']} -> {res.get('status_line')}",
            impact="Live video/audio of the monitored physical space, no auth",
            next="Require RTSP authentication; isolate the camera on its VLAN",
        )
    elif res.get("status") == 401:
        console.print("    [green]RTSP: stream requires authentication[/green]")
    elif res.get("error"):
        console.print(f"    [dim]RTSP unreachable: {res['error']}[/dim]")


def assess_host(ip, rtsp=True, creds=True):
    """Fingerprint a single host and run vendor-specific camera checks."""
    finding = {
        "host": ip, "open_ports": [], "vendor": "unknown", "banner": {},
        "dvrip": None, "hikvision": None, "rtsp": None,
    }

    ports = scan_ports(ip)
    finding["open_ports"] = ports
    if not ports:
        finding["vendor"] = "offline"
        return finding

    banner = http_banner(ip)
    finding["banner"] = banner
    vendor = classify(ports, banner)
    finding["vendor"] = vendor

    title = banner.get("title")
    label = f"  title={title!r}" if title else ""
    console.print(f"\n[bold]{ip}[/bold]  ports={ports}  "
                  f"vendor=[cyan]{vendor}[/cyan]{label}")

    if vendor == "xiongmai" or 34567 in ports:
        _assess_xiongmai(ip, finding, creds)

    if vendor == "hikvision" or 8000 in ports:
        _assess_hikvision(ip, finding, creds)

    if rtsp and 554 in ports:
        _assess_rtsp(ip, finding, vendor)

    return finding


def camera_scan_command(target, rtsp=True, creds=True, json_out=None):
    """
    Discover and assess IP cameras / DVRs / NVRs on `target`.

    `target` may be a single IP/host or a CIDR range. Authorized LAN reviews
    only - this performs default-credential testing and CVE detection.
    """
    console.print(f"[bold cyan]Camera assessment - target: {target}[/bold cyan]")
    console.print("[dim]Authorized LAN reviews only. Read-only fingerprinting + "
                  "known-default credential check + CVE detection.[/dim]")

    try:
        hosts = discover_hosts(target)
    except PermissionError:
        console.print("[red]Host discovery needs root (scapy ARP sweep). "
                      "Re-run with sudo, or pass a single IP instead of a CIDR."
                      "[/red]")
        return
    except Exception as e:
        console.print(f"[red]Discovery failed: {e}[/red]")
        return

    if not hosts:
        console.print("[yellow]No live hosts found.[/yellow]")
        return
    console.print(f"[dim]Hosts to assess: {len(hosts)}[/dim]")

    findings = []
    for ip in hosts:
        try:
            findings.append(assess_host(ip, rtsp=rtsp, creds=creds))
        except Exception as e:
            console.print(f"[red]{ip}: assessment error: {e}[/red]")
            findings.append({"host": ip, "error": str(e)})

    cameras = [f for f in findings
               if f.get("vendor") not in ("unknown", "offline", None)]
    console.print(f"\n[bold]Summary:[/bold] {len(cameras)} camera(s) identified "
                  f"across {len(findings)} host(s) assessed.")

    if json_out:
        with open(json_out, "w") as fh:
            json.dump(findings, fh, indent=2, default=str)
        console.print(f"[green]Findings written to {json_out}[/green]")

    return findings
