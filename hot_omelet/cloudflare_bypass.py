"""
Cloudflare IP Bypass Module - Find real IP behind Cloudflare/CDN services.

Techniques implemented based on common bypass methods:
1. Subdomain enumeration (direct, ftp, cpanel, mail, etc.)
2. MX record lookup
3. Historical DNS records
4. SSL Certificate search (Censys)
5. Cloudflare IP range validation
6. DNS brute force
"""

import socket
import subprocess
import ipaddress
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# Cloudflare IP ranges (from https://www.cloudflare.com/ips/)
CLOUDFLARE_IPV4_RANGES = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
]

# Common subdomains that might expose real IP
COMMON_SUBDOMAINS = [
    "direct",
    "direct-connect",
    "ftp",
    "cpanel",
    "mail",
    "webmail",
    "smtp",
    "pop",
    "imap",
    "mx",
    "mx1",
    "mx2",
    "email",
    "remote",
    "vpn",
    "admin",
    "panel",
    "dev",
    "staging",
    "test",
    "api",
    "backend",
    "server",
    "origin",
    "origin-www",
    "www2",
    "old",
    "legacy",
    "portal",
    "secure",
    "ssh",
    "sftp",
    "ns1",
    "ns2",
]


@dataclass
class IPResult:
    """Represents a discovered IP address."""
    ip: str
    source: str
    hostname: str = ""
    is_cloudflare: bool = False
    details: dict = field(default_factory=dict)


class CloudflareBypass:
    """Find real IP addresses behind Cloudflare protection."""

    def __init__(self, domain: str, verbose: bool = False):
        self.domain = self._clean_domain(domain)
        self.verbose = verbose
        self.results: list[IPResult] = []
        self._cf_networks = [ipaddress.ip_network(cidr) for cidr in CLOUDFLARE_IPV4_RANGES]

    def _clean_domain(self, domain: str) -> str:
        """Remove protocol and path from domain."""
        domain = domain.lower().strip()
        if "://" in domain:
            domain = domain.split("://")[1]
        if "/" in domain:
            domain = domain.split("/")[0]
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain

    def is_cloudflare_ip(self, ip: str) -> bool:
        """Check if IP belongs to Cloudflare ranges."""
        try:
            ip_addr = ipaddress.ip_address(ip)
            return any(ip_addr in network for network in self._cf_networks)
        except ValueError:
            return False

    def _resolve_hostname(self, hostname: str) -> list[str]:
        """Resolve hostname to IP addresses."""
        ips = []
        try:
            if HAS_DNSPYTHON:
                answers = dns.resolver.resolve(hostname, "A")
                ips = [rdata.address for rdata in answers]
            else:
                result = socket.getaddrinfo(hostname, None, socket.AF_INET)
                ips = list(set(addr[4][0] for addr in result))
        except Exception:
            pass
        return ips

    def _add_result(self, ip: str, source: str, hostname: str = "", details: dict = None):
        """Add IP result if not already found."""
        # Check if IP already exists
        existing_ips = {r.ip for r in self.results}
        if ip not in existing_ips:
            is_cf = self.is_cloudflare_ip(ip)
            self.results.append(IPResult(
                ip=ip,
                source=source,
                hostname=hostname or self.domain,
                is_cloudflare=is_cf,
                details=details or {}
            ))

    def scan_subdomains(self, subdomains: list[str] = None, workers: int = 20) -> list[IPResult]:
        """Method 1: Scan common subdomains for real IP."""
        subdomains = subdomains or COMMON_SUBDOMAINS
        found = []

        def check_subdomain(sub: str):
            hostname = f"{sub}.{self.domain}"
            ips = self._resolve_hostname(hostname)
            results = []
            for ip in ips:
                if not self.is_cloudflare_ip(ip):
                    results.append((ip, hostname))
            return results

        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in subdomains}
            for future in as_completed(futures):
                try:
                    results = future.result()
                    for ip, hostname in results:
                        self._add_result(ip, "subdomain", hostname)
                        found.append(ip)
                except Exception:
                    pass

        return [r for r in self.results if r.source == "subdomain"]

    def scan_mx_records(self) -> list[IPResult]:
        """Method 4: Check MX records for real mail server IP."""
        found = []

        if not HAS_DNSPYTHON:
            # Fallback to nslookup
            try:
                result = subprocess.run(
                    ["nslookup", "-type=MX", self.domain],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                # Parse MX records from output
                for line in result.stdout.split("\n"):
                    if "mail exchanger" in line.lower():
                        parts = line.split()
                        if parts:
                            mx_host = parts[-1].rstrip(".")
                            ips = self._resolve_hostname(mx_host)
                            for ip in ips:
                                if not self.is_cloudflare_ip(ip):
                                    self._add_result(ip, "mx_record", mx_host, {"priority": "unknown"})
                                    found.append(ip)
            except Exception:
                pass
        else:
            try:
                answers = dns.resolver.resolve(self.domain, "MX")
                for rdata in answers:
                    mx_host = str(rdata.exchange).rstrip(".")
                    priority = rdata.preference
                    ips = self._resolve_hostname(mx_host)
                    for ip in ips:
                        if not self.is_cloudflare_ip(ip):
                            self._add_result(ip, "mx_record", mx_host, {"priority": priority})
                            found.append(ip)
            except Exception:
                pass

        return [r for r in self.results if r.source == "mx_record"]

    def scan_dns_history(self, api_key: str = None) -> list[IPResult]:
        """Method 2: Check historical DNS records via SecurityTrails API."""
        if not HAS_REQUESTS:
            console.print("[yellow]requests library not installed, skipping DNS history[/yellow]")
            return []

        found = []

        # Try SecurityTrails if API key provided
        if api_key:
            try:
                headers = {"APIKEY": api_key}
                url = f"https://api.securitytrails.com/v1/history/{self.domain}/dns/a"
                response = requests.get(url, headers=headers, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    for record in data.get("records", []):
                        for value in record.get("values", []):
                            ip = value.get("ip")
                            if ip and not self.is_cloudflare_ip(ip):
                                self._add_result(ip, "dns_history", details={
                                    "first_seen": record.get("first_seen"),
                                    "last_seen": record.get("last_seen"),
                                    "source": "securitytrails"
                                })
                                found.append(ip)
            except Exception as e:
                if self.verbose:
                    console.print(f"[red]SecurityTrails error: {e}[/red]")

        # Try viewdns.info (free, no API key)
        try:
            url = f"https://viewdns.info/iphistory/?domain={self.domain}"
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                # Parse IP addresses from HTML
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                ips = re.findall(ip_pattern, response.text)
                for ip in set(ips):
                    if not self.is_cloudflare_ip(ip):
                        self._add_result(ip, "dns_history", details={"source": "viewdns"})
                        found.append(ip)
        except Exception as e:
            if self.verbose:
                console.print(f"[red]ViewDNS error: {e}[/red]")

        return [r for r in self.results if r.source == "dns_history"]

    def scan_ssl_certificates(self, censys_api_id: str = None, censys_api_secret: str = None) -> list[IPResult]:
        """Method 5: Search SSL certificates via Censys."""
        if not HAS_REQUESTS:
            console.print("[yellow]requests library not installed, skipping SSL scan[/yellow]")
            return []

        found = []

        # Try crt.sh (free, no API key)
        try:
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                certs = response.json()
                hostnames = set()
                for cert in certs:
                    name = cert.get("name_value", "")
                    for host in name.split("\n"):
                        host = host.strip().lstrip("*.")
                        if host and self.domain in host:
                            hostnames.add(host)

                # Resolve discovered hostnames
                for hostname in hostnames:
                    ips = self._resolve_hostname(hostname)
                    for ip in ips:
                        if not self.is_cloudflare_ip(ip):
                            self._add_result(ip, "ssl_cert", hostname, {"source": "crt.sh"})
                            found.append(ip)
        except Exception as e:
            if self.verbose:
                console.print(f"[red]crt.sh error: {e}[/red]")

        # Try Censys if API credentials provided
        if censys_api_id and censys_api_secret:
            try:
                url = "https://search.censys.io/api/v2/certificates/search"
                query = f"parsed.names: {self.domain}"
                headers = {"Accept": "application/json"}
                auth = (censys_api_id, censys_api_secret)

                response = requests.get(
                    url,
                    params={"q": query, "per_page": 100},
                    headers=headers,
                    auth=auth,
                    timeout=15
                )

                if response.status_code == 200:
                    data = response.json()
                    for hit in data.get("result", {}).get("hits", []):
                        for name in hit.get("parsed", {}).get("names", []):
                            if self.domain in name:
                                ips = self._resolve_hostname(name)
                                for ip in ips:
                                    if not self.is_cloudflare_ip(ip):
                                        self._add_result(ip, "ssl_cert", name, {"source": "censys"})
                                        found.append(ip)
            except Exception as e:
                if self.verbose:
                    console.print(f"[red]Censys error: {e}[/red]")

        return [r for r in self.results if r.source == "ssl_cert"]

    def scan_dns_bruteforce(self, wordlist: str = None, workers: int = 50) -> list[IPResult]:
        """Method 3: DNS bruteforce using nmap or custom wordlist."""
        found = []

        # Try nmap dns-brute first
        try:
            result = subprocess.run(
                ["nmap", "--script", "dns-brute", "-sn", self.domain],
                capture_output=True,
                text=True,
                timeout=120
            )

            # Parse nmap output for discovered hosts
            for line in result.stdout.split("\n"):
                if "DNS Brute-force" in line or ".{}".format(self.domain) in line:
                    # Extract hostname and IP
                    match = re.search(r'(\S+\.' + re.escape(self.domain) + r')\s+-\s+(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        hostname, ip = match.groups()
                        if not self.is_cloudflare_ip(ip):
                            self._add_result(ip, "dns_bruteforce", hostname)
                            found.append(ip)
        except subprocess.TimeoutExpired:
            if self.verbose:
                console.print("[yellow]nmap dns-brute timed out[/yellow]")
        except FileNotFoundError:
            if self.verbose:
                console.print("[yellow]nmap not found, skipping dns-brute[/yellow]")
        except Exception as e:
            if self.verbose:
                console.print(f"[red]DNS bruteforce error: {e}[/red]")

        return [r for r in self.results if r.source == "dns_bruteforce"]

    def scan_spf_records(self) -> list[IPResult]:
        """Check SPF records for IP addresses."""
        found = []

        try:
            if HAS_DNSPYTHON:
                answers = dns.resolver.resolve(self.domain, "TXT")
                for rdata in answers:
                    txt = str(rdata)
                    if "v=spf1" in txt.lower():
                        # Extract IP addresses from SPF record
                        ip_matches = re.findall(r'ip4:(\d+\.\d+\.\d+\.\d+(?:/\d+)?)', txt)
                        for ip_cidr in ip_matches:
                            ip = ip_cidr.split("/")[0]
                            if not self.is_cloudflare_ip(ip):
                                self._add_result(ip, "spf_record", details={"spf": txt})
                                found.append(ip)

                        # Extract included domains and resolve them
                        includes = re.findall(r'include:(\S+)', txt)
                        for include in includes:
                            ips = self._resolve_hostname(include)
                            for ip in ips:
                                if not self.is_cloudflare_ip(ip):
                                    self._add_result(ip, "spf_record", include)
                                    found.append(ip)
            else:
                # Fallback to nslookup
                result = subprocess.run(
                    ["nslookup", "-type=TXT", self.domain],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if "v=spf1" in result.stdout.lower():
                    ip_matches = re.findall(r'ip4:(\d+\.\d+\.\d+\.\d+)', result.stdout)
                    for ip in ip_matches:
                        if not self.is_cloudflare_ip(ip):
                            self._add_result(ip, "spf_record")
                            found.append(ip)
        except Exception as e:
            if self.verbose:
                console.print(f"[red]SPF lookup error: {e}[/red]")

        return [r for r in self.results if r.source == "spf_record"]

    def check_direct_ip(self) -> list[IPResult]:
        """Check if main domain resolves to non-Cloudflare IP."""
        found = []

        ips = self._resolve_hostname(self.domain)
        for ip in ips:
            is_cf = self.is_cloudflare_ip(ip)
            self._add_result(ip, "direct", self.domain)
            if not is_cf:
                found.append(ip)

        # Also check www subdomain
        www_domain = f"www.{self.domain}"
        www_ips = self._resolve_hostname(www_domain)
        for ip in www_ips:
            is_cf = self.is_cloudflare_ip(ip)
            self._add_result(ip, "direct", www_domain)
            if not is_cf:
                found.append(ip)

        return [r for r in self.results if r.source == "direct" and not r.is_cloudflare]

    def run_all_scans(
        self,
        securitytrails_key: str = None,
        censys_id: str = None,
        censys_secret: str = None,
        skip_bruteforce: bool = False
    ) -> list[IPResult]:
        """Run all bypass techniques."""

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:

            # Check direct resolution
            task = progress.add_task("[cyan]Checking direct DNS...", total=None)
            self.check_direct_ip()
            progress.remove_task(task)

            # Subdomain scan
            task = progress.add_task("[cyan]Scanning subdomains...", total=None)
            self.scan_subdomains()
            progress.remove_task(task)

            # MX records
            task = progress.add_task("[cyan]Checking MX records...", total=None)
            self.scan_mx_records()
            progress.remove_task(task)

            # SPF records
            task = progress.add_task("[cyan]Checking SPF records...", total=None)
            self.scan_spf_records()
            progress.remove_task(task)

            # SSL certificates
            task = progress.add_task("[cyan]Searching SSL certificates...", total=None)
            self.scan_ssl_certificates(censys_id, censys_secret)
            progress.remove_task(task)

            # DNS history
            task = progress.add_task("[cyan]Checking DNS history...", total=None)
            self.scan_dns_history(securitytrails_key)
            progress.remove_task(task)

            # DNS bruteforce (optional, slow)
            if not skip_bruteforce:
                task = progress.add_task("[cyan]Running DNS bruteforce...", total=None)
                self.scan_dns_bruteforce()
                progress.remove_task(task)

        return self.results

    def get_real_ips(self) -> list[IPResult]:
        """Get only non-Cloudflare IPs from results."""
        return [r for r in self.results if not r.is_cloudflare]

    def print_results(self):
        """Print results in a formatted table."""
        real_ips = self.get_real_ips()
        cf_ips = [r for r in self.results if r.is_cloudflare]

        if real_ips:
            console.print(Panel(
                f"[bold green]Found {len(real_ips)} potential real IP(s) for {self.domain}[/bold green]",
                expand=False
            ))

            table = Table(title="Potential Real IPs (Non-Cloudflare)")
            table.add_column("IP Address", style="green")
            table.add_column("Source", style="cyan")
            table.add_column("Hostname", style="yellow")
            table.add_column("Details", style="dim")

            for result in real_ips:
                details_str = ", ".join(f"{k}={v}" for k, v in result.details.items()) if result.details else ""
                table.add_row(result.ip, result.source, result.hostname, details_str)

            console.print(table)
        else:
            console.print(Panel(
                f"[bold yellow]No non-Cloudflare IPs found for {self.domain}[/bold yellow]",
                expand=False
            ))

        if cf_ips:
            console.print(f"\n[dim]Also found {len(cf_ips)} Cloudflare IP(s): {', '.join(r.ip for r in cf_ips)}[/dim]")

    def export_json(self, filepath: str):
        """Export results to JSON file."""
        data = {
            "domain": self.domain,
            "total_ips": len(self.results),
            "real_ips": len(self.get_real_ips()),
            "cloudflare_ips": len([r for r in self.results if r.is_cloudflare]),
            "results": [
                {
                    "ip": r.ip,
                    "source": r.source,
                    "hostname": r.hostname,
                    "is_cloudflare": r.is_cloudflare,
                    "details": r.details
                }
                for r in self.results
            ]
        }

        with open(filepath, "w") as f:
            json.dump(data, f, indent=2)

        console.print(f"[green]Results exported to {filepath}[/green]")


def find_real_ip(
    domain: str,
    verbose: bool = False,
    securitytrails_key: str = None,
    censys_id: str = None,
    censys_secret: str = None,
    skip_bruteforce: bool = False,
    output: str = None
) -> list[IPResult]:
    """
    Main function to find real IP behind Cloudflare.

    Args:
        domain: Target domain
        verbose: Show detailed output
        securitytrails_key: SecurityTrails API key (optional)
        censys_id: Censys API ID (optional)
        censys_secret: Censys API secret (optional)
        skip_bruteforce: Skip slow DNS bruteforce
        output: Output JSON file path (optional)

    Returns:
        List of discovered IP results
    """
    bypass = CloudflareBypass(domain, verbose=verbose)

    console.print(Panel(
        f"[bold cyan]Cloudflare Bypass Scanner[/bold cyan]\n"
        f"Target: [yellow]{bypass.domain}[/yellow]",
        expand=False
    ))

    bypass.run_all_scans(
        securitytrails_key=securitytrails_key,
        censys_id=censys_id,
        censys_secret=censys_secret,
        skip_bruteforce=skip_bruteforce
    )

    bypass.print_results()

    if output:
        bypass.export_json(output)

    return bypass.results
