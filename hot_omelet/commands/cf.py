"""`hot cf ...` - Cloudflare / CDN bypass."""
import click
from rich import print


@click.group("cf")
def cf():
    """Cloudflare / CDN bypass."""


@cf.command("bypass")
@click.argument("domain", required=False)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed output")
@click.option("--securitytrails-key", envvar="SECURITYTRAILS_API_KEY", help="SecurityTrails API key")
@click.option("--censys-id", envvar="CENSYS_API_ID", help="Censys API ID")
@click.option("--censys-secret", envvar="CENSYS_API_SECRET", help="Censys API secret")
@click.option("--skip-bruteforce", is_flag=True, help="Skip slow DNS bruteforce scan")
@click.option("--output", "-o", help="Output JSON file for results")
def cf_bypass(domain, verbose, securitytrails_key, censys_id, censys_secret, skip_bruteforce, output):
    """Find real IP behind Cloudflare/CDN protection."""
    from hot_omelet.cloudflare_bypass import find_real_ip
    if not domain:
        domain = click.prompt("Enter target domain", type=str)
    find_real_ip(domain=domain, verbose=verbose, securitytrails_key=securitytrails_key,
                 censys_id=censys_id, censys_secret=censys_secret,
                 skip_bruteforce=skip_bruteforce, output=output)


@cf.command("check")
@click.argument("ip", required=True)
def cf_check(ip):
    """Check if an IP belongs to Cloudflare."""
    from hot_omelet.cloudflare_bypass import CloudflareBypass
    bypass = CloudflareBypass("")
    is_cf = bypass.is_cloudflare_ip(ip)
    if is_cf:
        print(f"[yellow]{ip}[/yellow] is a [red]Cloudflare IP[/red]")
    else:
        print(f"[yellow]{ip}[/yellow] is [green]NOT a Cloudflare IP[/green]")


@cf.command("subdomain")
@click.argument("domain", required=False)
@click.option("--wordlist", "-w", help="Custom subdomain wordlist file")
@click.option("--workers", default=20, show_default=True, type=int, help="Number of parallel workers")
@click.option("--output", "-o", help="Output JSON file for results")
def cf_subdomain(domain, wordlist, workers, output):
    """Scan subdomains to find real IP behind Cloudflare."""
    from hot_omelet.cloudflare_bypass import CloudflareBypass
    if not domain:
        domain = click.prompt("Enter target domain", type=str)
    bypass = CloudflareBypass(domain)
    subdomains = None
    if wordlist:
        with open(wordlist) as f:
            subdomains = [line.strip() for line in f if line.strip()]
        print(f"Loaded {len(subdomains)} subdomains from {wordlist}")
    print(f"[cyan]Scanning subdomains for {domain}...[/cyan]")
    bypass.scan_subdomains(subdomains=subdomains, workers=workers)
    bypass.print_results()
    if output:
        bypass.export_json(output)


@cf.command("mx")
@click.argument("domain", required=False)
def cf_mx(domain):
    """Check MX records to find real mail server IP."""
    from hot_omelet.cloudflare_bypass import CloudflareBypass
    if not domain:
        domain = click.prompt("Enter target domain", type=str)
    bypass = CloudflareBypass(domain)
    print(f"[cyan]Checking MX records for {domain}...[/cyan]")
    bypass.scan_mx_records()
    bypass.print_results()
