"""`hot dns ...` - open recursive resolver assessment + DNS cache snooping."""
import json

import click

from hot_omelet.commands._common import (
    host_port_options,
    output_option,
    prompt_host,
    timeout_option,
    workers_option,
)


@click.group("dns")
def dns():
    """Open recursive resolver assessment + DNS cache snooping."""


def _category_option(f):
    return click.option(
        "--category", "-c", multiple=True,
        help="Snoop domain categories (e.g. banking_vn, ai, adult, crypto, "
             "social, cloud_saas, infra; or 'all'). Repeatable.",
    )(f)


@dns.command("snoop")
@host_port_options(53, "DNS port")
@_category_option
@click.option("--wordlist", "-w", help="Custom domain wordlist file (one per line)")
@timeout_option(2)
@workers_option(20)
@output_option()
def dns_snoop(host, port, category, wordlist, timeout, workers, output):
    """Cache-snoop a resolver (RD=0) to reveal what other clients resolved.

    A non-empty answer to a non-recursive query means the name is already in the
    resolver's cache -> someone on that network recently visited it.
    """
    from rich.console import Console
    from rich.table import Table

    from hot_omelet.dns_recon import OpenResolver, wordlists

    console = Console()
    host = prompt_host(host, "DNS resolver hostname or IP")
    domains = wordlists.build_list(categories=category or None, wordlist_file=wordlist)

    console.print(f"[bold]DNS cache snooping[/bold] -> [cyan]{host}:{port}[/cyan] "
                  f"([dim]{len(domains)} domains[/dim])")
    r = OpenResolver(host, port=port, timeout=timeout, workers=workers)
    if not r.reachable():
        console.print(f"[red]Resolver {host}:{port} not answering DNS.[/red]")
        raise SystemExit(1)
    hits = r.snoop(domains)

    table = Table(title="Cached domains (other clients' activity)")
    table.add_column("Domain", style="cyan", no_wrap=True)
    table.add_column("Resolved IP", style="green")
    table.add_column("TTL", justify="right", style="dim")
    for h in sorted(hits, key=lambda x: x.domain):
        table.add_row(h.domain, h.ip, str(h.ttl))
    console.print(table)
    console.print(f"[bold green]{len(hits)}[/bold green]/{len(domains)} cached")

    if output:
        with open(output, "w") as f:
            json.dump({"host": host, "port": port,
                       "hits": [{"domain": h.domain, "ip": h.ip, "ttl": h.ttl} for h in hits]},
                      f, indent=2)
        console.print(f"[dim]Saved -> {output}[/dim]")


@dns.command("scan")
@host_port_options(53, "DNS port")
@_category_option
@click.option("--wordlist", "-w", help="Custom domain wordlist file for snooping")
@click.option("--no-snoop", is_flag=True, help="Skip cache snooping (fingerprint only)")
@timeout_option(2)
@workers_option(20)
@output_option()
def dns_scan(host, port, category, wordlist, no_snoop, timeout, workers, output):
    """Full open-resolver assessment: fingerprint, recursion, DNSSEC, snoop."""
    from rich.console import Console
    from rich.table import Table

    from hot_omelet.dns_recon import OpenResolver, wordlists

    console = Console()
    host = prompt_host(host, "DNS resolver hostname or IP")
    r = OpenResolver(host, port=port, timeout=timeout, workers=workers)

    snoop_domains = [] if no_snoop else wordlists.build_list(
        categories=category or None, wordlist_file=wordlist)
    prof = r.assess(snoop_domains=snoop_domains)

    if not prof.reachable:
        console.print(f"[red]Resolver {host}:{port} not answering DNS.[/red]")
        raise SystemExit(1)

    def yn(v):
        return "[red]yes[/red]" if v else "[green]no[/green]" if v is False else "[dim]?[/dim]"

    summary = Table(show_header=False, box=None)
    summary.add_row("Resolver", f"[cyan]{host}:{port}[/cyan]")
    summary.add_row("Software", prof.software or "[dim]unknown[/dim]")
    if prof.hostname:
        summary.add_row("hostname.bind", prof.hostname)
    summary.add_row("Open recursion", yn(prof.recursion_open))
    summary.add_row("DNSSEC validating", yn(prof.dnssec_validating))
    if not no_snoop:
        summary.add_row("Cache snoop", f"{len(prof.snoop_hits)}/{prof.snoop_total} cached")
    console.print(summary)

    if prof.recursion_open:
        console.print("[yellow]\\[HIGH][/yellow] open recursive resolver - cache snooping / "
                      "amplification surface")
    if prof.snoop_hits:
        table = Table(title="Snooped cache (other clients' activity)")
        table.add_column("Domain", style="cyan", no_wrap=True)
        table.add_column("Resolved IP", style="green")
        table.add_column("TTL", justify="right", style="dim")
        for h in sorted(prof.snoop_hits, key=lambda x: x.domain):
            table.add_row(h.domain, h.ip, str(h.ttl))
        console.print(table)

    if output:
        with open(output, "w") as f:
            json.dump(prof.to_dict(), f, indent=2)
        console.print(f"[dim]Saved -> {output}[/dim]")


@dns.command("fingerprint")
@host_port_options(53, "DNS port")
@timeout_option(2)
def dns_fingerprint(host, port, timeout):
    """Identify resolver software via CHAOS TXT version.bind / hostname.bind."""
    from rich.console import Console

    from hot_omelet.dns_recon import OpenResolver

    console = Console()
    host = prompt_host(host, "DNS resolver hostname or IP")
    r = OpenResolver(host, port=port, timeout=timeout)
    software, hostname = r.fingerprint()
    console.print(f"[cyan]{host}:{port}[/cyan]  software=[bold]{software or 'unknown'}[/bold]"
                  + (f"  hostname={hostname}" if hostname else ""))


@dns.command("categories")
def dns_categories():
    """List available cache-snoop domain categories."""
    from rich.console import Console

    from hot_omelet.dns_recon import wordlists

    console = Console()
    for name, items in wordlists.CATEGORIES.items():
        console.print(f"[cyan]{name:16}[/cyan] [dim]{len(items)} domains[/dim]")
    console.print("\n[dim]Use: hot dns snoop --host TARGET -c banking_vn -c ai  (or -c all)[/dim]")
