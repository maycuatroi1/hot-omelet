"""Top-level standalone commands: scan, install, attack pipelines, tooling."""
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import click
from rich import print


# ── hot scan ─────────────────────────────────────────────

@click.command("scan")
@click.argument("target", required=False)
@click.option("--no-creds", is_flag=True, help="Disable automatic credential scanning")
def scan(target, no_creds):
    """Port scan + service detect (default command)."""
    from hot_omelet.scanner_utils import run_port_scan
    from hot_omelet.hot_redis.redis_extractor import extract_redis_data
    from hot_omelet.hot_redis.redis_cve_scanner import scan_redis_cves

    if not target:
        target = click.prompt("Enter target (IP, domain, or URL)", type=str)
    scan_results = run_port_scan(target)
    for service in scan_results:
        if service.get("service") != "redis":
            continue
        host = target
        port = service["port"]
        credentials = service.get("credentials", [])
        password = None
        for cred in credentials:
            extract_redis_data(ip=host, port=port,
                               username=cred["username"], password=cred["password"])
            password = cred["password"]
        scan_redis_cves(host=host, port=int(port), password=password)


# ── hot install ──────────────────────────────────────────

@click.command("install")
@click.option("--burpsuite", is_flag=True, help="Install Burp Suite Professional")
def install(burpsuite):
    """Install external tools."""
    from hot_omelet.install_utils import install_tools
    install_tools(burpsuite=burpsuite)


# ── pipeline scripts: hot attack / hot 0-day / hot assess ──

def _find_scripts_dir() -> Path:
    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        candidate = parent / "scripts" / "auto_attack.py"
        if candidate.exists():
            return candidate.parent
    return Path.cwd() / "scripts"


_SCRIPTS_DIR = _find_scripts_dir()


@click.command("attack")
@click.argument("target")
@click.option("--type", "target_type", default=None,
              type=click.Choice(["ip", "domain", "mobile", "source"]),
              help="Target type (auto-detected if omitted)")
@click.option("--threads", default=20, show_default=True, type=int)
@click.option("--skip-ai", is_flag=True, help="Skip AI analysis steps")
def attack_cmd(target, target_type, threads, skip_ai):
    """End-to-end automated attack pipeline.

    \b
    Examples:
      hot attack 1.2.3.4
      hot attack example.com
      hot attack app.apk
      hot attack https://github.com/org/repo
    """
    cmd = [sys.executable, str(_SCRIPTS_DIR / "auto_attack.py"), target, "--threads", str(threads)]
    if target_type:
        cmd.extend(["--type", target_type])
    if skip_ai:
        cmd.append("--skip-ai")
    subprocess.run(cmd)


@click.command("0-day")
@click.argument("repo_url")
@click.option("--project-name", default=None, help="Override project name")
@click.option("--skip-clone", is_flag=True, help="Skip cloning if source already exists")
@click.option("--focus", default=None, help="Focus area (e.g. auth, api, deserialization, crypto)")
def zero_day_cmd(repo_url, project_name, skip_clone, focus):
    """Source code 0-day hunting pipeline."""
    cmd = [sys.executable, str(_SCRIPTS_DIR / "zero_day_hunt.py"), repo_url]
    if project_name:
        cmd.extend(["--project-name", project_name])
    if skip_clone:
        cmd.append("--skip-clone")
    if focus:
        cmd.extend(["--focus", focus])
    subprocess.run(cmd)


@click.command("assess")
@click.argument("target")
@click.option("--no-ai", is_flag=True, help="Skip AI analysis phase")
@click.option("--threads", default=20, show_default=True, type=int)
def assess_cmd(target, no_ai, threads):
    """Automated assessment pipeline."""
    cmd = ["bash", str(_SCRIPTS_DIR / "assess.sh"), target, "--threads", str(threads)]
    if no_ai:
        cmd.append("--no-ai")
    subprocess.run(cmd)


# ── hot wordlist (was smart-wordlist) ────────────────────

@click.command("wordlist")
@click.option("--company", "-c", default=None, help="Company name")
@click.option("--domain", "-d", default=None, help="Target domain")
@click.option("--usernames", "-u", default=None, help="Comma-separated usernames")
@click.option("--emails", "-e", default=None, help="Comma-separated emails")
@click.option("--names", "-n", default=None, help="Comma-separated employee names")
@click.option("--keywords", "-k", default=None, help="Comma-separated extra keywords")
@click.option("--output", "-o", default="smart_wordlist.txt", help="Output file")
@click.option("--max", "-m", "max_passwords", default=5000, type=int, help="Max passwords")
@click.option("--pairs", "-p", is_flag=True, help="Output user:pass pairs")
def wordlist_cmd(company, domain, usernames, emails, names, keywords, output, max_passwords, pairs):
    """Generate smart contextual password wordlist from target intel.

    \b
    Examples:
      hot wordlist -c omelet -d omelet.vn -u admin,jdoe
      hot wordlist -c example -d example.com -u admin -k city -o example_wl.txt
      hot wordlist -c omelet -u admin,root -p -o cred_pairs.txt
    """
    from hot_omelet.smart_wordlist import SmartWordlist

    wl = SmartWordlist(
        company=company,
        domain=domain,
        usernames=usernames.split(",") if usernames else [],
        emails=emails.split(",") if emails else [],
        employee_names=names.split(",") if names else [],
        extra_keywords=keywords.split(",") if keywords else [],
        max_passwords=max_passwords,
    )
    path = wl.save_cred_pairs(output) if pairs else wl.save(output)
    stats = wl.stats()
    print(f"[green]Generated {stats['total_passwords']} passwords -> {path}[/green]")
    print(f"[dim]Sample: {stats['sample'][:5]}[/dim]")


# ── hot bf ───────────────────────────────────────────────

@click.command("bf")
@click.argument("service", required=False, type=click.Choice(["pgsql"]))
@click.option("--host", "-H", required=True, help="Target host")
@click.option("--port", "-p", default=None, help="Target port")
@click.option("--user", "-u", default="postgres,admin", help="Username(s), comma-separated")
@click.option("--wordlist", "-w", required=True, help="Password wordlist file")
@click.option("--threads", "-t", default=20, type=int, help="Concurrent threads")
@click.option("--timeout", default=8, type=int, help="Connection timeout seconds")
@click.option("--database", "-d", default="postgres", help="Database name (pgsql)")
@click.option("--creds", "-c", default=None, help="Credentials file (user:pass per line)")
def bf_cmd(service, host, port, user, wordlist, threads, timeout, database, creds):
    """Brute force service credentials (Rust-powered).

    \b
    Examples:
      hot bf pgsql -H 10.0.0.1 -u admin -w wordlist.txt
      hot bf pgsql -H 10.0.0.1 -c creds.txt
    """
    import shutil
    binary = shutil.which("hot-bf") or os.path.expanduser("~/.local/bin/hot-bf")
    if not os.path.isfile(binary):
        print("[red]hot-bf not found. Run: make bf-build[/red]")
        return
    service = service or "pgsql"
    cmd = [binary, service, "-H", host, "-u", user, "-w", wordlist,
           "-t", str(threads), "--timeout", str(timeout), "-d", database]
    if port:
        cmd.extend(["-p", str(port)])
    if creds:
        cmd.extend(["-c", creds])
    subprocess.run(cmd)


# ── hot apk (was apk-download) ───────────────────────────

@click.command("apk")
@click.argument("package", required=False)
@click.option("--source", "-s", type=click.Choice(["google-play", "apk-pure"]),
              default="google-play", help="Download source")
@click.option("--output", "-o", default=".", help="Output directory")
@click.option("--setup", is_flag=True, help="Setup Google account for Play Store downloads")
@click.option("--list-versions", "-l", is_flag=True, help="List available versions")
@click.option("--email", envvar="GOOGLE_EMAIL", help="Google email")
@click.option("--aas-token", envvar="GOOGLE_AAS_TOKEN", help="Google AAS token")
def apk_cmd(package, source, output, setup, list_versions, email, aas_token):
    """Download APK from Google Play Store or APKPure.

    \b
    Examples:
      hot apk org.ssi.iBoardSSI.Pro
      hot apk com.app -s apk-pure
      hot apk --setup
    """
    from hot_omelet.apk_downloader import (
        download_apk,
        extract_package_id,
        list_versions as apk_list_versions,
        setup_google_account,
    )
    if setup:
        setup_google_account(email)
        return
    if not package:
        package = click.prompt("Enter package ID or Play Store URL")
    try:
        package_id = extract_package_id(package)
    except ValueError as e:
        print(f"[red]{e}[/red]")
        return
    print(f"[cyan]Package:[/cyan] [yellow]{package_id}[/yellow]")
    if list_versions:
        apk_list_versions(package_id, email, aas_token)
        return
    result = download_apk(package_id, source, output, email, aas_token)
    if not result and source == "google-play":
        if click.confirm("Try downloading from APKPure instead?", default=True):
            download_apk(package_id, "apk-pure", output)


# ── hot censys ───────────────────────────────────────────

@click.command("censys")
@click.argument("query", required=False)
@click.option("--attack", "-a", help="Use attack preset (e.g., redis-noauth, docker-api)")
@click.option("--list-attacks", is_flag=True, help="List all attack presets")
@click.option("--resource", default="hosts", show_default=True, help="Search resource type")
@click.option("--pages", default=1, show_default=True, type=int, help="Number of pages")
@click.option("--no-headless", is_flag=True, help="Show browser window")
@click.option("--proxy", help="Proxy server (e.g., socks5://127.0.0.1:1080)")
@click.option("--output", "-o", help="Output JSON file")
@click.option("--interactive", "-i", is_flag=True, help="Interactive mode with rotate support")
@click.option("--login", is_flag=True, help="Login to Censys first")
def censys_cmd(query, attack, list_attacks, resource, pages, no_headless, proxy, output, interactive, login):
    """Censys search with IP rotation."""
    from hot_omelet.censys_search import (
        ATTACK_QUERIES,
        CensysSearch,
        censys_search_cli,
    )
    if list_attacks:
        from rich.table import Table
        table = Table(title="Attack Presets")
        table.add_column("Name", style="red")
        table.add_column("Description", style="yellow")
        for name, info in ATTACK_QUERIES.items():
            table.add_row(name, info["desc"])
        print(table)
        return
    if login:
        searcher = CensysSearch(headless=not no_headless, proxy=proxy)
        try:
            searcher.login()
        finally:
            searcher.close()
        return
    if interactive:
        censys_search_cli(None, interactive=True, headless=not no_headless, proxy=proxy)
        return
    if attack:
        censys_search_cli(None, resource=resource, max_pages=pages, headless=not no_headless,
                          proxy=proxy, output=output, attack=attack)
        return
    if not query:
        query = click.prompt("Enter Censys search query", type=str)
    censys_search_cli(query, resource, pages, headless=not no_headless, proxy=proxy, output=output)


# ── hot proxy ────────────────────────────────────────────

@click.command("proxy")
@click.argument("local_host")
@click.argument("remote_host")
@click.option("--ports", "-p", default=None,
              help="Ports to proxy (comma-separated, supports ranges: 80,443,8000-8100)")
@click.option("--all-common", "-a", is_flag=True, help="Proxy all common ports")
@click.option("--no-hosts", is_flag=True, help="Don't modify /etc/hosts")
@click.option("--bind", "-b", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
def proxy_cmd(local_host, remote_host, ports, all_common, no_hosts, bind):
    """TCP proxy: map a local hostname to a remote IP.

    \b
    Examples:
      hot proxy challenge.local 203.0.113.10
      hot proxy challenge.local 203.0.113.10 -p 80,443,8080
      hot proxy challenge.local 203.0.113.10 -p 1-65535 --no-hosts
    """
    from hot_omelet.proxy import proxy_command
    proxy_command(local_host, remote_host, ports, all_common, no_hosts, bind)


# ── hot setup-ssh ────────────────────────────────────────

@click.command("setup-ssh")
@click.option("--password", "-p", required=True, help="SSH password for current user")
@click.option("--ngrok-token", "-t", default=None, help="Ngrok authtoken (saved for future use)")
@click.option("--port", default=22, show_default=True, type=int, help="Local SSH port")
@click.option("--no-ngrok", is_flag=True, help="Only configure SSH, skip ngrok tunnel")
def setup_ssh_cmd(password, ngrok_token, port, no_ngrok):
    """Setup SSH server with password auth and expose via ngrok TCP tunnel.

    \b
    Examples:
      hot setup-ssh -p MyPass123
      hot setup-ssh -p MyPass123 -t 2xxxxx
      hot setup-ssh -p MyPass123 --no-ngrok
    """
    import getpass
    import shutil

    user = getpass.getuser()
    ngrok_bin = shutil.which("ngrok") or os.path.expanduser("~/bin/ngrok")
    ngrok_config = os.path.expanduser("~/.config/ngrok/ngrok.yml")

    print(f"[cyan]Setting up SSH for user:[/cyan] [yellow]{user}[/yellow]")

    sshd_config = f"""Port {port}
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
"""
    try:
        subprocess.run(
            ["sudo", "-S", "bash", "-c",
             f'apt-get install -y -qq openssh-server && '
             f'echo "{user}:{password}" | chpasswd && '
             f'cat > /etc/ssh/sshd_config << SSHEOF\n{sshd_config}SSHEOF\n'
             f'systemctl enable ssh && systemctl restart ssh'],
            input=f"{password}\n", text=True, capture_output=True,
        )
        subprocess.run(
            ["sudo", "-S", "bash", "-c", "systemctl status ssh --no-pager"],
            input=f"{password}\n", text=True, capture_output=True,
        )
        print("[green]SSH server configured and running[/green]")
    except Exception as e:
        print(f"[red]SSH setup failed: {e}[/red]")
        return

    if no_ngrok:
        print(f"[green]SSH ready on port {port}[/green]")
        return

    if not os.path.isfile(ngrok_bin):
        print("[yellow]Installing ngrok...[/yellow]")
        os.makedirs(os.path.expanduser("~/bin"), exist_ok=True)
        subprocess.run(
            ["bash", "-c",
             "curl -sL https://bin.equinox.io/c/bNyj1mQVY4c/ngrok-v3-stable-linux-amd64.tgz "
             "-o /tmp/ngrok.tgz && tar xzf /tmp/ngrok.tgz -C ~/bin/"],
            check=True,
        )
        print("[green]ngrok installed[/green]")

    if ngrok_token:
        subprocess.run([ngrok_bin, "config", "add-authtoken", ngrok_token], check=True)
        print("[green]ngrok authtoken saved[/green]")
    elif not os.path.isfile(ngrok_config):
        print("[red]No ngrok authtoken. Use --ngrok-token or: ngrok config add-authtoken <token>[/red]")
        return

    subprocess.run(["bash", "-c", "pkill -f 'ngrok tcp' || true"])

    proc = subprocess.Popen(
        [ngrok_bin, "tcp", str(port), "--log=stdout", "--log-format=json"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    tunnel_url = None
    deadline = time.time() + 15
    for line in proc.stdout:
        if time.time() > deadline:
            break
        if '"url"' in line:
            try:
                tunnel_url = json.loads(line).get("url", "")
                break
            except json.JSONDecodeError:
                continue
        if '"err"' in line and '"msg":"command failed"' in line:
            print(f"[red]ngrok error: {line.strip()}[/red]")
            proc.terminate()
            return

    if not tunnel_url:
        print("[red]Failed to get tunnel URL within 15s[/red]")
        proc.terminate()
        return

    host, remote_port = tunnel_url.replace("tcp://", "").split(":")
    print()
    print("[green]--- SSH Tunnel Ready ---[/green]")
    print(f"[cyan]Connect:[/cyan] ssh {user}@{host} -p {remote_port}")
    print(f"[cyan]Password:[/cyan] {password}")
    print()
    print(f"[dim]ngrok PID: {proc.pid} | Ctrl+C to stop[/dim]")
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        print("\n[yellow]Tunnel closed[/yellow]")


# ── hot mass-pwn ─────────────────────────────────────────

@click.command("mass-pwn")
@click.option("--targets", "-t", type=click.Path(exists=True), help="File with target IPs")
@click.option("--cidr", "-c", help="CIDR range (e.g., 10.10.10.0/24)")
@click.option("--ip", "-i", help="Comma-separated IPs")
@click.option("--threads", default=20, show_default=True, type=int)
@click.option("--timeout", default=3, show_default=True, type=int)
def mass_pwn_cmd(targets, cidr, ip, threads, timeout):
    """Mass scan + auto-exploit all services on target hosts."""
    from hot_omelet.mass_pwn import MassPwn, parse_targets
    target_list = parse_targets(targets_file=targets, cidr=cidr, ip_list=ip)
    if not target_list:
        click.echo("No targets specified. Use --targets, --cidr, or --ip")
        return
    MassPwn(targets=target_list, threads=threads, timeout=timeout).run()

