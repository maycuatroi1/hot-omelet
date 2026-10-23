"""
Scanner utilities module.
Handles port scanning with RustScan, service detection, and web crawling.
"""
import os
import re
import subprocess
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Tuple, Optional
from urllib.parse import urlparse

import click
import requests
from bs4 import BeautifulSoup
from rich.console import Console

from hot_omelet.default_creds.service_detector import ServiceDetector
from .credential_scanner import CredentialScanner

# Initialize rich console for formatted output
console = Console()


def tool_exists(name: str) -> bool:
    """Check if a command-line tool exists."""
    return shutil.which(name) is not None


def normalize_target(target: str) -> str:
    """Normalize target URL/IP."""
    parsed = urlparse(target)
    if parsed.scheme:
        return parsed.netloc or parsed.path
    return target


def run_command(command: List[str]):
    """Run a command and stream its output."""
    process = subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    for line in iter(process.stdout.readline, ""):
        click.echo(line.rstrip())
    process.wait()
    if process.returncode != 0:
        raise click.ClickException(
            f"Command failed with exit code {process.returncode}"
        )


def fetch_website_title(host: str, port: str, protocol: str):
    """Fetch and display the title of a website."""
    protocol = 'https' if protocol == 'https' else 'http'
    url = f"{protocol}://{host}:{port}"
    try:
        response = requests.get(url, timeout=5, verify=False)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.find("title")

        if title and title.string:
            # Use rich to format the output with colors
            title_text = title.string.strip()
            console.print(f"[bold blue]{url}[/bold blue] - [green]Title:[/green] [yellow]{title_text}[/yellow]")
        else:
            console.print(f"[bold blue]{url}[/bold blue] - [dim]No title found[/dim]")

    except requests.exceptions.SSLError:
        console.print(f"[bold blue]{url}[/bold blue] - [red]SSL error[/red]")
    except requests.exceptions.Timeout:
        console.print(f"[bold blue]{url}[/bold blue] - [yellow]Timeout[/yellow]")
    except requests.exceptions.ConnectionError:
        console.print(f"[bold blue]{url}[/bold blue] - [red]Connection error[/red]")
    except Exception as e:
        console.print(f"[bold blue]{url}[/bold blue] - [red]Error: {str(e)}[/red]")


def detect_services_from_scan(output: str, target: str) -> List[Tuple[str, str]]:
    """Parse scan output to detect services (works with RustScan+nmap output)."""
    services = []

    for line in output.split("\n"):
        port_match = re.match(r"(\d+)/tcp\s+open\s+(\S+)", line)
        if port_match:
            port = port_match.group(1)
            service = port_match.group(2)
            services.append((port, service))

    return services


def process_single_service(target: str, port: str, protocol: str) -> Optional[Tuple[str, str, str]]:
    """Process a single service: fetch title and detect service type.

    Args:
        target: Target host/IP
        port: Port number
        protocol: Protocol (e.g., 'http', 'https')

    Returns:
        Tuple of (port, service, protocol) if service detected, None otherwise
    """
    # Fetch website title (this prints directly)
    fetch_website_title(target, port, protocol)

    # Detect service
    service = ServiceDetector.detect_service(target, port, protocol)
    if service:
        return (port, service, protocol)
    return None


def run_port_scan(target: str) -> List[Dict[str, Any]]:
    """Run port scan using RustScan and optionally scan for default credentials."""
    # Check for rustscan in user's .cargo/bin or system-wide

    rustscan_user_path = os.path.expanduser("~/.cargo/bin/rustscan")
    rustscan_cmd = "rustscan"

    if os.path.exists(rustscan_user_path):
        rustscan_cmd = rustscan_user_path
    elif not tool_exists("rustscan"):
        raise click.ClickException(
            'RustScan is not installed. Run "hot install" first.'
        )

    target = normalize_target(target)

    # Run RustScan with service detection via nmap
    # RustScan will find open ports quickly, then pass them to nmap for service detection
    process = subprocess.Popen(
        [rustscan_cmd, "-a", target],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    output = ""
    for line in iter(process.stdout.readline, ""):
        click.echo(line.rstrip())
        output += line

    process.wait()
    if process.returncode != 0:
        raise click.ClickException(
            f"RustScan failed with exit code {process.returncode}"
        )

    # Parse services
    services = detect_services_from_scan(output, target)
    scan_results = []

    # Use ThreadPoolExecutor for parallel processing
    # Default to 10 workers for good balance between speed and not overwhelming the target
    max_workers = min(10, len(services)) if services else 1

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks to the executor
        future_to_service = {
            executor.submit(process_single_service, target, port, protocol): (port, protocol)
            for port, protocol in services
        }

        # Collect results as they complete
        for future in as_completed(future_to_service):
            port, protocol = future_to_service[future]
            try:
                result = future.result(timeout=10)  # 10 second timeout per service
            except Exception as exc:
                click.echo(f"Service detection for port {port} failed: {exc}")

    scan_results += [{"port": port, "service": "http", "protocol": protocol} for port, protocol in services]
    # Run default credential scans if enabled
    scanner = CredentialScanner()
    for port, service in services:
        result = scanner.scan_service(target, port, service)
        scan_results.append(result)
    return scan_results


def run_katana_scan(target: str):
    """Run katana web crawling tool."""
    if not tool_exists("katana"):
        raise click.ClickException('katana is not installed. Run "hot install" first.')
    target = normalize_target(target)
    run_command(["katana", "-u", target])


# Backward compatibility aliases
run_nmap_scan = run_port_scan
detect_services_from_nmap = detect_services_from_scan
