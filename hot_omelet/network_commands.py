"""
Network attack commands module.
Handles ARP poisoning, denial attacks, and MAC scanning.
"""

import time
import click
from typing import Optional

from hot_omelet.network import scan_network
from hot_omelet.network.mac_scanner import MACAddressScanner
from hot_omelet.network.arp_poisoner import ARPPoisoner, create_packet_callback


def mac_scan_command(
    network: Optional[str], timeout: int, online_oui: bool, output: Optional[str]
):
    """Scan network for MAC addresses and fingerprint devices."""
    scanner = MACAddressScanner()
    scanner.load_oui_database(online=online_oui)
    devices = scanner.scan_network_with_mac(network=network, timeout=timeout)
    scanner.display_results(devices)

    if output:
        scanner.export_results(devices, output)


def arp_poison_command(
    target: Optional[str], gateway: Optional[str], analyze: bool, show_all: bool
):
    """Perform ARP poisoning for Man-in-the-Middle attacks."""
    _show_warning("ARP poisoning")

    if not target:
        click.echo(
            click.style(
                "No target specified - will poison ALL devices on the network!",
                fg="red",
                bold=True,
            )
        )

    if not _confirm_attack():
        return

    poisoner = ARPPoisoner()

    try:
        callback = create_packet_callback(show_all=show_all) if analyze else None

        if poisoner.start_poisoning(
            target_ip=target, gateway_ip=gateway, packet_callback=callback
        ):
            _wait_for_interrupt()
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"))
    finally:
        poisoner.stop_poisoning(target_ip=target, gateway_ip=gateway)


def arp_denial_command(
    victim1: Optional[str],
    victim2: Optional[str],
    all: bool,
    bidirectional: bool,
    network: Optional[str],
):
    """Perform ARP denial attack to block communication between hosts."""
    _show_warning("ARP denial")

    poisoner = ARPPoisoner()

    if all:
        _handle_deny_all(poisoner, network)
    else:
        _handle_deny_pair(poisoner, victim1, victim2, bidirectional)


def network_scan_command(network: Optional[str]):
    """Scan the local network for active hosts."""
    ips = scan_network(network)
    for ip in ips:
        click.echo(ip)


# Helper functions
def _show_warning(attack_type: str):
    """Show security warning for attack commands."""
    click.echo(
        click.style(
            f"\n⚠️  WARNING: {attack_type} is a potentially harmful attack!",
            fg="red",
            bold=True,
        )
    )
    click.echo(
        click.style(
            "Only use this tool on networks you own or have explicit permission to test.",
            fg="yellow",
        )
    )
    click.echo(
        click.style(
            "Misuse of this tool may violate laws and regulations.\n", fg="yellow"
        )
    )


def _confirm_attack() -> bool:
    """Confirm user wants to proceed with attack."""
    return click.confirm("Do you want to continue?")


def _wait_for_interrupt():
    """Wait until keyboard interrupt."""
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        click.echo("\n\nStopping attack...")


def _handle_deny_all(poisoner: ARPPoisoner, network: Optional[str]):
    """Handle network-wide denial attack."""
    click.echo(
        click.style("⚠️  DENYING ALL NETWORK COMMUNICATION!", fg="red", bold=True)
    )
    click.echo(
        click.style(
            "This will prevent ALL devices on the network from communicating with each other!",
            fg="red",
        )
    )

    if not click.confirm("Are you ABSOLUTELY sure you want to continue?"):
        click.echo("Aborted.")
        return

    try:
        if poisoner.start_deny_all_network(network=network):
            _wait_for_interrupt()
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"))
    finally:
        poisoner.stop_deny_all_network()


def _handle_deny_pair(
    poisoner: ARPPoisoner,
    victim1: Optional[str],
    victim2: Optional[str],
    bidirectional: bool,
):
    """Handle denial attack between two hosts."""
    if not victim1 or not victim2:
        click.echo(
            click.style(
                "Error: --victim1 and --victim2 are required when not using --all",
                fg="red",
            )
        )
        return

    if victim1 == victim2:
        click.echo(click.style("Error: Victim IPs must be different!", fg="red"))
        return

    click.echo(f"This will block communication between {victim1} and {victim2}")
    if not bidirectional:
        click.echo(f"Only blocking: {victim1} → {victim2}")

    if not _confirm_attack():
        return

    try:
        if poisoner.start_denial(
            victim1_ip=victim1, victim2_ip=victim2, bidirectional=bidirectional
        ):
            _wait_for_interrupt()
    except Exception as e:
        click.echo(click.style(f"Error: {e}", fg="red"))
    finally:
        poisoner.stop_denial(victim1_ip=victim1, victim2_ip=victim2)
