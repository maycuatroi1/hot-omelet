"""
MITM (Man-in-the-Middle) universal traffic interceptor package.

Classes:
    MITMInterceptor  — ARP spoof + cleartext traffic interception
    SSLInterceptor   — ARP spoof + DNS spoof + mitmproxy HTTPS interception
    BaseMITM         — shared ARP/network base class

Functions:
    mitm_command     — CLI entry point
"""

from typing import Optional

from .base import BaseMITM
from .interceptor import MITMInterceptor
from .ssl_interceptor import SSLInterceptor

__all__ = ["BaseMITM", "MITMInterceptor", "SSLInterceptor", "mitm_command"]


def mitm_command(
    target: Optional[str],
    gateway: Optional[str],
    gateway_mac: Optional[str],
    interface: str,
    output: str,
    bpf_filter: Optional[str],
    network: Optional[str],
    ssl_intercept: bool = False,
    proxy_port: int = 443,
    domains: Optional[str] = None,
    stealth: bool = False,
):
    """Start MITM interceptor."""
    if ssl_intercept:
        domain_list = [d.strip() for d in domains.split(",")] if domains else []
        interceptor = SSLInterceptor(
            interface=interface, log_dir=output,
            proxy_port=proxy_port, domains=domain_list,
            stealth=stealth,
        )
        interceptor.start(target=target, gateway=gateway, gateway_mac=gateway_mac, network=network)
    else:
        interceptor = MITMInterceptor(interface=interface, log_dir=output, stealth=stealth)
        interceptor.start(
            target=target,
            gateway=gateway,
            gateway_mac=gateway_mac,
            network=network,
            bpf_filter=bpf_filter,
        )
