"""Network utility functions for ReconNinja v2.

Provides target validation, VPN interface detection, privilege checks,
private-IP classification, and CIDR expansion.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
import subprocess


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_IPV4_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6_RE = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")


# ---------------------------------------------------------------------------
# Target validation
# ---------------------------------------------------------------------------

def validate_target(target: str) -> tuple[bool, str]:
    """Validate and resolve a target specification.

    The function accepts:
    - **IPv4 addresses** — validated by regex and checked for octet
      range.
    - **IPv6 addresses** — validated by a basic regex.
    - **Hostnames** — resolved via DNS to an IP address.

    Parameters
    ----------
    target : str
        An IP address or hostname string.

    Returns
    -------
    tuple[bool, str]
        ``(True, resolved_ip)`` on success, or
        ``(False, error_message)`` on failure.
    """
    if not target or not target.strip():
        return False, "Target is empty."

    target = target.strip()

    # --- CIDR ---
    if "/" in target:
        try:
            network = ipaddress.IPv4Network(target, strict=False)
            return True, str(network.network_address)
        except (ipaddress.AddressValueError, ValueError):
            return False, f"Invalid CIDR notation: {target}"

    # --- IPv4 ---
    if _IPV4_RE.match(target):
        octets = target.split(".")
        for octet in octets:
            try:
                val = int(octet)
            except ValueError:
                return False, f"Invalid IPv4 octet: {octet}"
            if val < 0 or val > 255:
                return False, f"IPv4 octet out of range (0-255): {octet}"
        return True, target

    # --- IPv6 ---
    if _IPV6_RE.match(target):
        try:
            ipaddress.IPv6Address(target)
            return True, target
        except ipaddress.AddressValueError:
            return False, f"Invalid IPv6 address: {target}"

    # --- Hostname → DNS resolution ---
    if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?$", target):
        return False, f"Invalid hostname format: {target}"

    try:
        resolved = socket.gethostbyname(target)
        return True, resolved
    except socket.gaierror:
        return False, f"Could not resolve hostname: {target}"
    except socket.timeout:
        return False, f"DNS resolution timed out for: {target}"


# ---------------------------------------------------------------------------
# VPN interface check
# ---------------------------------------------------------------------------

def check_vpn_interface(interface: str = "tun0") -> tuple[bool, str]:
    """Check whether a VPN/network interface is up and has an IP.

    Parses the output of ``ip addr show <interface>``.

    Parameters
    ----------
    interface : str
        Network interface name (default ``"tun0"``).

    Returns
    -------
    tuple[bool, str]
        ``(True, ip_address)`` if the interface exists and has an
        assigned IP, or ``(False, error_message)`` otherwise.
    """
    try:
        result = subprocess.run(
            ["ip", "addr", "show", interface],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        return False, "'ip' command not found — cannot check interface."
    except subprocess.TimeoutExpired:
        return False, f"Timed out querying interface {interface}."

    output = result.stdout

    if not output.strip():
        return False, f"Interface '{interface}' does not exist."

    # Look for an inet line: "inet 10.10.x.x/..."
    inet_match = re.search(r"inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
    if inet_match:
        ip_addr = inet_match.group(1)
        return True, ip_addr

    return False, f"Interface '{interface}' exists but has no IP address assigned."


# ---------------------------------------------------------------------------
# Privilege check
# ---------------------------------------------------------------------------

def is_root() -> bool:
    """Check whether the current process is running as root.

    Returns
    -------
    bool
        ``True`` if the effective user ID is 0.
    """
    return os.geteuid() == 0


# ---------------------------------------------------------------------------
# Local IP helper
# ---------------------------------------------------------------------------

def get_local_ip(interface: str = "tun0") -> str | None:
    """Get the local IP address of the specified interface.

    Parameters
    ----------
    interface : str
        Network interface name (default ``"tun0"``).

    Returns
    -------
    str | None
        The IP address string, or ``None`` if unavailable.
    """
    is_up, result = check_vpn_interface(interface)
    if is_up:
        return result
    return None


# ---------------------------------------------------------------------------
# Private IP check
# ---------------------------------------------------------------------------

def is_private_ip(ip: str) -> bool:
    """Check whether an IP address falls within RFC 1918 private ranges.

    Private ranges:
    - ``10.0.0.0/8``
    - ``172.16.0.0/12``
    - ``192.168.0.0/16``

    Parameters
    ----------
    ip : str
        IPv4 address string.

    Returns
    -------
    bool
        ``True`` if the address is in a private range.
    """
    try:
        addr = ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return False

    private_networks = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    ]

    return any(addr in net for net in private_networks)


# ---------------------------------------------------------------------------
# CIDR expansion
# ---------------------------------------------------------------------------

def expand_cidr(cidr: str) -> list[str]:
    """Expand a CIDR notation into a list of individual IP addresses.

    Parameters
    ----------
    cidr : str
        A network in CIDR notation, e.g. ``"10.10.10.0/24"``.

    Returns
    -------
    list[str]
        All host addresses in the network, **excluding** the network
        and broadcast addresses for /24 and smaller.  For /31 and /32
        all addresses are returned as-is.

    Raises
    ------
    ValueError
        If *cidr* is not a valid network specification.
    """
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
    except ipaddress.AddressValueError as exc:
        raise ValueError(f"Invalid CIDR: {cidr}") from exc

    hosts: list[str] = []
    if network.prefixlen <= 30:
        # Exclude network and broadcast addresses
        hosts = [str(h) for h in network.hosts()]
    else:
        # /31 (point-to-point) or /32 (single host) — include all
        hosts = [str(h) for h in network]

    return hosts


__all__: list[str] = [
    "validate_target",
    "check_vpn_interface",
    "is_root",
    "get_local_ip",
    "is_private_ip",
    "expand_cidr",
]
