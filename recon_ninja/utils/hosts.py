"""/etc/hosts read/write helper for Recon Ninja v2.

Provides functions to read, search, and append entries to ``/etc/hosts``.
All write operations are **sudo-aware** — they use ``sudo tee -a`` to
append, which means the user running the tool must have sudo privileges
(or be root).
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


_ETC_HOSTS = Path("/etc/hosts")


# ---------------------------------------------------------------------------
# Reader
# ---------------------------------------------------------------------------

def read_etc_hosts() -> list[tuple[str, str]]:
    """Parse ``/etc/hosts`` and return all non-comment entries.

    Each valid line (after stripping comments and whitespace) is split
    into an IP address and a hostname.  Lines with multiple hostnames
    produce one entry per hostname.

    Returns
    -------
    list[tuple[str, str]]
        A list of ``(ip, hostname)`` pairs, preserving file order.

    Notes
    -----
    Malformed lines are silently skipped.  If ``/etc/hosts`` cannot be
    read (e.g. permission denied), an empty list is returned.
    """
    entries: list[tuple[str, str]] = []

    try:
        text = _ETC_HOSTS.read_text(encoding="utf-8")
    except (PermissionError, FileNotFoundError, OSError):
        return entries

    for line in text.splitlines():
        # Strip inline comments and whitespace
        line = line.split("#", 1)[0].strip()
        if not line:
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        ip = parts[0]
        # Validate it looks like an IP address
        if not re.match(r"^[\da-fA-F.:]+$", ip):
            continue

        # Each remaining token is a hostname / alias
        for hostname in parts[1:]:
            hostname = hostname.strip()
            if hostname:
                entries.append((ip, hostname))

    return entries


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------

def hostname_exists(hostname: str) -> bool:
    """Check whether a hostname already exists in ``/etc/hosts``.

    Parameters
    ----------
    hostname : str
        The hostname to search for (case-insensitive).

    Returns
    -------
    bool
        ``True`` if the hostname is found in any entry.
    """
    target = hostname.lower()
    for _, entry_host in read_etc_hosts():
        if entry_host.lower() == target:
            return True
    return False


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

def add_to_hosts(ip: str, hostname: str) -> bool:
    """Append an entry to ``/etc/hosts`` using ``sudo tee -a``.

    If an entry for *hostname* already exists, the function returns
    ``True`` without modifying the file (idempotent behaviour).

    Parameters
    ----------
    ip : str
        IPv4 or IPv6 address.
    hostname : str
        Hostname to associate with the IP.

    Returns
    -------
    bool
        ``True`` if the entry was successfully added (or already
        existed), ``False`` on failure.
    """
    # Idempotency check — do not add duplicates
    if hostname_exists(hostname):
        return True

    entry_line = f"{ip} {hostname}\n"

    try:
        result = subprocess.run(
            ["sudo", "tee", "-a", str(_ETC_HOSTS)],
            input=entry_line,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False

    if result.returncode != 0:
        return False

    return True


__all__: list[str] = [
    "read_etc_hosts",
    "add_to_hosts",
    "hostname_exists",
]
