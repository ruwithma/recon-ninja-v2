"""/etc/hosts read/write helper for ReconNinja v2.

Provides functions to read, search, and append/update entries to ``/etc/hosts``.
All write operations are **sudo-aware** — they use ``sudo tee`` to
overwrite, which means the user running the tool must have sudo privileges
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
    """Check whether a hostname already exists in ``/etc/hosts``."""
    target = hostname.lower()
    for _, entry_host in read_etc_hosts():
        if entry_host.lower() == target:
            return True
    return False


def get_ip_for_hostname(hostname: str) -> str | None:
    """Get the IP address associated with a hostname in ``/etc/hosts``."""
    target = hostname.lower()
    for ip, entry_host in read_etc_hosts():
        if entry_host.lower() == target:
            return ip
    return None


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

def add_to_hosts(ip: str, hostname: str) -> bool:
    """Append or update an entry in ``/etc/hosts`` using ``sudo tee``.

    If the hostname already points to the correct IP, the function returns
    ``True`` without modifying the file. If it points to a different IP,
    it updates `/etc/hosts` to point to the new IP.
    """
    hostname_lower = hostname.lower()
    current_ip = get_ip_for_hostname(hostname)

    if current_ip == ip:
        return True

    try:
        lines = _ETC_HOSTS.read_text(encoding="utf-8").splitlines()
    except Exception:
        return False

    updated_lines = []
    for line in lines:
        stripped = line.split("#", 1)[0].strip()
        if not stripped:
            updated_lines.append(line)
            continue
        parts = stripped.split()
        if len(parts) >= 2 and any(p.lower() == hostname_lower for p in parts[1:]):
            # Remove this hostname from the line
            remaining_hosts = [p for p in parts[1:] if p.lower() != hostname_lower]
            if remaining_hosts:
                new_line = f"{parts[0]} " + " ".join(remaining_hosts)
                if line.rstrip().endswith("#" + line.split("#", 1)[-1]):
                    new_line += " #" + line.split("#", 1)[-1]
                updated_lines.append(new_line)
        else:
            updated_lines.append(line)

    # Append the new mapping
    updated_lines.append(f"{ip} {hostname}")
    new_content = "\n".join(updated_lines) + "\n"

    try:
        result = subprocess.run(
            ["sudo", "tee", str(_ETC_HOSTS)],
            input=new_content,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except Exception:
        return False

    return result.returncode == 0


__all__: list[str] = [
    "read_etc_hosts",
    "add_to_hosts",
    "hostname_exists",
    "get_ip_for_hostname",
]
