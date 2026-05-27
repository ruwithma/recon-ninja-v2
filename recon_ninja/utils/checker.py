"""Tool availability checker for Recon Ninja v2.

Uses ``shutil.which()`` to verify that required and optional external
security tools are present on ``$PATH``.  Results can be consumed
programmatically or formatted for Rich console output.
"""

from __future__ import annotations

import shutil
from typing import Any

from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.console import Console

# ---------------------------------------------------------------------------
# Tool registries – maps CLI binary name → package / install hint
# ---------------------------------------------------------------------------

REQUIRED_TOOLS: dict[str, str] = {
    "nmap": "nmap",
    "smbclient": "samba-client",
    "nikto": "nikto",
    "whatweb": "whatweb",
    "sslscan": "sslscan",
    "dnsrecon": "dnsrecon",
    "searchsploit": "exploitdb",
    "ldapsearch": "ldap-utils",
}

OPTIONAL_TOOLS: dict[str, str] = {
    "rustscan": "rustscan",
    "feroxbuster": "feroxbuster",
    "gobuster": "gobuster",
    "ffuf": "ffuf",
    "nuclei": "nuclei",
    "subfinder": "subfinder",
    "httpx": "httpx-toolkit",
    "kerbrute": "kerbrute",
    "gowitness": "gowitness",
    "theHarvester": "theharvester",
    "crackmapexec": "crackmapexec",
    "ssh-audit": "ssh-audit",
    "wpscan": "wpscan",
    "droopescan": "droopescan",
    "testssl.sh": "testssl.sh",
    "amass": "amass",
    "windapsearch": "windapsearch",
    "enum4linux-ng": "enum4linux-ng",
    "smbmap": "smbmap",
    "onesixtyone": "onesixtyone",
    "snmpwalk": "snmp",
    "joomscan": "joomscan",
}


def check_tools() -> dict[str, bool]:
    """Check availability of **all** registered tools.

    Returns
    -------
    dict[str, bool]
        Mapping of tool name → ``True`` if the binary is found on
        ``$PATH``, ``False`` otherwise.
    """
    available: dict[str, bool] = {}
    for tool in {**REQUIRED_TOOLS, **OPTIONAL_TOOLS}:
        available[tool] = shutil.which(tool) is not None
    return available


def get_missing_required(available: dict[str, bool]) -> list[str]:
    """Return a list of required tools that are **not** available.

    Parameters
    ----------
    available : dict[str, bool]
        The result of :func:`check_tools` (or a subset thereof).

    Returns
    -------
    list[str]
        Names of required tools whose value is ``False`` in *available*.
    """
    return [tool for tool in REQUIRED_TOOLS if not available.get(tool, False)]


def format_tool_status(available: dict[str, bool]) -> str:
    """Build a Rich-renderable status table for all tools.

    The returned string is a ``rich.table.Table`` rendered to text via
    ``Console.export_text()`` so it can be printed anywhere.

    Parameters
    ----------
    available : dict[str, bool]
        The result of :func:`check_tools`.

    Returns
    -------
    str
        Plain-text rendering of the tool status table.
    """
    console = Console(width=80, force_terminal=True, legacy_windows=False, record=True)

    table = Table(title="Tool Availability", show_lines=False, expand=False)
    table.add_column("Tool", style="bold", no_wrap=True)
    table.add_column("Type", style="dim")
    table.add_column("Status", justify="center")
    table.add_column("Package", style="dim")

    def _status_icon(found: bool) -> Text:
        return Text("✔", style="green") if found else Text("✘", style="red")

    # Required tools first
    for tool, pkg in REQUIRED_TOOLS.items():
        found = available.get(tool, False)
        table.add_row(tool, "required", _status_icon(found), pkg)

    # Optional tools
    for tool, pkg in OPTIONAL_TOOLS.items():
        found = available.get(tool, False)
        table.add_row(tool, "optional", _status_icon(found), pkg)

    missing = get_missing_required(available)
    if missing:
        warning = Panel(
            f"[bold red]Missing required tools:[/bold red] {', '.join(missing)}\n"
            "Install them before running a full scan.",
            title="Warning",
            style="yellow",
        )
        console.print(table)
        console.print(warning)
    else:
        console.print(table)

    return console.export_text()


__all__: list[str] = [
    "REQUIRED_TOOLS",
    "OPTIONAL_TOOLS",
    "check_tools",
    "get_missing_required",
    "format_tool_status",
]
