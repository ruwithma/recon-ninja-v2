"""Enhanced tool availability checker for ReconNinja v2.

Uses multiple strategies to detect external security tools:
  1. ``shutil.which()`` — standard PATH lookup
  2. Alternative binary names — e.g. ``enum4linux`` vs ``enum4linux-ng``
  3. Common install paths — ``~/go/bin/``, ``/usr/local/bin/``, ``/opt/``
  4. Version detection — runs ``<tool> --version`` (or similar) when found
  5. Functional validation — ensures the binary is actually executable

Results can be consumed programmatically or formatted for Rich console output.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.console import Console

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ToolInfo — rich metadata about each tool
# ---------------------------------------------------------------------------


@dataclass
class ToolInfo:
    """Complete metadata about a single external tool.

    Attributes:
        name: Primary binary name (e.g. ``"nmap"``).
        category: ``"required"`` or ``"optional"``.
        install_method: How to install: ``"apt"``, ``"go"``, ``"pip"``,
            ``"cargo"``, ``"gem"``, ``"git"``, or ``"manual"``.
        install_package: Package name for the install method.
            For ``"apt"``: the apt package name.
            For ``"go"``: the Go module path (e.g. ``"github.com/ffuf/ffuf/v2@latest"``).
            For ``"pip"``: the pip package name.
            For ``"cargo"``: the crate name.
            For ``"gem"``: the gem name.
            For ``"git"``: the clone URL.
            For ``"manual"``: a hint string.
        alt_names: Alternative binary names to check (e.g. ``["enum4linux"]``
            for ``enum4linux-ng``).
        version_flag: CLI flag to get the version string.
            ``"--version"`` is the default; some tools use ``"-V"`` or
            ``"--help"`` (and we parse the first line).
        description: Short one-line description.
        found: Whether the tool was found on this system.
        path: Full path to the binary, or ``None`` if not found.
        version: Detected version string, or ``None`` if not detectable.
        which_name: The binary name that was actually found (may differ
            from ``name`` when an ``alt_names`` match is used).
    """

    name: str
    category: str = "optional"  # "required" | "optional"
    install_method: str = "apt"  # apt | go | pip | cargo | gem | git | manual
    install_package: str = ""
    alt_names: list[str] = field(default_factory=list)
    version_flag: str = "--version"
    description: str = ""
    # -- detection results (populated by check_tools) --
    found: bool = False
    path: str | None = None
    version: str | None = None
    which_name: str | None = None


# ---------------------------------------------------------------------------
# Tool registry — exhaustive list with rich metadata
# ---------------------------------------------------------------------------

TOOL_REGISTRY: list[ToolInfo] = [
    # ── Required tools ──────────────────────────────────────────────────
    ToolInfo(
        name="nmap",
        category="required",
        install_method="apt",
        install_package="nmap",
        version_flag="--version",
        description="Network port scanner and service enumerator",
    ),
    ToolInfo(
        name="smbclient",
        category="required",
        install_method="apt",
        install_package="samba-client",
        alt_names=["smbclient"],
        version_flag="--version",
        description="SMB/CIFS client for share enumeration",
    ),
    ToolInfo(
        name="nikto",
        category="required",
        install_method="apt",
        install_package="nikto",
        version_flag="-Version",
        description="Web server vulnerability scanner",
    ),
    ToolInfo(
        name="whatweb",
        category="required",
        install_method="apt",
        install_package="whatweb",
        version_flag="--version",
        description="Web technology fingerprinter",
    ),
    ToolInfo(
        name="sslscan",
        category="required",
        install_method="apt",
        install_package="sslscan",
        version_flag="--version",
        description="SSL/TLS cipher and certificate scanner",
    ),
    ToolInfo(
        name="dnsrecon",
        category="required",
        install_method="apt",
        install_package="dnsrecon",
        version_flag="--version",
        description="DNS enumeration and reconnaissance tool",
    ),
    ToolInfo(
        name="searchsploit",
        category="required",
        install_method="apt",
        install_package="exploitdb",
        alt_names=["searchsploit"],
        version_flag="-V",
        description="Offline exploit database search tool",
    ),
    ToolInfo(
        name="ldapsearch",
        category="required",
        install_method="apt",
        install_package="ldap-utils",
        version_flag="-VV",
        description="LDAP directory query client",
    ),

    # ── Optional tools — Go ─────────────────────────────────────────────
    ToolInfo(
        name="rustscan",
        category="optional",
        install_method="cargo",
        install_package="rustscan",
        version_flag="--version",
        description="Fast port scanner (Rust-based nmap wrapper)",
    ),
    ToolInfo(
        name="feroxbuster",
        category="optional",
        install_method="apt",
        install_package="feroxbuster",
        alt_names=["feroxbuster"],
        version_flag="--version",
        description="Recursive directory fuzzer (Rust)",
    ),
    ToolInfo(
        name="gobuster",
        category="optional",
        install_method="apt",
        install_package="gobuster",
        version_flag="--version",
        description="Directory/DNS/VHost fuzzer (Go)",
    ),
    ToolInfo(
        name="ffuf",
        category="optional",
        install_method="go",
        install_package="github.com/ffuf/ffuf/v2@latest",
        version_flag="-V",
        description="Fast web fuzzer (Go)",
    ),
    ToolInfo(
        name="nuclei",
        category="optional",
        install_method="go",
        install_package="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        version_flag="--version",
        description="Vulnerability scanner using templates",
    ),
    ToolInfo(
        name="subfinder",
        category="optional",
        install_method="go",
        install_package="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        version_flag="--version",
        description="Passive subdomain discovery tool",
    ),
    ToolInfo(
        name="httpx",
        category="optional",
        install_method="go",
        install_package="github.com/projectdiscovery/httpx/cmd/httpx@latest",
        version_flag="--version",
        description="Fast HTTP prober and toolkit",
    ),
    ToolInfo(
        name="kerbrute",
        category="optional",
        install_method="go",
        install_package="github.com/ropnop/kerbrute@latest",
        version_flag="--version",
        description="Kerberos pre-auth brute forcer",
    ),
    ToolInfo(
        name="gowitness",
        category="optional",
        install_method="go",
        install_package="github.com/sensepost/gowitness@latest",
        version_flag="--version",
        description="Web screenshot tool using Chrome headless",
    ),
    ToolInfo(
        name="amass",
        category="optional",
        install_method="go",
        install_package="github.com/owasp-amass/amass/v4/overrides/cmd/amass@latest",
        version_flag="--version",
        description="In-depth attack surface and asset mapping",
    ),
    ToolInfo(
        name="windapsearch",
        category="optional",
        install_method="go",
        install_package="github.com/ropnop/windapsearch-go@latest",
        alt_names=["windapsearch-go"],
        version_flag="--version",
        description="Active Directory LDAP enumeration tool",
    ),

    # ── Optional tools — Python ─────────────────────────────────────────
    ToolInfo(
        name="theHarvester",
        category="optional",
        install_method="pip",
        install_package="theHarvester",
        alt_names=["theharvester"],
        version_flag="--version",
        description="OSINT email, domain, and IP harvester",
    ),
    ToolInfo(
        name="crackmapexec",
        category="optional",
        install_method="pip",
        install_package="crackmapexec",
        alt_names=["cme"],
        version_flag="--version",
        description="Network swiss-army knife for AD pentesting",
    ),
    ToolInfo(
        name="ssh-audit",
        category="optional",
        install_method="pip",
        install_package="ssh-audit",
        version_flag="--version",
        description="SSH server configuration and policy auditor",
    ),
    ToolInfo(
        name="enum4linux-ng",
        category="optional",
        install_method="pip",
        install_package="enum4linux-ng",
        alt_names=["enum4linux-ng", "enum4linux"],
        version_flag="--version",
        description="SMB/NetBIOS enumeration tool (next-gen)",
    ),
    ToolInfo(
        name="smbmap",
        category="optional",
        install_method="pip",
        install_package="smbmap",
        version_flag="--version",
        description="SMB share permission enumeration tool",
    ),
    ToolInfo(
        name="droopescan",
        category="optional",
        install_method="pip",
        install_package="droopescan",
        version_flag="--version",
        description="CMS vulnerability scanner (Drupal, SilverStripe, etc.)",
    ),

    # ── Optional tools — apt ────────────────────────────────────────────
    ToolInfo(
        name="onesixtyone",
        category="optional",
        install_method="apt",
        install_package="onesixtyone",
        version_flag="--help",
        description="Fast SNMP community string brute forcer",
    ),
    ToolInfo(
        name="snmpwalk",
        category="optional",
        install_method="apt",
        install_package="snmp",
        alt_names=["snmpwalk"],
        version_flag="-v 2c",
        description="SNMP MIB tree walker",
    ),

    # ── Optional tools — Gem ────────────────────────────────────────────
    ToolInfo(
        name="wpscan",
        category="optional",
        install_method="gem",
        install_package="wpscan",
        version_flag="--version",
        description="WordPress security scanner",
    ),

    # ── Optional tools — Git clone ──────────────────────────────────────
    ToolInfo(
        name="testssl.sh",
        category="optional",
        install_method="git",
        install_package="https://github.com/drwetter/testssl.sh.git",
        alt_names=["testssl.sh", "testssl"],
        version_flag="--help",
        description="Comprehensive SSL/TLS testing tool",
    ),
    ToolInfo(
        name="joomscan",
        category="optional",
        install_method="git",
        install_package="https://github.com/OWASP/joomscan.git",
        alt_names=["joomscan", "joomscan.pl"],
        version_flag="--version",
        description="Joomla CMS vulnerability scanner",
    ),
]


# ---------------------------------------------------------------------------
# Extra search paths beyond $PATH
# ---------------------------------------------------------------------------

EXTRA_SEARCH_PATHS: list[Path] = [
    Path.home() / "go" / "bin",
    Path.home() / ".local" / "bin",
    Path("/usr/local/bin"),
    Path("/usr/local/sbin"),
    Path("/opt/recon-tools"),
    Path("/opt"),
]


def _find_binary(name: str) -> tuple[str | None, str | None]:
    """Locate a binary using multiple strategies.

    Returns:
        ``(path, matched_name)`` — the resolved path and the name that
        matched (useful when an ``alt_name`` was found instead).
        ``(None, None)`` if not found.
    """
    # Strategy 1: shutil.which (standard PATH lookup)
    resolved = shutil.which(name)
    if resolved:
        return resolved, name

    # Strategy 2: Check alternative names on PATH
    # (handled by caller iterating alt_names)

    # Strategy 3: Check extra search paths
    for search_dir in EXTRA_SEARCH_PATHS:
        if not search_dir.is_dir():
            continue
        candidate = search_dir / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate), name

    return None, None


def _detect_version(binary_path: str, version_flag: str) -> str | None:
    """Run a tool's version flag and capture the version string.

    Tries to extract a meaningful version from the first few lines of
    output.  Falls back gracefully — never raises.
    """
    if not binary_path:
        return None

    try:
        result = subprocess.run(
            [binary_path, version_flag],
            capture_output=True,
            text=True,
            timeout=10,
            env={**os.environ, "PATH": os.environ.get("PATH", "")},
        )
        output = (result.stdout or "") + (result.stderr or "")
        # Take the first non-empty line that looks like a version string
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Many tools print "ToolName vX.Y.Z" or just "vX.Y.Z" or "X.Y.Z"
            # Skip lines that are just usage/help headers
            if any(skip in line.lower() for skip in ("usage:", "options:", "arguments:", "example")):
                continue
            # Return the first meaningful line (usually contains version)
            # Truncate if too long
            if len(line) > 120:
                line = line[:120] + "..."
            return line
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, OSError) as exc:
        logger.debug("Version detection failed for %s: %s", binary_path, exc)

    return None


# ---------------------------------------------------------------------------
# Core detection API
# ---------------------------------------------------------------------------


def check_tool(tool_info: ToolInfo) -> ToolInfo:
    """Check a single tool's availability and populate detection results.

    Modifies *tool_info* in-place and returns it.

    Strategy:
        1. Try ``shutil.which(tool_info.name)``.
        2. Try each ``alt_name`` via ``shutil.which()``.
        3. Try extra search paths for ``name`` and each ``alt_name``.
        4. If found, detect the version string.
    """
    # Try primary name
    path, matched_name = _find_binary(tool_info.name)

    # Try alternative names
    if path is None and tool_info.alt_names:
        for alt in tool_info.alt_names:
            path, matched_name = _find_binary(alt)
            if path:
                break

    if path:
        tool_info.found = True
        tool_info.path = path
        tool_info.which_name = matched_name
        tool_info.version = _detect_version(path, tool_info.version_flag)
        logger.debug(
            "Tool found: %s → %s (version: %s)",
            tool_info.name,
            path,
            tool_info.version or "unknown",
        )
    else:
        tool_info.found = False
        logger.debug("Tool not found: %s", tool_info.name)

    return tool_info


def check_tools() -> dict[str, bool]:
    """Check availability of **all** registered tools.

    Backward-compatible function returning the same format as the original
    implementation: ``{tool_name: bool}``.

    Returns:
        Mapping of tool name → ``True`` if the binary is found.
    """
    results: dict[str, bool] = {}
    for tool_info in TOOL_REGISTRY:
        check_tool(tool_info)
        results[tool_info.name] = tool_info.found
    return results


def check_tools_detailed() -> list[ToolInfo]:
    """Check all tools and return detailed :class:`ToolInfo` results.

    This is the preferred API for callers that need version, path, or
    install metadata (e.g. the ``check-tools`` CLI command, the
    ``install`` command).
    """
    for tool_info in TOOL_REGISTRY:
        check_tool(tool_info)
    return list(TOOL_REGISTRY)


# ---------------------------------------------------------------------------
# Backward-compatible helpers (existing API surface)
# ---------------------------------------------------------------------------

# Maps used by the legacy API
REQUIRED_TOOLS: dict[str, str] = {
    t.name: t.install_package for t in TOOL_REGISTRY if t.category == "required"
}

OPTIONAL_TOOLS: dict[str, str] = {
    t.name: t.install_package for t in TOOL_REGISTRY if t.category == "optional"
}


def get_missing_required(available: dict[str, bool]) -> list[str]:
    """Return a list of required tools that are **not** available.

    Parameters
    ----------
    available:
        The result of :func:`check_tools` (or a subset thereof).

    Returns
    -------
    list[str]
        Names of required tools whose value is ``False`` in *available*.
    """
    return [tool for tool in REQUIRED_TOOLS if not available.get(tool, False)]


def get_missing_optional(available: dict[str, bool]) -> list[str]:
    """Return a list of optional tools that are **not** available."""
    return [tool for tool in OPTIONAL_TOOLS if not available.get(tool, False)]


# ---------------------------------------------------------------------------
# Rich display
# ---------------------------------------------------------------------------


def format_tool_status(available: dict[str, bool]) -> str:
    """Build a Rich-renderable status table for all tools.

    The returned string is a ``rich.table.Table`` rendered to text via
    ``Console.export_text()`` so it can be printed anywhere.
    """
    console = Console(width=100, force_terminal=True, legacy_windows=False, record=True)

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


def format_detailed_status(tools: list[ToolInfo]) -> None:
    """Print a detailed tool status table with versions and paths.

    Renders directly to the default Rich console — does **not** return
    a string (unlike :func:`format_tool_status`).
    """
    console = Console()

    # ── Summary header ──────────────────────────────────────────────────
    required_found = sum(1 for t in tools if t.category == "required" and t.found)
    required_total = sum(1 for t in tools if t.category == "required")
    optional_found = sum(1 for t in tools if t.category == "optional" and t.found)
    optional_total = sum(1 for t in tools if t.category == "optional")
    total_found = required_found + optional_found
    total_tools = required_total + optional_total

    console.print()
    console.print(Panel(
        f"[bold]Required:[/] [green]{required_found}/{required_total}[/] found  "
        f"[bold]Optional:[/] [green]{optional_found}/{optional_total}[/] found  "
        f"[bold]Total:[/] [bold cyan]{total_found}/{total_tools}[/] available",
        title="[bold]🥷 ReconNinja — Tool Inventory[/]",
        border_style="cyan",
    ))

    # ── Required tools table ────────────────────────────────────────────
    _print_tool_table(console, [t for t in tools if t.category == "required"], "Required Tools")
    _print_tool_table(console, [t for t in tools if t.category == "optional"], "Optional Tools")

    # ── Missing summary ─────────────────────────────────────────────────
    missing_required = [t for t in tools if t.category == "required" and not t.found]
    missing_optional = [t for t in tools if t.category == "optional" and not t.found]

    if missing_required or missing_optional:
        console.print()
        parts: list[str] = []
        if missing_required:
            names = ", ".join(t.name for t in missing_required)
            parts.append(f"[bold red]Missing required:[/] {names}")
        if missing_optional:
            names = ", ".join(t.name for t in missing_optional)
            parts.append(f"[yellow]Missing optional:[/] {names}")
        console.print(Panel(
            "\n".join(parts) + "\n\n[dim]Run [bold]reconninja install[/] to install missing tools.[/]",
            title="[bold yellow]⚠ Missing Tools[/]",
            border_style="yellow",
        ))


def _print_tool_table(console: Console, tools: list[ToolInfo], title: str) -> None:
    """Print a Rich table for a list of ToolInfo objects."""
    if not tools:
        return

    table = Table(title=title, show_lines=False, expand=True)
    table.add_column("Tool", style="bold", no_wrap=True, width=18)
    table.add_column("Status", justify="center", width=8)
    table.add_column("Version", style="dim", max_width=40)
    table.add_column("Path", style="dim", max_width=40, no_wrap=True)
    table.add_column("Install", style="bright_black", max_width=30)

    for tool in tools:
        if tool.found:
            status = Text("✔", style="green")
            version = tool.version or "—"
            path_display = tool.path or "—"
            # Shorten home dir
            if path_display.startswith(str(Path.home())):
                path_display = path_display.replace(str(Path.home()), "~", 1)
        else:
            status = Text("✘", style="red")
            version = ""
            path_display = ""
            # Show which_name if it's an alt match

        install_hint = _install_hint(tool)

        table.add_row(
            tool.name,
            status,
            version,
            path_display,
            install_hint,
        )

    console.print()
    console.print(table)


def _install_hint(tool: ToolInfo) -> str:
    """Build a short install hint string for display."""
    method = tool.install_method
    pkg = tool.install_package

    if method == "apt":
        return f"apt install {pkg}"
    elif method == "go":
        return f"go install {pkg}"
    elif method == "pip":
        return f"pip install {pkg}"
    elif method == "cargo":
        return f"cargo install {pkg}"
    elif method == "gem":
        return f"gem install {pkg}"
    elif method == "git":
        return f"git clone {pkg}"
    elif method == "manual":
        return pkg or "manual"
    else:
        return pkg or method


__all__: list[str] = [
    "REQUIRED_TOOLS",
    "OPTIONAL_TOOLS",
    "TOOL_REGISTRY",
    "ToolInfo",
    "check_tool",
    "check_tools",
    "check_tools_detailed",
    "get_missing_required",
    "get_missing_optional",
    "format_tool_status",
    "format_detailed_status",
]
