"""Rich terminal UI for ReconNinja v2.

Provides beautiful, real-time terminal output during and after scanning.
Uses the ``rich`` library for panels, tables, progress bars, and live displays.

Functions are split into two categories:

* **During-scan** — progress trackers, phase headers, and live updates.
* **Post-scan** — final summary displays combining all collected data.
"""

from __future__ import annotations

import logging

from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from recon_ninja.core.models import Finding, ScanState, ServiceInfo, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Shared console — callers may override via ``set_console`` if needed
# ---------------------------------------------------------------------------

_console: Console = Console()


def set_console(console: Console) -> None:
    """Replace the module-level :class:`~rich.console.Console` used by all display helpers.

    This is primarily useful for testing or when the caller needs output
    directed to a file / StringIO rather than ``sys.stdout``.
    """
    global _console  # noqa: PLW0603
    _console = console


def get_console() -> Console:
    """Return the current module-level :class:`~rich.console.Console`."""
    return _console


# ---------------------------------------------------------------------------
# Colour / icon helpers
# ---------------------------------------------------------------------------

# Service type → Rich style for the port table
_SERVICE_STYLES: dict[str, str] = {
    "http": "bold green",
    "https": "bold green",
    "ssl/http": "bold green",
    "http-alt": "green",
    "ssh": "bold cyan",
    "smb": "bold yellow",
    "microsoft-ds": "bold yellow",
    "netbios-ssn": "yellow",
    "ftp": "magenta",
    "smtp": "blue",
    "pop3": "blue",
    "imap": "blue",
    "dns": "bright_white",
    "domain": "bright_white",
    "kerberos": "bright_red",
    "kpasswd": "bright_red",
    "ldap": "bright_red",
    "ldaps": "bright_red",
    "msql": "red",
    "mysql": "red",
    "postgresql": "red",
    "rdp": "bright_yellow",
    "ms-wbt-server": "bright_yellow",
    "vnc": "bright_magenta",
    "nfs": "bright_cyan",
    "rpcbind": "cyan",
    "snmp": "dim white",
    "winrm": "bright_green",
}


def _service_style(service: str) -> str:
    """Return a Rich style string for *service*, falling back to ``white``."""
    svc_lower = service.lower().strip()
    for key, style in _SERVICE_STYLES.items():
        if key in svc_lower:
            return style
    return "white"


# ---------------------------------------------------------------------------
# Banner & pre-scan displays
# ---------------------------------------------------------------------------


def display_banner(target: str, interface: str, is_root: bool, tool_count: int) -> None:
    """Display the ReconNinja startup banner with target info.

    Parameters
    ----------
    target:
        The target IP or hostname.
    interface:
        The source interface IP (e.g. tun0 address).
    is_root:
        Whether the tool is running as root.
    tool_count:
        Number of external tools available for use.
    """
    console = get_console()

    root_status = "[bold green]✓[/] root" if is_root else "[bold red]✗[/] non-root"

    content = Text.from_markup(
        "🥷 [bold bright_green]ReconNinja v2[/]\n\n"
        f"  [bold]Target[/]    {target}\n"
        f"  [bold]Interface[/] {interface}\n"
        f"  [bold]Privilege[/] {root_status}\n"
        f"  [bold]Tools[/]     {tool_count} available"
    )

    panel = Panel(
        Align.center(content),
        border_style="bold green",
        padding=(1, 4),
        title="[bold green]🥷 ReconNinja[/]",
        title_align="center",
    )
    console.print(panel)
    console.print()


def display_preflight_checklist(
    available_tools: dict[str, bool],
    missing_required: list[str],
    seclists_found: bool,
    vpn_ok: bool,
    is_root: bool,
) -> None:
    """Display the pre-flight checklist panel.

    Parameters
    ----------
    available_tools:
        Mapping of tool name → whether it is installed.
    missing_required:
        Tools that are required but not found.
    seclists_found:
        Whether SecLists wordlists are available.
    vpn_ok:
        Whether the VPN interface is up.
    is_root:
        Whether running as root.
    """
    console = get_console()
    table = Table(show_header=True, header_style="bold white", box=None, padding=(0, 1))
    table.add_column("Status", width=3)
    table.add_column("Item", style="bold")
    table.add_column("Detail")

    # Required tools
    for tool_name, found in available_tools.items():
        if tool_name in missing_required:
            icon = "❌"
            detail = "[bold red]MISSING (required)[/]"
        elif found:
            icon = "✅"
            detail = "[green]found[/]"
        else:
            icon = "❌"
            detail = "[dim]not found[/]"
        table.add_row(icon, tool_name, detail)

    # SecLists
    sl_icon = "✅" if seclists_found else "⚠️"
    sl_detail = "[green]found[/]" if seclists_found else "[yellow]not found — some modules will be limited[/]"
    table.add_row(sl_icon, "SecLists", sl_detail)

    # VPN
    vpn_icon = "✅" if vpn_ok else "⚠️"
    vpn_detail = "[green]connected[/]" if vpn_ok else "[yellow]not detected[/]"
    table.add_row(vpn_icon, "VPN", vpn_detail)

    # Root
    root_icon = "✅" if is_root else "⚠️"
    root_detail = "[green]running as root[/]" if is_root else "[yellow]non-root — some scans limited[/]"
    table.add_row(root_icon, "Root", root_detail)

    panel = Panel(
        table,
        title="[bold]📋 Pre-Flight Checklist[/]",
        border_style="bright_blue",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Phase headers
# ---------------------------------------------------------------------------


def display_phase_header(phase_num: int, phase_name: str) -> None:
    """Print a phase header line.

    Parameters
    ----------
    phase_num:
        The phase number (1–4).
    phase_name:
        A human-readable name for the phase.
    """
    console = get_console()
    console.print()
    console.rule(f"[bold bright_yellow]⚡ Phase {phase_num}: {phase_name}", style="bright_yellow")
    console.print()


# ---------------------------------------------------------------------------
# Port / service display
# ---------------------------------------------------------------------------


def display_port_table(services: dict[int, ServiceInfo]) -> None:
    """Display the open-ports table after Phase 2 (service enumeration).

    Parameters
    ----------
    services:
        Mapping of port number → :class:`ServiceInfo`.
    """
    if not services:
        get_console().print("[dim]No open ports discovered.[/]")
        return

    console = get_console()
    table = Table(
        title="🌐 Open Ports & Services",
        show_header=True,
        header_style="bold white",
        border_style="blue",
        title_style="bold bright_cyan",
    )
    table.add_column("PORT", style="bold", justify="right", width=6)
    table.add_column("PROTO", width=5)
    table.add_column("SERVICE", width=16)
    table.add_column("PRODUCT", min_width=20)
    table.add_column("VERSION", min_width=14)

    for port in sorted(services):
        svc = services[port]
        style = _service_style(svc.service)
        table.add_row(
            str(port),
            svc.proto,
            f"[{style}]{svc.service}[/]",
            svc.product or "—",
            svc.version or "—",
        )

    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Box profile
# ---------------------------------------------------------------------------


def display_box_profile(profile: str) -> None:
    """Display the box-profile classification badge.

    Parameters
    ----------
    profile:
        The classification string (e.g. ``"WINDOWS_AD"``).
    """
    console = get_console()

    # Choose an accent colour based on common profile keywords
    profile_upper = profile.upper()
    if "WINDOWS" in profile_upper or "AD" in profile_upper:
        accent = "bright_blue"
    elif "LINUX" in profile_upper:
        accent = "bright_yellow"
    elif "WEB" in profile_upper:
        accent = "bright_green"
    else:
        accent = "white"

    console.print(
        f"  🎯 Box profile: [bold {accent}]{profile}[/]"
    )
    console.print()


# ---------------------------------------------------------------------------
# Findings display
# ---------------------------------------------------------------------------


def display_findings_panel(findings: list[Finding]) -> None:
    """Display findings sorted by severity in a Rich panel.

    Parameters
    ----------
    findings:
        The complete list of :class:`Finding` objects.
    """
    if not findings:
        get_console().print("[dim]No findings recorded.[/]")
        return

    console = get_console()
    sorted_findings = sorted(findings, key=lambda f: f.severity.rank)

    lines: list[str] = []
    for finding in sorted_findings:
        style = finding.severity.rich_style
        icon = finding.severity.icon
        cve_tag = f" [dim]({finding.cve})[/]" if finding.cve else ""
        lines.append(
            f"  {icon} [{style}][{finding.severity.value}][/] "
            f"[bold]{finding.title}[/]{cve_tag} — "
            f"{finding.description}"
        )

    content = "\n".join(lines)
    panel = Panel(
        content,
        title="🔥 FINDINGS",
        border_style="bold red",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Next steps
# ---------------------------------------------------------------------------


def display_next_steps(findings: list[Finding]) -> None:
    """Display suggested next-steps panel derived from finding ``suggested_commands``.

    Commands are deduplicated and limited to the top 8.

    Parameters
    ----------
    findings:
        The complete list of :class:`Finding` objects.
    """
    console = get_console()

    # Collect and deduplicate commands while preserving order
    seen: set[str] = set()
    commands: list[str] = []
    for finding in sorted(findings, key=lambda f: f.severity.rank):
        for cmd in finding.suggested_commands:
            if cmd not in seen:
                seen.add(cmd)
                commands.append(cmd)
            if len(commands) >= 8:
                break
        if len(commands) >= 8:
            break

    if not commands:
        console.print("[dim]No suggested next steps.[/]")
        return

    lines: list[str] = []
    for i, cmd in enumerate(commands, 1):
        lines.append(f"  [bold bright_cyan]{i}.[/]  {cmd}")

    content = "\n".join(lines)
    panel = Panel(
        content,
        title="💡 SUGGESTED NEXT STEPS",
        border_style="bright_cyan",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Loot summary
# ---------------------------------------------------------------------------

_LOOT_ICONS: dict[str, str] = {
    "usernames": "👤",
    "hashes": "🔑",
    "emails": "📧",
    "urls": "🔗",
    "shares": "📂",
    "kerberos": "🎫",
    "certificates": "📜",
    "configs": "📝",
}


def display_loot_summary(loot_counts: dict[str, int]) -> None:
    """Display a loot-extraction summary with icons.

    Parameters
    ----------
    loot_counts:
        Mapping of loot category → count (e.g. ``{"usernames": 5, "hashes": 12}``).
    """
    if not loot_counts or all(v == 0 for v in loot_counts.values()):
        get_console().print("[dim]No loot extracted.[/]")
        return

    console = get_console()
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Icon", width=2)
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right", style="bright_green")

    for category, count in sorted(loot_counts.items()):
        if count <= 0:
            continue
        icon = _LOOT_ICONS.get(category, "📦")
        table.add_row(icon, category, str(count))

    panel = Panel(
        table,
        title="💰 LOOT EXTRACTED",
        border_style="bright_yellow",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Full scan summary (post-scan)
# ---------------------------------------------------------------------------


def display_attack_paths(state: ScanState) -> None:
    """Display context-aware attack path suggestions."""
    from recon_ninja.core.report import _generate_attack_paths, _deduplicated_commands
    console = get_console()

    finding_cmds = _deduplicated_commands(state.all_findings, limit=10)
    context_cmds = _generate_attack_paths(state)
    all_cmds = finding_cmds + [c for c in context_cmds if c not in set(finding_cmds)]

    if not all_cmds:
        console.print("[dim]No suggested attack paths.[/]")
        return

    lines = []
    for i, cmd in enumerate(all_cmds[:15], 1):
        lines.append(f"  [bold bright_cyan]{i:2d}.[/]  {cmd}")

    content = "\n".join(lines)
    panel = Panel(
        content,
        title="⚔️ ATTACK PATHS",
        border_style="bright_red",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


def display_scan_summary(state: ScanState) -> None:
    """Display the complete final scan summary.

    Combines the port table, box profile, findings, attack paths, next steps,
    and loot into one cohesive final display.

    Parameters
    ----------
    state:
        The fully-populated :class:`ScanState` after the scan completes.
    """
    console = get_console()

    console.print()
    console.rule("[bold bright_green]🥷 Scan Complete", style="bright_green")
    console.print()

    # --- Ports & services ---
    display_port_table(state.services)

    # --- Box profile ---
    display_box_profile(state.box_profile)

    # --- Findings ---
    display_findings_panel(state.all_findings)

    # --- Loot ---
    # Build loot_counts from module results (best-effort heuristic)
    loot_counts = _extract_loot_counts(state)
    display_loot_summary(loot_counts)

    # --- Attack paths ---
    display_attack_paths(state)

    # --- Next steps ---
    display_next_steps(state.all_findings)

    # --- Footer ---
    _display_footer(state)


def _extract_loot_counts(state: ScanState) -> dict[str, int]:
    """Derive loot category counts from module raw output.

    This is a best-effort heuristic that scans raw output for common
    patterns.  In the future, modules should push structured loot data
    into the state.
    """
    counts: dict[str, int] = {
        "usernames": 0,
        "hashes": 0,
        "emails": 0,
        "shares": 0,
    }

    for result in state.module_results:
        raw = result.raw_output.lower()
        if "username" in raw or "user:" in raw or "accounts:" in raw:
            counts["usernames"] += raw.count("\n")  # rough estimate
        if "hash" in raw or "ntlm" in raw or "kerberoast" in raw:
            counts["hashes"] += raw.count("\n")
        if "share" in raw or "enum4linux" in result.module_name.lower():
            counts["shares"] += raw.count("\n")

    return counts


def _display_footer(state: ScanState) -> None:
    """Print the summary footer with timing, tool counts, and severity breakdown."""
    console = get_console()

    # Severity breakdown
    by_sev = state.findings_by_severity()
    sev_parts: list[str] = []
    for sev in Severity:
        count = len(by_sev.get(sev, []))
        if count:
            sev_parts.append(f"[{sev.rich_style}]{sev.icon} {sev.value}: {count}[/]")

    severity_line = "  ".join(sev_parts) if sev_parts else "[dim]No findings[/]"

    # Duration
    duration = state.duration
    mins, secs = divmod(int(duration), 60)

    # Output directory
    output_dir = state.output_dir

    footer_text = (
        f"  [bold]Output[/]    {output_dir}\n"
        f"  [bold]Duration[/]  {mins}m {secs}s\n"
        f"  [bold]Modules[/]   {len(state.completed_modules)} completed\n"
        f"  [bold]Findings[/]  {severity_line}\n\n"
        f"  [dim]Reports: {output_dir}/00_SUMMARY.md  "
        f"{output_dir}/00_findings.json[/]"
    )

    panel = Panel(
        footer_text,
        title="📊 SCAN SUMMARY",
        border_style="bright_green",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Progress tracker (for Live display during scanning)
# ---------------------------------------------------------------------------


def create_progress_tracker(modules: list[str]) -> Progress:
    """Create a Rich :class:`~rich.progress.Progress` bar for tracking module execution.

    The returned Progress instance is pre-configured with spinner, bar,
    percentage, and elapsed-time columns.  Each module name is added as
    a task so the caller can advance them independently.

    Parameters
    ----------
    modules:
        Ordered list of module names that will be tracked.

    Returns
    -------
    Progress
        A configured Progress instance with one task per module.

    Example
    -------
    ::

        progress = create_progress_tracker(["nmap", "smb", "web"])
        with Live(progress, console=console, refresh_per_second=4):
            progress.advance(progress.task_ids[0])  # advance nmap
    """
    progress = Progress(
        SpinnerColumn("dots"),
        TextColumn("[bold blue]{task.description}", justify="right"),
        BarColumn(bar_width=40, style="blue", complete_style="bright_green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=get_console(),
        transient=False,
    )

    for module_name in modules:
        progress.add_task(module_name, total=100)

    return progress


def create_phase_progress(phase_name: str) -> Progress:
    """Create a simple indeterminate progress for a single phase.

    Unlike :func:`create_progress_tracker` this creates a single task
    with no total, suitable for ``rich.live.Live`` display while a
    phase is running.

    Parameters
    ----------
    phase_name:
        The name of the phase being executed.

    Returns
    -------
    Progress
        A configured Progress instance with one indeterminate task.
    """
    progress = Progress(
        SpinnerColumn("earth"),
        TextColumn("[bold bright_yellow]{task.description}"),
        BarColumn(bar_width=None),
        TimeElapsedColumn(),
        console=get_console(),
    )
    progress.add_task(phase_name, total=None)
    return progress


# ---------------------------------------------------------------------------
# Utility: Live context for scan phases
# ---------------------------------------------------------------------------


def live_scan_display(modules: list[str]) -> Live:
    """Create a :class:`~rich.live.Live` context wrapping a progress tracker.

    Parameters
    ----------
    modules:
        The module names to track.

    Returns
    -------
    Live
        A Live display instance (not yet started).  Use as a context
        manager::

            with live_scan_display(modules) as live:
                ...
    """
    progress = create_progress_tracker(modules)
    return Live(
        progress,
        console=get_console(),
        refresh_per_second=4,
        vertical_overflow="visible",
    )
