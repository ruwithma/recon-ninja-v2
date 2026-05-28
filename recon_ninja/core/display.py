"""Rich terminal UI for ReconNinja v2.

Provides beautiful, real-time terminal output during and after scanning.
Uses the ``rich`` library for panels, tables, progress bars, and live displays.

Functions are split into two categories:

* **During-scan** — progress trackers, phase headers, and live updates.
* **Post-scan** — final summary displays combining all collected data.
"""

from __future__ import annotations

import logging
import re

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

from recon_ninja.core.models import Finding, ScanState, ServiceInfo, Severity, TechInfo

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

# Category → icon for tech stack
_CATEGORY_ICONS: dict[str, str] = {
    "language": "[LANG]",
    "framework": "[FW]",
    "cms": "[CMS]",
    "server": "[SRV]",
    "waf": "[WAF]",
    "library": "[LIB]",
    "os": "[OS]",
    "cdn": "[CDN]",
    "database": "[DB]",
    "analytics": "[AN]",
    "other": "[OTHER]",
}


def _service_style(service: str) -> str:
    """Return a Rich style string for *service*, falling back to ``white``."""
    svc_lower = service.lower().strip()
    for key, style in _SERVICE_STYLES.items():
        if key in svc_lower:
            return style
    return "white"


def _truncate(text: str, max_len: int = 120) -> str:
    """Truncate text to max_len with ellipsis, preserving first line."""
    first_line = text.split("\n")[0]
    if len(first_line) > max_len:
        return first_line[:max_len - 1] + "…"
    return first_line


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

    root_status = "[bold green][+][/] root" if is_root else "[bold yellow][!][/] non-root"

    content = Text.from_markup(
        "[bold bright_green]RECON_NINJA v2[/]\n\n"
        f"  [bold]Target[/]    {target}\n"
        f"  [bold]Interface[/] {interface}\n"
        f"  [bold]Privilege[/] {root_status}\n"
        f"  [bold]Tools[/]     {tool_count} available"
    )

    panel = Panel(
        Align.center(content),
        border_style="bold green",
        padding=(1, 4),
        title="[bold green] RECON_NINJA [/]",
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
    table.add_column("Status", width=8)
    table.add_column("Item", style="bold")
    table.add_column("Detail")

    # Required tools
    for tool_name, found in available_tools.items():
        if tool_name in missing_required:
            icon = "[bold red][x][/]"
            detail = "[bold red]MISSING (required)[/]"
        elif found:
            icon = "[bold green][+][/]"
            detail = "[green]found[/]"
        else:
            icon = "[dim][x][/]"
            detail = "[dim]not found[/]"
        table.add_row(icon, tool_name, detail)

    # SecLists
    sl_icon = "[bold green][+][/]" if seclists_found else "[bold yellow][!][/]"
    sl_detail = (
        "[green]found[/]"
        if seclists_found
        else "[yellow]not found — some modules limited[/]"
    )
    table.add_row(sl_icon, "SecLists", sl_detail)

    # VPN
    vpn_icon = "[bold green][+][/]" if vpn_ok else "[bold yellow][!][/]"
    vpn_detail = "[green]connected[/]" if vpn_ok else "[yellow]not detected[/]"
    table.add_row(vpn_icon, "VPN", vpn_detail)

    # Root
    root_icon = "[bold green][+][/]" if is_root else "[bold yellow][!][/]"
    root_detail = (
        "[green]running as root[/]"
        if is_root
        else "[yellow]non-root — some scans limited[/]"
    )
    table.add_row(root_icon, "Root", root_detail)

    panel = Panel(
        table,
        title="[bold] PRE-FLIGHT CHECKLIST [/]",
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
        The phase number (1–7).
    phase_name:
        A human-readable name for the phase.
    """
    console = get_console()
    console.print()
    console.rule(
        f"[bold bright_yellow]>>> Phase {phase_num}: {phase_name}",
        style="bright_yellow",
    )
    console.print()


# ---------------------------------------------------------------------------
# Port / service display
# ---------------------------------------------------------------------------


def display_port_table(services: dict[int, ServiceInfo], techs: list | None = None) -> None:
    """Display the open-ports table after Phase 2 (service enumeration).

    When nmap fails to detect product/version (shows "—"), supplements
    with tech detected by Wappalyzer/headers if available.

    Parameters
    ----------
    services:
        Mapping of port number → :class:`ServiceInfo`.
    techs:
        Optional list of :class:`TechInfo` to supplement product/version.
    """
    if not services:
        get_console().print("[dim]No open ports discovered.[/]")
        return

    console = get_console()
    table = Table(
        title="[bold bright_cyan] OPEN PORTS & SERVICES [/]",
        show_header=True,
        header_style="bold white",
        border_style="blue",
        title_style="bold bright_cyan",
    )
    table.add_column("PORT", style="bold", justify="right", width=6)
    table.add_column("PROTO", width=5)
    table.add_column("STATE", width=7)
    table.add_column("SERVICE", width=16)
    table.add_column("PRODUCT", min_width=20)
    table.add_column("VERSION", min_width=14)

    # Build a port → tech map for supplementing missing product/version
    port_tech_map: dict[int, list] = {}
    if techs:
        from recon_ninja.core.models import TechInfo
        for t in techs:
            port_tech_map.setdefault(t.port, []).append(t)

    for port in sorted(services):
        svc = services[port]
        style = _service_style(svc.service)
        state_icon = "[green]open[/]" if svc.state == "open" else f"[yellow]{svc.state}[/]"

        product_display = svc.product or "—"
        version_display = svc.version or "—"

        # If nmap didn't detect product/version, supplement with Wappalyzer
        if product_display == "—" and port in port_tech_map:
            server_techs = [t for t in port_tech_map[port] if t.category in ("server", "language")]
            if server_techs:
                product_display = server_techs[0].name
                version_display = server_techs[0].version or "—"
        elif version_display == "—" and port in port_tech_map and svc.product:
            # nmap detected product but not version — check if tech has version
            for t in port_tech_map[port]:
                if t.name.lower() in svc.product.lower() and t.version:
                    version_display = t.version
                    break

        table.add_row(
            str(port),
            svc.proto,
            state_icon,
            f"[{style}]{svc.service}[/]",
            product_display,
            version_display,
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

    console.print(f"  [bold cyan][*][/] Box profile: [bold {accent}]{profile}[/]")
    console.print()


# ---------------------------------------------------------------------------
# Tech stack display
# ---------------------------------------------------------------------------


def display_tech_stack(techs: list[TechInfo]) -> None:
    """Display the detected technology stack in a Rich table.

    Parameters
    ----------
    techs:
        List of :class:`TechInfo` objects detected during scanning.
    """
    if not techs:
        get_console().print("[dim]No technologies detected.[/]")
        return

    console = get_console()

    # Group by port
    ports_with_techs = sorted({t.port for t in techs})
    for port in ports_with_techs:
        port_techs = [t for t in techs if t.port == port]

        table = Table(
            title=f"[bold bright_cyan] Tech Stack — Port {port} [/]",
            show_header=True,
            header_style="bold white",
            border_style="cyan",
            title_style="bold bright_cyan",
        )
        table.add_column("Tag", width=12)
        table.add_column("Technology", style="bold", min_width=16)
        table.add_column("Version", width=12)
        table.add_column("Category", width=12)
        table.add_column("Confidence", width=10)
        table.add_column("Source", width=14)
        table.add_column("CVEs", min_width=10)

        for tech in port_techs:
            cat_icon = _CATEGORY_ICONS.get(tech.category, "[OTHER]")

            category_style = {
                "language": "bold yellow",
                "framework": "bold cyan",
                "cms": "bold magenta",
                "server": "bold green",
                "waf": "bold red",
                "library": "blue",
                "os": "white",
            }.get(tech.category, "white")

            if tech.is_vulnerable:
                cves = ", ".join(tech.cves)
                cve_str = f"[bold red]{cves}[/]"
                row_icon = f"{cat_icon} [bold red][!][/]"
            else:
                cve_str = "[dim]—[/]"
                row_icon = cat_icon

            table.add_row(
                row_icon,
                tech.name,
                tech.version or "—",
                f"[{category_style}]{tech.category or '—'}[/]",
                tech.confidence,
                tech.source,
                cve_str,
            )

        console.print(table)
        console.print()

    # Vulnerable techs alert panel
    vulnerable = [t for t in techs if t.is_vulnerable]
    if vulnerable:
        lines: list[str] = []
        for vtech in vulnerable:
            cve_list = ", ".join(vtech.cves)
            lines.append(
                f"  [bold red][!][/] [bold]{vtech.name} {vtech.version}[/] "
                f"(port {vtech.port}) — [{cve_list}] via {vtech.source}"
            )
            lines.append(
                f"     [dim]→ searchsploit {vtech.name} {vtech.version}[/]"
            )

        content = "\n".join(lines)
        panel = Panel(
            content,
            title="[bold red] VULNERABLE TECHNOLOGIES [/]",
            border_style="bold red",
            padding=(1, 2),
        )
        console.print(panel)
        console.print()


# ---------------------------------------------------------------------------
# Findings display
# ---------------------------------------------------------------------------


def display_findings_panel(findings: list[Finding]) -> None:  # noqa: C901
    """Display findings sorted by severity in a Rich panel.

    Groups findings by severity level with count badges, and truncates
    long descriptions for a cleaner display.  INFO findings are
    collapsed into a summary count to keep the panel focused on
    actionable items for CTF players.

    Parameters
    ----------
    findings:
        The complete list of :class:`Finding` objects.
    """
    if not findings:
        get_console().print("[dim]No findings recorded.[/]")
        return

    console = get_console()

    # Separate INFO from actionable findings
    actionable = [f for f in findings if f.severity != Severity.INFO]
    info_findings = [f for f in findings if f.severity == Severity.INFO]

    sorted_findings = sorted(actionable, key=lambda f: f.severity.rank)

    # Group by severity for structured display
    lines: list[str] = []
    current_sev: Severity | None = None

    for finding in sorted_findings:
        # Add severity group header when severity changes
        if finding.severity != current_sev:
            current_sev = finding.severity
            count = sum(1 for f in sorted_findings if f.severity == current_sev)
            style = current_sev.rich_style
            icon = current_sev.icon
            lines.append(
                f"  [{style}]{icon} {current_sev.value} ({count} findings)[/]"
            )
            lines.append(f"  [{'─' * 40}]")

        cve_tag = f" [dim]({finding.cve})[/]" if finding.cve else ""
        desc = _truncate(finding.description, 100)
        module_tag = f"[dim][{finding.module}][/]"
        lines.append(
            f"    [bold]{finding.title}[/]{cve_tag} {module_tag}"
        )
        if desc and desc != finding.title:
            # Normalize title and description for redundancy comparison
            title_norm = re.sub(r'https?://[^\s/]+', '', finding.title.lower())
            title_norm = re.sub(r'[^a-z0-9]', '', title_norm)

            desc_norm = re.sub(r'https?://[^\s/]+', '', desc.lower())
            desc_norm = re.sub(r'[^a-z0-9]', '', desc_norm)

            for word in ["nikto", "nuclei", "fuzz", "pathfound",
                         "techdetected", "wafdetected", "findingon"]:
                title_norm = title_norm.replace(word, "")
                desc_norm = desc_norm.replace(word, "")

            is_redundant = False
            if not title_norm or not desc_norm:
                is_redundant = True
            elif title_norm in desc_norm or desc_norm in title_norm:
                is_redundant = True

            if not is_redundant:
                lines.append(f"    [dim]{desc}[/]")

    # Collapse INFO findings into a single summary line
    if info_findings:
        info_count = len(info_findings)
        # Group by category for a cleaner summary
        categories: dict[str, int] = {}
        for f in info_findings:
            # Extract category from title
            cat = f.title.split(":")[0] if ":" in f.title else "Other"
            categories[cat] = categories.get(cat, 0) + 1

        lines.append(
            f"  [dim][INFO] INFO ({info_count} findings)[/]"
        )
        lines.append(f"  [{'─' * 40}]")
        cat_parts = [f"{cat} ({cnt})" for cat, cnt in sorted(categories.items())]
        lines.append(
            f"    [dim]{', '.join(cat_parts[:8])}[/]"
        )
        lines.append(
            "    [dim]See full report for details[/]"
        )

    content = "\n".join(lines)
    panel = Panel(
        content,
        title="[bold red] FINDINGS [/]",
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
        # Highlight comments differently from actual commands
        if cmd.startswith("#"):
            lines.append(f"  [bold bright_cyan]{i}.[/]  [dim italic]{cmd}[/]")
        else:
            lines.append(f"  [bold bright_cyan]{i}.[/]  [bright_green]{cmd}[/]")

    content = "\n".join(lines)
    panel = Panel(
        content,
        title="[bold bright_cyan] SUGGESTED NEXT STEPS [/]",
        border_style="bright_cyan",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Loot summary
# ---------------------------------------------------------------------------

_LOOT_ICONS: dict[str, str] = {
    "usernames": "[bold cyan][+][/]",
    "hashes": "[bold red][+][/]",
    "emails": "[bold blue][+][/]",
    "urls": "[bold green][+][/]",
    "shares": "[bold yellow][+][/]",
    "kerberos": "[bold magenta][+][/]",
    "certificates": "[bold white][+][/]",
    "configs": "[bold white][+][/]",
    "credentials": "[bold red][+][/]",
    "flags": "[bold red][!][/]",
    "keys": "[bold yellow][+][/]",
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
    table.add_column("Icon")
    table.add_column("Category", style="bold")
    table.add_column("Count", justify="right", style="bright_green")

    for category, count in sorted(loot_counts.items()):
        if count <= 0:
            continue
        icon = _LOOT_ICONS.get(category, "[bold white][+][/]")
        table.add_row(icon, category, str(count))

    panel = Panel(
        table,
        title="[bold bright_yellow] LOOT EXTRACTED [/]",
        border_style="bright_yellow",
        padding=(1, 2),
    )
    console.print(panel)
    console.print()


# ---------------------------------------------------------------------------
# Full scan summary (post-scan)
# ---------------------------------------------------------------------------


def display_attack_paths(state: ScanState) -> None:
    """Display context-aware attack path suggestions.

    Commands are categorized into recon vs. exploitation for clarity.
    """
    from recon_ninja.core.report import _generate_attack_paths, _deduplicated_commands

    console = get_console()

    finding_cmds = _deduplicated_commands(state.all_findings, limit=10)
    context_cmds = _generate_attack_paths(state)
    all_cmds = finding_cmds + [c for c in context_cmds if c not in set(finding_cmds)]

    if not all_cmds:
        console.print("[dim]No suggested attack paths.[/]")
        return

    lines: list[str] = []
    for i, cmd in enumerate(all_cmds[:15], 1):
        # Style comments vs commands differently
        if cmd.startswith("#"):
            lines.append("")
            lines.append(
                f"  [bold bright_yellow]{cmd}[/]"
            )
        else:
            lines.append(
                f"  [bold bright_cyan]{i:2d}.[/]  [bright_green]{cmd}[/]"
            )

    content = "\n".join(lines)
    panel = Panel(
        content,
        title="[bold bright_red] SUGGESTED ATTACK PATHS [/]",
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
    console.rule("[bold bright_green] Scan Complete ", style="bright_green")
    console.print()

    # --- Ports & services ---
    display_port_table(state.services, techs=state.detected_techs)

    # --- Box profile ---
    display_box_profile(state.box_profile)

    # --- Tech stack ---
    if state.detected_techs:
        display_tech_stack(state.detected_techs)

    # --- Discovered paths & vhosts (CTF-critical!) ---
    dirfuzz_findings = [
        f for f in state.all_findings
        if f.module == "web_dirfuzz"
        and (f.title.startswith("Fuzz:") or f.title.startswith("Path found:"))
    ]
    vhost_findings = [
        f for f in state.all_findings
        if f.module == "web_dirfuzz" and f.title.startswith("Vhost found:")
    ]
    if dirfuzz_findings or vhost_findings:
        display_discovered_paths(dirfuzz_findings, vhost_findings)

    # --- Exploit results ---
    exploit_findings = [f for f in state.all_findings if f.module == "vuln_correlate"]
    if exploit_findings:
        display_exploit_results(exploit_findings)

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

    # Tech count
    tech_count = len(state.detected_techs)
    vuln_tech_count = len(state.vulnerable_techs())

    # Hostnames
    hostname_str = ", ".join(state.hostnames[:3]) if state.hostnames else "—"

    footer_text = (
        f"  [bold]Target[/]      {state.target}\n"
        f"  [bold]Hostname[/]    {hostname_str}\n"
        f"  [bold]Output[/]      {output_dir}\n"
        f"  [bold]Duration[/]    {mins}m {secs}s\n"
        f"  [bold]Modules[/]     {len(state.completed_modules)} completed\n"
        f"  [bold]Tech Stack[/]  {tech_count} detected"
        + (
            f"  [bold red]({vuln_tech_count} vulnerable)[/]"
            if vuln_tech_count
            else ""
        )
        + "\n"
        f"  [bold]Findings[/]    {severity_line}\n\n"
        f"  [dim]Reports: {output_dir}/00_SUMMARY.md  "
        f"{output_dir}/00_findings.json[/]"
    )

    panel = Panel(
        footer_text,
        title="[bold bright_green] SCAN SUMMARY [/]",
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
        SpinnerColumn("dots"),
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


# ---------------------------------------------------------------------------
# Discovered paths & vhosts display
# ---------------------------------------------------------------------------


def display_discovered_paths(
    dirfuzz_findings: list[Finding],
    vhost_findings: list[Finding],
) -> None:
    """Display discovered directories and vhosts from web_dirfuzz.

    Parameters
    ----------
    dirfuzz_findings:
        Findings whose titles start with "Fuzz:" or "Path found:".
    vhost_findings:
        Findings whose titles start with "Vhost found:".
    """
    console = get_console()

    # --- Directory / path findings ---
    if dirfuzz_findings:
        # Group by port — extract port from description or evidence
        port_paths: dict[str, list[tuple[str, str, str]]] = {}  # port → [(path, status, size)]
        import re as _re
        for f in dirfuzz_findings:
            # Try to extract structured info from the finding
            # Titles like "Fuzz: /admin (HTTP 200, 1234B)" or "Path found: /.git/ (HTTP 200)"
            # or older format "Fuzz: /admin [200] [1234b]"
            path = ""
            status_code = ""
            size = ""
            title = f.title

            # Extract path — stop before parenthesis or bracket
            path_match = _re.search(r"(?:Fuzz|Path found):\s*(\S+?)(?:\s*[(\[])", title)
            if path_match:
                path = path_match.group(1)
            else:
                # Fallback: grab path without the trailing metadata
                path_match2 = _re.search(r"(?:Fuzz|Path found):\s*(\S+)", title)
                if path_match2:
                    path = path_match2.group(1)

            # Extract status code — supports both (HTTP 200, ...) and [200]
            status_match = _re.search(r"(?:HTTP\s+|Status:\s+)?(\d{3})", title)
            if status_match:
                status_code = status_match.group(1)

            # Extract size — supports (HTTP 200, 1234B), [1234b], Size: 1234
            size = ""
            size_match = _re.search(r"[,(\[]\s*(\d+)\s*B\b", title, _re.IGNORECASE)
            if not size_match:
                size_match = _re.search(r"Size:\s*(\d+)", title, _re.IGNORECASE)
            if not size_match:
                size_match = _re.search(r"\[(\d+)\s*b(?:ytes)?\]", title, _re.IGNORECASE)
            if size_match:
                size = size_match.group(1)

            # Try to extract port from description (URL patterns)
            port = "—"
            port_match = _re.search(r":(\d{1,5})/", f.description or "")
            if port_match:
                port = port_match.group(1)
            elif f.evidence:
                port_match2 = _re.search(r":(\d{1,5})/", f.evidence)
                if port_match2:
                    port = port_match2.group(1)

            port_paths.setdefault(port, []).append((path or title, status_code, size))

        for port, paths in sorted(port_paths.items()):
            table = Table(
                title=f"[bold bright_green] Discovered Paths — Port {port} [/]",
                show_header=True,
                header_style="bold white",
                border_style="green",
                title_style="bold bright_green",
            )
            table.add_column("Status", width=6, justify="center")
            table.add_column("Path", style="bold", min_width=20)
            table.add_column("Size", width=10, justify="right")

            # Sort: status 2xx first, then 3xx, then others
            def _sort_key(item: tuple[str, str, str]) -> str:
                code = item[1]
                if code.startswith("2"):
                    return f"0{code}"
                elif code.startswith("3"):
                    return f"1{code}"
                return f"2{code}"

            for p, sc, sz in sorted(paths, key=_sort_key):
                if sc.startswith("2"):
                    sc_display = f"[bold green]{sc}[/]"
                elif sc.startswith("3"):
                    sc_display = f"[bold cyan]{sc}[/]"
                elif sc.startswith("4"):
                    sc_display = f"[yellow]{sc}[/]"
                elif sc.startswith("5"):
                    sc_display = f"[red]{sc}[/]"
                else:
                    sc_display = sc or "—"
                table.add_row(sc_display, p, sz or "—")

            console.print(table)
            console.print()

    # --- Vhost findings ---
    if vhost_findings:
        table = Table(
            title="[bold bright_magenta] Discovered Vhosts [/]",
            show_header=True,
            header_style="bold white",
            border_style="magenta",
            title_style="bold bright_magenta",
        )
        table.add_column("Vhost", style="bold", min_width=20)
        table.add_column("Status", width=8, justify="center")
        table.add_column("Detail", min_width=20)

        import re as _re2
        for f in vhost_findings:
            title = f.title
            # "Vhost found: models.smarthire.htb Status: 401 Size: 1234"
            # or "Vhost found: models.smarthire.htb (HTTP 401, 1234B)"
            vhost = ""
            status_code = ""
            vhost_match = _re2.search(r"Vhost found:\s*(\S+)", title)
            if vhost_match:
                vhost = vhost_match.group(1)
            # Extract status — supports both (HTTP 401) and Status: 401
            status_match = _re2.search(r"(?:HTTP\s+|Status:\s+)(\d{3})", title)
            if status_match:
                status_code = status_match.group(1)

            if status_code.startswith("2"):
                sc_display = f"[bold green]{status_code}[/]"
            elif status_code.startswith("3"):
                sc_display = f"[bold cyan]{status_code}[/]"
            elif status_code.startswith("4"):
                sc_display = f"[yellow]{status_code}[/]"
            else:
                sc_display = status_code or "—"

            detail = f.description[:80] if f.description else ""
            table.add_row(vhost or title, sc_display, detail)

        console.print(table)
        console.print()


# ---------------------------------------------------------------------------
# Exploit results display
# ---------------------------------------------------------------------------


def display_exploit_results(findings: list[Finding]) -> None:
    """Display searchsploit/exploit findings in a clear table.

    Parameters
    ----------
    findings:
        Findings from the vuln_correlate module.
    """
    if not findings:
        return

    console = get_console()

    table = Table(
        title="[bold bright_red] EXPLOIT RESULTS [/]",
        show_header=True,
        header_style="bold white",
        border_style="red",
        title_style="bold bright_red",
    )
    table.add_column("Query", style="bold", min_width=16)
    table.add_column("Count", justify="right", width=6)
    table.add_column("Top Exploits", min_width=40)

    import re as _re
    for f in findings:
        # Parse: "Exploits found: searchsploit-22 (3 results)"
        # or: "Exploits (broad): Nginx (5 results)"
        title = f.title
        count_match = _re.search(r"\((\d+)\s+results?\)", title)
        count = count_match.group(1) if count_match else "?"

        # Extract query from description
        query = ""
        q_match = _re.search(r"for\s+'([^']+)'", f.description or "")
        if q_match:
            query = q_match.group(1)
        elif "broad" in title.lower():
            broad_match = _re.search(r"broad\):\s*(\S+)", title)
            if broad_match:
                query = broad_match.group(1)

        # Get top exploits from description
        top = ""
        top_match = _re.search(r"Top results?:\s*(.+)", f.description or "")
        if top_match:
            top = top_match.group(1)[:100]

        sev_style = f.severity.rich_style if hasattr(f.severity, "rich_style") else "white"
        table.add_row(
            query or title[:40],
            f"[{sev_style}]{count}[/]",
            top or f.description[:80] if f.description else "—",
        )

    console.print(table)
    console.print()
