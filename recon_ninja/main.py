"""ReconNinja v2 — CLI entry point.

This module defines the ``app`` Typer application that serves as the main
entry point referenced in ``pyproject.toml``::

    reconninja = "recon_ninja.main:app"

CLI commands:
    - ``reconninja <target>``  — run a scan (default when a target is given)
    - ``reconninja scan <target>`` — explicit scan command
    - ``reconninja install``   — auto-install all required/optional tools
    - ``reconninja check-tools`` — check tool availability with version info
"""

from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
import typer
from typer.core import TyperGroup
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from recon_ninja import __version__
from recon_ninja.core.config import load_config, MergeConfig
from recon_ninja.core.engine import ReconEngine, PHASE_NAMES
from recon_ninja.core.models import ReconConfig
from recon_ninja.core.state import StateManager
from recon_ninja.utils.checker import (
    check_tools,
    check_tools_detailed,
    format_detailed_status,
    get_missing_required,
)
from recon_ninja.utils.hosts import add_to_hosts
from recon_ninja.utils.network import (
    check_vpn_interface,
    is_root,
    validate_target,
)
from recon_ninja.utils.wordlists import find_seclists

# ---------------------------------------------------------------------------
# Custom Click group — routes bare args to the 'scan' command
# ---------------------------------------------------------------------------


class ReconNinjaGroup(TyperGroup):
    """Custom Click group that treats unknown first arguments as scan targets.

    If the first positional argument doesn't match a known subcommand,
    it is automatically routed to the ``scan`` command so that
    ``reconninja 10.10.10.1`` works the same as
    ``reconninja scan 10.10.10.1``.
    """

    def resolve_command(self, ctx: click.Context, args: list[str]) -> tuple[str | None, click.Command | None, list[str]]:  # type: ignore[override]
        """Override command resolution to default to 'scan'."""
        # If there are no args, just show help
        if not args:
            return super().resolve_command(ctx, args)  # type: ignore[arg-type, return-value]

        # Known subcommands
        cmd_name = args[0]
        known_commands = set(self.list_commands(ctx))  # type: ignore[arg-type]

        # If the first arg matches a known command, use it normally
        if cmd_name in known_commands:
            return super().resolve_command(ctx, args)  # type: ignore[arg-type, return-value]

        # If first arg starts with '-', it's a flag — route to scan
        # If first arg looks like a target (IP, hostname, CIDR), route to scan
        # This handles: reconninja 10.10.10.1, reconninja --fast 10.10.10.1
        return super().resolve_command(ctx, ["scan"] + args)  # type: ignore[arg-type, return-value]


# ---------------------------------------------------------------------------
# Typer application with custom group
# ---------------------------------------------------------------------------

app = typer.Typer(
    name="reconninja",
    help="Automated reconnaissance tool for CTFs and pentesting",
    add_completion=False,
    rich_markup_mode="rich",
    cls=ReconNinjaGroup,
)


@app.callback(invoke_without_command=True)
def _main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", help="Show version"),
) -> None:
    """RECON_NINJA v2 — Automated reconnaissance for CTFs and pentesting."""
    if version:
        console.print(f"reconninja v{__version__}")
        raise typer.Exit()

console = Console()
err_console = Console(stderr=True)

# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

_BANNER = (
    "[bold bright_cyan]"
    "   __    __  ___   ___    __    __ _____    __ __    _   \n"
    "  /__\\  /__\\/ __\\ /___\\/\\ \\ \\/\\ \\ \\\\_   /\\ \\ \\\\ \\  /_\\ \n"
    " / \\// /_\\ / /   //  //  \\/ /  \\/ / / /\\/  \\/ / \\ \\//_\\\\ \n"
    "/ _  \\/__/ /___/ \\_// /\\  / /\\  /\\/ /_/ /\\  /\\_/ /  _  \\\n"
    "\\/ \\_/\\__/\\____/\\___/\\_\\ \\/\\_\\ \\/\\____/\\_\\ \\/\\___/\\_/ \\_\\\n"
    "[/bold bright_cyan]"
    "                  [dim]v{version}[/dim]\n"
    "         [dim]Automated recon for CTFs & pentesting[/dim]"
)


def _print_banner() -> None:
    """Display the ReconNinja banner."""
    console.print(_BANNER.format(version=__version__))


# ---------------------------------------------------------------------------
# CLI overrides → MergeConfig dict
# ---------------------------------------------------------------------------


def _build_cli_overrides(
    *,
    fast: bool,
    full: bool,
    udp: bool,
    stealth: bool,
    rate: int,
    timeout: int,
    threads: int,
    no_osint: bool,
) -> dict:
    """Translate CLI flags into the nested-dict format expected by ``load_config``."""
    overrides: dict = {
        "scan": {
            "default_threads": threads,
            "default_timeout": timeout,
            "nmap_min_rate": rate,
            "udp_enabled": udp,
            "stealth_mode": stealth,
        },
    }
    return overrides


# ---------------------------------------------------------------------------
# CLI flags → ReconConfig
# ---------------------------------------------------------------------------


def _build_recon_config(
    merge_cfg: MergeConfig,
    *,
    target: str,
    fast: bool,
    full: bool,
    udp: bool,
    stealth: bool,
    aggressive: bool,
    ports: Optional[str],
    rate: int,
    timeout: int,
    threads: int,
    no_web: bool,
    no_smb: bool,
    no_vuln: bool,
    no_osint: bool,
    only_web: bool,
    only_ports: bool,
    wordlist: Optional[Path],
    html: bool,
    json_output: bool,
    creds: Optional[str],
    domain: Optional[str],
    htb: bool,
    add_hosts: bool,
    platform: Optional[str],
    verbose: bool,
    quiet: bool,
    proxy: Optional[str],
    seclists_path: Optional[str] = None,
) -> ReconConfig:
    """Build a :class:`ReconConfig` from the merged file config + CLI flags."""

    cfg = ReconConfig(
        fast_mode=fast,
        udp_scan=udp or merge_cfg.scan.udp_enabled,
        osint_enabled=not no_osint,
        max_concurrent=threads or merge_cfg.scan.default_threads,
        default_timeout=timeout or merge_cfg.scan.default_timeout,
        adaptive_fuzz=merge_cfg.scan.adaptive_fuzz,
    )

    # --- Module toggles ---------------------------------------------------
    module_toggles: dict[str, bool] = {}

    if only_web:
        module_toggles["web"] = True
        for name in ("smb", "ssh", "ftp", "smtp", "snmp", "dns", "ldap",
                      "kerberos", "rpc", "nfs", "rdp", "vnc", "winrm",
                      "database", "ssl"):
            module_toggles[name] = False
        cfg.osint_enabled = False
        cfg.skip_vuln_correlate = True
        cfg.skip_loot = True
    else:
        if no_web:
            module_toggles["web"] = False
        if no_smb:
            module_toggles["smb"] = False
        if no_vuln:
            cfg.skip_vuln_correlate = True
        if only_ports:
            cfg.skip_vuln_correlate = True
            cfg.skip_loot = True
            cfg.osint_enabled = False

    if full:
        module_toggles["nuclei"] = True
        module_toggles["amass"] = True
        module_toggles["theHarvester"] = True
        module_toggles["testssl"] = True

    if aggressive:
        module_toggles["aggressive_checks"] = True

    cfg.module_toggles = module_toggles

    # --- Extra nmap flags -------------------------------------------------
    extra_flags: list[str] = []

    if stealth:
        extra_flags.extend(["-T2", "--scan-delay", "200ms"])
    elif fast:
        extra_flags.append("-T4")

    if ports:
        extra_flags.extend(["-p", ports])

    if rate != 5000:
        extra_flags.extend(["--min-rate", str(rate)])

    cfg.extra_nmap_flags = extra_flags

    # --- Wordlists --------------------------------------------------------
    from recon_ninja.utils.wordlists import get_dir_wordlist, get_vhost_wordlist, resolve_wordlist

    base_seclists = seclists_path or merge_cfg.wordlists.seclists_base
    custom_dir = merge_cfg.wordlists.custom_dir

    if wordlist:
        cfg.web_wordlist = wordlist
    else:
        # 1. Try to resolve using get_dir_wordlist
        resolved_web = get_dir_wordlist(base_seclists, custom_dir) if base_seclists else None
        if resolved_web and resolved_web.is_file():
            cfg.web_wordlist = resolved_web
        else:
            # 2. Try the configured relative path
            resolved_med = resolve_wordlist(merge_cfg.wordlists.dir_medium, base_seclists, custom_dir) if base_seclists else None
            if resolved_med and resolved_med.is_file():
                cfg.web_wordlist = resolved_med
            else:
                # 3. Fallback to standard wordlists that commonly exist on Kali
                fallbacks = [
                    Path("/usr/share/wordlists/dirb/common.txt"),
                    Path("/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"),
                    Path("/usr/share/wordlists/dirb/big.txt"),
                ]
                for fb in fallbacks:
                    if fb.is_file():
                        cfg.web_wordlist = fb
                        break
                else:
                    cfg.web_wordlist = merge_cfg.wordlists.dir_medium_path

    # DNS wordlist
    resolved_dns = get_vhost_wordlist(base_seclists, custom_dir) if base_seclists else None
    if resolved_dns and resolved_dns.is_file():
        cfg.dns_wordlist = resolved_dns
    else:
        resolved_vh = resolve_wordlist(merge_cfg.wordlists.vhosts, base_seclists, custom_dir) if base_seclists else None
        if resolved_vh and resolved_vh.is_file():
            cfg.dns_wordlist = resolved_vh
        else:
            fallbacks_dns = [
                Path("/usr/share/wordlists/dns/subdomains-top1million-5000.txt"),
                Path("/usr/share/wordlists/amass/subdomains-top1million-5000.txt"),
                Path("/usr/share/wordlists/dirb/common.txt"),
            ]
            for fb in fallbacks_dns:
                if fb.is_file():
                    cfg.dns_wordlist = fb
                    break
            else:
                cfg.dns_wordlist = merge_cfg.wordlists.vhosts_path

    # --- Domain detection -------------------------------------------------
    cfg.is_domain = bool(re.match(r"^[a-zA-Z]", target))

    return cfg


# ---------------------------------------------------------------------------
# Output directory with timestamp
# ---------------------------------------------------------------------------


def _create_output_dir(
    target: str,
    output: Optional[Path],
    timestamp_dirs: bool,
) -> Path:
    """Create and return the output directory path.

    Falls back to ``~/reconninja-results/`` if the default ``results/``
    directory is not writable (e.g. when a previous ``sudo`` run left it
    owned by root).
    """
    if output is not None:
        base = output.parent if output.suffix else output
        dirname = output.name if output.suffix else None
    else:
        base = Path("results")
        dirname = None

    if dirname is None:
        if timestamp_dirs:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            dirname = f"{target}_{ts}"
        else:
            dirname = target

    out = (output if output is not None and output.suffix else base / dirname)

    try:
        out.mkdir(parents=True, exist_ok=True)
        return out
    except PermissionError:
        # The directory (likely ./results/) is owned by root from a previous
        # sudo run.  Fall back to a user-writable location.
        fallback_base = Path.home() / "reconninja-results"
        fallback = fallback_base / dirname
        Console(stderr=True).print(
            f"[bold yellow][!][/] [yellow]Cannot write to[/] [bold]{out}[/] "
            f"[yellow](permission denied).[/]\n"
            f"    [dim]This usually happens when a previous scan was run with sudo.[/]\n"
            f"    [dim]Fix:[/] [cyan]sudo chown -R $(whoami) results/[/]  "
            f"[dim]or run with sudo.[/]\n"
            f"    [dim]Using fallback:[/] [bold green]{fallback}[/]"
        )
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback


# ---------------------------------------------------------------------------
# Pre-flight checklist display
# ---------------------------------------------------------------------------


def _display_preflight(
    *,
    target: str,
    resolved_ip: str,
    is_root_user: bool,
    vpn_ok: Optional[tuple[bool, str]],
    tools: dict[str, bool],
    seclists_path: Optional[str],
    web_wordlist: Path,
    dns_wordlist: Path,
    output_dir: Path,
) -> None:
    """Print the pre-flight checklist panel."""
    table = Table(show_header=False, show_lines=False, expand=False, pad_edge=False)
    table.add_column("Item", style="bold")
    table.add_column("Status")

    table.add_row("Target", f"[cyan]{target}[/cyan] → [dim]{resolved_ip}[/dim]")

    root_icon = "[bold green][+][/] [green]root[/]" if is_root_user else "[bold yellow][!][/] [yellow]non-root (some scans limited)[/]"
    table.add_row("Privileges", root_icon)

    if vpn_ok is not None:
        vpn_up, vpn_ip = vpn_ok
        if vpn_up:
            table.add_row("VPN", f"[bold green][+][/] [green]{vpn_ip}[/green]")
        else:
            table.add_row("VPN", f"[bold red][x][/] [red]{vpn_ip}[/red]")

    missing = get_missing_required(tools)
    total = len(tools)
    available = sum(1 for v in tools.values() if v)
    tool_status = f"{available}/{total} available"
    if missing:
        tool_status += f" [red](missing: {', '.join(missing)})[/red]"
    table.add_row("Tools", tool_status)

    seclists_status = f"[bold green][+][/] [green]{seclists_path}[/green]" if seclists_path else "[bold yellow][!][/] [yellow]not found[/yellow]"
    table.add_row("SecLists", seclists_status)

    web_wl_status = f"[bold green][+][/] [green]{web_wordlist}[/green]" if web_wordlist.is_file() else f"[bold red][x][/] [red]{web_wordlist} (not found)[/red]"
    table.add_row("Dir Fuzz", web_wl_status)

    dns_wl_status = f"[bold green][+][/] [green]{dns_wordlist}[/green]" if dns_wordlist.is_file() else f"[bold red][x][/] [red]{dns_wordlist} (not found)[/red]"
    table.add_row("Subdomain", dns_wl_status)

    table.add_row("Output", str(output_dir))

    console.print(Panel(table, title="[bold]Pre-flight Checklist[/bold]", border_style="cyan"))


# ---------------------------------------------------------------------------
# Scan command — the primary scan entry point
# ---------------------------------------------------------------------------


@app.command(name="scan")
def scan_cmd(
    target: Optional[str] = typer.Argument(None, help="Target IP, hostname, or CIDR"),
    # Scan control
    fast: bool = typer.Option(False, "--fast", help="Port scan + basic service enum only"),
    full: bool = typer.Option(False, "--full", help="All modules incl. nuclei, amass, theHarvester, testssl"),
    udp: bool = typer.Option(False, "--udp", help="Enable UDP scanning (requires root)"),
    stealth: bool = typer.Option(False, "--stealth", help="Low-rate scanning (T2, --scan-delay 200ms)"),
    aggressive: bool = typer.Option(False, "--aggressive", help="Include potentially disruptive checks"),
    ports: Optional[str] = typer.Option(None, "--ports", help="Override port list (e.g. 80,443,8080)"),
    rate: int = typer.Option(5000, "--rate", help="Nmap --min-rate override"),
    timeout: int = typer.Option(300, "--timeout", help="Global per-tool timeout in seconds"),
    threads: int = typer.Option(10, "-t", "--threads", help="Max concurrent modules"),
    # Module toggles
    no_web: bool = typer.Option(False, "--no-web", help="Skip web modules"),
    no_smb: bool = typer.Option(False, "--no-smb", help="Skip SMB modules"),
    no_vuln: bool = typer.Option(False, "--no-vuln", help="Skip vulnerability scanning"),
    no_osint: bool = typer.Option(False, "--no-osint", help="Skip OSINT"),
    only_web: bool = typer.Option(False, "--only-web", help="Only run web enumeration"),
    only_ports: bool = typer.Option(False, "--only-ports", help="Phase 1+2 only"),
    # Input/Output
    output: Optional[Path] = typer.Option(None, "-o", "--output", help="Output directory"),
    config_file: Optional[Path] = typer.Option(None, "--config", help="Config file path"),
    wordlist: Optional[Path] = typer.Option(None, "--wordlist", help="Custom wordlist for dir fuzzing"),
    html: bool = typer.Option(False, "--html", help="Generate HTML report"),
    json_output: bool = typer.Option(True, "--json/--no-json", help="Generate JSON findings file"),
    resume: bool = typer.Option(False, "--resume", help="Resume from last checkpoint"),
    no_vpn_check: bool = typer.Option(False, "--no-vpn-check", help="Skip VPN interface check"),
    # Authentication
    creds: Optional[str] = typer.Option(None, "--creds", help="USER:PASS for authenticated scans"),
    domain: Optional[str] = typer.Option(None, "--domain", help="AD domain name"),
    # HTB/CTF helpers
    htb: bool = typer.Option(False, "--htb", help="HackTheBox mode: VPN check, auto-/etc/hosts"),
    add_hosts: bool = typer.Option(False, "--add-hosts", help="Auto-add hostname to /etc/hosts"),
    platform: Optional[str] = typer.Option(None, "--platform", help="Platform: htb,thm,oscp,bugbounty"),
    # Output verbosity
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Print raw tool output"),
    quiet: bool = typer.Option(False, "-q", "--quiet", help="Final summary only"),
    proxy: Optional[str] = typer.Option(None, "--proxy", help="HTTP proxy URL"),
    version: bool = typer.Option(False, "--version", help="Show version"),
) -> None:
    """Run a reconnaissance scan against a target.

    Usage: reconninja <target>  OR  reconninja scan <target>
    """

    # ------------------------------------------------------------------
    # 1. Version
    # ------------------------------------------------------------------
    if version:
        console.print(f"reconninja v{__version__}")
        raise typer.Exit()

    # ------------------------------------------------------------------
    # 2. No target → help
    # ------------------------------------------------------------------
    if target is None:
        console.print("Usage: reconninja <target> [OPTIONS]")
        console.print("       reconninja scan <target> [OPTIONS]")
        console.print("       reconninja check-tools")
        console.print("       reconninja install")
        console.print()
        console.print("Run [bold]reconninja --help[/] for full options.")
        raise typer.Exit()

    # ------------------------------------------------------------------
    # 3. Phase 0 — Pre-flight
    # ------------------------------------------------------------------

    _print_banner()

    # 3a. Load config (from --config or default), merge with CLI flags
    cli_overrides = _build_cli_overrides(
        fast=fast,
        full=full,
        udp=udp,
        stealth=stealth,
        rate=rate,
        timeout=timeout,
        threads=threads,
        no_osint=no_osint,
    )
    merge_cfg = load_config(config_path=config_file, cli_overrides=cli_overrides)

    # 3b. Validate target
    valid, resolved_ip = validate_target(target)
    if not valid:
        err_console.print(f"[bold red]Invalid target:[/bold red] {resolved_ip}")
        raise typer.Exit(code=1)

    # 3c. VPN check if --htb (unless --no-vpn-check)
    vpn_result: Optional[tuple[bool, str]] = None
    if htb and not no_vpn_check:
        vpn_interface = merge_cfg.htb.vpn_interface
        vpn_result = check_vpn_interface(vpn_interface)
        if not vpn_result[0]:
            err_console.print(
                f"[bold red]VPN check failed:[/bold red] {vpn_result[1]}  "
                f"Use --no-vpn-check to skip."
            )
            raise typer.Exit(code=1)

    # 3d. Root check
    is_root_user = is_root()
    if udp and not is_root_user:
        err_console.print("[bold red]UDP scanning requires root privileges.[/bold red]")
        raise typer.Exit(code=1)

    # 3e. Tool inventory
    tools = check_tools()
    missing_required = get_missing_required(tools)
    if missing_required and not quiet:
        err_console.print(
            f"[bold yellow][!][/] [yellow]Missing required tools:[/yellow] {', '.join(missing_required)}\n"
            f"[dim]Run 'reconninja install' to install them, "
            f"or 'reconninja check-tools' for details.[/dim]"
        )

    # 3f. SecLists check
    seclists_path = find_seclists()

    # 3g. Create output directory with timestamp
    output_dir = _create_output_dir(
        target=target,
        output=output,
        timestamp_dirs=merge_cfg.output.timestamp_dirs,
    )

    # ------------------------------------------------------------------
    # Build ReconConfig from MergeConfig + CLI flags
    # ------------------------------------------------------------------
    recon_config = _build_recon_config(
        merge_cfg,
        target=target,
        fast=fast,
        full=full,
        udp=udp,
        stealth=stealth,
        aggressive=aggressive,
        ports=ports,
        rate=rate,
        timeout=timeout,
        threads=threads,
        no_web=no_web,
        no_smb=no_smb,
        no_vuln=no_vuln,
        no_osint=no_osint,
        only_web=only_web,
        only_ports=only_ports,
        wordlist=wordlist,
        html=html,
        json_output=json_output,
        creds=creds,
        domain=domain,
        htb=htb,
        add_hosts=add_hosts,
        platform=platform,
        verbose=verbose,
        quiet=quiet,
        proxy=proxy,
        seclists_path=seclists_path,
    )

    # Store extra CLI context
    recon_config.module_toggles["_html_report"] = html
    recon_config.module_toggles["_json_report"] = json_output
    recon_config.module_toggles["_add_hosts"] = add_hosts
    recon_config.module_toggles["_htb"] = htb
    recon_config.module_toggles["_seclists_base"] = seclists_path or merge_cfg.wordlists.seclists_base
    recon_config.module_toggles["_custom_dir"] = merge_cfg.wordlists.custom_dir
    if creds:
        recon_config.module_toggles["_creds"] = creds  # type: ignore[assignment]
    if domain:
        recon_config.module_toggles["_domain"] = domain  # type: ignore[assignment]
    if proxy:
        recon_config.module_toggles["_proxy"] = proxy  # type: ignore[assignment]
    recon_config.module_toggles["_verbose"] = verbose
    recon_config.module_toggles["_quiet"] = quiet

    # 3h. Display banner + pre-flight checklist
    if not quiet:
        _display_preflight(
            target=target,
            resolved_ip=resolved_ip,
            is_root_user=is_root_user,
            vpn_ok=vpn_result,
            tools=tools,
            seclists_path=seclists_path,
            web_wordlist=recon_config.web_wordlist,
            dns_wordlist=recon_config.dns_wordlist,
            output_dir=output_dir,
        )

    # ------------------------------------------------------------------
    # 4. Resume or fresh state
    # ------------------------------------------------------------------
    state_manager = StateManager(target=target)

    if resume:
        state = state_manager.load_state()
        if state is None:
            err_console.print(
                "[bold yellow][!][/] [yellow]--resume specified but no checkpoint found. "
                "Starting fresh scan.[/yellow]"
            )
            state = state_manager.init_state()
        else:
            if not quiet:
                console.print(
                    f"[green]Resuming scan from phase {state.current_phase} "
                    f"({PHASE_NAMES.get(state.current_phase, '?')})[/green]"
                )
            state.output_dir = output_dir
    else:
        state = state_manager.init_state()
        state.output_dir = output_dir

    # Seed available tools into state
    state.available_tools = tools

    # ------------------------------------------------------------------
    # 5. Create engine and run
    # ------------------------------------------------------------------

    # Set up logging: file only (Rich UI handles console output)
    root_logger = logging.getLogger("recon_ninja")
    root_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Remove any existing handlers
    root_logger.handlers.clear()

    # File handler — always write to log file
    log_path = output_dir / "reconninja.log"
    file_handler = logging.FileHandler(str(log_path), encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root_logger.addHandler(file_handler)

    # Console handler — only show warnings and above (errors)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.WARNING)
    console_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    root_logger.addHandler(console_handler)

    engine = ReconEngine(target=target, config=recon_config, state=state, quiet=quiet)

    try:
        final_state = asyncio.run(engine.run())
    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow][!][/] [yellow]Scan interrupted"
            " by user. State saved for --resume.[/yellow]"
        )
        state.save()
        if not quiet and state.all_findings:
            from recon_ninja.core.display import display_findings_panel
            console.print("\n[bold]Findings collected so far:[/bold]")
            display_findings_panel(state.all_findings)
        raise typer.Exit(code=130)
    except Exception as exc:
        err_console.print(f"[bold red]Scan failed:[/bold red] {exc}")
        state.save()
        raise typer.Exit(code=1)

    # ------------------------------------------------------------------
    # 6. Display final summary
    # ------------------------------------------------------------------
    if not quiet:
        from recon_ninja.core.display import display_scan_summary
        display_scan_summary(final_state)

    # ------------------------------------------------------------------
    # 7. Auto-add hostnames to /etc/hosts if --add-hosts or --htb
    # ------------------------------------------------------------------
    if (add_hosts or htb) and final_state.hostnames:
        for hostname in final_state.hostnames:
            success = add_to_hosts(resolved_ip, hostname)
            if success and not quiet:
                console.print(f"[dim]Added {resolved_ip} → {hostname} to /etc/hosts[/dim]")
            elif not quiet:
                err_console.print(
                    f"[bold yellow][!][/] [yellow]Failed to add {hostname} to /etc/hosts[/yellow]"
                )

    # Final output path hint
    if not quiet:
        console.print(f"\n[dim]Results saved to: {final_state.output_dir}[/dim]")


# ---------------------------------------------------------------------------
# Subcommand: check-tools
# ---------------------------------------------------------------------------


@app.command(name="check-tools")
def check_tools_cmd(
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show detailed output with paths and versions"),
) -> None:
    """Check which external tools are installed and show versions.

    Scans for all 30+ external tools that ReconNinja uses, detects
    their versions, and displays a detailed status report.
    """
    _print_banner()

    tools = check_tools_detailed()
    format_detailed_status(tools)


# ---------------------------------------------------------------------------
# Subcommand: install
# ---------------------------------------------------------------------------


@app.command(name="install")
def install_cmd(
    required_only: bool = typer.Option(False, "--required", help="Install only required tools"),
    optional_only: bool = typer.Option(False, "--optional", help="Install only optional tools"),
    verbose: bool = typer.Option(False, "-v", "--verbose", help="Show detailed output"),
) -> None:
    """Auto-install all tools that ReconNinja needs.

    Detects your OS and package manager, then installs tools using:
      - System package manager (apt/dnf/pacman)
      - Go install (for Go-based tools)
      - pip install (for Python-based tools)
      - cargo install (for Rust-based tools)
      - gem install (for Ruby-based tools)
      - git clone (for tools distributed via Git)

    Run with sudo for best results.  Already-installed tools are skipped.
    """
    _print_banner()

    from recon_ninja.utils.installer import ToolInstaller

    installer = ToolInstaller(verbose=verbose)

    if required_only:
        results = installer.install_required_only()
    else:
        results = installer.install_all(include_optional=True)

    installer.print_summary(results)
