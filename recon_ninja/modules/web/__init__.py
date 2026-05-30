"""Web reconnaissance module — top-level orchestrator.

This is the entry point imported by :mod:`recon_ninja.core.engine`.  It
iterates over every HTTP/HTTPS port discovered in Phase 2, constructs
the appropriate URL, and then runs the sub-modules:

    web_core  →  web_tech  →  web_dirfuzz

**CTF-first design**: Only fast, actionable modules are run — directory
fuzzing, vhost enumeration, tech detection, and quick exploit lookup.
Deep vuln scanners (nikto, nuclei, cms) are excluded to keep scans
fast and focused for CTF workflows.

**Priority output**: All results are printed IMMEDIATELY as they are
found, so CTF players can start working right away.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from recon_ninja.core.models import (
    Finding,
    ModuleResult,
    ReconConfig,
    ScanState,
    Severity,
)
from recon_ninja.modules.web.web_core import run_web_core
from recon_ninja.modules.web.web_tech import run_web_tech
from recon_ninja.modules.web.web_dirfuzz import run_web_dirfuzz
from recon_ninja.core.utils import module_guard
from recon_ninja.core.display import get_console
from recon_ninja.core.runner import run_tool

logger = logging.getLogger(__name__)


def _is_valid_hostname(name: str) -> bool:
    """Check if a string looks like a valid hostname.

    Filters out garbage like ``"Did not follow redirect to http://X/"``
    that nmap's http-title script sometimes produces.
    """
    if not name:
        return False
    # Must not contain spaces, slashes, or protocol indicators
    if " " in name or "/" in name or ":" in name:
        return False
    # Must contain at least one dot (for FQDN)
    if "." not in name:
        return False
    # Must not be all digits (IP without dots, or similar)
    if name.replace(".", "").isdigit():
        return False
    return True


def _rebuild_url_with_hostname(url: str, hostname: str, port: int) -> str:
    """Replace the host component of a URL while preserving suffixes."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, f"{hostname}:{port}", parts.path, parts.query, parts.fragment))


def _print_fast_findings(findings: list[Finding], port: int, category: str) -> None:
    """Print actionable findings immediately so CTF players can start working.

    Shows MEDIUM severity and above inline, plus a count summary for
    directory and path findings (which are typically LOW/INFO but critical
    for CTF players to see).
    """
    console = get_console()
    # Show actionable findings (not INFO-level noise)
    actionable = [f for f in findings if f.severity != Severity.INFO]
    for f in actionable:
        sev_style = f.severity.rich_style
        console.print(
            f"      [{sev_style}]•[/] {f.title}"
        )
    # Also show directory/path findings even if they're LOW severity
    # — these are CRITICAL for CTF players
    dir_findings = [
        f for f in findings
        if (f.title.startswith("Fuzz:") or f.title.startswith("Path found:"))
        and f.severity == Severity.LOW
    ]
    for f in dir_findings[:10]:
        console.print(
            f"      [dim]•[/] {f.title}"
        )





# ---------------------------------------------------------------------------
# Sub-module runners (per port)
# ---------------------------------------------------------------------------


async def _scan_port(
    target: str,
    port: int,
    url: str,
    hostname: str | None,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> list[ModuleResult]:
    """Execute the fast sub-module pipeline for a single HTTP port.

    Steps 1-2 (web_core, web_tech) run sequentially because web_tech
    needs headers from web_core.  Step 3 (web_dirfuzz) runs next to
    produce actionable results FAST.  Deep vuln scans (nikto, nuclei,
    cms) are excluded to keep scans fast for CTF workflows.

    Parameters
    ----------
    target:
        The raw target IP or hostname.
    port:
        The port number.
    url:
        Fully-qualified URL (e.g. ``http://10.10.10.1:8080``).
    hostname:
        Detected hostname for this service (may be ``None``).
    state:
        Shared scan state.
    config:
        Scan configuration.
    output_dir:
        Per-target output directory.

    Returns
    -------
    list[ModuleResult]
        Results from each sub-module executed for this port.
    """
    results: list[ModuleResult] = []
    host_suffix = f"_{hostname}" if (hostname and hostname != target) else ""
    port_dir = output_dir / f"port_{port}{host_suffix}"
    port_dir.mkdir(parents=True, exist_ok=True)
    console = get_console()

    # ================================================================
    # FAST PHASE — Core + Tech + DirFuzz (results printed immediately)
    # CTF players need these FIRST: headers, tech, directories, vhosts
    # ================================================================

    # Step 1 — Core fingerprinting (must run first — fetches headers,
    # hostnames, security headers, WAF detection)
    logger.info("[web:%d] Running web_core …", port)
    console.print(f"    [dim]▸[/] Fingerprinting web server on port {port}…")
    core_result = await run_web_core(target, port, url, state, config, port_dir)
    results.append(core_result)

    # After web_core: check if a new hostname was discovered via redirect.
    # If so, rebuild the URL so feroxbuster uses the hostname
    # instead of the raw IP (which may 301-redirect everything).
    refreshed_hostname = state.primary_hostname
    if refreshed_hostname and _is_valid_hostname(refreshed_hostname) and refreshed_hostname != hostname:
        logger.info(
            "[web:%d] Hostname discovered: %s — rebuilding URL",
            port, refreshed_hostname,
        )
        hostname = refreshed_hostname
        url = _rebuild_url_with_hostname(url, hostname, port)

    # Print core findings immediately
    _print_fast_findings(core_result.findings, port, "fingerprint")

    # Step 2 — Deep technology detection (needs headers from web_core)
    logger.info("[web:%d] Running web_tech …", port)
    console.print(f"    [dim]▸[/] Detecting technologies on port {port}…")
    tech_result = await run_web_tech(target, port, url, state, config, port_dir)
    results.append(tech_result)

    # Print tech findings immediately (especially vulnerable tech!)
    _print_fast_findings(tech_result.findings, port, "tech")

    # Step 3 — Directory fuzzing + vhost enum (CTF-critical!)
    # This gives the CTF player actionable directories and subdomains
    # quickly, before slow vuln scanners like nikto/nuclei run.
    logger.info("[web:%d] Running web_dirfuzz (fast results first) …", port)
    console.print(f"    [dim]▸[/] Fuzzing directories & vhosts on port {port}…")
    dirfuzz_result = await run_web_dirfuzz(
        target, port, url, hostname, state, config, port_dir,
    )
    results.append(dirfuzz_result)

    # Print directory and vhost findings immediately — these are the
    # MOST VALUABLE results for CTF players
    dir_findings = [
        f for f in dirfuzz_result.findings
        if f.title.startswith("Fuzz:") or f.title.startswith("Path found:")
    ]
    vhost_findings = [
        f for f in dirfuzz_result.findings
        if f.title.startswith("Vhost found:")
    ]
    if dir_findings or vhost_findings:
        console.print(
            f"    [bold green][+][/] Fast scan done on port {port}!"
        )
        if dir_findings:
            console.print(
                f"    [bold green][+][/] Found "
                f"[bold cyan]{len(dir_findings)}[/] directories/files"
            )
            sorted_dirs = sorted(dir_findings, key=lambda f: f.severity.rank)
            for f in sorted_dirs[:10]:
                sev_style = f.severity.rich_style
                console.print(
                    f"      [{sev_style}]•[/] {f.title}"
                )
        if vhost_findings:
            console.print(
                f"    [bold green][+][/] Found "
                f"[bold cyan]{len(vhost_findings)}[/] vhosts"
            )
            for f in vhost_findings[:5]:
                console.print(
                    f"      [bold yellow]•[/] {f.title}"
                )
    else:
        console.print(
            f"    [dim][-] No directories or vhosts found on port {port}[/]"
        )

    # Print tech stack summary immediately so CTF players can act on it
    port_techs = state.techs_by_port(port)
    if port_techs:
        console.print(
            f"    [bold cyan][*][/] Tech stack on port {port}:"
        )
        for tech in port_techs:
            vuln_tag = f" [bold red]({', '.join(tech.cves)})[/]" if tech.is_vulnerable else ""
            ver_tag = f" {tech.version}" if tech.version else ""
            console.print(
                f"      [dim]•[/] [bold]{tech.name}[/]{ver_tag}"
                f" [dim][{tech.category}][/]{vuln_tag}"
            )

    # Quick searchsploit on detected tech versions — CTF players need
    # this BEFORE deep scans.  Run only for techs with versions.
    _versioned_techs = [
        t for t in port_techs if t.version and t.name
    ]
    if _versioned_techs and shutil.which("searchsploit"):
        console.print(
            f"    [bold magenta][*][/] Running quick exploit lookup on port {port}…"
        )
        for tech in _versioned_techs:
            query = f"{tech.name} {tech.version}"
            _found_exploits = False
            try:
                rc, stdout, _stderr = await run_tool(
                    cmd=["searchsploit", "--json", query],
                    timeout=30,
                )
                if rc in (0, 1) and stdout.strip():
                    try:
                        data = json.loads(stdout)
                        results_list = (
                            data.get("RESULTS_EXPLOIT", [])
                            or data.get("RESULTS_SEARCH", [])
                            or data.get("results", [])
                        )
                        if results_list:
                            _found_exploits = True
                            console.print(
                                f"      [bold yellow]⚔[/] [bold]{tech.name} {tech.version}[/]"
                                f" — [bold cyan]{len(results_list)}[/] exploits found"
                            )
                            for entry in results_list[:5]:
                                title = entry.get("Title", "") if isinstance(entry, dict) else str(entry)
                                etype = entry.get("Type", "") if isinstance(entry, dict) else ""
                                type_tag = f" [dim][{etype}][/]" if etype else ""
                                if title:
                                    console.print(
                                        f"        [dim]•[/] {title}{type_tag}"
                                    )
                            # Add as finding so it appears in the final report
                            state.add_finding(Finding(
                                severity=Severity.MEDIUM,
                                title=f"Exploits available: {tech.name} {tech.version} ({len(results_list)} found)",
                                description=(
                                    f"searchsploit found {len(results_list)} exploits for "
                                    f"{tech.name} {tech.version}. "
                                    f"Top: {', '.join(e.get('Title', '') if isinstance(e, dict) else str(e) for e in results_list[:5])}"
                                ),
                                module="web",
                                evidence=f"searchsploit --json '{query}'",
                                suggested_commands=[
                                    f"searchsploit {tech.name} {tech.version}",
                                ],
                            ))
                    except Exception:
                        pass
            except Exception:
                pass

            # Broad searchsploit fallback: if the specific version query
            # returned nothing, try just the product name (e.g. "Nginx"
            # instead of "Nginx 1.18.0").  This catches cases where
            # searchsploit doesn't have version-specific entries but has
            # generic exploits for the product.
            if not _found_exploits:
                broad_query = tech.name
                if broad_query.lower() != query.lower():
                    try:
                        brc, bstdout, _ = await run_tool(
                            cmd=["searchsploit", "--json", broad_query],
                            timeout=30,
                        )
                        if brc in (0, 1) and bstdout.strip():
                            try:
                                bdata = json.loads(bstdout)
                                broad_results = (
                                    bdata.get("RESULTS_EXPLOIT", [])
                                    or bdata.get("RESULTS_SEARCH", [])
                                    or bdata.get("results", [])
                                )
                                if broad_results:
                                    console.print(
                                        f"      [bold yellow]⚔[/] [bold]{tech.name}[/]"
                                        f" — [bold cyan]{len(broad_results)}[/] exploits (broad search)"
                                    )
                                    for entry in broad_results[:3]:
                                        title = entry.get("Title", "") if isinstance(entry, dict) else str(entry)
                                        if title:
                                            console.print(
                                                f"        [dim]•[/] {title}"
                                            )
                                    state.add_finding(Finding(
                                        severity=Severity.INFO,
                                        title=f"Exploits (broad): {tech.name} ({len(broad_results)} results)",
                                        description=(
                                            f"No exploits found for '{query}', but"
                                            f" {len(broad_results)} found for broader"
                                            f" query '{broad_query}'. "
                                            f"Top: {', '.join(e.get('Title', '') if isinstance(e, dict) else str(e) for e in broad_results[:5])}"
                                        ),
                                        module="web",
                                        evidence=f"searchsploit --json '{broad_query}'",
                                        suggested_commands=[
                                            f"searchsploit {broad_query}",
                                        ],
                                    ))
                            except Exception:
                                pass
                    except Exception:
                        pass

    # ================================================================
    # VHOST SCANNING — Tech detect + quick searchsploit on discovered
    # vhosts.  This is CRITICAL for CTF: subdomains often have
    # different tech stacks and attack surfaces.
    # ================================================================
    if vhost_findings:
        console.print(
            f"    [bold cyan][*][/] Scanning discovered vhosts for tech & exploits…"
        )
        for vf in vhost_findings[:5]:
            # Extract vhost hostname from the finding title
            _vh_match = re.search(
                r"Vhost found:\s*([^\s]+)", vf.title,
            )
            if not _vh_match:
                continue
            _vhost_name = _vh_match.group(1).split(":")[0]
            _vhost_url = f"{urlsplit(url).scheme}://{_vhost_name}:{port}"

            # Probe vhost for HTTP response details (auth type, headers, etc.)
            _vhost_auth_type = ""
            _vhost_server = ""
            if shutil.which("curl"):
                try:
                    _crc, _cout, _ = await run_tool(
                        cmd=[
                            "curl", "-sI", "-o", "/dev/null",
                            "-w", "%{http_code}",
                            "--connect-timeout", "5",
                            "--max-time", "10",
                            _vhost_url,
                        ],
                        timeout=15,
                    )
                    if _crc == 0 and _cout.strip():
                        # Get full headers for auth detection
                        _hrc, _hout, _ = await run_tool(
                            cmd=[
                                "curl", "-sI",
                                "--connect-timeout", "5",
                                "--max-time", "10",
                                _vhost_url,
                            ],
                            timeout=15,
                        )
                        if _hrc == 0 and _hout.strip():
                            # Detect WWW-Authenticate header (401 responses)
                            for _hline in _hout.splitlines():
                                _hline_lower = _hline.lower()
                                if _hline_lower.startswith("www-authenticate:"):
                                    _vhost_auth_type = _hline.split(":", 1)[1].strip()
                                    break
                                if _hline_lower.startswith("server:"):
                                    _vhost_server = _hline.split(":", 1)[1].strip()
                except Exception:
                    pass

            # Report auth type findings — extremely valuable for CTF!
            if _vhost_auth_type:
                console.print(
                    f"      [bold red][!][/] [bold]{_vhost_name}[/] requires auth:"
                    f" [bold yellow]{_vhost_auth_type}[/]"
                )
                state.add_finding(Finding(
                    severity=Severity.HIGH,
                    title=f"Vhost auth required: {_vhost_name} ({_vhost_auth_type})",
                    description=(
                        f"Virtual host {_vhost_name} on port {port} returns HTTP 401 "
                        f"with authentication type: {_vhost_auth_type}. "
                        f"This is a high-value target — authenticated vhosts often "
                        f"contain admin panels, APIs, or sensitive functionality."
                    ),
                    module="web",
                    evidence=f"WWW-Authenticate: {_vhost_auth_type}",
                    suggested_commands=[
                        f"curl -v {_vhost_url}  # Test auth type",
                    ] + (
                        [f"hydra -L users.txt -P /usr/share/wordlists/rockyou.txt {_vhost_url} http-get"]
                        if "basic" in _vhost_auth_type.lower() else []
                    ),
                ))

            if _vhost_server:
                console.print(
                    f"      [dim]•[/] Server on [bold]{_vhost_name}[/]: {_vhost_server}"
                )

            # Quick tech detection on the vhost
            try:
                _vhost_tech_result = await run_web_tech(
                    target, port, _vhost_url, state, config, port_dir,
                )
                results.append(_vhost_tech_result)
                # Print discovered techs immediately
                _vhost_techs = [
                    t for t in _vhost_tech_result.findings
                    if t.title.startswith("Tech stack")
                ]
                _new_techs = state.techs_by_port(port)
                _vhost_specific = [
                    t for t in _new_techs
                    if t.name not in {_ot.name for _ot in port_techs}
                ]
                if _vhost_specific:
                    console.print(
                        f"      [bold cyan]▸[/] Tech on [bold]{_vhost_name}[/]:"
                    )
                    for t in _vhost_specific:
                        ver_tag = f" {t.version}" if t.version else ""
                        vuln_tag = f" [bold red]({', '.join(t.cves)})[/]" if t.is_vulnerable else ""
                        console.print(
                            f"        [dim]•[/] [bold]{t.name}[/]{ver_tag}"
                            f" [dim][{t.category}][/]{vuln_tag}"
                        )
                    # Quick searchsploit on vhost tech (with broad fallback)
                    _vh_versioned = [t for t in _vhost_specific if t.version and t.name]
                    if _vh_versioned and shutil.which("searchsploit"):
                        for t in _vh_versioned:
                            _vh_found = False
                            try:
                                rc, stdout, _ = await run_tool(
                                    cmd=["searchsploit", "--json", f"{t.name} {t.version}"],
                                    timeout=30,
                                )
                                if rc in (0, 1) and stdout.strip():
                                    try:
                                        data = json.loads(stdout)
                                        rlist = (
                                            data.get("RESULTS_EXPLOIT", [])
                                            or data.get("RESULTS_SEARCH", [])
                                            or data.get("results", [])
                                        )
                                        if rlist:
                                            _vh_found = True
                                            console.print(
                                                f"        [bold yellow]⚔[/] {t.name} {t.version}"
                                                f" — [bold cyan]{len(rlist)}[/] exploits"
                                            )
                                            for e in rlist[:3]:
                                                et = e.get("Title", "") if isinstance(e, dict) else str(e)
                                                if et:
                                                    console.print(f"          [dim]•[/] {et}")
                                            state.add_finding(Finding(
                                                severity=Severity.MEDIUM,
                                                title=f"Exploits: {t.name} {t.version} on {_vhost_name} ({len(rlist)} found)",
                                                description=(
                                                    f"searchsploit found {len(rlist)} exploits for "
                                                    f"{t.name} {t.version} on vhost {_vhost_name}. "
                                                    f"Top: {', '.join(e.get('Title', '') if isinstance(e, dict) else str(e) for e in rlist[:5])}"
                                                ),
                                                module="web",
                                                evidence=f"searchsploit --json '{t.name} {t.version}'",
                                                suggested_commands=[
                                                    f"searchsploit {t.name} {t.version}",
                                                ],
                                            ))
                                    except Exception:
                                        pass
                            except Exception:
                                pass

                            # Broad fallback for vhost tech
                            if not _vh_found and shutil.which("searchsploit"):
                                try:
                                    brc, bstdout, _ = await run_tool(
                                        cmd=["searchsploit", "--json", t.name],
                                        timeout=30,
                                    )
                                    if brc in (0, 1) and bstdout.strip():
                                        try:
                                            bdata = json.loads(bstdout)
                                            brlist = (
                                                bdata.get("RESULTS_EXPLOIT", [])
                                                or bdata.get("RESULTS_SEARCH", [])
                                                or bdata.get("results", [])
                                            )
                                            if brlist:
                                                console.print(
                                                    f"        [bold yellow]⚔[/] {t.name}"
                                                    f" — [bold cyan]{len(brlist)}[/] exploits (broad)"
                                                )
                                                for e in brlist[:3]:
                                                    et = e.get("Title", "") if isinstance(e, dict) else str(e)
                                                    if et:
                                                        console.print(f"          [dim]•[/] {et}")
                                        except Exception:
                                            pass
                                except Exception:
                                    pass
                elif not _vhost_specific and _vhost_server:
                    # No Wappalyzer tech detected but we found a server header
                    console.print(
                        f"      [dim]▸[/] Limited tech on [bold]{_vhost_name}[/]:"
                        f" {_vhost_server} (401 blocks deeper detection)"
                    )
            except Exception as exc:
                logger.debug("[web:%d] Vhost tech scan failed for %s: %s", port, _vhost_name, exc)

    # Print a clear separator so CTF players know they can start working
    console.print(
        f"    [bold bright_green]⚡ Web scan on port {port} complete![/]"
    )

    return results


# ---------------------------------------------------------------------------
# Public entry point (called by engine.py)
# ---------------------------------------------------------------------------


@module_guard()
async def run_web_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Orchestrate all web sub-modules across every HTTP port.

    This function is the **top-level entry point** imported by
    :mod:`recon_ninja.core.engine`.  It filters the discovered services
    to those containing ``"http"``, then runs the sub-module pipeline
    for each qualifying port.  **Multiple ports are scanned concurrently**
    (bounded to 2 at a time to avoid overloading the target).

    Parameters
    ----------
    target:
        The raw target (IP or hostname).
    state:
        Shared :class:`ScanState` with service information.
    config:
        Scan configuration.
    output_dir:
        Per-target output directory.

    Returns
    -------
    ModuleResult
        A combined result with ``module_name="web"`` containing all
        findings from every sub-module and port.
    """
    t0 = time.monotonic()

    # --- Identify HTTP ports ---
    web_ports = state.web_ports
    if not web_ports:
        logger.info("No HTTP services found — skipping web module")
        return ModuleResult(
            module_name="web",
            status="skipped",
            duration_seconds=time.monotonic() - t0,
            error_message="No HTTP services detected",
        )

    logger.info("Web module: scanning %d HTTP port(s): %s", len(web_ports), web_ports)

    all_findings: list[Finding] = []
    all_raw: list[str] = []
    any_error = False

    # --- Scan ports concurrently (bounded to 2 at a time) ---
    port_semaphore = asyncio.Semaphore(2)

    async def _scan_port_bounded(  # noqa: C901
        port: int,
    ) -> tuple[int, list[ModuleResult]]:
        """Scan a single port inside a semaphore,
        including any dynamically discovered virtual hosts.
        """
        async with port_semaphore:
            svc = state.services.get(port)
            if svc is None:
                logger.warning("No ServiceInfo for port %d — skipping", port)
                return port, []

            scheme = "https" if (port in (443, 8443) or "ssl" in svc.service.lower()) else "http"

            hosts_to_scan = []
            if svc.hostname and _is_valid_hostname(svc.hostname):
                hosts_to_scan.append(svc.hostname)
            elif svc.hostname:
                logger.warning(
                    "[web:%d] Ignoring invalid hostname from nmap: %r",
                    port, svc.hostname,
                )
            if state.primary_hostname and _is_valid_hostname(state.primary_hostname) and state.primary_hostname not in hosts_to_scan:
                hosts_to_scan.append(state.primary_hostname)
            if not hosts_to_scan:
                hosts_to_scan.append(target)

            scanned_hosts = set()
            all_port_results = []

            # Scan the primary host/IP.  Vhosts discovered during
            # scanning will be scanned separately in _scan_port after
            # dirfuzz finds them (tech detection + quick searchsploit).
            for current_host in hosts_to_scan:
                if current_host.lower() in scanned_hosts:
                    continue

                logger.info("[web:%d] Starting web scan pipeline for host: %s", port, current_host)
                scanned_hosts.add(current_host.lower())

                if svc.url and "TARGET" in svc.url:
                    url = svc.url.replace("TARGET", current_host)
                else:
                    url = f"{scheme}://{current_host}:{port}"

                try:
                    port_results = await _scan_port(
                        target=target,
                        port=port,
                        url=url,
                        hostname=current_host,
                        state=state,
                        config=config,
                        output_dir=output_dir,
                    )
                    all_port_results.extend(port_results)

                except Exception as exc:
                    logger.exception(
                        "[web:%d] Pipeline failed for %s: %s",
                        port, current_host, exc,
                    )
                    error_finding = Finding(
                        severity=Severity.HIGH,
                        title=f"Web scan pipeline failed on port {port} for {current_host}",
                        description=str(exc),
                        module="web",
                    )
                    all_port_results.append(ModuleResult(
                        module_name="web",
                        status="error",
                        findings=[error_finding],
                        error_message=str(exc),
                    ))

            return port, all_port_results

    port_tasks = [
        asyncio.create_task(_scan_port_bounded(port))
        for port in web_ports
    ]
    port_results_list = await asyncio.gather(*port_tasks, return_exceptions=True)

    for result in port_results_list:
        if isinstance(result, Exception):
            logger.error("Port scan task raised: %s", result)
            any_error = True
            continue

        port, port_results = result
        for mod_result in port_results:
            all_findings.extend(mod_result.findings)
            if mod_result.raw_output:
                all_raw.append(
                    f"--- {mod_result.module_name} (port {port})"
                    f" ---\n{mod_result.raw_output}"
                )
            if mod_result.status == "error":
                any_error = True

    # --- Combine into single ModuleResult ---
    status = "error" if any_error else "done"
    combined_raw = "\n\n".join(all_raw) if all_raw else ""

    return ModuleResult(
        module_name="web",
        status=status,
        findings=all_findings,
        raw_output=combined_raw[:10000],  # cap to avoid bloated state
        duration_seconds=time.monotonic() - t0,
    )

