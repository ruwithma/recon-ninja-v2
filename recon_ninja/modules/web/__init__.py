"""Web reconnaissance module — top-level orchestrator.

This is the entry point imported by :mod:`recon_ninja.core.engine`.  It
iterates over every HTTP/HTTPS port discovered during Phase 2, constructs
the appropriate URL, and then runs the sub-modules:

    web_core  →  web_tech  →  web_dirfuzz  →  [web_vuln | web_cms]  (concurrent)

**CTF-first design**: directory fuzzing and vhost enumeration run BEFORE
slow vulnerability scanners (nikto, nuclei).  This ensures the CTF player
gets actionable paths and subdomains quickly, while the longer vuln scans
continue in the background.

**Priority output**: Fast results (dirs, vhosts, tech) are printed
IMMEDIATELY as they are found, so CTF players can start working
while slow vuln scans continue in the background.
"""

from __future__ import annotations

import asyncio
import logging
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
from recon_ninja.modules.web.web_vuln import run_web_vuln
from recon_ninja.modules.web.web_cms import run_web_cms
from recon_ninja.core.utils import module_guard
from recon_ninja.core.display import get_console

logger = logging.getLogger(__name__)


def _rebuild_url_with_hostname(url: str, hostname: str, port: int) -> str:
    """Replace the host component of a URL while preserving suffixes."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, f"{hostname}:{port}", parts.path, parts.query, parts.fragment))


def _print_fast_findings(findings: list[Finding], port: int, category: str) -> None:
    """Print actionable findings immediately so CTF players can start working.

    Only prints findings that are MEDIUM severity or above — INFO findings
    are deferred to the final report to avoid terminal noise.
    """
    console = get_console()
    # Only show actionable findings (not INFO-level noise)
    actionable = [f for f in findings if f.severity != Severity.INFO]
    for f in actionable:
        sev_style = f.severity.rich_style
        console.print(
            f"      [{sev_style}]•[/] {f.title}"
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
    """Execute the full sub-module pipeline for a single HTTP port.

    Steps 1-2 (web_core, web_tech) run sequentially because web_tech
    needs headers from web_core.  Step 3 (web_dirfuzz) runs next to
    produce actionable results FAST.  Steps 4-5 (web_vuln, web_cms)
    run concurrently after dirs are found.

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
    # If so, rebuild the URL so feroxbuster/nikto/etc use the hostname
    # instead of the raw IP (which may 301-redirect everything).
    refreshed_hostname = state.primary_hostname
    if refreshed_hostname and refreshed_hostname != hostname:
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

    # Print a clear separator so CTF players know they can start working
    console.print(
        "    [bold bright_green]⚡ Fast results complete!"
        " Deep vuln scans continuing in background…[/]"
    )

    # ================================================================
    # SLOW PHASE — Nikto + Nuclei + CMS (concurrent, less urgent)
    # These run in parallel but CTF players already have what they need
    # ================================================================
    logger.info(
        "[web:%d] Running web_vuln + web_cms concurrently …", port,
    )
    console.print(
        f"    [dim]▸[/] Running deep vuln scanners on port {port}"
        f" (nikto, nuclei, cms)…"
    )

    async def _safe_run(name: str, coro):
        """Wrap a sub-module call so exceptions don't cancel siblings."""
        try:
            return await coro
        except Exception as exc:
            logger.exception("[web:%d] %s failed: %s", port, name, exc)
            return ModuleResult(
                module_name=name,
                status="error",
                error_message=str(exc),
            )

    concurrent_results = await asyncio.gather(
        _safe_run("web_vuln", run_web_vuln(
            target, port, url, state, config, port_dir,
        )),
        _safe_run("web_cms", run_web_cms(
            target, port, url, state, config, port_dir,
        )),
    )

    results.extend(concurrent_results)
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
            if svc.hostname:
                hosts_to_scan.append(svc.hostname)
            if state.primary_hostname and state.primary_hostname not in hosts_to_scan:
                hosts_to_scan.append(state.primary_hostname)
            if not hosts_to_scan:
                hosts_to_scan.append(target)

            scanned_hosts = set()
            all_port_results = []

            # Only scan the primary host/IP — do NOT re-scan vhosts
            # discovered during scanning.  Vhosts are already reported as
            # findings and auto-added to /etc/hosts by web_dirfuzz.
            # Re-scanning them wastes time and causes duplicate output.
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

