"""Web reconnaissance module — top-level orchestrator.

This is the entry point imported by :mod:`recon_ninja.core.engine`.  It
iterates over every HTTP/HTTPS port discovered during Phase 2, constructs
the appropriate URL, and then runs the sub-modules:

    web_core  →  web_tech  →  [web_dirfuzz | web_vuln | web_cms]  (concurrent)

Each sub-module returns its own :class:`ModuleResult`.  All findings are
aggregated into a single combined result with ``module_name="web"``.
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

logger = logging.getLogger(__name__)


def _rebuild_url_with_hostname(url: str, hostname: str, port: int) -> str:
    """Replace the host component of a URL while preserving suffixes."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, f"{hostname}:{port}", parts.path, parts.query, parts.fragment))


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
    needs headers from web_core.  Steps 3-5 (web_dirfuzz, web_vuln,
    web_cms) are independent and run **concurrently** via
    ``asyncio.gather``.

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
    port_dir = output_dir / f"port_{port}"
    port_dir.mkdir(parents=True, exist_ok=True)

    # Step 1 — Core fingerprinting (must run first — fetches headers, hostnames)
    logger.info("[web:%d] Running web_core …", port)
    core_result = await run_web_core(target, port, url, state, config, port_dir)
    results.append(core_result)

    # After web_core: check if a new hostname was discovered via redirect.
    # If so, rebuild the URL so feroxbuster/nikto/etc use the hostname
    # instead of the raw IP (which may 301-redirect everything).
    refreshed_hostname = state.primary_hostname
    if refreshed_hostname and refreshed_hostname != hostname:
        logger.info("[web:%d] Hostname discovered: %s — rebuilding URL", port, refreshed_hostname)
        hostname = refreshed_hostname
        url = _rebuild_url_with_hostname(url, hostname, port)

    # Step 2 — Deep technology detection (needs headers from web_core)
    logger.info("[web:%d] Running web_tech …", port)
    tech_result = await run_web_tech(target, port, url, state, config, port_dir)
    results.append(tech_result)

    # Steps 3-5 — Independent sub-modules run CONCURRENTLY
    logger.info("[web:%d] Running web_dirfuzz + web_vuln + web_cms concurrently …", port)

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
        _safe_run("web_dirfuzz", run_web_dirfuzz(
            target, port, url, hostname, state, config, port_dir,
        )),
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

    async def _scan_port_bounded(port: int) -> tuple[int, list[ModuleResult]]:
        """Scan a single port inside a semaphore."""
        async with port_semaphore:
            svc = state.services.get(port)
            if svc is None:
                logger.warning("No ServiceInfo for port %d — skipping", port)
                return port, []

            if svc.url:
                url = svc.url.replace("TARGET", target)
            else:
                scheme = "https" if (port in (443, 8443) or "ssl" in svc.service.lower()) else "http"
                host = svc.hostname or target
                url = f"{scheme}://{host}:{port}"

            hostname = svc.hostname or state.primary_hostname

            try:
                port_results = await _scan_port(
                    target=target,
                    port=port,
                    url=url,
                    hostname=hostname,
                    state=state,
                    config=config,
                    output_dir=output_dir,
                )
                return port, port_results
            except Exception as exc:
                logger.exception("[web:%d] Sub-module pipeline failed: %s", port, exc)
                error_finding = Finding(
                    severity=Severity.HIGH,
                    title=f"Web scan pipeline failed on port {port}",
                    description=str(exc),
                    module="web",
                )
                return port, [ModuleResult(
                    module_name="web",
                    status="error",
                    findings=[error_finding],
                    error_message=str(exc),
                )]

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
                all_raw.append(f"--- {mod_result.module_name} (port {port}) ---\n{mod_result.raw_output}")
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

