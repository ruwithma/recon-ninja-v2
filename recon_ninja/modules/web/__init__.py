"""Web reconnaissance module — top-level orchestrator.

This is the entry point imported by :mod:`recon_ninja.core.engine`.  It
iterates over every HTTP/HTTPS port discovered during Phase 2, constructs
the appropriate URL, and then runs the sub-modules in sequence:

    web_core  →  web_dirfuzz  →  web_vuln  →  web_cms

Each sub-module returns its own :class:`ModuleResult`.  All findings are
aggregated into a single combined result with ``module_name="web"``.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path

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

    # Step 1 — Core fingerprinting
    logger.info("[web:%d] Running web_core …", port)
    core_result = await run_web_core(target, port, url, state, config, port_dir)
    results.append(core_result)

    # Step 2 — Deep technology detection
    logger.info("[web:%d] Running web_tech …", port)
    tech_result = await run_web_tech(target, port, url, state, config, port_dir)
    results.append(tech_result)

    # Step 3 — Directory / file fuzzing
    logger.info("[web:%d] Running web_dirfuzz …", port)
    dirfuzz_result = await run_web_dirfuzz(
        target, port, url, hostname, state, config, port_dir,
    )
    results.append(dirfuzz_result)

    # Step 4 — Vulnerability scanning
    logger.info("[web:%d] Running web_vuln …", port)
    vuln_result = await run_web_vuln(target, port, url, state, config, port_dir)
    results.append(vuln_result)

    # Step 5 — CMS detection & API discovery
    logger.info("[web:%d] Running web_cms …", port)
    cms_result = await run_web_cms(target, port, url, state, config, port_dir)
    results.append(cms_result)

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
    (web_core → web_dirfuzz → web_vuln → web_cms) for each qualifying
    port.

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

    for port in web_ports:
        svc = state.services.get(port)
        if svc is None:
            logger.warning("No ServiceInfo for port %d — skipping", port)
            continue

        # Build URL; replace the placeholder "TARGET" in ServiceInfo.url
        if svc.url:
            url = svc.url.replace("TARGET", target)
        else:
            # Fallback: construct URL manually
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
        except Exception as exc:
            logger.exception("[web:%d] Sub-module pipeline failed: %s", port, exc)
            any_error = True
            all_findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title=f"Web scan pipeline failed on port {port}",
                    description=str(exc),
                    module="web",
                )
            )
            continue

        for result in port_results:
            all_findings.extend(result.findings)
            if result.raw_output:
                all_raw.append(f"--- {result.module_name} (port {port}) ---\n{result.raw_output}")
            if result.status == "error":
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
