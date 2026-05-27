"""Vulnerability correlation module for Recon Ninja v2.

Correlates discovered services with known vulnerabilities using
searchsploit and nuclei, and enriches CVE findings with severity
data from the NVD API.

Workflow:
    1. For each ServiceInfo with product+version, query searchsploit.
    2. Broader searchsploit search if specific query returns nothing.
    3. Run nuclei templates against web targets (if available).
    4. Deduplicate findings (same CVE from multiple sources → one finding).
    5. Enrich CVE severity via the NVD API.

Tools used:
    - searchsploit: local exploit database lookups
    - nuclei: template-based vulnerability scanning (optional)
    - NVD API: CVE severity enrichment
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import time
from pathlib import Path
from typing import Any

import requests

from recon_ninja.core.models import (
    Finding,
    ModuleResult,
    ReconConfig,
    ScanState,
    ServiceInfo,
    Severity,
)
from recon_ninja.core.runner import run_tool

logger = logging.getLogger(__name__)

MODULE_NAME = "vuln_correlate"

# NVD API endpoint for CVE lookups
_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Timeout for NVD API requests (seconds)
_NVD_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


def _severity_from_exploit_type(exploit_type: str) -> Severity:
    """Map searchsploit exploit type to a Severity level.

    Args:
        exploit_type: The type string from searchsploit (e.g. ``remote``,
            ``webapps``, ``local``, ``dos``).

    Returns:
        Severity based on exploit type:
        - remote / webapps → HIGH
        - local / dos → MEDIUM
        - anything else → LOW
    """
    exploit_lower = exploit_type.lower()
    if "remote" in exploit_lower or "webapps" in exploit_lower:
        return Severity.HIGH
    if "local" in exploit_lower or "dos" in exploit_lower:
        return Severity.MEDIUM
    return Severity.LOW


def _severity_from_cvss(cvss_score: float) -> Severity:
    """Convert a CVSS v3.x base score to a Severity enum.

    Args:
        cvss_score: CVSS base score (0.0 – 10.0).

    Returns:
        Severity mapping:
        - 9.0+ → CRITICAL
        - 7.0+ → HIGH
        - 4.0+ → MEDIUM
        - otherwise → LOW
    """
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    if cvss_score >= 7.0:
        return Severity.HIGH
    if cvss_score >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


# ---------------------------------------------------------------------------
# NVD API enrichment
# ---------------------------------------------------------------------------


def _lookup_nvd_severity(cve_id: str, api_key: str | None = None) -> Severity | None:
    """Query the NVD API for a CVE's CVSS severity.

    Uses the ``keywordSearch`` parameter to find the CVE entry and
    extracts the CVSS v3 (preferred) or v2 base score.

    Args:
        cve_id: CVE identifier (e.g. ``CVE-2021-44228``).
        api_key: Optional NVD API key for higher rate limits.

    Returns:
        Severity derived from the CVSS score, or ``None`` if lookup fails.
    """
    params: dict[str, str] = {"keywordSearch": cve_id}
    headers: dict[str, str] = {"User-Agent": "ReconNinja/2.0 vuln_correlate"}

    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(
            _NVD_API_URL,
            params=params,
            headers=headers,
            timeout=_NVD_TIMEOUT,
        )
        resp.raise_for_status()
        data: dict[str, Any] = resp.json()

        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            return None

        cve_item = vulnerabilities[0].get("cve", {})

        # Try CVSS v3 first
        metrics = cve_item.get("metrics", {})
        cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
        if cvss_v3:
            cvss_data = cvss_v3[0].get("cvssData", {})
            base_score = cvss_data.get("baseScore")
            if base_score is not None:
                return _severity_from_cvss(float(base_score))

        # Fall back to CVSS v2
        cvss_v2 = metrics.get("cvssMetricV2", [])
        if cvss_v2:
            cvss_data = cvss_v2[0].get("cvssData", {})
            base_score = cvss_data.get("baseScore")
            if base_score is not None:
                return _severity_from_cvss(float(base_score))

    except requests.exceptions.RequestException as exc:
        logger.debug("NVD lookup failed for %s: %s", cve_id, exc)
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        logger.debug("NVD parse error for %s: %s", cve_id, exc)

    return None


# ---------------------------------------------------------------------------
# searchsploit parsing
# ---------------------------------------------------------------------------


def _parse_searchsploit_json(
    stdout: str, product: str, version: str, port: int
) -> list[Finding]:
    """Parse searchsploit JSON output into Findings.

    searchsploit ``--json`` returns a structure like::

        {
          "RESULTS_SEARCH": [
            {
              "Title": "...",
              "Type": "remote",
              "Path": "exploits/.../12345.py",
              "CVE": "CVE-20XX-XXXX"
            }
          ]
        }

    Args:
        stdout: Raw searchsploit JSON output.
        product: Product name that was queried.
        version: Version string that was queried.
        port: Port on which the service runs.

    Returns:
        List of Findings, one per exploit result.
    """
    findings: list[Finding] = []

    try:
        data: dict[str, Any] = json.loads(stdout)
    except json.JSONDecodeError as exc:
        logger.warning("Failed to parse searchsploit JSON: %s", exc)
        return findings

    # searchsploit uses different keys depending on version
    results: list[dict[str, Any]] = (
        data.get("RESULTS_SEARCH", [])
        or data.get("RESULTS_EXPLOIT", [])
        or data.get("results", [])
    )

    for entry in results:
        title = entry.get("Title", "Unknown exploit")
        exploit_type = entry.get("Type", "")
        exploit_path = entry.get("Path", "")
        cve = entry.get("CVE", None)

        # Clean up CVE field — sometimes it's a list or comma-separated
        if cve and isinstance(cve, list):
            cve = cve[0] if cve else None
        if cve and isinstance(cve, str):
            # Extract first CVE from potentially messy strings
            cve_match = re.search(r"CVE-\d{4}-\d{4,}", cve)
            cve = cve_match.group(0) if cve_match else None

        severity = _severity_from_exploit_type(exploit_type)

        findings.append(
            Finding(
                severity=severity,
                title=f"[Port {port}] {product} {version}: {title}",
                description=f"searchsploit found an exploit for {product} {version}: "
                f"{title} (type: {exploit_type})",
                module=MODULE_NAME,
                evidence=f"Path: {exploit_path}  Type: {exploit_type}",
                cve=cve,
                suggested_commands=[
                    f"searchsploit -x {exploit_path}" if exploit_path else "",
                    f"searchsploit --nmap xml/nmap.xml",
                ],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# nuclei parsing
# ---------------------------------------------------------------------------


def _parse_nuclei_output(stdout: str) -> list[Finding]:
    """Parse nuclei JSON output into Findings.

    nuclei with ``-json`` outputs one JSON object per line::

        {
          "templateID": "cves/2021/CVE-2021-44228",
          "type": "cve",
          "host": "https://example.com",
          "matched": "https://example.com",
          "info": {
            "name": "Apache Log4j RCE",
            "severity": "critical",
            "description": "...",
            "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
          }
        }

    Args:
        stdout: Raw nuclei output (may contain JSON lines mixed with text).

    Returns:
        List of Findings from nuclei results.
    """
    findings: list[Finding] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue

        try:
            entry: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = entry.get("info", {})
        name = info.get("name", "Unknown nuclei finding")
        severity_str = info.get("severity", "info").upper()
        template_id = entry.get("templateID", "")
        host = entry.get("host", entry.get("matched", ""))
        description = info.get("description", "")
        references = info.get("reference", [])

        # Map nuclei severity to our Severity enum
        severity_map: dict[str, Severity] = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
            "INFO": Severity.INFO,
            "WARNING": Severity.MEDIUM,
            "UNKNOWN": Severity.LOW,
        }
        severity = severity_map.get(severity_str, Severity.INFO)

        # Try to extract CVE from template ID or references
        cve: str | None = None
        cve_match = re.search(r"CVE-\d{4}-\d{4,}", template_id)
        if cve_match:
            cve = cve_match.group(0)
        else:
            for ref in references:
                ref_cve = re.search(r"CVE-\d{4}-\d{4,}", str(ref))
                if ref_cve:
                    cve = ref_cve.group(0)
                    break

        findings.append(
            Finding(
                severity=severity,
                title=f"[nuclei] {name}",
                description=description or f"nuclei template {template_id} matched on {host}",
                module=MODULE_NAME,
                evidence=f"Template: {template_id}  Host: {host}",
                cve=cve,
                suggested_commands=[
                    f"nuclei -u {host} -t {template_id}" if template_id else "",
                ],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def _deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate findings where the same CVE appears from multiple sources.

    Two findings are considered duplicates if they share the same CVE ID.
    When merging, the finding with the higher severity is kept.

    Args:
        findings: Raw list of potentially duplicate Findings.

    Returns:
        Deduplicated list of Findings.
    """
    by_cve: dict[str, Finding] = {}
    no_cve: list[Finding] = []
    seen_titles: set[str] = set()

    for f in findings:
        if f.cve:
            existing = by_cve.get(f.cve)
            if existing is None:
                by_cve[f.cve] = f
            else:
                # Keep the one with higher severity
                if f.severity.rank < existing.severity.rank:
                    by_cve[f.cve] = f
        else:
            # Deduplicate non-CVE findings by title
            if f.title not in seen_titles:
                no_cve.append(f)
                seen_titles.add(f.title)

    return list(by_cve.values()) + no_cve


# ---------------------------------------------------------------------------
# Service enumeration helpers
# ---------------------------------------------------------------------------


def _services_with_version(state: ScanState) -> list[ServiceInfo]:
    """Filter services that have both product and version information.

    Args:
        state: Current scan state.

    Returns:
        List of ServiceInfo objects with non-empty product and version.
    """
    return [
        svc
        for svc in state.services.values()
        if svc.product.strip() and svc.version.strip()
    ]


def _web_targets(state: ScanState) -> list[str]:
    """Build a list of web target URLs from the scan state.

    Args:
        state: Current scan state.

    Returns:
        List of URLs for HTTP/HTTPS services.
    """
    targets: list[str] = []
    for port, svc in state.services.items():
        url = svc.url
        if url:
            # Replace 'TARGET' placeholder with the actual target
            url = url.replace("TARGET", state.target)
            targets.append(url)
    return targets


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def run_vuln_correlate_module(
    target: str, state: ScanState, config: ReconConfig, output_dir: Path
) -> ModuleResult:
    """Correlate discovered services with known vulnerabilities.

    Queries searchsploit for each service with product+version, runs
    nuclei templates against web targets, and enriches CVE findings
    with severity data from the NVD API.

    Args:
        target: The primary target IP or hostname.
        state: Current scan state with discovered services.
        config: Scan configuration (timeouts, toggles, API keys, etc.).
        output_dir: Directory for module output files.

    Returns:
        ModuleResult with vulnerability findings, or a skipped result
        if no services have product/version info and no web targets exist.
    """
    start_time = time.monotonic()
    findings: list[Finding] = []
    raw_outputs: list[str] = []

    # Ensure output directory exists
    vuln_output_dir = output_dir / "vuln_correlate"
    vuln_output_dir.mkdir(parents=True, exist_ok=True)

    timeout = config.default_timeout
    has_searchsploit = shutil.which("searchsploit") is not None
    has_nuclei = shutil.which("nuclei") is not None

    # ------------------------------------------------------------------
    # searchsploit queries
    # ------------------------------------------------------------------
    versioned_services = _services_with_version(state)

    if versioned_services and has_searchsploit:
        for svc in versioned_services:
            product = svc.product.strip()
            version = svc.version.strip()
            port = svc.port

            # Specific query: "Product Version"
            specific_query = f"{product} {version}"
            specific_output = vuln_output_dir / f"searchsploit_{port}_specific.txt"
            rc, stdout, stderr = await run_tool(
                cmd=["searchsploit", "--json", specific_query],
                output_file=specific_output,
                timeout=timeout,
            )
            raw_outputs.append(
                f"=== searchsploit '{specific_query}' (port {port}) ===\n{stdout}"
            )

            specific_findings: list[Finding] = []
            if rc >= 0 and stdout:
                specific_findings = _parse_searchsploit_json(
                    stdout, product, version, port
                )

            # Broader query if specific returns nothing
            if not specific_findings:
                broad_query = product
                broad_output = vuln_output_dir / f"searchsploit_{port}_broad.txt"
                rc, stdout, stderr = await run_tool(
                    cmd=["searchsploit", "--json", broad_query],
                    output_file=broad_output,
                    timeout=timeout,
                )
                raw_outputs.append(
                    f"=== searchsploit '{broad_query}' (port {port}) ===\n{stdout}"
                )

                if rc >= 0 and stdout:
                    broad_findings = _parse_searchsploit_json(
                        stdout, product, "", port
                    )
                    findings.extend(broad_findings)
            else:
                findings.extend(specific_findings)

    elif not versioned_services:
        logger.info("No services with product+version info — skipping searchsploit")
    else:
        logger.info("searchsploit not available — skipping exploit search")

    # ------------------------------------------------------------------
    # nuclei scan against web targets
    # ------------------------------------------------------------------
    web_targets = _web_targets(state)

    if web_targets and has_nuclei:
        for url in web_targets:
            safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", url)[:60]
            nuclei_output = vuln_output_dir / f"nuclei_{safe_name}.txt"

            # Build nuclei command with JSON output and specific templates
            nuclei_cmd: list[str] = [
                "nuclei",
                "-u", url,
                "-t", "cves/",
                "-t", "exposures/",
                "-t", "misconfiguration/",
                "-severity", "critical,high,medium",
                "-json",
                "-silent",
            ]

            # Add custom templates path if configured
            if config.nuclei_templates:
                nuclei_cmd.extend(["-t", config.nuclei_templates])

            rc, stdout, stderr = await run_tool(
                cmd=nuclei_cmd,
                output_file=nuclei_output,
                timeout=timeout * 3,  # nuclei can be slow
            )
            raw_outputs.append(f"=== nuclei {url} ===\n{stdout}")

            if rc >= 0 and stdout:
                nuclei_findings = _parse_nuclei_output(stdout)
                findings.extend(nuclei_findings)

    elif not web_targets:
        logger.info("No web targets found — skipping nuclei")
    else:
        logger.info("nuclei not available — skipping template scan")

    # ------------------------------------------------------------------
    # Early exit if nothing was found
    # ------------------------------------------------------------------
    if not findings:
        return ModuleResult(
            module_name=MODULE_NAME,
            status="done",
            findings=[],
            raw_output="\n\n".join(raw_outputs)[:5000],
            output_file=vuln_output_dir,
            duration_seconds=time.monotonic() - start_time,
        )

    # ------------------------------------------------------------------
    # Deduplicate findings (same CVE from multiple sources)
    # ------------------------------------------------------------------
    findings = _deduplicate_findings(findings)

    # ------------------------------------------------------------------
    # NVD API enrichment for CVE findings
    # ------------------------------------------------------------------
    nvd_api_key: str | None = None
    api_keys = getattr(config, "api_keys", None)
    if api_keys and hasattr(api_keys, "nvd") and api_keys.nvd:
        nvd_api_key = api_keys.nvd

    cve_findings = [f for f in findings if f.cve]
    if cve_findings:
        logger.info("Enriching %d CVE findings via NVD API", len(cve_findings))
        for f in cve_findings:
            nvd_severity = _lookup_nvd_severity(f.cve, api_key=nvd_api_key)
            if nvd_severity is not None:
                # Upgrade severity if NVD says it's worse than our initial guess
                if nvd_severity.rank < f.severity.rank:
                    logger.debug(
                        "Upgrading %s severity: %s → %s (NVD)",
                        f.cve,
                        f.severity.value,
                        nvd_severity.value,
                    )
                    f.severity = nvd_severity

    # Save enriched results
    results_file = vuln_output_dir / "vuln_findings.json"
    try:
        results_data = [f.to_dict() for f in findings]
        results_file.write_text(
            json.dumps(results_data, indent=2), encoding="utf-8"
        )
    except OSError as exc:
        logger.warning("Failed to write vuln correlation results: %s", exc)

    duration = time.monotonic() - start_time

    return ModuleResult(
        module_name=MODULE_NAME,
        status="done",
        findings=findings,
        raw_output="\n\n".join(raw_outputs)[:10000],
        output_file=vuln_output_dir,
        duration_seconds=duration,
    )
