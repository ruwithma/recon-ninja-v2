"""Vulnerability scanning sub-module.

Implements Step 4 of the web module specification:

* **nikto** — comprehensive web-server vulnerability scanner
  (timeout: 180 s).
* **nuclei** — template-based vulnerability scanner (if available,
  timeout: 300 s, tags: ``cve,exposure,misconfig``).
* Parse output for CVE references and flag each as a
  :class:`Finding` with appropriate severity.
"""

from __future__ import annotations

import logging
import re
import shutil
import time
from pathlib import Path

from recon_ninja.core.models import (
    Finding,
    ModuleResult,
    ReconConfig,
    ScanState,
    Severity,
)
from recon_ninja.core.runner import run_tool
from recon_ninja.core.utils import module_guard

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Timeout for nikto scans (seconds).
NIKTO_TIMEOUT = 180

#: Timeout for nuclei scans (seconds).
NUCLEI_TIMEOUT = 300

#: Nuclei tags to target — CTF-focused, skip info-level noise.
NUCLEI_TAGS = "cve,exposure,misconfig"

#: Nuclei severity levels to scan — skip INFO (noise for CTF players).
NUCLEI_SEVERITY = "critical,high,medium,low"

#: Nuclei templates to EXCLUDE — these generate noise, not signal.
NUCLEI_EXCLUDE_TAGS = "fuzz,headless,dos,misc,tokens"

#: Nikto line patterns to suppress (duplicated by web_core or noise).
NIKTO_NOISE_PATTERNS = [
    "suggested security header missing",
    "x-content-type-options",
    "strict-transport-security",
    "content-security-policy",
    "referrer-policy",
    "permissions-policy",
    "cross-origin",
    "x-frame-options",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_nikto_findings(raw: str, url: str) -> list[Finding]:
    """Parse nikto output into a list of Findings.

    Nikto lines typically look like::

        + OSVDB-3092: /admin/: This might be interesting.
        + /config.php: PHP config file found.
        + Server: Apache/2.4.52

    We look for lines starting with ``+`` that contain OSVDB or CVE
    references, or that flag interesting / potentially dangerous items.

    Parameters
    ----------
    raw:
        Full stdout from nikto.
    url:
        Target URL (included in finding descriptions).

    Returns
    -------
    list[Finding]
        Parsed findings from nikto output.
    """
    findings: list[Finding] = []

    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("+"):
            continue

        # Remove leading "+ "
        content = line.lstrip("+ ").strip()
        if not content:
            continue

        # Filter out metadata and noise
        content_lower = content.lower()
        metadata_prefixes = (
            "target ip:",
            "target hostname:",
            "target port:",
            "platform:",
            "start time:",
            "end time:",
            "server:",
            "scan terminated:",
            "1 host(s) tested",
            "no cgi directories found",
            "target database:",
        )
        if any(content_lower.startswith(prefix) for prefix in metadata_prefixes):
            continue

        # Filter duplicate security-header warnings (already in web_core)
        if any(noise in content_lower for noise in NIKTO_NOISE_PATTERNS):
            continue

        # Check for CVE reference
        cve: str | None = None
        cve_match = re.search(r"CVE-\d{4}-\d{4,}", content)
        if cve_match:
            cve = cve_match.group(0)

        # Check for OSVDB reference
        osvdb_match = re.search(r"OSVDB-\d+", content)
        osvdb_ref = osvdb_match.group(0) if osvdb_match else None

        # Determine severity
        severity = Severity.INFO
        high_keywords = [
            "password", "credential", "shell", "exec", "upload",
            "injection", "xss", "sqli", "rce", "traversal",
            "config file", "source code", ".env", ".git",
        ]
        content_lower = content.lower()
        if any(kw in content_lower for kw in high_keywords):
            severity = Severity.MEDIUM
        if cve or osvdb_ref:
            severity = Severity.MEDIUM

        title_prefix = "Nikto"
        if osvdb_ref:
            title_prefix = f"Nikto [{osvdb_ref}]"

        findings.append(
            Finding(
                severity=severity,
                title=f"{title_prefix}: {content[:120]}",
                description=f"Nikto finding on {url}: {content}",
                module="web_vuln",
                evidence=content[:500],
                cve=cve,
                suggested_commands=[
                    f"nikto -h {url} -Tuning x",
                ] if cve else [],
            )
        )

    return findings


def _parse_nuclei_findings(raw: str, url: str) -> list[Finding]:
    """Parse nuclei output into a list of Findings.

    Nuclei outputs structured lines like::

        [CVE-2021-44228] [http] [high] https://example.com/...

    Or JSON-like lines when ``-json`` is used. We handle the standard
    text format.

    Parameters
    ----------
    raw:
        Full stdout from nuclei.
    url:
        Target URL.

    Returns
    -------
    list[Finding]
        Parsed findings from nuclei output.
    """
    findings: list[Finding] = []

    # Pattern: [template-id] [type] [severity] matched-url
    line_pattern = re.compile(
        r"\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)",
    )

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        match = line_pattern.search(line)
        if not match:
            # Try a simpler pattern for informational lines
            if "[" in line:
                # Could be a partial match — log and skip
                logger.debug("Unparsed nuclei line: %s", line[:200])
            continue

        template_id = match.group(1)
        # scan_type = match.group(2)  # e.g. "http"
        severity_str = match.group(3).lower()
        matched_url = match.group(4)

        # Map nuclei severity to our Severity enum
        severity_map: dict[str, Severity] = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "info": Severity.INFO,
            "informational": Severity.INFO,
        }
        severity = severity_map.get(severity_str, Severity.INFO)

        # Skip info-level nuclei findings — they're noise for CTF players
        # (missing headers, SSH algo detection, etc.)
        if severity == Severity.INFO:
            continue

        # Extract CVE if present in template ID
        cve: str | None = None
        cve_match = re.search(r"CVE-\d{4}-\d{4,}", template_id)
        if cve_match:
            cve = cve_match.group(0)

        findings.append(
            Finding(
                severity=severity,
                title=f"Nuclei [{template_id}]: {severity_str.upper()}",
                description=f"Nuclei detected {template_id} on {matched_url}",
                module="web_vuln",
                evidence=line[:500],
                cve=cve,
                suggested_commands=[
                    f"nuclei -u {url} -t {template_id}",
                ],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Main sub-module function
# ---------------------------------------------------------------------------


@module_guard()
async def run_web_vuln(
    target: str,
    port: int,
    url: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Vulnerability scanning sub-module.

    Runs nikto and (if available) nuclei against the target URL, parses
    their output, and returns findings.

    Parameters
    ----------
    target:
        Raw target IP or hostname.
    port:
        Port number of the HTTP service.
    url:
        Fully-qualified URL (e.g. ``http://10.10.10.1:80``).
    state:
        Shared scan state.
    config:
        Scan configuration.
    output_dir:
        Per-port output directory.

    Returns
    -------
    ModuleResult
        Result with all vulnerability scanning findings.
    """
    t0 = time.monotonic()
    findings: list[Finding] = []
    raw_parts: list[str] = []

    # ------------------------------------------------------------------
    # 1. nikto
    # ------------------------------------------------------------------
    if shutil.which("nikto"):
        nikto_out = output_dir / "nikto.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "nikto",
                "-h", url,
                "-maxtime", f"{NIKTO_TIMEOUT}s",
                "-nointeractive",
            ],
            output_file=nikto_out,
            timeout=NIKTO_TIMEOUT + 30,  # a little buffer
        )
        raw_parts.append(f"=== nikto ===\n{stdout[:5000]}")

        if rc in (0, 1) and stdout.strip():
            nikto_findings = _parse_nikto_findings(stdout, url)
            findings.extend(nikto_findings)
            logger.info("[web_vuln] nikto found %d issues on port %d", len(nikto_findings), port)
        else:
            logger.debug("[web_vuln] nikto returned rc=%d on port %d", rc, port)
    else:
        logger.debug("nikto not found — skipping")
        raw_parts.append("=== nikto === SKIPPED (not found)")

    # ------------------------------------------------------------------
    # 2. nuclei — CTF-focused templates only
    # ------------------------------------------------------------------
    if shutil.which("nuclei"):
        nuclei_out = output_dir / "nuclei.txt"

        nuclei_cmd: list[str] = [
            "nuclei",
            "-u", url,
            "-o", str(nuclei_out),
            "-severity", NUCLEI_SEVERITY,
            "-tags", NUCLEI_TAGS,
            "-exclude-tags", NUCLEI_EXCLUDE_TAGS,
            "-silent",
        ]

        # Use custom templates if configured
        if config.nuclei_templates:
            nuclei_cmd.extend(["-t", config.nuclei_templates])

        rc, stdout, stderr = await run_tool(
            cmd=nuclei_cmd,
            output_file=nuclei_out,
            timeout=NUCLEI_TIMEOUT + 30,
        )
        raw_parts.append(f"=== nuclei ===\n{stdout[:5000]}")

        if stdout.strip():
            nuclei_findings = _parse_nuclei_findings(stdout, url)
            findings.extend(nuclei_findings)
            logger.info("[web_vuln] nuclei found %d issues on port %d", len(nuclei_findings), port)
        else:
            # nuclei may also write to the output file directly
            try:
                file_content = nuclei_out.read_text(encoding="utf-8", errors="replace")
                if file_content.strip():
                    nuclei_findings = _parse_nuclei_findings(file_content, url)
                    findings.extend(nuclei_findings)
                    raw_parts.append(f"=== nuclei (from file) ===\n{file_content[:3000]}")
            except OSError:
                pass
    else:
        logger.debug("nuclei not found — skipping")
        raw_parts.append("=== nuclei === SKIPPED (not found)")

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    combined_raw = "\n\n".join(raw_parts)

    return ModuleResult(
        module_name="web_vuln",
        status="done",
        findings=findings,
        raw_output=combined_raw[:8000],
        duration_seconds=time.monotonic() - t0,
    )
