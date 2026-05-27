"""Core web fingerprinting sub-module.

Implements Step 1 of the web module specification:

* ``curl -sI -L --max-redirs 5 <URL>`` — headers, redirects, server banner,
  cookies.
* ``whatweb -a 3 <URL>`` — technology-stack fingerprint.
* ``wafw00f <URL>`` — WAF detection.
* Fetch ``robots.txt`` and ``sitemap.xml`` via curl.
* ``gowitness single <URL>`` — screenshot capture (if available).
* Security-header analysis: CSP, HSTS, X-Frame-Options,
  X-Content-Type-Options, Referrer-Policy.
* Parse whatweb output for CMS name + version, server, frameworks.
* Extract hostnames from ``Location`` headers and ``Set-Cookie`` domain.
* Flag each missing security header as :class:`Finding`(severity=INFO).
* Flag detected WAF as :class:`Finding`(severity=INFO) with evidence.
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

#: Security headers we expect on every modern HTTPS (and HTTP) response.
REQUIRED_SECURITY_HEADERS: dict[str, str] = {
    "content-security-policy": "Content-Security-Policy (CSP)",
    "strict-transport-security": "HTTP Strict Transport Security (HSTS)",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_curl_headers(raw: str) -> dict[str, str]:
    """Parse curl ``-sI`` output into a lowercase header dictionary.

    Only the **final** response's headers are kept (i.e. after following
    redirects).  Earlier responses separated by blank lines are discarded.

    Parameters
    ----------
    raw:
        Full stdout from ``curl -sI -L``.

    Returns
    -------
    dict[str, str]
        Mapping of lowercased header names to their values.
    """
    headers: dict[str, str] = {}
    # curl -L prints all response headers; the final block follows the
    # last blank line before the end.
    blocks = re.split(r"\r?\n\r?\n", raw.strip())
    last_block = blocks[-1] if blocks else ""

    for line in last_block.splitlines():
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()

    return headers


def _extract_hostnames_from_headers(raw: str) -> list[str]:
    """Extract hostnames from Location and Set-Cookie domain directives.

    Parameters
    ----------
    raw:
        Full stdout from ``curl -sI -L`` (includes all redirect hops).

    Returns
    -------
    list[str]
        Deduplicated hostnames found.
    """
    hostnames: list[str] = []

    # Location headers
    for match in re.finditer(r"^Location:\s*https?://([^/:]+)", raw, re.MULTILINE | re.IGNORECASE):
        host = match.group(1)
        if host not in hostnames:
            hostnames.append(host)

    # Set-Cookie domain=
    for match in re.finditer(r"domain=\.?([^\s;]+)", raw, re.IGNORECASE):
        host = match.group(1)
        if host not in hostnames:
            hostnames.append(host)

    return hostnames


def _parse_whatweb(raw: str) -> dict[str, str]:
    """Parse whatweb output into a tech-name → detail mapping.

    whatweb prints lines like::

        http://example.com [200 OK] Apache[2.4.52], PHP[7.4], WordPress[5.9]

    We extract bracketed details into a dict.

    Parameters
    ----------
    raw:
        Full stdout from ``whatweb -a 3 <URL>``.

    Returns
    -------
    dict[str, str]
        Mapping of technology name to detected version / detail.
    """
    # Strip ANSI escape codes
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    raw = ansi_escape.sub('', raw)

    tech: dict[str, str] = {}
    for match in re.finditer(r"(\w[\w\s\-]*?)\[([^\]]+)\]", raw):
        name = match.group(1).strip()
        detail = match.group(2).strip()
        tech[name] = detail
    return tech


def _check_security_headers(headers: dict[str, str], url: str) -> list[Finding]:
    """Flag missing security headers as INFO findings.

    Parameters
    ----------
    headers:
        Lowercased header dictionary from the final response.
    url:
        The URL being checked (included in finding description).

    Returns
    -------
    list[Finding]
        One finding per missing header.
    """
    findings: list[Finding] = []
    for header_key, header_display in REQUIRED_SECURITY_HEADERS.items():
        if header_key not in headers:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"Missing security header: {header_display}",
                    description=f"{header_display} header is not set on {url}.",
                    module="web_core",
                    evidence=f"Header '{header_key}' absent from response",
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Main sub-module function
# ---------------------------------------------------------------------------


@module_guard()
async def run_web_core(
    target: str,
    port: int,
    url: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Core web fingerprinting sub-module.

    Runs curl, whatweb, wafw00f, gowitness, and checks security headers
    for a single HTTP service.

    Parameters
    ----------
    target:
        Raw target IP or hostname.
    port:
        Port number of the HTTP service.
    url:
        Fully-qualified URL (e.g. ``https://10.10.10.1:443``).
    state:
        Shared scan state (findings are added here too).
    config:
        Scan configuration.
    output_dir:
        Per-port output directory.

    Returns
    -------
    ModuleResult
        Result containing all core fingerprinting findings.
    """
    t0 = time.monotonic()
    findings: list[Finding] = []
    raw_parts: list[str] = []

    # ------------------------------------------------------------------
    # 1. curl — headers, redirects, server banner, cookies
    # ------------------------------------------------------------------
    if shutil.which("curl"):
        curl_out = output_dir / "curl_headers.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["curl", "-sI", "-L", "--max-redirs", "5", url],
            output_file=curl_out,
            timeout=config.default_timeout,
        )
        raw_parts.append(f"=== curl -sI -L ===\n{stdout}")

        headers = _parse_curl_headers(stdout)

        # Server banner
        server = headers.get("server", "")
        if server:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"Server banner: {server}",
                    description=f"HTTP Server header on {url}: {server}",
                    module="web_core",
                    evidence=f"Server: {server}",
                )
            )

        # Extract hostnames from Location / Set-Cookie
        discovered_hosts = _extract_hostnames_from_headers(stdout)
        for host in discovered_hosts:
            if host not in state.hostnames:
                state.hostnames.append(host)
                logger.debug("[web_core] Discovered hostname from headers: %s", host)

        # Security headers
        sec_findings = _check_security_headers(headers, url)
        findings.extend(sec_findings)
    else:
        logger.warning("curl not found — skipping header analysis")
        raw_parts.append("=== curl === SKIPPED (not found)")

    # ------------------------------------------------------------------
    # 2. whatweb — tech stack fingerprint
    # ------------------------------------------------------------------
    if shutil.which("whatweb"):
        whatweb_out = output_dir / "whatweb.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["whatweb", "-a", "3", "--color=never", url],
            output_file=whatweb_out,
            timeout=config.default_timeout,
        )
        raw_parts.append(f"=== whatweb ===\n{stdout}")

        if rc == 0 and stdout.strip():
            tech_map = _parse_whatweb(stdout)

            # CMS detection
            cms_names = {"WordPress", "Drupal", "Joomla", "Magento", "Shopify"}
            for name in cms_names:
                if name in tech_map:
                    version = tech_map[name]
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title=f"CMS detected: {name} {version}",
                            description=f"{name} (version {version}) detected on {url}",
                            module="web_core",
                            evidence=f"{name}[{version}]",
                        )
                    )

            # Framework / language detection
            fw_names = {"PHP", "Express", "Django", "Flask", "Laravel", "Ruby", "ASP.NET", "JSP"}
            for name in fw_names:
                if name in tech_map:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title=f"Framework: {name} {tech_map[name]}",
                            description=f"{name} (version {tech_map[name]}) detected on {url}",
                            module="web_core",
                            evidence=f"{name}[{tech_map[name]}]",
                        )
                    )

            # General tech info
            for name, detail in tech_map.items():
                if name not in cms_names and name not in fw_names:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title=f"Tech detected: {name} [{detail}]",
                            description=f"{name} ({detail}) found on {url}",
                            module="web_core",
                            evidence=f"{name}[{detail}]",
                        )
                    )
    else:
        logger.debug("whatweb not found — skipping tech fingerprint")
        raw_parts.append("=== whatweb === SKIPPED (not found)")

    # ------------------------------------------------------------------
    # 3. wafw00f — WAF detection
    # ------------------------------------------------------------------
    if shutil.which("wafw00f"):
        waf_out = output_dir / "wafw00f.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["wafw00f", url],
            output_file=waf_out,
            timeout=config.default_timeout,
        )
        raw_parts.append(f"=== wafw00f ===\n{stdout}")

        # Parse for "is behind" or "Firewall detected"
        for line in stdout.splitlines():
            line_lower = line.lower()
            if "is behind" in line_lower or "firewall" in line_lower:
                waf_name = line.strip()
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title=f"WAF detected: {waf_name}",
                        description=f"Web Application Firewall detected on {url}",
                        module="web_core",
                        evidence=waf_name,
                        suggested_commands=[
                            f"wafw00f -a {url}",
                        ],
                    )
                )
                break  # only flag the first match
    else:
        logger.debug("wafw00f not found — skipping WAF detection")
        raw_parts.append("=== wafw00f === SKIPPED (not found)")

    # ------------------------------------------------------------------
    # 4. robots.txt and sitemap.xml
    # ------------------------------------------------------------------
    if shutil.which("curl"):
        for path in ("robots.txt", "sitemap.xml"):
            fetch_url = f"{url}/{path}"
            outfile = output_dir / path.replace(".", "_")
            rc, stdout, stderr = await run_tool(
                cmd=["curl", "-sL", "--max-time", "10", fetch_url],
                output_file=outfile,
                timeout=15,
            )
            if rc == 0 and stdout.strip() and "<!doctype" not in stdout.lower()[:100]:
                raw_parts.append(f"=== {path} ===\n{stdout[:2000]}")
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title=f"Discovered /{path}",
                        description=f"/{path} is accessible on {url} ({len(stdout)} bytes)",
                        module="web_core",
                        evidence=stdout[:500],
                    )
                )

    # ------------------------------------------------------------------
    # 5. gowitness — screenshot
    # ------------------------------------------------------------------
    if shutil.which("gowitness"):
        screenshot_dir = output_dir / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        rc, stdout, stderr = await run_tool(
            cmd=[
                "gowitness", "single",
                url,
                "--screenshot-path", str(screenshot_dir),
            ],
            timeout=60,
        )
        if rc == 0:
            raw_parts.append(f"=== gowitness === Screenshot saved to {screenshot_dir}")
        else:
            raw_parts.append(f"=== gowitness === Failed: {stderr[:200]}")
    else:
        logger.debug("gowitness not found — skipping screenshot")
        raw_parts.append("=== gowitness === SKIPPED (not found)")

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    combined_raw = "\n\n".join(raw_parts)

    return ModuleResult(
        module_name="web_core",
        status="done",
        findings=findings,
        raw_output=combined_raw[:8000],
        duration_seconds=time.monotonic() - t0,
    )
