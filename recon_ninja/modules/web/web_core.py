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

import ipaddress
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
from recon_ninja.core.display import get_console
from recon_ninja.utils.hosts import hostname_exists, add_to_hosts, get_ip_for_hostname

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
        line = line.strip()
        if not line:
            continue
        if line.startswith(":"):
            # Pseudo-header (HTTP/2)
            line_clean = line[1:]
            if ":" in line_clean:
                name, _, value = line_clean.partition(":")
            elif " " in line_clean:
                name, _, value = line_clean.partition(" ")
            else:
                continue
            headers[name.strip().lower()] = value.strip()
        else:
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
        if not _is_ip_target(host) and host not in hostnames:
            hostnames.append(host)

    # Set-Cookie domain=
    for match in re.finditer(r"domain=\.?([^\s;]+)", raw, re.IGNORECASE):
        host = match.group(1)
        if not _is_ip_target(host) and host not in hostnames:
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
    _WHATWEB_METADATA_FIELDS = {
        "ip", "title", "country", "httpserver", "redirectlocation",
        "cookies", "email", "uncommonheaders", "html5", "x-frame-options",
        "x-xss-protection", "strict-transport-security", "x-powered-by",
        "meta-author", "script", "frame", "passwordfield",
    }

    for line in raw.splitlines():
        # Strip URL and status code prefix
        line_clean = re.sub(r"^(?:https?://)?\S+\s+\[\d{3}(?:\s+[^\]]*)?\]", "", line, flags=re.IGNORECASE)
        for match in re.finditer(r"(\w[\w\s\-]*?)\[([^\]]+)\]", line_clean):
            name = match.group(1).strip()
            detail = match.group(2).strip()
            if name.isdigit() or name.startswith("http"):
                continue
            if name.lower() in _WHATWEB_METADATA_FIELDS:
                continue
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


def _is_ip_target(target: str) -> bool:
    """Return True when the scan target is an IP address."""
    try:
        ipaddress.ip_address(target)
    except ValueError:
        return False
    return True


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
        if rc != 0 and stderr.strip():
            raw_parts.append(f"=== curl -sI -L (error) ===\n{stderr}")

        if rc == 0:
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
            target_is_ip = _is_ip_target(target)
            for host in discovered_hosts:
                if host not in state.hostnames:
                    state.add_hostname(host)
                    logger.debug("[web_core] Discovered hostname from headers: %s", host)

                if target_is_ip and (get_ip_for_hostname(host) != target):
                    # Auto-add if enabled
                    auto_add = config.module_toggles.get("_add_hosts", False) or config.module_toggles.get("_htb", False)
                    added_successfully = False
                    if auto_add:
                        if add_to_hosts(target, host):
                            logger.info("[web_core] Automatically added/updated %s -> %s in /etc/hosts", target, host)
                            if not config.module_toggles.get("_quiet", False):
                                console = get_console()
                                console.print(f"  [bold green][+][/] Automatically added/updated [bold cyan]{host}[/] in /etc/hosts")
                            added_successfully = True

                    if not added_successfully:
                        console = get_console()
                        console.print()
                        console.print(
                            f"  [bold yellow][!] Hostname detected via redirect:[/] "
                            f"[bold cyan]{host}[/]"
                        )
                        console.print(
                            f"      Add to /etc/hosts:  "
                            f"[bold]echo \"{target} {host}\" >> /etc/hosts[/]"
                        )
                        console.print(
                            f"      Or re-run with:     "
                            f"[bold]reconninja {target} --htb --add-hosts[/]"
                        )
                        console.print()
                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                title=f"Hostname redirect detected: {host}",
                                description=(
                                    f"Server redirects to hostname {host} which is not in /etc/hosts. "
                                    f"Add it with: echo \"{target} {host}\" >> /etc/hosts"
                                ),
                                module="web_core",
                                evidence=f"301 redirect to {host}",
                                suggested_commands=[
                                    f'echo "{target} {host}" >> /etc/hosts',
                                    f"reconninja {target} --htb --add-hosts",
                                ],
                            )
                        )

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
        if rc != 0 and stderr.strip():
            raw_parts.append(f"=== whatweb (error) ===\n{stderr}")

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
        if rc != 0 and stderr.strip():
            raw_parts.append(f"=== wafw00f (error) ===\n{stderr}")

        # Parse for "is behind" or "Firewall detected"
        detected_wafs = []
        for line in stdout.splitlines():
            line_lower = line.lower()
            if "is behind" in line_lower or "firewall" in line_lower:
                waf_name = line.strip()
                if waf_name not in detected_wafs:
                    detected_wafs.append(waf_name)

        for waf_name in detected_wafs:
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
                cmd=[
                    "curl", "-sL",
                    "-w", "%{http_code}",
                    "-o", str(outfile),
                    "--max-time", str(config.default_timeout),
                    fetch_url
                ],
                timeout=config.default_timeout,
            )
            if rc != 0 and stderr.strip():
                raw_parts.append(f"=== {path} (error) ===\n{stderr}")

            valid = False
            if rc == 0 and stdout.strip() == "200" and outfile.is_file():
                content = outfile.read_text(encoding="utf-8", errors="replace")
                content_lower = content.lower()
                is_html = (
                    "<!doctype" in content_lower[:200]
                    or "<html" in content_lower[:200]
                    or "<body" in content_lower[:200]
                    or "<head" in content_lower[:200]
                )
                if content.strip() and not is_html:
                    valid = True
                    raw_parts.append(f"=== {path} ===\n{content[:2000]}")
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title=f"Discovered /{path}",
                            description=f"/{path} is accessible on {url} ({len(content)} bytes)",
                            module="web_core",
                            evidence=content[:500],
                        )
                    )

            if not valid:
                try:
                    outfile.unlink(missing_ok=True)
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # 5. gowitness — screenshot
    # ------------------------------------------------------------------
    if shutil.which("gowitness"):
        screenshot_dir = output_dir / "screenshots"
        screenshot_dir.mkdir(parents=True, exist_ok=True)
        # Try modern command first: gowitness scan single
        rc, stdout, stderr = await run_tool(
            cmd=[
                "gowitness", "scan", "single",
                url,
                "--screenshot-path", str(screenshot_dir),
            ],
            timeout=60,
        )
        if rc != 0:
            logger.debug("gowitness scan single failed (rc=%d), trying fallback gowitness single", rc)
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
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="Gowitness screenshot failed",
                    description=f"gowitness was unable to capture a screenshot of {url}.",
                    module="web_core",
                    evidence=f"Exit code: {rc}\nStderr: {stderr[:500]}",
                )
            )
    else:
        logger.debug("gowitness not found — skipping screenshot")
        raw_parts.append("=== gowitness === SKIPPED (not found)")

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    combined_raw = "\n\n".join(raw_parts)
    raw_len = len(combined_raw)
    raw_truncated = combined_raw[:8000]
    if raw_len > 8000:
        raw_truncated += "\n[TRUNCATED]"

    return ModuleResult(
        module_name="web_core",
        status="done",
        findings=findings,
        raw_output=raw_truncated,
        duration_seconds=time.monotonic() - t0,
    )
