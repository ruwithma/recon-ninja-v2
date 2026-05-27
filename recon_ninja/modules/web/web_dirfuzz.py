"""Directory and file fuzzing sub-module.

Implements Steps 2 and 3 of the web module specification:

* Determine file extensions from detected technology stack:
  - Apache/Nginx + Linux  →  ``-x php,txt,html,sh,bak``
  - IIS + Windows          →  ``-x asp,aspx,txt,html,config``
  - Tomcat/Java            →  ``-x jsp,do,action,java``
  - Generic                →  ``-x php,html,txt,js,json``
* Run **feroxbuster** (primary) or **gobuster dir** (fallback) with
  ``raft-medium-directories`` wordlist.
* Run vhost scan with **gobuster vhost** or **ffuf** if a hostname is
  known.
* Check common sensitive paths via async HEAD requests:
  ``/.git/``, ``/.env``, ``/admin``, ``/api/``, ``/swagger.json``,
  ``/graphql``, ``/backup/``, ``/config.php.bak``, ``/web.config``.
* Each discovered path is flagged as a :class:`Finding` with appropriate
  severity.
"""

from __future__ import annotations

import asyncio
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

#: Common sensitive paths to probe with HEAD requests.
COMMON_PATHS: list[tuple[str, Severity]] = [
    ("/", Severity.INFO),                  # baseline — not usually a finding
    ("/.git/", Severity.HIGH),             # git repository exposure
    ("/.git/HEAD", Severity.HIGH),         # git HEAD file
    ("/.env", Severity.CRITICAL),          # environment file leak
    ("/admin", Severity.LOW),              # admin panel
    ("/admin/", Severity.LOW),
    ("/api/", Severity.INFO),              # API root
    ("/swagger.json", Severity.MEDIUM),    # OpenAPI spec
    ("/graphql", Severity.MEDIUM),         # GraphQL endpoint
    ("/backup/", Severity.MEDIUM),         # backup directory
    ("/config.php.bak", Severity.HIGH),    # PHP config backup
    ("/web.config", Severity.MEDIUM),      # IIS config
    ("/.htaccess", Severity.LOW),          # Apache config
    ("/.htpasswd", Severity.HIGH),         # Apache password file
    ("/server-status", Severity.LOW),      # Apache server-status
    ("/phpinfo.php", Severity.MEDIUM),     # PHP info page
    ("/wp-login.php", Severity.INFO),      # WordPress login
    ("/wp-admin/", Severity.INFO),         # WordPress admin
    ("/robots.txt", Severity.INFO),        # robots (already in core, but check here too)
]

#: Extension sets keyed by technology stack.
EXTENSION_MAP: dict[str, str] = {
    "lamp": "php,txt,html,sh,bak",
    "iis": "asp,aspx,txt,html,config",
    "java": "jsp,do,action,java",
    "node": "js,json,html,txt",
    "generic": "php,html,txt,js,json",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _determine_extensions(state: ScanState, port: int) -> str:
    """Choose file extensions based on detected technology.

    Parameters
    ----------
    state:
        Shared scan state with service and finding information.
    port:
        The port we are scanning (used to look up service info).

    Returns
    -------
    str
        Comma-separated extension list suitable for ``-x`` flags.
    """
    svc = state.services.get(port)

    # Check product for IIS
    product = (svc.product.lower() if svc else "") or ""

    # Check findings from web_core for tech stack hints
    tech_stack: set[str] = set()
    for finding in state.all_findings:
        if finding.module != "web_core":
            continue
        title_lower = finding.title.lower()
        if "iis" in title_lower or "asp.net" in title_lower:
            tech_stack.add("iis")
        if "tomcat" in title_lower or "jsp" in title_lower or "spring" in title_lower:
            tech_stack.add("java")
        if "apache" in title_lower or "nginx" in title_lower or "php" in title_lower:
            tech_stack.add("lamp")
        if "next.js" in title_lower or "node.js" in title_lower or "react" in title_lower or "express" in title_lower:
            tech_stack.add("node")

    # Also check detected_techs directly
    for tech in state.detected_techs:
        if tech.port != port:
            continue
        name_lower = tech.name.lower()
        if "iis" in name_lower or "asp.net" in name_lower:
            tech_stack.add("iis")
        if "tomcat" in name_lower or "jsp" in name_lower or "spring" in name_lower:
            tech_stack.add("java")
        if "apache" in name_lower or "nginx" in name_lower or "php" in name_lower:
            tech_stack.add("lamp")
        if "next.js" in name_lower or "node.js" in name_lower or "react" in name_lower or "express" in name_lower:
            tech_stack.add("node")

    # Also check product directly
    if "iis" in product:
        tech_stack.add("iis")
    if "tomcat" in product or "apache tomcat" in product:
        tech_stack.add("java")
    if "apache" in product or "nginx" in product:
        tech_stack.add("lamp")

    if "iis" in tech_stack:
        return EXTENSION_MAP["iis"]
    if "java" in tech_stack:
        return EXTENSION_MAP["java"]
    if "lamp" in tech_stack:
        return EXTENSION_MAP["lamp"]
    if "node" in tech_stack:
        return EXTENSION_MAP["node"]

    return EXTENSION_MAP["generic"]


def _parse_feroxbuster(raw: str) -> list[tuple[int, str, int]]:
    """Parse feroxbuster output for discovered paths.

    Typical line format::

        200      GET       48l http://10.10.10.1/admin

    Parameters
    ----------
    raw:
        Full stdout from feroxbuster.

    Returns
    -------
    list[tuple[int, str, int]]
        List of (status_code, path, size) tuples.
    """
    results: list[tuple[int, str, int]] = []
    # Match lines: STATUS  METHOD  SIZE  URL
    pattern = re.compile(
        r"^(\d{3})\s+\w+\s+(\d+\w?)\s+(https?://\S+)$", re.MULTILINE,
    )
    for match in pattern.finditer(raw):
        status = int(match.group(1))
        url = match.group(3)
        size_str = match.group(2)
        # size may be like "48l" (lines) — just extract digits
        size_digits = re.sub(r"[^\d]", "", size_str)
        size = int(size_digits) if size_digits else 0
        results.append((status, url, size))
    return results


def _parse_gobuster(raw: str) -> list[tuple[int, str, int]]:
    """Parse gobuster dir output for discovered paths.

    Typical line format::

        /admin (Status: 301) [Size: 185]

    Parameters
    ----------
    raw:
        Full stdout from gobuster.

    Returns
    -------
    list[tuple[int, str, int]]
        List of (status_code, path, size) tuples.
    """
    results: list[tuple[int, str, int]] = []
    pattern = re.compile(
        r"^(/\S*)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]", re.MULTILINE,
    )
    for match in pattern.finditer(raw):
        path = match.group(1)
        status = int(match.group(2))
        size = int(match.group(3))
        results.append((status, path, size))
    return results


def _severity_for_status(status: int, path: str) -> Severity:
    """Determine finding severity from HTTP status and path.

    Parameters
    ----------
    status:
        HTTP response status code.
    path:
        Request path.

    Returns
    -------
    Severity
        Appropriate severity level.
    """
    if status == 200:
        # Sensitive paths are more severe
        sensitive = {".git", ".env", "config.php.bak", ".htpasswd", "web.config"}
        if any(s in path.lower() for s in sensitive):
            return Severity.HIGH
        return Severity.LOW
    if status in (301, 302, 303, 307, 308):
        return Severity.INFO
    if status == 403:
        return Severity.INFO  # forbidden but path exists
    if status == 401:
        return Severity.INFO
    return Severity.INFO


# ---------------------------------------------------------------------------
# Async HEAD checker
# ---------------------------------------------------------------------------


async def _check_path(
    url: str,
    path: str,
    severity: Severity,
) -> Finding | None:
    """Send a HEAD request via curl and return a Finding if the path exists.

    Parameters
    ----------
    url:
        Base URL (e.g. ``http://10.10.10.1:80``).
    path:
        URL path to check (e.g. ``/.git/``).
    severity:
        Default severity if the path is found.

    Returns
    -------
    Finding | None
        A finding if the path responded with a non-404 status, else None.
    """
    full_url = f"{url}{path}"
    try:
        rc, stdout, stderr = await run_tool(
            cmd=["curl", "-sI", "-o", "/dev/null", "-w", "%{http_code}", full_url],
            timeout=10,
        )
        # stdout contains just the status code with -w
        status_str = stdout.strip()
        if not status_str:
            return None
        status = int(status_str)
        if status == 0 or status >= 500:
            return None
        if status == 404:
            return None

        # Path exists — adjust severity
        actual_sev = _severity_for_status(status, path)
        if actual_sev.rank > severity.rank:
            # Use the more severe of (default, status-based)
            actual_sev = severity

        return Finding(
            severity=actual_sev,
            title=f"Path found: {path} (HTTP {status})",
            description=f"{full_url} returned HTTP {status}",
            module="web_dirfuzz",
            evidence=f"HEAD {full_url} → {status}",
        )
    except Exception as exc:
        logger.debug("Error checking %s: %s", full_url, exc)
        return None


# ---------------------------------------------------------------------------
# Main sub-module function
# ---------------------------------------------------------------------------


@module_guard()
async def run_web_dirfuzz(
    target: str,
    port: int,
    url: str,
    hostname: str | None,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Directory and file fuzzing sub-module.

    Runs feroxbuster (primary) or gobuster (fallback) for directory
    discovery, performs vhost enumeration when a hostname is known,
    and checks common sensitive paths via async HEAD requests.

    Parameters
    ----------
    target:
        Raw target IP or hostname.
    port:
        Port number of the HTTP service.
    url:
        Fully-qualified URL (e.g. ``http://10.10.10.1:80``).
    hostname:
        Detected hostname (may be ``None``).
    state:
        Shared scan state.
    config:
        Scan configuration.
    output_dir:
        Per-port output directory.

    Returns
    -------
    ModuleResult
        Result with all directory/file fuzzing findings.
    """
    t0 = time.monotonic()
    findings: list[Finding] = []
    raw_parts: list[str] = []

    extensions = _determine_extensions(state, port)
    wordlist = str(config.web_wordlist)

    threads = "10" if port not in (80, 443) else "20"
    depth = "1" if config.fast_mode else "2"

    # ------------------------------------------------------------------
    # 1. Directory fuzzing — feroxbuster or gobuster
    # ------------------------------------------------------------------
    if shutil.which("feroxbuster"):
        ferox_out = output_dir / "feroxbuster.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "feroxbuster",
                "-u", url,
                "-w", wordlist,
                "-x", extensions,
                "-t", threads,
                "--depth", depth,
                "--scan-limit", "3",
                "--timeout", "10",
                "-q",  # quiet mode — only print results
            ],
            output_file=ferox_out,
            timeout=config.default_timeout,
        )
        raw_parts.append(f"=== feroxbuster ===\n{stdout[:5000]}")

        if rc in (0, 1) and stdout.strip():  # rc=1 means ctrl-c or early exit, but output is valid
            for status, found_url, size in _parse_feroxbuster(stdout):
                path = found_url.replace(url, "") or "/"
                sev = _severity_for_status(status, path)
                findings.append(
                    Finding(
                        severity=sev,
                        title=f"Fuzz: {path} (HTTP {status}, {size}B)",
                        description=f"Discovered path on {url}: {found_url}",
                        module="web_dirfuzz",
                        evidence=f"HTTP {status} Size:{size}",
                    )
                )

    elif shutil.which("gobuster"):
        gobuster_out = output_dir / "gobuster_dir.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "gobuster", "dir",
                "-u", url,
                "-w", wordlist,
                "-x", extensions,
                "-t", threads,
                "--timeout", "10s",
                "-q",
            ],
            output_file=gobuster_out,
            timeout=config.default_timeout,
        )
        raw_parts.append(f"=== gobuster dir ===\n{stdout[:5000]}")

        if rc in (0, 1) and stdout.strip():
            for status, path, size in _parse_gobuster(stdout):
                sev = _severity_for_status(status, path)
                findings.append(
                    Finding(
                        severity=sev,
                        title=f"Fuzz: {path} (HTTP {status}, {size}B)",
                        description=f"Discovered path on {url}: {path}",
                        module="web_dirfuzz",
                        evidence=f"HTTP {status} Size:{size}",
                    )
                )
    else:
        logger.warning("Neither feroxbuster nor gobuster found — skipping directory fuzzing")
        raw_parts.append("=== directory fuzzing === SKIPPED (no tool available)")

    # ------------------------------------------------------------------
    # 2. Vhost scan — if hostname is known
    # ------------------------------------------------------------------
    if hostname:
        vhost_wordlist = str(
            config.web_wordlist.parent.parent / "Discovery" / "DNS" / "subdomains-top1million-5000.txt"
        )

        if shutil.which("gobuster"):
            vhost_out = output_dir / "gobuster_vhost.txt"
            rc, stdout, stderr = await run_tool(
                cmd=[
                    "gobuster", "vhost",
                    "-u", url,
                    "-w", vhost_wordlist,
                    "--hostname", hostname,
                    "-t", "20",
                    "-q",
                ],
                output_file=vhost_out,
                timeout=config.default_timeout,
            )
            raw_parts.append(f"=== gobuster vhost ===\n{stdout[:3000]}")

            if stdout.strip():
                for line in stdout.splitlines():
                    if "Status:" in line:
                        findings.append(
                            Finding(
                                severity=Severity.INFO,
                                title=f"Vhost found: {line.strip()}",
                                description=f"Virtual host discovered on {url}",
                                module="web_dirfuzz",
                                evidence=line.strip(),
                            )
                        )

        elif shutil.which("ffuf"):
            vhost_out = output_dir / "ffuf_vhost.txt"
            rc, stdout, stderr = await run_tool(
                cmd=[
                    "ffuf",
                    "-u", url,
                    "-H", f"Host: FUZZ.{hostname}",
                    "-w", vhost_wordlist,
                    "-mc", "200,301,302",
                    "-o", str(vhost_out),
                ],
                output_file=vhost_out,
                timeout=config.default_timeout,
            )
            raw_parts.append(f"=== ffuf vhost ===\n{stdout[:3000]}")
    else:
        logger.debug("No hostname known — skipping vhost scan")

    # ------------------------------------------------------------------
    # 3. Common path probing (async HEAD requests)
    # ------------------------------------------------------------------
    if shutil.which("curl"):
        # Run HEAD checks concurrently (bounded)
        semaphore = asyncio.Semaphore(10)

        async def _bounded_check(
            u: str, p: str, s: Severity,
        ) -> Finding | None:
            async with semaphore:
                return await _check_path(u, p, s)

        head_tasks = [
            asyncio.create_task(_bounded_check(url, path, sev))
            for path, sev in COMMON_PATHS
            if path not in ("/", "/robots.txt")
        ]

        head_results = await asyncio.gather(*head_tasks, return_exceptions=True)

        for result in head_results:
            if isinstance(result, Finding):
                findings.append(result)
            elif isinstance(result, Exception):
                logger.debug("HEAD check raised: %s", result)

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    combined_raw = "\n\n".join(raw_parts)

    return ModuleResult(
        module_name="web_dirfuzz",
        status="done",
        findings=findings,
        raw_output=combined_raw[:8000],
        duration_seconds=time.monotonic() - t0,
    )
