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
import json
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
    # Match lines: STATUS  METHOD  [optional columns]  SIZE  URL
    pattern = re.compile(
        r"^(\d{3})\s+\w+\s+(?:[\d\w]+\s+)*(\d+)[a-zA-Z]?\s+(https?://\S+)$", re.MULTILINE,
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


async def _head_status(url: str, path: str) -> tuple[int | None, str]:
    """Run a HEAD request and return the HTTP status code and redirect URL if available."""
    full_url = f"{url}{path}"
    try:
        _rc, stdout, _stderr = await run_tool(
            cmd=[
                "curl", "-sI", "-o", "/dev/null", "-w", "%{http_code} %{redirect_url}",
                "--connect-timeout", "3",
                "--max-time", "5",
                full_url,
            ],
            timeout=10,  # generous — curl's own --max-time handles the real limit
        )
        parts = stdout.strip().split(maxsplit=1)
        if not parts:
            return None, ""
        status_code = int(parts[0]) if parts[0].isdigit() else None
        redirect_url = parts[1] if len(parts) > 1 else ""
        return status_code, redirect_url
    except Exception as exc:
        logger.debug("Error checking %s: %s", full_url, exc)
        return None, ""


# ---------------------------------------------------------------------------
# Async HEAD checker
# ---------------------------------------------------------------------------


async def _check_path(
    url: str,
    path: str,
    severity: Severity,
    baseline_status: int | None = None,
    baseline_redirect: str = "",
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
        status, redirect_url = await _head_status(url, path)
        if status is None:
            return None
        if status == 0 or status >= 500:
            return None
        if status == 404:
            return None
        if baseline_status is not None and status == baseline_status:
            if status in (301, 302, 307, 308):
                if redirect_url == baseline_redirect:
                    return None
            else:
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


def _register_vhost(vhost: str, target: str, state: ScanState, config: ReconConfig) -> None:
    """Register a newly discovered virtual host in state and /etc/hosts if enabled."""
    vhost = vhost.split(":")[0].strip()  # Strip port if present
    if not vhost or vhost.replace(".", "").isdigit():
        return
    if vhost not in state.hostnames:
        state.hostnames.append(vhost)
        auto_add = config.module_toggles.get("_add_hosts", False) or config.module_toggles.get("_htb", False)
        from recon_ninja.utils.hosts import get_ip_for_hostname, add_to_hosts
        if auto_add and get_ip_for_hostname(vhost) != target:
            if add_to_hosts(target, vhost):
                logger.info("[web_dirfuzz] Automatically added/updated %s -> %s in /etc/hosts", target, vhost)


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
    baseline_status: int | None = None
    baseline_redirect: str = ""

    # ------------------------------------------------------------------
    # 1. Common path probing (async HEAD requests) — run FIRST
    #    These are lightweight and must execute before feroxbuster
    #    hammers the target (which could trigger WAF/rate-limiting).
    # ------------------------------------------------------------------
    if shutil.which("curl"):
        baseline_status, baseline_redirect = await _head_status(url, "/rn_404_baseline_check")

        # Run HEAD checks concurrently (bounded)
        semaphore = asyncio.Semaphore(5)

        async def _bounded_check(
            u: str, p: str, s: Severity,
        ) -> Finding | None:
            async with semaphore:
                return await _check_path(u, p, s, baseline_status, baseline_redirect)

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
    # 2. Directory fuzzing — adaptive feroxbuster or gobuster
    # ------------------------------------------------------------------
    # Determine if we should use adaptive mode
    use_adaptive = config.adaptive_fuzz and not config.fast_mode

    # Resolve small directory wordlist for Stage 1
    from recon_ninja.utils.wordlists import get_dir_small_wordlist
    seclists_base = config.module_toggles.get("_seclists_base")
    custom_dir = config.module_toggles.get("_custom_dir")

    small_wl = get_dir_small_wordlist(seclists_base, custom_dir) if seclists_base else None
    if not small_wl or not small_wl.is_file():
        # Fallback to common.txt inside standard path
        small_wl = Path("/usr/share/wordlists/dirb/common.txt")
        if not small_wl.is_file():
            small_wl = Path(wordlist)

    stage1_wl = str(small_wl) if use_adaptive else wordlist
    stage1_findings: list[Finding] = []

    if shutil.which("feroxbuster"):
        ferox_out = output_dir / "feroxbuster.txt"
        ferox_cmd = [
            "feroxbuster",
            "-u", url,
            "-w", stage1_wl,
            "-x", extensions,
            "-t", threads,
            "--scan-limit", "3",
            "--timeout", "10",
            "-q",  # quiet mode
        ]
        if use_adaptive:
            ferox_cmd.append("--no-recursion")
        else:
            ferox_cmd.extend(["--depth", depth])

        rc, stdout, stderr = await run_tool(
            cmd=ferox_cmd,
            output_file=ferox_out,
            timeout=config.default_timeout,
        )
        raw_parts.append(f"=== feroxbuster (Stage 1) ===\n{stdout[:5000]}")

        if rc in (0, 1) and stdout.strip():
            for status, found_url, size in _parse_feroxbuster(stdout):
                path = found_url.replace(url, "") or "/"
                sev = _severity_for_status(status, path)
                stage1_findings.append(
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
                "-w", stage1_wl,
                "-x", extensions,
                "-t", threads,
                "--timeout", "10s",
                "-q",
            ],
            output_file=gobuster_out,
            timeout=config.default_timeout,
        )
        raw_parts.append(f"=== gobuster dir (Stage 1) ===\n{stdout[:5000]}")

        if rc in (0, 1) and stdout.strip():
            for status, path, size in _parse_gobuster(stdout):
                sev = _severity_for_status(status, path)
                stage1_findings.append(
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

    findings.extend(stage1_findings)

    # Trigger Stage 2 if adaptive and Stage 1 found directories (excluding basic root redirects)
    has_meaningful_stage1 = any(
        f.title.startswith("Fuzz:") and not f.title.startswith("Fuzz: / ") and not f.title.startswith("Fuzz: /rn_404_")
        for f in stage1_findings
    )

    if use_adaptive and has_meaningful_stage1 and stage1_wl != wordlist:
        logger.info("[web_dirfuzz] Stage 1 found active directories. Upgrading to Stage 2 (large list: %s)", wordlist)
        if shutil.which("feroxbuster"):
            ferox_out_2 = output_dir / "feroxbuster_stage2.txt"
            rc2, stdout2, stderr2 = await run_tool(
                cmd=[
                    "feroxbuster",
                    "-u", url,
                    "-w", wordlist,
                    "-x", extensions,
                    "-t", threads,
                    "--depth", depth,
                    "--scan-limit", "3",
                    "--timeout", "10",
                    "-q",
                ],
                output_file=ferox_out_2,
                timeout=config.default_timeout,
            )
            raw_parts.append(f"=== feroxbuster (Stage 2) ===\n{stdout2[:5000]}")

            if rc2 in (0, 1) and stdout2.strip():
                for status, found_url, size in _parse_feroxbuster(stdout2):
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
            gobuster_out_2 = output_dir / "gobuster_dir_stage2.txt"
            rc2, stdout2, stderr2 = await run_tool(
                cmd=[
                    "gobuster", "dir",
                    "-u", url,
                    "-w", wordlist,
                    "-x", extensions,
                    "-t", threads,
                    "--timeout", "10s",
                    "-q",
                ],
                output_file=gobuster_out_2,
                timeout=config.default_timeout,
            )
            raw_parts.append(f"=== gobuster dir (Stage 2) ===\n{stdout2[:5000]}")

            if rc2 in (0, 1) and stdout2.strip():
                for status, path, size in _parse_gobuster(stdout2):
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
    elif use_adaptive and not has_meaningful_stage1:
        logger.info("[web_dirfuzz] Stage 1 found no active directories. Skipping Stage 2 to save time.")

    # ------------------------------------------------------------------
    # 3. Vhost scan — if hostname is known
    # ------------------------------------------------------------------
    vhost_hostname = hostname or state.primary_hostname
    # Only run vhost scanning on the primary hostname/domain, not on subdomains
    is_subdomain_scan = False
    if hostname and state.primary_hostname and hostname.lower() != state.primary_hostname.lower():
        is_subdomain_scan = True

    if vhost_hostname and not is_subdomain_scan:
        vhost_wordlist = str(config.dns_wordlist)

        # Smart adaptive vhost logic
        use_adaptive_vhost = config.adaptive_fuzz and not config.fast_mode
        # If passive OSINT found subdomains, we immediately trust the signal and use the full list.
        # Otherwise, if adaptive is active, we probe with a 5k list first.
        passive_subdomains_found = any(
            f.module == "osint" and "subdomain" in f.title.lower()
            for f in state.all_findings
        )

        stage1_vhost_wl = vhost_wordlist
        if use_adaptive_vhost and not passive_subdomains_found:
            # Resolve small subdomain list
            from recon_ninja.utils.wordlists import resolve_wordlist
            seclists_base = config.module_toggles.get("_seclists_base")
            custom_dir = config.module_toggles.get("_custom_dir")
            small_dns = resolve_wordlist("Discovery/DNS/subdomains-top1million-5000.txt", seclists_base, custom_dir) if seclists_base else None
            if small_dns and small_dns.is_file():
                stage1_vhost_wl = str(small_dns)
            else:
                fallback_dns = Path("/usr/share/wordlists/dirb/common.txt")
                if fallback_dns.is_file():
                    stage1_vhost_wl = str(fallback_dns)

        stage1_vhost_findings: list[Finding] = []

        if shutil.which("gobuster"):
            vhost_out = output_dir / "gobuster_vhost.txt"
            vhost_url = url
            cmd = [
                "gobuster", "vhost",
                "-u", vhost_url,
                "-w", stage1_vhost_wl,
                "--append-domain",
                "-t", "20",
                "-q",
            ]
            rc, stdout, stderr = await run_tool(
                cmd=cmd,
                output_file=vhost_out,
                timeout=config.default_timeout,
            )
            raw_parts.append(f"=== gobuster vhost (Stage 1) ===\n{stdout[:3000]}")

            if stdout.strip():
                for line in stdout.splitlines():
                    if "Found:" in line or "Status:" in line:
                        vhost = None
                        m = re.search(r"Found:\s*([^\s:]+)", line)
                        if m:
                            vhost = m.group(1)
                        else:
                            parts = line.split()
                            if parts:
                                vhost = parts[0].split(":")[0]
                        if vhost:
                            _register_vhost(vhost, target, state, config)

                        stage1_vhost_findings.append(
                            Finding(
                                severity=Severity.INFO,
                                title=f"Vhost found: {line.strip()}",
                                description=f"Virtual host discovered on {url}",
                                module="web_dirfuzz",
                                evidence=line.strip(),
                            )
                        )

        elif shutil.which("ffuf"):
            vhost_out = output_dir / "ffuf_vhost.json"
            rc, stdout, stderr = await run_tool(
                cmd=[
                    "ffuf",
                    "-u", url,
                    "-H", f"Host: FUZZ.{vhost_hostname}",
                    "-w", stage1_vhost_wl,
                    "-mc", "200,301,302",
                    "-ac",  # auto-calibrate to filter out baseline noise/size
                    "-o", str(vhost_out),
                    "-of", "json",
                ],
                output_file=vhost_out,
                timeout=config.default_timeout,
            )
            raw_parts.append(f"=== ffuf vhost (Stage 1) ===\n{stdout[:3000]}")

            if vhost_out.is_file():
                try:
                    ffuf_data = json.loads(vhost_out.read_text(encoding="utf-8", errors="replace"))
                    for entry in ffuf_data.get("results", []):
                        vhost_found = entry.get("host", "")
                        status_found = entry.get("status", 0)
                        size_found = entry.get("size", 0)
                        if vhost_found:
                            _register_vhost(vhost_found, target, state, config)
                            stage1_vhost_findings.append(
                                Finding(
                                    severity=Severity.INFO,
                                    title=f"Vhost found: {vhost_found} (HTTP {status_found}, {size_found}B)",
                                    description=f"Virtual host discovered on {url}: {vhost_found}",
                                    module="web_dirfuzz",
                                    evidence=f"Host: {vhost_found} Status: {status_found} Size: {size_found}",
                                )
                            )
                except Exception as exc:
                    logger.debug("Failed to parse ffuf vhost output: %s", exc)

        findings.extend(stage1_vhost_findings)

        # Trigger Stage 2 vhost brute force if Stage 1 found active virtual hosts
        if use_adaptive_vhost and stage1_vhost_findings and stage1_vhost_wl != vhost_wordlist:
            logger.info("[web_dirfuzz] Stage 1 found active virtual hosts. Upgrading to Stage 2 (large list: %s)", vhost_wordlist)
            if shutil.which("gobuster"):
                vhost_out_2 = output_dir / "gobuster_vhost_stage2.txt"
                cmd2 = [
                    "gobuster", "vhost",
                    "-u", url,
                    "-w", vhost_wordlist,
                    "--append-domain",
                    "-t", "20",
                    "-q",
                ]
                rc2, stdout2, stderr2 = await run_tool(
                    cmd=cmd2,
                    output_file=vhost_out_2,
                    timeout=config.default_timeout,
                )
                raw_parts.append(f"=== gobuster vhost (Stage 2) ===\n{stdout2[:3000]}")

                if stdout2.strip():
                    for line in stdout2.splitlines():
                        if "Found:" in line or "Status:" in line:
                            vhost = None
                            m = re.search(r"Found:\s*([^\s:]+)", line)
                            if m:
                                vhost = m.group(1)
                            else:
                                parts = line.split()
                                if parts:
                                    vhost = parts[0].split(":")[0]
                            if vhost:
                                _register_vhost(vhost, target, state, config)

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
                vhost_out_2 = output_dir / "ffuf_vhost_stage2.json"
                rc2, stdout2, stderr2 = await run_tool(
                    cmd=[
                        "ffuf",
                        "-u", url,
                        "-H", f"Host: FUZZ.{vhost_hostname}",
                        "-w", vhost_wordlist,
                        "-mc", "200,301,302",
                        "-ac",
                        "-o", str(vhost_out_2),
                        "-of", "json",
                    ],
                    output_file=vhost_out_2,
                    timeout=config.default_timeout,
                )
                raw_parts.append(f"=== ffuf vhost (Stage 2) ===\n{stdout2[:3000]}")

                if vhost_out_2.is_file():
                    try:
                        ffuf_data2 = json.loads(vhost_out_2.read_text(encoding="utf-8", errors="replace"))
                        for entry in ffuf_data2.get("results", []):
                            vhost_found = entry.get("host", "")
                            status_found = entry.get("status", 0)
                            size_found = entry.get("size", 0)
                            if vhost_found:
                                _register_vhost(vhost_found, target, state, config)
                                findings.append(
                                    Finding(
                                        severity=Severity.INFO,
                                        title=f"Vhost found: {vhost_found} (HTTP {status_found}, {size_found}B)",
                                        description=f"Virtual host discovered on {url}: {vhost_found}",
                                        module="web_dirfuzz",
                                        evidence=f"Host: {vhost_found} Status: {status_found} Size: {size_found}",
                                    )
                                )
                    except Exception as exc:
                        logger.debug("Failed to parse ffuf vhost output: %s", exc)
        elif use_adaptive_vhost and not stage1_vhost_findings and not passive_subdomains_found:
            logger.info("[web_dirfuzz] Stage 1 found no active virtual hosts. Skipping Stage 2 to save time.")
    else:
        logger.debug("No hostname known or subdomain scan — skipping vhost scan")

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
