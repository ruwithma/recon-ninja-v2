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
from urllib.parse import urlsplit, urlunsplit

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
from recon_ninja.utils.hosts import add_to_hosts, get_ip_for_hostname
from recon_ninja.utils.network import is_root
from recon_ninja.utils.wordlists import get_dir_small_wordlist, resolve_wordlist

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# URL cleaning helper
# ---------------------------------------------------------------------------


def _clean_url(url: str) -> str:
    """Remove default ports (:80 for HTTP, :443 for HTTPS) from a URL.

    Many tools (feroxbuster, gobuster, curl) include ``:80`` in their output
    even though browsers and curl redirect such URLs to the bare hostname.
    This produces clean, browser-friendly URLs for findings and display.

    Parameters
    ----------
    url:
        A fully-qualified URL, e.g. ``http://silentium.htb:80/admin``.

    Returns
    -------
    str
        URL with default port removed, e.g. ``http://silentium.htb/admin``.
    """
    try:
        parts = urlsplit(url)
        if parts.scheme == "http" and parts.port == 80:
            netloc = parts.hostname or parts.netloc.split(":")[0]
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
        if parts.scheme == "https" and parts.port == 443:
            netloc = parts.hostname or parts.netloc.split(":")[0]
            return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception:
        pass
    return url


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


def _determine_extensions(state: ScanState, port: int) -> str:  # noqa: C901
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
        if (
            "next.js" in title_lower
            or "node.js" in title_lower
            or "react" in title_lower
            or "express" in title_lower
        ):
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
        if (
            "next.js" in name_lower
            or "node.js" in name_lower
            or "react" in name_lower
            or "express" in name_lower
        ):
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

    Typical line formats::

        200      GET       48l      162w     2436c http://10.10.10.1/admin
        301      GET        9l       28w      315c http://10.10.10.1/api
        403      GET        7l       10w      162c http://10.10.10.1/secret

    In quiet mode (``-q``) the output has 3 numeric columns (lines, words,
    chars/size) between the method and URL.  Each may have a trailing letter
    (``l``, ``w``, ``c``).

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

    # Pattern 1: Full feroxbuster output with lines/words/chars columns
    # Matches: STATUS  METHOD  LINES  WORDS  SIZE  URL
    pattern_full = re.compile(
        r"^(\d{3})\s+\w+\s+\d+[a-zA-Z]?\s+\d+[a-zA-Z]?\s+(\d+)[a-zA-Z]?\s+(https?://\S+)$",
        re.MULTILINE,
    )
    # Pattern 2: Shorter feroxbuster output (some versions omit columns)
    # Matches: STATUS  METHOD  SIZE  URL
    pattern_short = re.compile(
        r"^(\d{3})\s+\w+\s+(\d+)[a-zA-Z]?\s+(https?://\S+)$",
        re.MULTILINE,
    )

    seen_urls: set[str] = set()

    for match in pattern_full.finditer(raw):
        status = int(match.group(1))
        size_str = match.group(2)
        url = match.group(3)
        size_digits = re.sub(r"[^\d]", "", size_str)
        size = int(size_digits) if size_digits else 0
        if url not in seen_urls:
            seen_urls.add(url)
            results.append((status, url, size))

    # Only use short pattern for URLs not already captured by full pattern
    for match in pattern_short.finditer(raw):
        status = int(match.group(1))
        size_str = match.group(2)
        url = match.group(3)
        if url in seen_urls:
            continue
        size_digits = re.sub(r"[^\d]", "", size_str)
        size = int(size_digits) if size_digits else 0
        seen_urls.add(url)
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
        return Severity.LOW  # redirect — path exists, follow it
    if status == 403:
        return Severity.LOW  # forbidden but path EXISTS — valuable for CTF
    if status == 401:
        return Severity.MEDIUM  # auth required — very interesting for CTF
    return Severity.INFO


async def _head_status(url: str, path: str) -> tuple[int | None, str, int]:
    """Run a GET request (discarding body) and return status code, redirect URL, and size.

    Uses ``curl -s -o /dev/null`` (NOT ``-I``/HEAD) because:

    * HEAD requests return ``size_download=0`` since no body is transferred.
    * Many SPA / catch-all servers return HTTP 200 for *every* path with
      the same HTML body — the only way to detect this is by comparing
      response body sizes, which requires actually downloading the body.
    * ``-o /dev/null`` discards the body so memory usage stays low.

    Returns ``(status_code, redirect_url, size)`` where *size* is the
    number of bytes in the response body.
    """
    full_url = f"{url}{path}"
    try:
        _rc, stdout, _stderr = await run_tool(
            cmd=[
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{http_code} %{redirect_url} %{size_download}",
                "--connect-timeout", "3",
                "--max-time", "8",
                "-L",  # follow redirects to get final size
                full_url,
            ],
            timeout=12,
        )
        parts = stdout.strip().split(maxsplit=2)
        if not parts:
            return None, "", 0
        status_code = int(parts[0]) if parts[0].isdigit() else None
        redirect_url = parts[1] if len(parts) > 1 else ""
        size = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
        return status_code, redirect_url, size
    except Exception as exc:
        logger.debug("Error checking %s: %s", full_url, exc)
        return None, "", 0


# ---------------------------------------------------------------------------
# Async HEAD checker
# ---------------------------------------------------------------------------


async def _check_path(  # noqa: C901
    url: str,
    path: str,
    severity: Severity,
    baseline_status: int | None = None,
    baseline_redirect: str = "",
    baseline_size: int = 0,
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
    baseline_status:
        Status code from a known-nonexistent path (baseline).
    baseline_redirect:
        Redirect URL from the baseline response.
    baseline_size:
        Response size from the baseline response.  Responses matching
        both the baseline status AND size (within 10%%) are filtered
        as likely identical default pages.

    Returns
    -------
    Finding | None
        A finding if the path responded with a non-404 status, else None.
    """
    full_url = _clean_url(f"{url}{path}")
    try:
        status, redirect_url, size = await _head_status(url, path)
        if status is None:
            return None
        if status == 0 or status >= 500:
            return None
        if status == 404:
            return None
        # Baseline comparison: filter responses that match the catch-all /
        # wildcard default page.  Many SPAs and misconfigured servers return
        # HTTP 200 with the same HTML for *every* URL — we detect this by
        # comparing the response body size against a known-nonexistent path.
        if baseline_status is not None and status == baseline_status:
            if status in (301, 302, 307, 308):
                if redirect_url == baseline_redirect:
                    return None
            elif baseline_size > 0 and size > 0:
                # Same status + similar size = same default page
                size_diff = abs(size - baseline_size) / max(baseline_size, 1)
                if size_diff < 0.1:
                    return None
            elif baseline_size > 0 and size == 0:
                # We got a body size of 0 but the baseline had content.
                # This is suspicious — could be an empty redirect or
                # error.  Keep the finding but log it.
                logger.debug(
                    "Path %s returned 0B (baseline %dB) — keeping",
                    path, baseline_size,
                )
            # If both sizes are 0, we can't compare.  In this case,
            # the response is very likely the same default page —
            # filter it as a false positive.  Genuine sensitive files
            # (.env, .git, config.php.bak) almost always have non-zero
            # content, and feroxbuster/gobuster will find them anyway.
            elif baseline_size == 0 and size == 0:
                # Exception: keep if the path is a known sensitive path
                # that might genuinely be empty (e.g. a blank .env file
                # is still interesting because it reveals the app uses
                # environment variables).
                always_keep = {".env", ".git/", ".git/HEAD", ".htpasswd",
                               "config.php.bak", "web.config", ".htaccess"}
                if path.rstrip("/") not in always_keep and path not in always_keep:
                    logger.debug(
                        "Filtering likely false-positive %s "
                        "(0B response matches baseline)",
                        path,
                    )
                    return None

        # Path exists — adjust severity
        actual_sev = _severity_for_status(status, path)
        # Use the more severe of (default, status-based) — lower rank = more severe
        if severity.rank < actual_sev.rank:
            actual_sev = severity

        return Finding(
            severity=actual_sev,
            title=f"Path found: {path} (HTTP {status})",
            description=f"{full_url} returned HTTP {status} ({size}B)",
            module="web_dirfuzz",
            evidence=f"HEAD {full_url} → {status} ({size}B)",
        )
    except Exception as exc:
        logger.debug("Error checking %s: %s", full_url, exc)
        return None


def _register_vhost(vhost: str, target: str, state: ScanState, config: ReconConfig) -> None:
    """Register a newly discovered virtual host in state and /etc/hosts.

    Automatically adds to /etc/hosts when running as root (typical CTF
    usage) or when ``--htb`` / ``--add-hosts`` flags are set.
    Prints a clear, prominent message so CTF players see it immediately.
    """
    vhost = vhost.split(":")[0].strip()  # Strip port if present
    if not vhost or vhost.replace(".", "").isdigit():
        return
    # Additional validation: skip garbage hostnames (spaces, slashes)
    if " " in vhost or "/" in vhost:
        return

    is_new = vhost not in state.hostnames
    if is_new:
        state.add_hostname(vhost)

    auto_add = (
        config.module_toggles.get("_add_hosts", False)
        or config.module_toggles.get("_htb", False)
    )
    # Auto-add when running as root — typical CTF usage via sudo
    if not auto_add:
        auto_add = is_root()

    already_mapped = get_ip_for_hostname(vhost) == target

    if auto_add and not already_mapped:
        if add_to_hosts(target, vhost):
            logger.info(
                "[web_dirfuzz] Automatically added/updated"
                " %s -> %s in /etc/hosts",
                target, vhost,
            )
            # Prominent announcement — CTF players MUST see this!
            console = get_console()
            console.print()
            console.print(
                f"    [bold black on bright_green] VHOST ADDED TO /etc/hosts [/]"
                f" [bold cyan]{vhost}[/] -> {target}"
            )
            console.print(
                f"    [bold green]>>>[/] Browse: "
                f"[bold white on blue] http://{vhost} [/]"
            )
            console.print()
    elif not already_mapped:
        # Not auto-added — print a clear hint for the user
        console = get_console()
        console.print()
        console.print(
            f"    [bold black on yellow] VHOST FOUND — ADD TO /etc/hosts [/]"
            f" [bold cyan]{vhost}[/]"
        )
        console.print(
            f"    [bold yellow]>>>[/] Run: "
            f"[bold]echo \"{target} {vhost}\" | sudo tee -a /etc/hosts[/]"
        )
        console.print(
            f"    [bold yellow]>>>[/] Then browse: "
            f"[bold white on blue] http://{vhost} [/]"
        )
        console.print()


# ---------------------------------------------------------------------------
# Main sub-module function
# ---------------------------------------------------------------------------


@module_guard()
async def run_web_dirfuzz(  # noqa: C901
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
    baseline_size: int = 0
    if shutil.which("curl"):
        baseline_status, baseline_redirect, baseline_size = (
            await _head_status(url, "/rn_404_baseline_check")
        )

        # Run HEAD checks concurrently (bounded)
        semaphore = asyncio.Semaphore(5)

        async def _bounded_check(
            u: str, p: str, s: Severity,
        ) -> Finding | None:
            async with semaphore:
                return await _check_path(
                    u, p, s, baseline_status, baseline_redirect,
                    baseline_size,
                )

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

        # Pre-flight connectivity check with response-time measurement.
        # Skip feroxbuster if target is unreachable (e.g. filtered ports
        # on HTB) and adapt parameters for slow targets.
        _preflight_rc, _preflight_out, _ = await run_tool(
            cmd=[
                "curl", "-sI", "-o", "/dev/null",
                "-w", "%{http_code} %{time_total}",
                "--connect-timeout", "5", "--max-time", "10", url,
            ],
            timeout=15,
        )
        preflight_parts = _preflight_out.strip().split()
        target_reachable = (
            _preflight_rc == 0
            and preflight_parts
            and preflight_parts[0] not in ("", "000")
        )

        # Measure response time for adaptive tuning
        response_time = 0.0
        if len(preflight_parts) >= 2:
            try:
                response_time = float(preflight_parts[1])
            except ValueError:
                pass

        # For slow targets, reduce extensions and threads to avoid
        # spending 800+ seconds on a wordlist × extension explosion.
        ferox_extensions = extensions
        ferox_threads = threads
        if target_reachable and response_time > 3.0:
            logger.warning(
                "[web_dirfuzz] Target %s is slow (%.1fs/response)"
                " — reducing extensions and threads",
                url, response_time,
            )
            # Keep only the most essential extensions
            ferox_extensions = "php,html,txt"
            ferox_threads = "10"

        if not target_reachable:
            logger.warning(
                "[web_dirfuzz] Target %s appears unreachable"
                " — skipping feroxbuster",
                url,
            )
            raw_parts.append(
                "=== feroxbuster (Stage 1) === SKIPPED (target unreachable)"
            )
        else:
            ferox_cmd = [
                "feroxbuster",
                "-u", url,
                "-w", stage1_wl,
                "-x", ferox_extensions,
                "-t", ferox_threads,
                "--timeout", "4",
                "--connect-timeout", "3",
                # Let feroxbuster auto-filter same-sized responses.
                # Without --dont-filter, feroxbuster detects wildcard/
                # catch-all pages (common on CTF boxes) and suppresses
                # false-positive directories that just return the
                # default homepage.
                "-q",  # quiet mode
            ]
            # Filter only true junk codes — NOT 403 (interesting for CTF!)
            ferox_cmd.extend(
                ["--filter-code", "429,502,503"]
            )
            if use_adaptive:
                ferox_cmd.append("--no-recursion")
            else:
                ferox_cmd.extend(["--depth", depth])

            # Give feroxbuster 1.5× the default timeout — directory
            # fuzzing is inherently slower than single-command tools.
            ferox_timeout = int(config.default_timeout * 1.5)
            rc, stdout, stderr = await run_tool(
                cmd=ferox_cmd,
                output_file=ferox_out,
                timeout=ferox_timeout,
            )
            raw_parts.append(
                f"=== feroxbuster (Stage 1) ===\n{stdout[:5000]}"
            )

            if rc in (0, 1) and stdout.strip():
                for status, found_url, size in _parse_feroxbuster(
                    stdout,
                ):
                    # Clean URLs to remove :80/:443 default ports
                    clean_found_url = _clean_url(found_url)
                    path = clean_found_url.replace(_clean_url(url), "") or "/"

                    # Baseline filtering: skip results that match the
                    # catch-all/wildcard response (same status + similar
                    # size).  This is a safety net even when feroxbuster
                    # auto-filters — some edge cases slip through.
                    if baseline_status is not None and status == baseline_status:
                        if baseline_size > 0 and size > 0:
                            size_diff = abs(size - baseline_size) / max(baseline_size, 1)
                            if size_diff < 0.1:
                                logger.debug(
                                    "[web_dirfuzz] Filtering false-positive"
                                    " dir %s (size %d ~ baseline %d)",
                                    path, size, baseline_size,
                                )
                                continue

                    sev = _severity_for_status(status, path)
                    stage1_findings.append(
                        Finding(
                            severity=sev,
                            title=(
                                f"Fuzz: {path}"
                                f" (HTTP {status}, {size}B)"
                            ),
                            description=(
                                f"Discovered path on {_clean_url(url)}:"
                                f" {clean_found_url}"
                            ),
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
                "--timeout", "7s",
                "-q",
            ],
            output_file=gobuster_out,
            timeout=int(config.default_timeout * 1.5),
        )
        raw_parts.append(f"=== gobuster dir (Stage 1) ===\n{stdout[:5000]}")

        if rc in (0, 1) and stdout.strip():
            for status, path, size in _parse_gobuster(stdout):
                # Baseline filtering for gobuster results too
                if baseline_status is not None and status == baseline_status:
                    if baseline_size > 0 and size > 0:
                        size_diff = abs(size - baseline_size) / max(baseline_size, 1)
                        if size_diff < 0.1:
                            logger.debug(
                                "[web_dirfuzz] Filtering false-positive"
                                " dir %s (gobuster, size %d ~ baseline %d)",
                                path, size, baseline_size,
                            )
                            continue

                sev = _severity_for_status(status, path)
                stage1_findings.append(
                    Finding(
                        severity=sev,
                        title=f"Fuzz: {path} (HTTP {status}, {size}B)",
                        description=f"Discovered path on {_clean_url(url)}: {path}",
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
        f.title.startswith("Fuzz:")
        and not f.title.startswith("Fuzz: / ")
        and not f.title.startswith("Fuzz: /rn_404_")
        for f in stage1_findings
    )

    if use_adaptive and has_meaningful_stage1 and stage1_wl != wordlist:
        logger.info(
            "[web_dirfuzz] Stage 1 found active directories."
            " Upgrading to Stage 2 (large list: %s)",
            wordlist,
        )
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
                    "--timeout", "7",
                    "--connect-timeout", "5",
                    # No --dont-filter: let feroxbuster auto-filter
                    # catch-all/wildcard pages to avoid false positives
                    "--filter-code", "429,502,503",
                    "-q",
                ],
                output_file=ferox_out_2,
                timeout=int(config.default_timeout * 1.5),
            )
            raw_parts.append(f"=== feroxbuster (Stage 2) ===\n{stdout2[:5000]}")

            if rc2 in (0, 1) and stdout2.strip():
                for status, found_url, size in _parse_feroxbuster(stdout2):
                    clean_found_url = _clean_url(found_url)
                    path = clean_found_url.replace(_clean_url(url), "") or "/"

                    # Baseline filtering for Stage 2 results too
                    if baseline_status is not None and status == baseline_status:
                        if baseline_size > 0 and size > 0:
                            size_diff = abs(size - baseline_size) / max(baseline_size, 1)
                            if size_diff < 0.1:
                                logger.debug(
                                    "[web_dirfuzz] Filtering false-positive"
                                    " dir %s (Stage 2, size %d ~ baseline %d)",
                                    path, size, baseline_size,
                                )
                                continue

                    sev = _severity_for_status(status, path)
                    findings.append(
                        Finding(
                            severity=sev,
                            title=f"Fuzz: {path} (HTTP {status}, {size}B)",
                            description=f"Discovered path on {_clean_url(url)}: {clean_found_url}",
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
                    "--timeout", "7s",
                    "-q",
                ],
                output_file=gobuster_out_2,
                timeout=int(config.default_timeout * 1.5),
            )
            raw_parts.append(f"=== gobuster dir (Stage 2) ===\n{stdout2[:5000]}")

            if rc2 in (0, 1) and stdout2.strip():
                for status, path, size in _parse_gobuster(stdout2):
                    # Baseline filtering for gobuster Stage 2 results too
                    if baseline_status is not None and status == baseline_status:
                        if baseline_size > 0 and size > 0:
                            size_diff = abs(size - baseline_size) / max(baseline_size, 1)
                            if size_diff < 0.1:
                                logger.debug(
                                    "[web_dirfuzz] Filtering false-positive"
                                    " dir %s (gobuster Stage 2, size %d ~ baseline %d)",
                                    path, size, baseline_size,
                                )
                                continue

                    sev = _severity_for_status(status, path)
                    findings.append(
                        Finding(
                            severity=sev,
                            title=f"Fuzz: {path} (HTTP {status}, {size}B)",
                            description=f"Discovered path on {_clean_url(url)}: {path}",
                            module="web_dirfuzz",
                            evidence=f"HTTP {status} Size:{size}",
                        )
                    )
    elif use_adaptive and not has_meaningful_stage1:
        logger.info(
            "[web_dirfuzz] Stage 1 found no active directories."
            " Skipping Stage 2 to save time."
        )

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
            seclists_base = config.module_toggles.get("_seclists_base")
            custom_dir = config.module_toggles.get("_custom_dir")
            small_dns = (
                resolve_wordlist(
                    "Discovery/DNS/subdomains-top1million-5000.txt",
                    seclists_base, custom_dir,
                )
                if seclists_base else None
            )
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
                timeout=int(config.default_timeout * 1.5),
            )
            raw_parts.append(f"=== gobuster vhost (Stage 1) ===\n{stdout[:3000]}")

            if stdout.strip():
                for line in stdout.splitlines():
                    if "Found:" in line or "Status:" in line:
                        vhost = None
                        status_code = ""
                        size = ""
                        m = re.search(r"Found:\s*([^\s:]+)", line)
                        if m:
                            vhost = m.group(1)
                        else:
                            parts = line.split()
                            if parts:
                                vhost = parts[0].split(":")[0]
                        # Try to extract status and size
                        status_match = re.search(r"Status:\s*(\d+)", line)
                        if status_match:
                            status_code = status_match.group(1)
                        size_match = re.search(r"Size:\s*(\d+)", line)
                        if size_match:
                            size = size_match.group(1)
                        if vhost:
                            _register_vhost(vhost, target, state, config)

                        # Build the vhost URL for the finding description
                        vhost_scheme = urlsplit(url).scheme
                        vhost_url = _clean_url(f"{vhost_scheme}://{vhost}")

                        # Build a clean finding title
                        title_parts = [f"Vhost found: {vhost}"]
                        if status_code:
                            title_parts.append(f"Status: {status_code}")
                        if size:
                            title_parts.append(f"Size: {size}")
                        clean_title = " ".join(title_parts)

                        # 401 = auth required = very interesting for CTF
                        vhost_sev = Severity.INFO
                        if status_code == "401":
                            vhost_sev = Severity.MEDIUM
                        elif status_code == "200":
                            vhost_sev = Severity.LOW

                        stage1_vhost_findings.append(
                            Finding(
                                severity=vhost_sev,
                                title=clean_title,
                                description=(
                                    f"Virtual host discovered: {vhost_url}"
                                    f" (on {url})"
                                ),
                                module="web_dirfuzz",
                                evidence=line.strip(),
                                suggested_commands=[
                                    f"curl -sI {vhost_url}",
                                ],
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
                timeout=int(config.default_timeout * 1.5),
            )
            raw_parts.append(f"=== ffuf vhost (Stage 1) ===\n{stdout[:3000]}")

            if vhost_out.is_file():
                try:
                    ffuf_data = json.loads(
                        vhost_out.read_text(
                            encoding="utf-8", errors="replace"
                        )
                    )
                    for entry in ffuf_data.get("results", []):
                        vhost_found = entry.get("host", "")
                        status_found = entry.get("status", 0)
                        size_found = entry.get("size", 0)
                        if vhost_found:
                            _register_vhost(vhost_found, target, state, config)
                            # Build the vhost URL
                            ffuf_scheme = urlsplit(url).scheme
                            ffuf_vhost_url = _clean_url(f"{ffuf_scheme}://{vhost_found}")
                            stage1_vhost_findings.append(
                                Finding(
                                    severity=Severity.INFO,
                                    title=(
                                        f"Vhost found: {vhost_found}"
                                        f" (HTTP {status_found},"
                                        f" {size_found}B)"
                                    ),
                                    description=(
                                        f"Virtual host discovered:"
                                        f" {ffuf_vhost_url} (on {url})"
                                    ),
                                    module="web_dirfuzz",
                                    evidence=(
                                        f"Host: {vhost_found}"
                                        f" Status: {status_found}"
                                        f" Size: {size_found}"
                                    ),
                                    suggested_commands=[
                                        f"curl -sI {ffuf_vhost_url}",
                                    ],
                                )
                            )
                except Exception as exc:
                    logger.debug("Failed to parse ffuf vhost output: %s", exc)

        findings.extend(stage1_vhost_findings)

        # Trigger Stage 2 vhost brute force if Stage 1 found active virtual hosts
        if (
            use_adaptive_vhost
            and stage1_vhost_findings
            and stage1_vhost_wl != vhost_wordlist
        ):
            logger.info(
                "[web_dirfuzz] Stage 1 found active virtual hosts."
                " Upgrading to Stage 2 (large list: %s)",
                vhost_wordlist,
            )
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
                    timeout=int(config.default_timeout * 1.5),
                )
                raw_parts.append(f"=== gobuster vhost (Stage 2) ===\n{stdout2[:3000]}")

                if stdout2.strip():
                    for line in stdout2.splitlines():
                        if "Found:" in line or "Status:" in line:
                            vhost = None
                            status_code = ""
                            size = ""
                            m = re.search(r"Found:\s*([^\s:]+)", line)
                            if m:
                                vhost = m.group(1)
                            else:
                                parts = line.split()
                                if parts:
                                    vhost = parts[0].split(":")[0]
                            # Try to extract status and size
                            status_match = re.search(r"Status:\s*(\d+)", line)
                            if status_match:
                                status_code = status_match.group(1)
                            size_match = re.search(r"Size:\s*(\d+)", line)
                            if size_match:
                                size = size_match.group(1)
                            if vhost:
                                _register_vhost(vhost, target, state, config)

                            # Build the vhost URL for the finding description
                            s2_scheme = urlsplit(url).scheme
                            s2_vhost_url = _clean_url(f"{s2_scheme}://{vhost}")

                            title_parts = [f"Vhost found: {vhost}"]
                            if status_code:
                                title_parts.append(f"Status: {status_code}")
                            if size:
                                title_parts.append(f"Size: {size}")
                            clean_title = " ".join(title_parts)

                            vhost_sev = Severity.INFO
                            if status_code == "401":
                                vhost_sev = Severity.MEDIUM
                            elif status_code == "200":
                                vhost_sev = Severity.LOW

                            findings.append(
                                Finding(
                                    severity=vhost_sev,
                                    title=clean_title,
                                    description=(
                                        f"Virtual host discovered: {s2_vhost_url}"
                                        f" (on {url})"
                                    ),
                                    module="web_dirfuzz",
                                    evidence=line.strip(),
                                    suggested_commands=[
                                        f"curl -sI {s2_vhost_url}",
                                    ],
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
                    timeout=int(config.default_timeout * 1.5),
                )
                raw_parts.append(f"=== ffuf vhost (Stage 2) ===\n{stdout2[:3000]}")

                if vhost_out_2.is_file():
                    try:
                        ffuf_data2 = json.loads(
                            vhost_out_2.read_text(
                                encoding="utf-8", errors="replace"
                            )
                        )
                        for entry in ffuf_data2.get("results", []):
                            vhost_found = entry.get("host", "")
                            status_found = entry.get("status", 0)
                            size_found = entry.get("size", 0)
                            if vhost_found:
                                _register_vhost(vhost_found, target, state, config)
                                # Build the vhost URL
                                s2_ffuf_scheme = urlsplit(url).scheme
                                s2_ffuf_vhost_url = _clean_url(f"{s2_ffuf_scheme}://{vhost_found}")
                                findings.append(
                                    Finding(
                                        severity=Severity.INFO,
                                        title=(
                                            f"Vhost found: {vhost_found}"
                                            f" (HTTP {status_found},"
                                            f" {size_found}B)"
                                        ),
                                        description=(
                                            f"Virtual host discovered:"
                                            f" {s2_ffuf_vhost_url} (on {url})"
                                        ),
                                        module="web_dirfuzz",
                                        evidence=(
                                            f"Host: {vhost_found}"
                                            f" Status: {status_found}"
                                            f" Size: {size_found}"
                                        ),
                                        suggested_commands=[
                                            f"curl -sI {s2_ffuf_vhost_url}",
                                        ],
                                    )
                                )
                    except Exception as exc:
                        logger.debug("Failed to parse ffuf vhost output: %s", exc)
        elif (
            use_adaptive_vhost
            and not stage1_vhost_findings
            and not passive_subdomains_found
        ):
            logger.info(
                "[web_dirfuzz] Stage 1 found no active virtual hosts."
                " Skipping Stage 2 to save time."
            )
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
        raw_output=combined_raw[:10000],
        duration_seconds=time.monotonic() - t0,
    )
