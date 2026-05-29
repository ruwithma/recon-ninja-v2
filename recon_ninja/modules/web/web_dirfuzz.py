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
#: Includes both security-sensitive paths AND common CTF web pages
#: that CTF players need to see immediately.
COMMON_PATHS: list[tuple[str, Severity]] = [
    # --- Baseline (not usually a finding) ---
    ("/", Severity.INFO),

    # --- High-value security paths ---
    ("/.git/", Severity.HIGH),             # git repository exposure
    ("/.git/HEAD", Severity.HIGH),         # git HEAD file
    ("/.git/config", Severity.HIGH),       # git config
    ("/.env", Severity.CRITICAL),          # environment file leak
    ("/.env.bak", Severity.CRITICAL),      # environment backup
    ("/config.php.bak", Severity.HIGH),    # PHP config backup
    ("/.htaccess", Severity.LOW),          # Apache config
    ("/.htpasswd", Severity.HIGH),         # Apache password file
    ("/web.config", Severity.MEDIUM),      # IIS config

    # --- Admin / auth pages (CTF gold) ---
    ("/admin", Severity.LOW),
    ("/admin/", Severity.LOW),
    ("/admin/login", Severity.MEDIUM),
    ("/login", Severity.LOW),
    ("/login/", Severity.LOW),
    ("/signin", Severity.LOW),
    ("/register", Severity.LOW),
    ("/signup", Severity.LOW),
    ("/dashboard", Severity.LOW),
    ("/dashboard/", Severity.LOW),
    ("/console", Severity.MEDIUM),         # admin console

    # --- Common CTF web pages ---
    ("/contact", Severity.INFO),
    ("/contact/", Severity.INFO),
    ("/about", Severity.INFO),
    ("/about/", Severity.INFO),
    ("/profile", Severity.INFO),
    ("/profile/", Severity.INFO),
    ("/settings", Severity.INFO),
    ("/settings/", Severity.INFO),
    ("/home", Severity.INFO),
    ("/home/", Severity.INFO),
    ("/search", Severity.INFO),
    ("/upload", Severity.MEDIUM),          # upload endpoints are interesting
    ("/upload/", Severity.MEDIUM),
    ("/uploads/", Severity.MEDIUM),
    ("/download", Severity.INFO),
    ("/logout", Severity.INFO),
    ("/forgot-password", Severity.INFO),
    ("/reset-password", Severity.INFO),
    ("/change-password", Severity.INFO),

    # --- API / service endpoints ---
    ("/api/", Severity.INFO),
    ("/api/v1/", Severity.INFO),
    ("/api/v2/", Severity.INFO),
    ("/swagger.json", Severity.MEDIUM),    # OpenAPI spec
    ("/swagger-ui/", Severity.MEDIUM),     # Swagger UI
    ("/api-docs", Severity.MEDIUM),        # API docs
    ("/graphql", Severity.MEDIUM),         # GraphQL endpoint
    ("/graphiql", Severity.MEDIUM),        # GraphiQL IDE

    # --- Server info / debug paths ---
    ("/server-status", Severity.LOW),      # Apache server-status
    ("/server-info", Severity.LOW),        # Apache server-info
    ("/phpinfo.php", Severity.MEDIUM),     # PHP info page
    ("/debug", Severity.MEDIUM),           # debug endpoint
    ("/debug/", Severity.MEDIUM),
    ("/actuator", Severity.MEDIUM),        # Spring Boot actuator
    ("/actuator/", Severity.MEDIUM),
    ("/actuator/health", Severity.INFO),   # Spring Boot health
    ("/actuator/env", Severity.HIGH),      # Spring Boot env

    # --- Backup / config directories ---
    ("/backup/", Severity.MEDIUM),
    ("/backups/", Severity.MEDIUM),
    ("/config/", Severity.MEDIUM),
    ("/conf/", Severity.MEDIUM),
    ("/db/", Severity.MEDIUM),
    ("/database/", Severity.MEDIUM),

    # --- CMS-specific paths ---
    ("/wp-login.php", Severity.INFO),      # WordPress login
    ("/wp-admin/", Severity.INFO),         # WordPress admin
    ("/wp-content/", Severity.INFO),       # WordPress content
    ("/wp-json/", Severity.INFO),          # WordPress REST API

    # --- Static / misc ---
    ("/robots.txt", Severity.INFO),        # robots (already in core, but check here too)
    ("/sitemap.xml", Severity.INFO),       # sitemap
    ("/favicon.ico", Severity.INFO),       # favicon
    ("/static/", Severity.INFO),           # static files
    ("/assets/", Severity.INFO),           # assets
    ("/public/", Severity.INFO),           # public dir
    ("/media/", Severity.INFO),            # media files
    ("/images/", Severity.INFO),           # images
    ("/css/", Severity.INFO),              # stylesheets
    ("/js/", Severity.INFO),               # javascript
    ("/fonts/", Severity.INFO),            # fonts
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
    """Run a HEAD request and return status code, redirect URL, and size."""
    full_url = f"{url}{path}"
    try:
        _rc, stdout, _stderr = await run_tool(
            cmd=[
                "curl", "-sI", "-o", "/dev/null",
                "-w", "%{http_code} %{redirect_url} %{size_download}",
                "--connect-timeout", "3",
                "--max-time", "5",
                full_url,
            ],
            timeout=10,
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
    full_url = f"{url}{path}"
    try:
        status, redirect_url, size = await _head_status(url, path)
        if status is None:
            return None
        if status == 0 or status >= 500:
            return None
        if status == 404:
            return None
        # Baseline comparison: filter only if both status AND size match.
        # A 200 response with a DIFFERENT size than the baseline is
        # genuinely different content — don't filter it!
        if baseline_status is not None and status == baseline_status:
            if status in (301, 302, 307, 308):
                if redirect_url == baseline_redirect:
                    return None
            elif baseline_size > 0 and size > 0:
                # Same status + similar size = same default page
                size_diff = abs(size - baseline_size) / max(baseline_size, 1)
                if size_diff < 0.1:
                    return None
            else:
                # Same status but no size info — be conservative and
                # keep the finding (better false positive than miss)
                pass

        # Path exists — adjust severity
        actual_sev = _severity_for_status(status, path)
        if actual_sev.rank > severity.rank:
            # Use the more severe of (default, status-based)
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

    is_new = vhost not in state.hostnames
    if is_new:
        state.add_hostname(vhost)

    auto_add = (
        config.module_toggles.get("_add_hosts", False)
        or config.module_toggles.get("_htb", False)
    )
    # Auto-add when running as root — typical CTF usage via sudo
    if not auto_add:
        from recon_ninja.utils.network import is_root
        auto_add = is_root()

    from recon_ninja.utils.hosts import (
        add_to_hosts,
        get_ip_for_hostname,
    )
    already_mapped = get_ip_for_hostname(vhost) == target

    if auto_add and not already_mapped:
        if add_to_hosts(target, vhost):
            logger.info(
                "[web_dirfuzz] Automatically added/updated"
                " %s -> %s in /etc/hosts",
                target, vhost,
            )
            from recon_ninja.core.display import get_console
            get_console().print(
                f"    [bold green][+][/] Auto-added "
                f"[bold cyan]{vhost}[/] -> {target} "
                f"in /etc/hosts"
            )
    elif not already_mapped:
        # Not auto-added — print a clear hint for the user
        from recon_ninja.core.display import get_console
        get_console().print(
            f"    [bold yellow][!][/] Vhost [bold cyan]{vhost}[/]"
            f" found but not in /etc/hosts"
        )
        get_console().print(
            f"        [dim]Add it:[/]"
            f" [bold]echo \"{target} {vhost}\" | sudo tee -a /etc/hosts[/]"
        )


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
    target_reachable = True  # default optimistic; set by preflight check

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
                "--dont-filter",  # don't auto-filter same-sized responses
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

            # Cap feroxbuster at 180s for CTF use — 7+ minute hangs
            # are unacceptable.  Most CTF directories are found in the
            # first 2 minutes of scanning.
            ferox_timeout = min(int(config.default_timeout * 1.5), 180)

            # Stream feroxbuster output so paths appear in REAL-TIME
            # instead of waiting for the entire scan to finish silently.
            from recon_ninja.core.runner import run_tool_streaming
            from recon_ninja.core.display import get_console

            collected_lines: list[str] = []
            live_findings_count = 0
            _stream_pattern = re.compile(
                r"^(\d{3})\s+\w+\s+\d+[a-zA-Z]?\s+\d+[a-zA-Z]?\s+(\d+)[a-zA-Z]?\s+(https?://\S+)$"
            )
            _stream_pattern_short = re.compile(
                r"^(\d{3})\s+\w+\s+(\d+)[a-zA-Z]?\s+(https?://\S+)$"
            )
            _seen_stream_urls: set[str] = set()
            console = get_console()

            try:
                async for line in run_tool_streaming(
                    cmd=ferox_cmd,
                    output_file=ferox_out,
                    timeout=ferox_timeout,
                ):
                    collected_lines.append(line)
                    # Check if this line is a discovered path
                    match = _stream_pattern.match(line) or _stream_pattern_short.match(line)
                    if match:
                        status_code = match.group(1)
                        found_url = match.group(3) if _stream_pattern.match(line) else match.group(3)
                        if found_url not in _seen_stream_urls:
                            _seen_stream_urls.add(found_url)
                            live_findings_count += 1
                            # Print discovered path immediately!
                            path = found_url.replace(url, "") or "/"
                            if status_code.startswith("2"):
                                console.print(
                                    f"      [bold green]✓[/] [bold]{path}[/]"
                                    f" [dim](HTTP {status_code})[/]"
                                )
                            elif status_code.startswith("3"):
                                console.print(
                                    f"      [cyan]→[/] [bold]{path}[/]"
                                    f" [dim](HTTP {status_code})[/]"
                                )
                            elif status_code == "401":
                                console.print(
                                    f"      [bold yellow]🔐[/] [bold]{path}[/]"
                                    f" [dim](HTTP {status_code} — auth required!)[/]"
                                )
                            elif status_code == "403":
                                console.print(
                                    f"      [yellow]⊘[/] [bold]{path}[/]"
                                    f" [dim](HTTP {status_code} — forbidden)[/]"
                                )
                            else:
                                console.print(
                                    f"      [dim]•[/] [bold]{path}[/]"
                                    f" [dim](HTTP {status_code})[/]"
                                )
            except Exception as exc:
                logger.warning("[web_dirfuzz] feroxbuster streaming failed: %s", exc)
                # Fallback to non-streaming if streaming fails
                rc, stdout, stderr = await run_tool(
                    cmd=ferox_cmd,
                    output_file=ferox_out,
                    timeout=ferox_timeout,
                )
                collected_lines = stdout.splitlines()

            # Reconstruct stdout from collected lines for parsing below
            stdout = "\n".join(collected_lines)
            raw_parts.append(
                f"=== feroxbuster (Stage 1) ===\n{stdout[:5000]}"
            )

            if rc in (0, 1) and stdout.strip():
                for status, found_url, size in _parse_feroxbuster(
                    stdout,
                ):
                    path = found_url.replace(url, "") or "/"
                    sev = _severity_for_status(status, path)
                    stage1_findings.append(
                        Finding(
                            severity=sev,
                            title=(
                                f"Fuzz: {path}"
                                f" (HTTP {status}, {size}B)"
                            ),
                            description=(
                                f"Discovered path on {url}:"
                                f" {found_url}"
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
            timeout=min(int(config.default_timeout * 1.5), 180),
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
                    "--dont-filter",
                    "--filter-code", "429,502,503",
                    "-q",
                ],
                output_file=ferox_out_2,
                timeout=min(int(config.default_timeout * 1.5), 180),
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
                    "--timeout", "7s",
                    "-q",
                ],
                output_file=gobuster_out_2,
                timeout=min(int(config.default_timeout * 1.5), 180),
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
        logger.info(
            "[web_dirfuzz] Stage 1 found no active directories."
            " Skipping Stage 2 to save time."
        )

    # ------------------------------------------------------------------
    # 2b. Content wordlist fuzzing — catches pages the directory wordlist
    #     misses (login, contact, signup, etc.).  The directory wordlist
    #     (raft-medium-directories) only has folder names; this content
    #     wordlist (raft-medium-words) includes common page names that
    #     CTF players need to see.
    # ------------------------------------------------------------------
    content_wl = None
    seclists_base = config.module_toggles.get("_seclists_base")
    custom_dir = config.module_toggles.get("_custom_dir")
    if seclists_base:
        from recon_ninja.utils.wordlists import get_content_wordlist
        content_wl = get_content_wordlist(seclists_base, custom_dir)

    # Only run content fuzz if we found a different wordlist than the
    # directory one (avoid redundant scanning with the same wordlist).
    content_wl_str = str(content_wl) if content_wl and content_wl.is_file() else None
    if content_wl_str and content_wl_str != stage1_wl and content_wl_str != wordlist:
        # Deduplicate against already-found paths to avoid noise
        already_found_paths = {
            f.title.split(" (HTTP")[0].replace("Fuzz: ", "").replace("Path found: ", "").strip()
            for f in findings
            if f.module == "web_dirfuzz" and (f.title.startswith("Fuzz:") or f.title.startswith("Path found:"))
        }

        if shutil.which("feroxbuster") and target_reachable:
            content_out = output_dir / "feroxbuster_content.txt"
            content_cmd = [
                "feroxbuster",
                "-u", url,
                "-w", content_wl_str,
                "-x", extensions,
                "-t", threads,
                "--timeout", "4",
                "--connect-timeout", "3",
                "--dont-filter",
                "--filter-code", "429,502,503",
                "--depth", "1",  # shallow — we want pages, not deep recursion
                "-q",
            ]
            try:
                crc, cstdout, cstderr = await run_tool(
                    cmd=content_cmd,
                    output_file=content_out,
                    timeout=min(int(config.default_timeout * 1.2), 120),  # shorter timeout for content fuzz
                )
                raw_parts.append(f"=== feroxbuster (content wordlist) ===\n{cstdout[:5000]}")

                if crc in (0, 1) and cstdout.strip():
                    for status, found_url, size in _parse_feroxbuster(cstdout):
                        path = found_url.replace(url, "") or "/"
                        # Skip already-found paths
                        path_clean = path.rstrip("/")
                        if path_clean in already_found_paths or path in already_found_paths:
                            continue
                        sev = _severity_for_status(status, path)
                        findings.append(
                            Finding(
                                severity=sev,
                                title=f"Fuzz: {path} (HTTP {status}, {size}B)",
                                description=f"Discovered page on {url}: {found_url}",
                                module="web_dirfuzz",
                                evidence=f"HTTP {status} Size:{size}",
                            )
                        )
            except Exception as exc:
                logger.debug("[web_dirfuzz] Content wordlist fuzzing failed: %s", exc)

        elif shutil.which("gobuster") and target_reachable:
            content_out = output_dir / "gobuster_content.txt"
            try:
                crc, cstdout, cstderr = await run_tool(
                    cmd=[
                        "gobuster", "dir",
                        "-u", url,
                        "-w", content_wl_str,
                        "-x", extensions,
                        "-t", threads,
                        "--timeout", "7s",
                        "-q",
                    ],
                    output_file=content_out,
                    timeout=min(int(config.default_timeout * 1.2), 120),
                )
                raw_parts.append(f"=== gobuster (content wordlist) ===\n{cstdout[:5000]}")

                if crc in (0, 1) and cstdout.strip():
                    for status, path, size in _parse_gobuster(cstdout):
                        path_clean = path.rstrip("/")
                        if path_clean in already_found_paths or path in already_found_paths:
                            continue
                        sev = _severity_for_status(status, path)
                        findings.append(
                            Finding(
                                severity=sev,
                                title=f"Fuzz: {path} (HTTP {status}, {size}B)",
                                description=f"Discovered page on {url}: {path}",
                                module="web_dirfuzz",
                                evidence=f"HTTP {status} Size:{size}",
                            )
                        )
            except Exception as exc:
                logger.debug("[web_dirfuzz] Content wordlist gobuster failed: %s", exc)

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
                timeout=min(int(config.default_timeout * 1.5), 180),
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
                timeout=min(int(config.default_timeout * 1.5), 180),
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
                            stage1_vhost_findings.append(
                                Finding(
                                    severity=Severity.INFO,
                                    title=(
                                        f"Vhost found: {vhost_found}"
                                        f" (HTTP {status_found},"
                                        f" {size_found}B)"
                                    ),
                                    description=(
                                        f"Virtual host discovered on"
                                        f" {url}: {vhost_found}"
                                    ),
                                    module="web_dirfuzz",
                                    evidence=(
                                        f"Host: {vhost_found}"
                                        f" Status: {status_found}"
                                        f" Size: {size_found}"
                                    ),
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
                    timeout=min(int(config.default_timeout * 1.5), 180),
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
                    timeout=min(int(config.default_timeout * 1.5), 180),
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
                                findings.append(
                                    Finding(
                                        severity=Severity.INFO,
                                        title=(
                                            f"Vhost found: {vhost_found}"
                                            f" (HTTP {status_found},"
                                            f" {size_found}B)"
                                        ),
                                        description=(
                                            f"Virtual host discovered on"
                                            f" {url}: {vhost_found}"
                                        ),
                                        module="web_dirfuzz",
                                        evidence=(
                                            f"Host: {vhost_found}"
                                            f" Status: {status_found}"
                                            f" Size: {size_found}"
                                        ),
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
        raw_output=combined_raw[:8000],
        duration_seconds=time.monotonic() - t0,
    )
