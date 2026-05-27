"""Deep technology detection sub-module.

Detects the underlying tech stack of web applications using multiple
detection strategies:

* **HTTP header analysis** — Server, X-Powered-By, X-AspNet-Version,
  X-Generator, and other fingerprinting headers.
* **Cookie-based detection** — framework signatures in cookie names
  (PHPSESSID, csrftoken, laravel_session, etc.).
* **HTML meta/JS analysis** — generator tags, script/CSS patterns,
  framework-specific HTML comments.
* **Whatweb integration** — enhanced parsing of whatweb output.
* **Built-in vulnerability database** — known CVEs for common tech versions.

Detected technologies are stored in ``state.detected_techs`` as
:class:`~recon_ninja.core.models.TechInfo` objects and flagged with CVEs
when applicable.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import time
from pathlib import Path
from typing import Any

from recon_ninja.core.models import (
    Finding,
    ModuleResult,
    ReconConfig,
    ScanState,
    Severity,
    TechInfo,
)
from recon_ninja.core.runner import run_tool
from recon_ninja.core.utils import module_guard

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Built-in vulnerability database
# ---------------------------------------------------------------------------

#: Known vulnerable technology versions mapping.
#: Key: (tech_name_lower, version_prefix) → list of CVE strings.
KNOWN_VULN_DB: dict[tuple[str, str], list[str]] = {
    # Apache HTTP Server
    ("apache", "2.4.49"): ["CVE-2021-41773"],
    ("apache", "2.4.50"): ["CVE-2021-42013"],
    ("apache http server", "2.4.49"): ["CVE-2021-41773"],
    ("apache http server", "2.4.50"): ["CVE-2021-42013"],
    # OpenSSH
    ("openssh", "7.2"): ["CVE-2016-0777"],
    ("openssh", "7.2p2"): ["CVE-2016-0777"],
    ("openssh", "8.2"): ["CVE-2020-15778"],
    # vsftpd
    ("vsftpd", "2.3.4"): ["CVE-2011-2523"],
    # ProFTPD
    ("proftpd", "1.3.5"): ["CVE-2015-3306"],
    # PHP
    ("php", "7.2"): ["CVE-2022-31615"],
    ("php", "5."): ["CVE-EOL"],  # End of life
    ("php", "7.0"): ["CVE-EOL"],
    ("php", "7.1"): ["CVE-EOL"],
    # nginx
    ("nginx", "0."): ["CVE-EOL"],
    ("nginx", "1.0"): ["CVE-EOL"],
    ("nginx", "1.1"): ["CVE-EOL"],
    # Node.js / Express
    ("node.js", "8"): ["CVE-EOL"],
    ("node.js", "10"): ["CVE-EOL"],
    ("node.js", "12"): ["CVE-EOL"],
    # WordPress
    ("wordpress", "4."): ["CVE-2019-8943", "CVE-2019-8942"],
    ("wordpress", "5.0"): ["CVE-2019-8943"],
    # Drupal
    ("drupal", "7."): ["CVE-2019-6340"],
    ("drupal", "8.5"): ["CVE-2019-6340"],
    ("drupal", "8.6"): ["CVE-2019-6340"],
    # Tomcat
    ("apache tomcat", "8.5."): ["CVE-2020-1938"],
    ("apache tomcat", "9.0."): ["CVE-2020-1938"],
    ("tomcat", "8.5."): ["CVE-2020-1938"],
    ("tomcat", "9.0."): ["CVE-2020-1938"],
    # Spring Boot
    ("spring", "1.5"): ["CVE-EOL"],
    # IIS
    ("iis", "6.0"): ["CVE-2017-7269"],
    ("iis", "7.5"): ["CVE-2015-1635"],
    # OpenSSL
    ("openssl", "1.0.1"): ["CVE-2014-0160"],  # Heartbleed
    ("openssl", "1.0.2"): ["CVE-2016-0800"],
    # Django
    ("django", "1."): ["CVE-EOL"],
    ("django", "2.0"): ["CVE-EOL"],
    ("django", "2.1"): ["CVE-EOL"],
    # jQuery
    ("jquery", "1."): ["CVE-2020-11022"],
    ("jquery", "2."): ["CVE-2020-11022"],
    ("jquery", "3.0"): ["CVE-2020-11022"],
    # Next.js
    ("next.js", "9."): ["CVE-2021-22893"],
    # Flask
    ("flask", "0."): ["CVE-EOL"],
    # Ruby on Rails
    ("ruby on rails", "3."): ["CVE-EOL"],
    ("ruby on rails", "4."): ["CVE-EOL"],
    ("ruby on rails", "5.0"): ["CVE-EOL"],
}

# ---------------------------------------------------------------------------
# HTTP header → technology detection rules
# ---------------------------------------------------------------------------

HEADER_TECH_RULES: list[dict[str, Any]] = [
    # Server header
    {"header": "server", "pattern": r"^Apache/([\d.]+)", "name": "Apache HTTP Server", "category": "server"},
    {"header": "server", "pattern": r"^nginx/([\d.]+)", "name": "Nginx", "category": "server"},
    {"header": "server", "pattern": r"^Microsoft-IIS/([\d.]+)", "name": "IIS", "category": "server"},
    {"header": "server", "pattern": r"^LiteSpeed", "name": "LiteSpeed", "category": "server"},
    {"header": "server", "pattern": r"^Caddy", "name": "Caddy", "category": "server"},
    {"header": "server", "pattern": r"^openresty/([\d.]+)", "name": "OpenResty", "category": "server"},
    {"header": "server", "pattern": r"^Cherokee", "name": "Cherokee", "category": "server"},
    {"header": "server", "pattern": r"^lighttpd/([\d.]+)", "name": "lighttpd", "category": "server"},
    {"header": "server", "pattern": r"^Apache-Coyote", "name": "Apache Tomcat", "category": "server"},
    {"header": "server", "pattern": r"^Cowboy", "name": "Cowboy", "category": "server"},
    {"header": "server", "pattern": r"^Jetty", "name": "Jetty", "category": "server"},
    {"header": "server", "pattern": r"^WEBrick", "name": "WEBrick", "category": "server"},
    {"header": "server", "pattern": r"^Werkzeug/([\d.]+)", "name": "Werkzeug", "category": "server"},
    {"header": "server", "pattern": r"^gunicorn/([\d.]+)", "name": "Gunicorn", "category": "server"},
    {"header": "server", "pattern": r"^uvicorn", "name": "Uvicorn", "category": "server"},
    {"header": "server", "pattern": r"^Express", "name": "Express", "category": "framework"},
    {"header": "server", "pattern": r"^Next\.js", "name": "Next.js", "category": "framework"},
    # X-Powered-By header
    {"header": "x-powered-by", "pattern": r"^PHP/([\d.]+)", "name": "PHP", "category": "language"},
    {"header": "x-powered-by", "pattern": r"^ASP\.NET", "name": "ASP.NET", "category": "framework"},
    {"header": "x-powered-by", "pattern": r"^Express", "name": "Express", "category": "framework"},
    {"header": "x-powered-by", "pattern": r"^Next\.js\s*([\d.]+)?", "name": "Next.js", "category": "framework"},
    {"header": "x-powered-by", "pattern": r"^Phusion Passenger", "name": "Phusion Passenger", "category": "server"},
    {"header": "x-powered-by", "pattern": r"^RESTFramework", "name": "Django REST Framework", "category": "framework"},
    {"header": "x-powered-by", "pattern": r"^Rails\s*([\d.]+)?", "name": "Ruby on Rails", "category": "framework"},
    {"header": "x-powered-by", "pattern": r"^Plesk", "name": "Plesk", "category": "server"},
    {"header": "x-powered-by", "pattern": r"^Craft CMS", "name": "Craft CMS", "category": "cms"},
    # X-AspNet-Version header
    {"header": "x-aspnet-version", "pattern": r"^([\d.]+)", "name": "ASP.NET", "category": "framework"},
    # X-Generator header
    {"header": "x-generator", "pattern": r"Ghost\s*([\d.]+)?", "name": "Ghost", "category": "cms"},
    {"header": "x-generator", "pattern": r"Hugo\s*([\d.]+)?", "name": "Hugo", "category": "framework"},
    {"header": "x-generator", "pattern": r"Jekyll\s*([\d.]+)?", "name": "Jekyll", "category": "framework"},
    {"header": "x-generator", "pattern": r"WordPress\s*([\d.]+)?", "name": "WordPress", "category": "cms"},
    {"header": "x-generator", "pattern": r"Drupal\s*([\d.]+)?", "name": "Drupal", "category": "cms"},
    # X-Drupal-Cache header
    {"header": "x-drupal-cache", "pattern": r".*", "name": "Drupal", "category": "cms"},
]

# ---------------------------------------------------------------------------
# Cookie → technology detection rules
# ---------------------------------------------------------------------------

COOKIE_TECH_RULES: list[dict[str, Any]] = [
    {"cookie_pattern": r"PHPSESSID", "name": "PHP", "category": "language", "confidence": "certain"},
    {"cookie_pattern": r"csrftoken", "name": "Django", "category": "framework", "confidence": "probable"},
    {"cookie_pattern": r"laravel_session", "name": "Laravel", "category": "framework", "confidence": "certain"},
    {"cookie_pattern": r"XSRF-TOKEN", "name": "Laravel", "category": "framework", "confidence": "probable"},
    {"cookie_pattern": r"_session_id", "name": "Ruby on Rails", "category": "framework", "confidence": "probable"},
    {"cookie_pattern": r"JSESSIONID", "name": "Java", "category": "language", "confidence": "certain"},
    {"cookie_pattern": r"ASP\.NET_SessionId", "name": "ASP.NET", "category": "framework", "confidence": "certain"},
    {"cookie_pattern": r"connect\.sid", "name": "Express", "category": "framework", "confidence": "probable"},
    {"cookie_pattern": r"next-auth\.", "name": "Next.js", "category": "framework", "confidence": "certain"},
    {"cookie_pattern": r"__Host-next-auth", "name": "Next.js", "category": "framework", "confidence": "certain"},
    {"cookie_pattern": r"flask_session", "name": "Flask", "category": "framework", "confidence": "certain"},
    {"cookie_pattern": r"wp-settings-", "name": "WordPress", "category": "cms", "confidence": "certain"},
    {"cookie_pattern": r"SSESS[a-f0-9]+", "name": "Drupal", "category": "cms", "confidence": "certain"},
    {"cookie_pattern": r"wfvt_[a-f0-9]+", "name": "Wordfence", "category": "waf", "confidence": "probable"},
    {"cookie_pattern": r"cfduid", "name": "Cloudflare", "category": "waf", "confidence": "certain"},
    {"cookie_pattern": r"__cf_bm", "name": "Cloudflare", "category": "waf", "confidence": "certain"},
]

# ---------------------------------------------------------------------------
# HTML → technology detection rules
# ---------------------------------------------------------------------------

HTML_TECH_RULES: list[dict[str, Any]] = [
    # Meta generator tags
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress\s*([\d.]+)?',
     "name": "WordPress", "category": "cms", "confidence": "certain"},
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal\s*([\d.]+)?',
     "name": "Drupal", "category": "cms", "confidence": "certain"},
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla!?\s*([\d.]+)?',
     "name": "Joomla", "category": "cms", "confidence": "certain"},
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']Ghost\s*([\d.]+)?',
     "name": "Ghost", "category": "cms", "confidence": "certain"},
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']Hugo\s*([\d.]+)?',
     "name": "Hugo", "category": "framework", "confidence": "certain"},
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']Gatsby\s*([\d.]+)?',
     "name": "Gatsby", "category": "framework", "confidence": "certain"},
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']Next\.js\s*([\d.]+)?',
     "name": "Next.js", "category": "framework", "confidence": "certain"},
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']Nuxt\.js\s*([\d.]+)?',
     "name": "Nuxt.js", "category": "framework", "confidence": "certain"},
    {"pattern": r'<meta\s+name=["\']generator["\']\s+content=["\']Vite\s*([\d.]+)?',
     "name": "Vite", "category": "framework", "confidence": "certain"},
    # Script source patterns
    {"pattern": r'src=["\'][^"\']*jquery[/-]([\d.]+)',
     "name": "jQuery", "category": "library", "confidence": "certain"},
    {"pattern": r'src=["\'][^"\']*jquery[\w/.-]*\.js',
     "name": "jQuery", "category": "library", "confidence": "probable"},
    {"pattern": r'ver=([\d.]+)[^"\']*jquery',
     "name": "jQuery", "category": "library", "confidence": "probable"},
    {"pattern": r'jquery[/-]([\d.]+)',
     "name": "jQuery", "category": "library", "confidence": "probable"},
    {"pattern": r'src=["\'][^"\']*react(\.production)?\.min\.js',
     "name": "React", "category": "framework", "confidence": "probable"},
    {"pattern": r'src=["\'][^"\']*vue(\.min)?\.js',
     "name": "Vue.js", "category": "framework", "confidence": "probable"},
    {"pattern": r'src=["\'][^"\']*angular(\.min)?\.js',
     "name": "Angular", "category": "framework", "confidence": "probable"},
    {"pattern": r'src=["\'][^"\']*_next/',
     "name": "Next.js", "category": "framework", "confidence": "certain"},
    {"pattern": r'src=["\'][^"\']*/nuxt/',
     "name": "Nuxt.js", "category": "framework", "confidence": "certain"},
    {"pattern": r'src=["\'][^"\']*svelte',
     "name": "Svelte", "category": "framework", "confidence": "probable"},
    {"pattern": r'src=["\'][^"\']*bootstrap(\.min)?\.js',
     "name": "Bootstrap", "category": "library", "confidence": "certain"},
    {"pattern": r'src=["\'][^"\']*tailwind',
     "name": "Tailwind CSS", "category": "library", "confidence": "probable"},
    # Link href patterns (CSS)
    {"pattern": r'href=["\'][^"\']*bootstrap[/-]([\d.]+)',
     "name": "Bootstrap", "category": "library", "confidence": "certain"},
    {"pattern": r'href=["\'][^"\']*font-awesome',
     "name": "Font Awesome", "category": "library", "confidence": "certain"},
    {"pattern": r'href=["\'][^"\']*tailwind',
     "name": "Tailwind CSS", "category": "library", "confidence": "probable"},
    # HTML comment patterns
    {"pattern": r'<!--\s*This is Squarespace',
     "name": "Squarespace", "category": "cms", "confidence": "certain"},
    {"pattern": r'<!--\s*Wix',
     "name": "Wix", "category": "cms", "confidence": "certain"},
    {"pattern": r'<!--\s*Shopify',
     "name": "Shopify", "category": "cms", "confidence": "certain"},
    # Next.js specific patterns
    {"pattern": r'__NEXT_DATA__',
     "name": "Next.js", "category": "framework", "confidence": "certain"},
    {"pattern": r'id=["\']__next["\']',
     "name": "Next.js", "category": "framework", "confidence": "certain"},
    {"pattern": r'data-next-mark',
     "name": "Next.js", "category": "framework", "confidence": "probable"},
    # Laravel specific
    {"pattern": r'csrf-token["\']\s+content=["\'][^"\']*',
     "name": "Laravel", "category": "framework", "confidence": "probable"},
]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _check_known_vulns(name: str, version: str) -> list[str]:
    """Check the built-in vulnerability database for known CVEs.

    Parameters
    ----------
    name:
        Technology name (case-insensitive match).
    version:
        Version string.

    Returns
    -------
    list[str]
        List of CVE identifiers that match this tech+version.
    """
    cves: list[str] = []
    name_lower = name.lower()

    for (tech_key, ver_prefix), vuln_cves in KNOWN_VULN_DB.items():
        if tech_key == name_lower and version.startswith(ver_prefix):
            cves.extend(vuln_cves)

    return cves


def _detect_from_headers(headers: dict[str, str], port: int) -> list[TechInfo]:
    """Detect technologies from HTTP response headers.

    Parameters
    ----------
    headers:
        Lowercased header dictionary from the HTTP response.
    port:
        Port number the tech was detected on.

    Returns
    -------
    list[TechInfo]
        Detected technologies from header analysis.
    """
    techs: list[TechInfo] = []

    for rule in HEADER_TECH_RULES:
        header_val = headers.get(rule["header"], "")
        if not header_val:
            continue

        match = re.search(rule["pattern"], header_val, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex else ""
            cves = _check_known_vulns(rule["name"], version) if version else []
            techs.append(TechInfo(
                name=rule["name"],
                version=version,
                category=rule.get("category", ""),
                confidence="certain",
                source="header",
                port=port,
                cves=cves,
                is_vulnerable=bool(cves),
            ))

    return techs


def _detect_from_cookies(headers: dict[str, str], port: int) -> list[TechInfo]:
    """Detect technologies from Set-Cookie header values.

    Parameters
    ----------
    headers:
        Lowercased header dictionary from the HTTP response.
    port:
        Port number the tech was detected on.

    Returns
    -------
    list[TechInfo]
        Detected technologies from cookie analysis.
    """
    techs: list[TechInfo] = []
    cookie_header = headers.get("set-cookie", "")

    if not cookie_header:
        return techs

    for rule in COOKIE_TECH_RULES:
        pattern = rule["cookie_pattern"]
        if re.search(pattern, cookie_header, re.IGNORECASE):
            techs.append(TechInfo(
                name=rule["name"],
                version="",
                category=rule.get("category", ""),
                confidence=rule.get("confidence", "probable"),
                source="cookie",
                port=port,
            ))

    return techs


def _detect_from_html(html: str, port: int) -> list[TechInfo]:
    """Detect technologies from HTML page source.

    Parameters
    ----------
    html:
        The HTML source of the page.
    port:
        Port number the tech was detected on.

    Returns
    -------
    list[TechInfo]
        Detected technologies from HTML analysis.
    """
    techs: list[TechInfo] = []

    for rule in HTML_TECH_RULES:
        match = re.search(rule["pattern"], html, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex and match.group(1) else ""
            cves = _check_known_vulns(rule["name"], version) if version else []
            techs.append(TechInfo(
                name=rule["name"],
                version=version,
                category=rule.get("category", ""),
                confidence=rule.get("confidence", "probable"),
                source="html",
                port=port,
                cves=cves,
                is_vulnerable=bool(cves),
            ))

    return techs


def _detect_from_whatweb(raw: str, port: int) -> list[TechInfo]:
    """Parse whatweb output into structured TechInfo objects.

    Enhances the basic whatweb parsing from web_core with proper
    categorisation and vulnerability checking.

    Parameters
    ----------
    raw:
        Full stdout from ``whatweb -a 3 <URL>``.
    port:
        Port number the tech was detected on.

    Returns
    -------
    list[TechInfo]
        Detected technologies from whatweb analysis.
    """
    techs: list[TechInfo] = []

    # Category mapping for common whatweb tech names
    whatweb_categories: dict[str, tuple[str, str]] = {
        # name → (category, confidence)
        "WordPress": ("cms", "certain"),
        "Drupal": ("cms", "certain"),
        "Joomla": ("cms", "certain"),
        "Magento": ("cms", "certain"),
        "PHP": ("language", "certain"),
        "Express": ("framework", "certain"),
        "Django": ("framework", "certain"),
        "Flask": ("framework", "certain"),
        "Laravel": ("framework", "certain"),
        "Ruby": ("language", "certain"),
        "ASP.NET": ("framework", "certain"),
        "JSP": ("language", "certain"),
        "Apache": ("server", "certain"),
        "Nginx": ("server", "certain"),
        "IIS": ("server", "certain"),
        "Tomcat": ("server", "certain"),
        "jQuery": ("library", "certain"),
        "Bootstrap": ("library", "certain"),
        "React": ("framework", "probable"),
        "Angular": ("framework", "probable"),
        "Vue.js": ("framework", "probable"),
        "Next.js": ("framework", "certain"),
        "CloudFlare": ("waf", "certain"),
        "Incapsula": ("waf", "certain"),
        "ModSecurity": ("waf", "certain"),
    }

    for match in re.finditer(r"(\w[\w\s\-]*?)\[([^\]]+)\]", raw):
        name = match.group(1).strip()
        detail = match.group(2).strip()

        # Skip HTTP status code and URL
        if name.isdigit() or name.startswith("http"):
            continue

        category, confidence = whatweb_categories.get(name, ("", "probable"))

        # Try to extract version from the detail
        version = ""
        ver_match = re.search(r"[\d]+[\d.]*[a-z0-9]*", detail)
        if ver_match:
            version = ver_match.group(0)

        cves = _check_known_vulns(name, version) if version else []

        techs.append(TechInfo(
            name=name,
            version=version,
            category=category,
            confidence=confidence,
            source="whatweb",
            port=port,
            cves=cves,
            is_vulnerable=bool(cves),
        ))

    return techs


def _detect_from_nmap(services: dict[int, Any], port: int) -> list[TechInfo]:
    """Extract technology info from nmap service detection.

    Parameters
    ----------
    services:
        The services dict from ScanState.
    port:
        The specific port to check.

    Returns
    -------
    list[TechInfo]
        Detected technologies from nmap service info.
    """
    techs: list[TechInfo] = []
    svc = services.get(port)
    if not svc:
        return techs

    if svc.product:
        version = svc.version or ""
        cves = _check_known_vulns(svc.product, version) if version else []
        techs.append(TechInfo(
            name=svc.product,
            version=version,
            category="server" if "server" in svc.product.lower() or "httpd" in svc.product.lower() else "",
            confidence="certain",
            source="nmap",
            port=port,
            cves=cves,
            is_vulnerable=bool(cves),
        ))

    # Check extra_info for additional tech
    if svc.extra_info:
        # e.g., "Ubuntu Linux" or "PHP 7.4.3"
        php_match = re.search(r"PHP\s*([\d.]+)", svc.extra_info, re.IGNORECASE)
        if php_match:
            version = php_match.group(1)
            cves = _check_known_vulns("PHP", version)
            techs.append(TechInfo(
                name="PHP",
                version=version,
                category="language",
                confidence="certain",
                source="nmap",
                port=port,
                cves=cves,
                is_vulnerable=bool(cves),
            ))

    # Check NSE scripts for tech info
    for script_name, output in svc.scripts.items():
        if "http-server-header" in script_name:
            # Already handled via headers, skip
            pass
        if "http-headers" in script_name:
            # Parse Server: from NSE output
            server_match = re.search(r"Server:\s*(.+)", output, re.IGNORECASE)
            if server_match:
                server_val = server_match.group(1).strip()
                # Check if already detected
                existing_names = {t.name.lower() for t in techs}
                if not any(n in server_val.lower() for n in existing_names):
                    techs.append(TechInfo(
                        name=server_val.split("/")[0],
                        version=server_val.split("/")[-1] if "/" in server_val else "",
                        category="server",
                        confidence="certain",
                        source="nmap-script",
                        port=port,
                    ))

    return techs


# ---------------------------------------------------------------------------
# Main sub-module function
# ---------------------------------------------------------------------------


@module_guard()
async def run_web_tech(
    target: str,
    port: int,
    url: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Deep technology detection sub-module.

    Runs multiple detection strategies to identify the underlying tech
    stack of a web application, then checks detected technologies against
    a built-in vulnerability database.

    Parameters
    ----------
    target:
        Raw target IP or hostname.
    port:
        Port number of the HTTP service.
    url:
        Fully-qualified URL (e.g. ``http://10.10.10.1:3000``).
    state:
        Shared scan state (detected techs are added here).
    config:
        Scan configuration.
    output_dir:
        Per-port output directory.

    Returns
    -------
    ModuleResult
        Result with all technology detection findings.
    """
    t0 = time.monotonic()
    findings: list[Finding] = []
    raw_parts: list[str] = []
    all_techs: list[TechInfo] = []

    # ------------------------------------------------------------------
    # 1. Fetch headers via curl
    # ------------------------------------------------------------------
    headers: dict[str, str] = {}
    if shutil.which("curl"):
        curl_out = output_dir / "curl_headers_tech.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["curl", "-sI", "-L", "--max-redirs", "5", url],
            output_file=curl_out,
            timeout=config.default_timeout,
        )

        if rc == 0 and stdout.strip():
            # Parse headers
            blocks = re.split(r"\r?\n\r?\n", stdout.strip())
            last_block = blocks[-1] if blocks else ""
            for line in last_block.splitlines():
                if ":" not in line:
                    continue
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()

            raw_parts.append(f"=== Headers ===\n{last_block}")

            # Detect from headers
            header_techs = _detect_from_headers(headers, port)
            all_techs.extend(header_techs)
            logger.info("[web_tech:%d] Header analysis found %d techs", port, len(header_techs))

            # Detect from cookies
            cookie_techs = _detect_from_cookies(headers, port)
            all_techs.extend(cookie_techs)
            if cookie_techs:
                logger.info("[web_tech:%d] Cookie analysis found %d techs", port, len(cookie_techs))

    # ------------------------------------------------------------------
    # 2. Fetch HTML page source
    # ------------------------------------------------------------------
    html_source = ""
    if shutil.which("curl"):
        html_out = output_dir / "page_source.html"
        rc, stdout, stderr = await run_tool(
            cmd=["curl", "-sL", "--max-time", "15", url],
            output_file=html_out,
            timeout=20,
        )
        if rc == 0 and stdout.strip():
            html_source = stdout[:100000]  # cap at 100KB
            raw_parts.append(f"=== HTML Source (first 5KB) ===\n{html_source[:5000]}")

            # Detect from HTML
            html_techs = _detect_from_html(html_source, port)
            all_techs.extend(html_techs)
            logger.info("[web_tech:%d] HTML analysis found %d techs", port, len(html_techs))

    # ------------------------------------------------------------------
    # 3. Whatweb (enhanced parsing)
    # ------------------------------------------------------------------
    if shutil.which("whatweb"):
        whatweb_out = output_dir / "whatweb_tech.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["whatweb", "-a", "3", url],
            output_file=whatweb_out,
            timeout=config.default_timeout,
        )
        if rc == 0 and stdout.strip():
            raw_parts.append(f"=== Whatweb ===\n{stdout}")

            whatweb_techs = _detect_from_whatweb(stdout, port)
            all_techs.extend(whatweb_techs)
            logger.info("[web_tech:%d] Whatweb found %d techs", port, len(whatweb_techs))

    # ------------------------------------------------------------------
    # 4. Nmap service info (from state)
    # ------------------------------------------------------------------
    nmap_techs = _detect_from_nmap(state.services, port)
    all_techs.extend(nmap_techs)
    if nmap_techs:
        logger.info("[web_tech:%d] Nmap service info found %d techs", port, len(nmap_techs))

    # ------------------------------------------------------------------
    # 5. Deduplicate and store in state
    # ------------------------------------------------------------------
    seen_keys: set[tuple[str, str, int]] = set()
    for tech in all_techs:
        key = (tech.name.lower(), tech.version, tech.port)
        if key not in seen_keys:
            seen_keys.add(key)
            state.add_tech(tech)

    # ------------------------------------------------------------------
    # 6. Generate findings for detected techs
    # ------------------------------------------------------------------
    port_techs = state.techs_by_port(port)

    # Group techs by category for a summary finding
    if port_techs:
        categories: dict[str, list[str]] = {}
        for tech in port_techs:
            cat = tech.category or "other"
            label = f"{tech.name}" + (f" {tech.version}" if tech.version else "")
            categories.setdefault(cat, []).append(label)

        tech_summary_parts = []
        for cat, items in sorted(categories.items()):
            tech_summary_parts.append(f"  {cat.upper()}: {', '.join(items)}")

        tech_summary = "\n".join(tech_summary_parts)
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"Tech stack detected on port {port} ({len(port_techs)} technologies)",
            description=f"Detected technologies on {url}:\n{tech_summary}",
            module="web_tech",
            evidence=json.dumps([t.to_dict() for t in port_techs], indent=2)[:2000],
        ))

    # ------------------------------------------------------------------
    # 7. Generate findings for vulnerable techs
    # ------------------------------------------------------------------
    vulnerable = [t for t in port_techs if t.is_vulnerable]
    for vtech in vulnerable:
        cve_list = ", ".join(vtech.cves)
        findings.append(Finding(
            severity=Severity.HIGH if "EOL" not in cve_list else Severity.MEDIUM,
            title=f"Vulnerable tech: {vtech.name} {vtech.version} ({cve_list})",
            description=(
                f"{vtech.name} {vtech.version} on port {port} has known vulnerabilities: {cve_list}. "
                f"Detected via {vtech.source}."
            ),
            module="web_tech",
            evidence=f"{vtech.name} {vtech.version} → {cve_list}",
            cve=vtech.cves[0] if len(vtech.cves) == 1 else None,
            suggested_commands=[
                f"searchsploit {vtech.name} {vtech.version}",
                f"nuclei -u {url} -t cves/",
            ] if vtech.cves else [],
        ))

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    combined_raw = "\n\n".join(raw_parts)

    logger.info(
        "[web_tech:%d] Detection complete: %d techs, %d vulnerable",
        port, len(port_techs), len(vulnerable),
    )

    return ModuleResult(
        module_name="web_tech",
        status="done",
        findings=findings,
        raw_output=combined_raw[:8000],
        duration_seconds=time.monotonic() - t0,
    )
