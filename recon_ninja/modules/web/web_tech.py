"""Deep technology detection sub-module — Wappalyzer-powered.

Detects the underlying tech stack of web applications using a layered
detection strategy:

**Layer 0 — Headless browser rendering (optional)**: If Chromium or Chrome
is available, the page is rendered with ``--dump-dom`` to capture the
full JavaScript-rendered DOM.  This is critical for detecting client-side
frameworks like React, Vue, Angular, Emotion, and Material UI whose
signatures only appear after JavaScript execution.  When a rendered DOM
is available, it is fed to Wappalyzer alongside the raw HTML — matching
the behaviour of the Wappalyzer browser extension.

**Layer 1 — Wappalyzer (primary)**: Uses the ``python-Wappalyzer`` package
which bundles Wappalyzer's 6,000+ technology fingerprint database.
When a rendered DOM (from Layer 0) is available, Wappalyzer analyses
**both** the raw HTML and the rendered DOM for maximum coverage.

**Layer 2 — Custom fingerprint rules (fallback + confirmation)**: Built-in
header, cookie, HTML, CSS-class, and JS-bundle detection rules that run
regardless.  These include patterns for React, Emotion, Material UI,
Google Font API, PWA, and many more.  When both Wappalyzer and custom
rules detect the same technology, the confidence is boosted to "certain";
if only one detects, confidence is "probable".

**Layer 3 — External tools**: whatweb and nmap service detection provide
additional context and cross-referencing.

**Layer 4 — Vulnerability correlation**: All detected technologies are
checked against a built-in CVE database covering 25+ known vulnerable
versions (Heartbleed, Apache path traversal, vsftpd backdoor, etc.).

Detected technologies are stored in ``state.detected_techs`` as
:class:`~recon_ninja.core.models.TechInfo` objects.
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
from recon_ninja.modules.web.web_core import _WHATWEB_METADATA_FIELDS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Wappalyzer availability check
# ---------------------------------------------------------------------------

_HAS_WAPPALYZER = False
try:
    from Wappalyzer import Wappalyzer, WebPage
    _HAS_WAPPALYZER = True
    logger.debug("python-Wappalyzer available — will use as primary detection engine")
except ImportError:
    logger.debug("python-Wappalyzer not installed — falling back to custom detection rules")

# Wappalyzer instance cache (avoids re-downloading fingerprints every port)
_wappalyzer_instance = None


def _get_wappalyzer() -> Any:
    """Return a cached Wappalyzer instance (downloads fingerprints once)."""
    global _wappalyzer_instance
    if _wappalyzer_instance is None and _HAS_WAPPALYZER:
        try:
            _wappalyzer_instance = Wappalyzer.latest()
            logger.info("Wappalyzer fingerprint database loaded")
        except Exception as exc:
            logger.warning("Failed to initialise Wappalyzer: %s", exc)
            return None
    return _wappalyzer_instance


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
    ("php", "5."): ["EOL"],
    ("php", "7.0"): ["EOL"],
    ("php", "7.1"): ["EOL"],
    # nginx
    ("nginx", "0."): ["EOL"],
    ("nginx", "1.0"): ["EOL"],
    ("nginx", "1.1"): ["EOL"],
    # Node.js / Express
    ("node.js", "8"): ["EOL"],
    ("node.js", "10"): ["EOL"],
    ("node.js", "12"): ["EOL"],
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
    ("spring", "1.5"): ["EOL"],
    # IIS
    ("iis", "6.0"): ["CVE-2017-7269"],
    ("iis", "7.5"): ["CVE-2015-1635"],
    # OpenSSL
    ("openssl", "1.0.1"): ["CVE-2014-0160"],  # Heartbleed
    ("openssl", "1.0.2"): ["CVE-2016-0800"],
    # Django
    ("django", "1."): ["EOL"],
    ("django", "2.0"): ["EOL"],
    ("django", "2.1"): ["EOL"],
    # jQuery
    ("jquery", "1."): ["CVE-2020-11022"],
    ("jquery", "2."): ["CVE-2020-11022"],
    ("jquery", "3.0"): ["CVE-2020-11022"],
    # Next.js
    ("next.js", "9."): ["CVE-2021-22893"],
    # Flask
    ("flask", "0."): ["EOL"],
    # Ruby on Rails
    ("ruby on rails", "3."): ["EOL"],
    ("ruby on rails", "4."): ["EOL"],
    ("ruby on rails", "5.0"): ["EOL"],
}

# ---------------------------------------------------------------------------
# Wappalyzer category → our category mapping
# ---------------------------------------------------------------------------

_WAPPALYZER_CATEGORY_MAP: dict[str, str] = {
    "cms": "cms",
    "blogs": "cms",
    "ecommerce": "cms",
    "message boards": "cms",
    "web frameworks": "framework",
    "javascript frameworks": "framework",
    "javascript libraries": "library",
    "ui frameworks": "framework",
    "web servers": "server",
    "reverse proxies": "server",
    "programming languages": "language",
    "databases": "database",
    "cdn": "cdn",
    "security": "waf",
    "analytics": "analytics",
    "caching": "server",
    "operating systems": "os",
    "font scripts": "library",
    "media servers": "server",
    "search engines": "server",
    "miscellaneous": "other",
    "rich text editors": "library",
    "lms": "cms",
    "wikis": "cms",
    "build tools": "framework",
    "containerization": "server",
    "api tools": "library",
    "progressive web apps": "framework",
    "development": "framework",
    "obfuscators": "other",
    "indentifiers": "other",
    "ssl/tls certificate authorities": "other",
    "advertising": "analytics",
    "tag managers": "analytics",
    "issue trackers": "other",
    "documentation": "other",
    "dart": "language",
}


# ---------------------------------------------------------------------------
# Custom fingerprint rules (fallback + confirmation layer)
# ---------------------------------------------------------------------------

HEADER_TECH_RULES: list[dict[str, Any]] = [
    # Server header
    {"header": "server", "pattern": r"^Apache/([\d.]+)", "name": "Apache", "category": "server"},
    {"header": "server", "pattern": r"^nginx/([\d.]+)", "name": "Nginx", "category": "server"},
    {"header": "server", "pattern": r"^Microsoft-IIS/([\d.]+)", "name": "IIS", "category": "server"},
    {"header": "server", "pattern": r"^LiteSpeed", "name": "LiteSpeed", "category": "server"},
    {"header": "server", "pattern": r"^Caddy", "name": "Caddy", "category": "server"},
    {"header": "server", "pattern": r"^openresty/([\d.]+)", "name": "OpenResty", "category": "server"},
    {"header": "server", "pattern": r"^lighttpd/([\d.]+)", "name": "lighttpd", "category": "server"},
    {"header": "server", "pattern": r"^Apache-Coyote", "name": "Apache Tomcat", "category": "server"},
    {"header": "server", "pattern": r"^Cowboy", "name": "Cowboy", "category": "server"},
    {"header": "server", "pattern": r"^Jetty", "name": "Jetty", "category": "server"},
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
    {"header": "x-powered-by", "pattern": r"^Rails\s*([\d.]+)?", "name": "Ruby on Rails", "category": "framework"},
    {"header": "x-powered-by", "pattern": r"^Craft CMS", "name": "Craft CMS", "category": "cms"},
    # X-AspNet-Version header
    {"header": "x-aspnet-version", "pattern": r"^([\d.]+)", "name": "ASP.NET", "category": "framework"},
    # X-Generator header
    {"header": "x-generator", "pattern": r"Ghost\s*([\d.]+)?", "name": "Ghost", "category": "cms"},
    {"header": "x-generator", "pattern": r"Hugo\s*([\d.]+)?", "name": "Hugo", "category": "framework"},
    {"header": "x-generator", "pattern": r"WordPress\s*([\d.]+)?", "name": "WordPress", "category": "cms"},
    {"header": "x-generator", "pattern": r"Drupal\s*([\d.]+)?", "name": "Drupal", "category": "cms"},
    # X-Drupal-Cache header
    {"header": "x-drupal-cache", "pattern": r".*", "name": "Drupal", "category": "cms"},
]

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
    {"cookie_pattern": r"wp-settings-", "name": "WordPress", "category": "cms", "confidence": "certain"},
    {"cookie_pattern": r"SSESS[a-f0-9]+", "name": "Drupal", "category": "cms", "confidence": "certain"},
    {"cookie_pattern": r"cfduid", "name": "Cloudflare", "category": "waf", "confidence": "certain"},
    {"cookie_pattern": r"__cf_bm", "name": "Cloudflare", "category": "waf", "confidence": "certain"},
]

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
    # Script source patterns
    {"pattern": r'src=["\'][^"\']*jquery[/-]([\d.]+)',
     "name": "jQuery", "category": "library", "confidence": "certain"},
    {"pattern": r'src=["\'][^"\']*jquery[\w/.-]*\.js',
     "name": "jQuery", "category": "library", "confidence": "probable"},
    {"pattern": r'jquery[/-]([\d.]+)',
     "name": "jQuery", "category": "library", "confidence": "probable"},
    # React — multiple detection strategies for SPA/CSR apps
    {"pattern": r'src=["\'][^"\']*react(\.production|\.development)?\.min\.js',
     "name": "React", "category": "framework", "confidence": "probable"},
    {"pattern": r'src=["\'][^"\']*react[\w/.-]*\.js',
     "name": "React", "category": "framework", "confidence": "probable"},
    {"pattern": r'data-reactroot',
     "name": "React", "category": "framework", "confidence": "certain"},
    {"pattern": r'data-reactid',
     "name": "React", "category": "framework", "confidence": "probable"},
    {"pattern": r'_reactRootContainer',
     "name": "React", "category": "framework", "confidence": "certain"},
    {"pattern": r'__REACT_DEVTOOLS',
     "name": "React", "category": "framework", "confidence": "certain"},
    {"pattern": r'react-dom',
     "name": "React", "category": "framework", "confidence": "probable"},
    {"pattern": r'src=["\'][^"\']*react-dom',
     "name": "React", "category": "framework", "confidence": "probable"},
    # Vue.js
    {"pattern": r'src=["\'][^"\']*vue(\.min|\.runtime)?\.js',
     "name": "Vue.js", "category": "framework", "confidence": "probable"},
    {"pattern": r'data-v-[a-f0-9]{4,8}',
     "name": "Vue.js", "category": "framework", "confidence": "probable"},
    {"pattern": r'__VUE_APP_',
     "name": "Vue.js", "category": "framework", "confidence": "certain"},
    # Angular
    {"pattern": r'src=["\'][^"\']*angular(\.min)?\.js',
     "name": "Angular", "category": "framework", "confidence": "probable"},
    {"pattern": r'_ngcontent',
     "name": "Angular", "category": "framework", "confidence": "probable"},
    {"pattern": r'_nghost',
     "name": "Angular", "category": "framework", "confidence": "probable"},
    {"pattern": r'ng-version=["\']([\d.]+)',
     "name": "Angular", "category": "framework", "confidence": "certain"},
    # Next.js
    {"pattern": r'src=["\'][^"\']*_next/',
     "name": "Next.js", "category": "framework", "confidence": "certain"},
    {"pattern": r'__NEXT_DATA__',
     "name": "Next.js", "category": "framework", "confidence": "certain"},
    {"pattern": r'id=["\']__next["\']',
     "name": "Next.js", "category": "framework", "confidence": "certain"},
    # Nuxt.js
    {"pattern": r'src=["\'][^"\']*/nuxt/',
     "name": "Nuxt.js", "category": "framework", "confidence": "certain"},
    {"pattern": r'__NUXT__',
     "name": "Nuxt.js", "category": "framework", "confidence": "certain"},
    # Svelte
    {"pattern": r'class="svelte-[a-z0-9]+"',
     "name": "Svelte", "category": "framework", "confidence": "probable"},
    # Emotion (CSS-in-JS)
    {"pattern": r'css-[a-z0-9]+',
     "name": "Emotion", "category": "framework", "confidence": "probable"},
    {"pattern": r'emotion-cache',
     "name": "Emotion", "category": "framework", "confidence": "certain"},
    {"pattern": r'data-emotion',
     "name": "Emotion", "category": "framework", "confidence": "certain"},
    {"pattern": r'<style\s+data-emotion=["\']css',
     "name": "Emotion", "category": "framework", "confidence": "certain"},
    {"pattern": r'@emotion[/\s]',
     "name": "Emotion", "category": "framework", "confidence": "probable"},
    # Material UI (MUI)
    {"pattern": r'class="[^"]*Mui[A-Z]\w+',
     "name": "Material UI", "category": "framework", "confidence": "probable"},
    {"pattern": r'class="[^"]*MuiButton',
     "name": "Material UI", "category": "framework", "confidence": "certain"},
    {"pattern": r'class="[^"]*MuiPaper',
     "name": "Material UI", "category": "framework", "confidence": "certain"},
    {"pattern": r'class="[^"]*MuiTypography',
     "name": "Material UI", "category": "framework", "confidence": "certain"},
    {"pattern": r'class="[^"]*MuiBox',
     "name": "Material UI", "category": "framework", "confidence": "certain"},
    {"pattern": r'mui\.com',
     "name": "Material UI", "category": "framework", "confidence": "probable"},
    {"pattern": r'@mui[/\s]',
     "name": "Material UI", "category": "framework", "confidence": "probable"},
    # Chakra UI
    {"pattern": r'class="[^"]*chakra[^"]*"',
     "name": "Chakra UI", "category": "framework", "confidence": "probable"},
    {"pattern": r'css-0\s*\{',
     "name": "Chakra UI", "category": "framework", "confidence": "possible"},
    # Ant Design
    {"pattern": r'class="[^"]*ant-[\w-]+"',
     "name": "Ant Design", "category": "framework", "confidence": "probable"},
    {"pattern": r'antd[\w/.-]*\.js',
     "name": "Ant Design", "category": "framework", "confidence": "probable"},
    # Bootstrap
    {"pattern": r'src=["\'][^"\']*bootstrap(\.min)?\.js',
     "name": "Bootstrap", "category": "library", "confidence": "certain"},
    {"pattern": r'href=["\'][^"\']*bootstrap[/-]([\d.]+)',
     "name": "Bootstrap", "category": "library", "confidence": "certain"},
    # Tailwind CSS
    {"pattern": r'src=["\'][^"\']*tailwind',
     "name": "Tailwind CSS", "category": "library", "confidence": "probable"},
    {"pattern": r'class="[^"]*\bflex\b[^"]*\bitems-center\b',
     "name": "Tailwind CSS", "category": "library", "confidence": "possible"},
    {"pattern": r'class="[^"]*\bgrid\b[^"]*\bgap-',
     "name": "Tailwind CSS", "category": "library", "confidence": "possible"},
    # Font Awesome
    {"pattern": r'href=["\'][^"\']*font-awesome',
     "name": "Font Awesome", "category": "library", "confidence": "certain"},
    {"pattern": r'class="[^"]*fa\s+fa-',
     "name": "Font Awesome", "category": "library", "confidence": "certain"},
    {"pattern": r'class="[^"]*fas\s+fa-',
     "name": "Font Awesome", "category": "library", "confidence": "certain"},
    {"pattern": r'class="[^"]*fab\s+fa-',
     "name": "Font Awesome", "category": "library", "confidence": "certain"},
    # Google Font API
    {"pattern": r'href=["\'][^"\']*fonts\.googleapis\.com',
     "name": "Google Font API", "category": "library", "confidence": "certain"},
    {"pattern": r'href=["\'][^"\']*fonts\.gstatic\.com',
     "name": "Google Font API", "category": "library", "confidence": "certain"},
    {"pattern": r'src=["\'][^"\']*fonts\.googleapis\.com',
     "name": "Google Font API", "category": "library", "confidence": "certain"},
    {"pattern": r'link[^>]*googleapis\.com/css\?family',
     "name": "Google Font API", "category": "library", "confidence": "certain"},
    # PWA (Progressive Web App)
    {"pattern": r'rel=["\']manifest["\']',
     "name": "PWA", "category": "framework", "confidence": "probable"},
    {"pattern": r'serviceWorker\.register',
     "name": "PWA", "category": "framework", "confidence": "probable"},
    {"pattern": r'navigator\.serviceWorker',
     "name": "PWA", "category": "framework", "confidence": "probable"},
    {"pattern": r'href=["\'][^"\']*manifest\.json',
     "name": "PWA", "category": "framework", "confidence": "probable"},
    {"pattern": r'href=["\'][^"\']*manifest\.webmanifest',
     "name": "PWA", "category": "framework", "confidence": "probable"},
    # Open Graph
    {"pattern": r'<meta\s+(?:property|name)=["\']og:',
     "name": "Open Graph", "category": "other", "confidence": "certain"},
    # HTML comment patterns
    {"pattern": r'<!--\s*This is Squarespace',
     "name": "Squarespace", "category": "cms", "confidence": "certain"},
    {"pattern": r'<!--\s*Shopify',
     "name": "Shopify", "category": "cms", "confidence": "certain"},
    # Laravel specific
    {"pattern": r'csrf-token["\']\s+content=["\'][^"\']*',
     "name": "Laravel", "category": "framework", "confidence": "probable"},
    # Webpack / Vite / Parcel (build tools)
    {"pattern": r'src=["\'][^"\']*webpack[\w/.-]*\.js',
     "name": "Webpack", "category": "framework", "confidence": "probable"},
    {"pattern": r'src=["\'][^"\']*chunk\.js',
     "name": "Webpack", "category": "framework", "confidence": "possible"},
    {"pattern": r'src=["\'][^"\']*vendor[\w/.-]*\.js',
     "name": "Webpack", "category": "framework", "confidence": "possible"},
    {"pattern": r'src=["\'][^"\']*@[a-f0-9]{4,16}\.js',
     "name": "Vite", "category": "framework", "confidence": "possible"},
    {"pattern": r'type=["\']module["\']\s+src=["\'][^"\']*/@vite',
     "name": "Vite", "category": "framework", "confidence": "certain"},
    # Stimulus (Rails)
    {"pattern": r'data-controller=["\']',
     "name": "Stimulus", "category": "framework", "confidence": "probable"},
    # Alpine.js
    {"pattern": r'x-data=["\']',
     "name": "Alpine.js", "category": "framework", "confidence": "probable"},
    {"pattern": r'x-show=["\']',
     "name": "Alpine.js", "category": "framework", "confidence": "probable"},
    # HTMX
    {"pattern": r'hx-get=["\']',
     "name": "HTMX", "category": "library", "confidence": "certain"},
    {"pattern": r'hx-post=["\']',
     "name": "HTMX", "category": "library", "confidence": "certain"},
    {"pattern": r'src=["\'][^"\']*htmx',
     "name": "HTMX", "category": "library", "confidence": "certain"},
    # Cloudflare
    {"pattern": r'cdn-cgi/',
     "name": "Cloudflare", "category": "cdn", "confidence": "certain"},
    {"pattern": r'__cf_bm',
     "name": "Cloudflare", "category": "waf", "confidence": "certain"},
    # WordPress additional
    {"pattern": r'wp-content/',
     "name": "WordPress", "category": "cms", "confidence": "probable"},
    {"pattern": r'wp-includes/',
     "name": "WordPress", "category": "cms", "confidence": "probable"},
    # Drupal additional
    {"pattern": r'Drupal\.settings',
     "name": "Drupal", "category": "cms", "confidence": "probable"},
    {"pattern": r'sites/default/files',
     "name": "Drupal", "category": "cms", "confidence": "possible"},
    # GraphQL
    {"pattern": r'graphql',
     "name": "GraphQL", "category": "library", "confidence": "possible"},
    # Chart.js
    {"pattern": r'src=["\'][^"\']*chart(\.min)?\.js',
     "name": "Chart.js", "category": "library", "confidence": "probable"},
    # D3.js
    {"pattern": r'src=["\'][^"\']*d3(\.min)?\.js',
     "name": "D3.js", "category": "library", "confidence": "probable"},
    # Three.js
    {"pattern": r'src=["\'][^"\']*three(\.min)?\.js',
     "name": "Three.js", "category": "library", "confidence": "probable"},
    # Lodash
    {"pattern": r'src=["\'][^"\']*lodash(\.min)?\.js',
     "name": "Lodash", "category": "library", "confidence": "probable"},
    # Moment.js
    {"pattern": r'src=["\'][^"\']*moment(\.min)?\.js',
     "name": "Moment.js", "category": "library", "confidence": "probable"},
]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _check_known_vulns(name: str, version: str) -> list[str]:
    """Check the built-in vulnerability database for known CVEs."""
    cves: list[str] = []
    name_lower = name.lower()

    for (tech_key, ver_prefix), vuln_cves in KNOWN_VULN_DB.items():
        if tech_key == name_lower and version.startswith(ver_prefix):
            # Check if the character following the prefix is a digit.
            # If so, this is a longer version number (e.g. prefix "1.1" matching "1.18.0").
            prefix_len = len(ver_prefix)
            if len(version) > prefix_len and version[prefix_len].isdigit():
                continue
            cves.extend(vuln_cves)

    return cves


def _map_wappalyzer_category(wa_cats: list[dict[str, Any]] | list[str]) -> str:
    """Map Wappalyzer category names to our simplified category system."""
    if not wa_cats:
        return ""

    # Handle both string and dict category formats
    cat_names: list[str] = []
    for cat in wa_cats:
        if isinstance(cat, dict):
            cat_names.append(cat.get("name", ""))
        elif isinstance(cat, str):
            cat_names.append(cat)

    for cat_name in cat_names:
        cat_lower = cat_name.lower()
        for wa_key, our_cat in _WAPPALYZER_CATEGORY_MAP.items():
            if wa_key in cat_lower:
                return our_cat

    return ""


def _detect_with_wappalyzer(
    url: str,
    headers: dict[str, str],
    html_source: str,
    port: int,
) -> list[TechInfo]:
    """Run Wappalyzer detection using pre-fetched headers and HTML.

    This is the PRIMARY detection engine.  Wappalyzer's fingerprint
    database covers 6,000+ technologies — far more than our custom rules.

    Parameters
    ----------
    url:
        Target URL.
    headers:
        Lowercased header dictionary from the HTTP response.
    html_source:
        HTML page source.
    port:
        Port number the tech was detected on.

    Returns
    -------
    list[TechInfo]
        Technologies detected by Wappalyzer.
    """
    wappalyzer = _get_wappalyzer()
    if wappalyzer is None:
        return []

    techs: list[TechInfo] = []

    try:
        # Build a WebPage from already-fetched data (no extra request)
        webpage = WebPage(url, html=html_source, headers=headers)
        results = wappalyzer.analyze_with_versions_and_categories(webpage)

        for name, data in results.items():
            versions = data.get("versions", [])
            version = versions[0] if versions else ""
            wa_cats = data.get("categories", [])

            category = _map_wappalyzer_category(wa_cats)
            cves = _check_known_vulns(name, version) if version else []

            techs.append(TechInfo(
                name=name,
                version=version,
                category=category,
                confidence="certain",  # Wappalyzer is highly reliable
                source="wappalyzer",
                port=port,
                cves=cves,
                is_vulnerable=bool(cves),
            ))

        logger.info("[web_tech:%d] Wappalyzer detected %d technologies", port, len(techs))

    except Exception as exc:
        logger.warning("[web_tech:%d] Wappalyzer analysis failed: %s", port, exc)

    return techs


def _detect_from_headers(headers: dict[str, str], port: int) -> list[TechInfo]:
    """Detect technologies from HTTP response headers (custom rules)."""
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
    """Detect technologies from Set-Cookie header values."""
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
    """Detect technologies from HTML page source."""
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
    """Parse whatweb output into structured TechInfo objects."""
    # Strip ANSI escape codes
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    raw = ansi_escape.sub('', raw)

    techs: list[TechInfo] = []

    whatweb_categories: dict[str, tuple[str, str]] = {
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

            category, confidence = whatweb_categories.get(name, ("", "probable"))
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
    """Extract technology info from nmap service detection."""
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

    if svc.extra_info:
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

    for script_name, output in svc.scripts.items():
        if "http-headers" in script_name:
            server_match = re.search(r"Server:\s*(.+)", output, re.IGNORECASE)
            if server_match:
                server_val = server_match.group(1).strip()
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
# Headless browser rendering (Layer 0)
# ---------------------------------------------------------------------------

#: Candidate binaries for headless browser rendering (in preference order).
_HEADLESS_BROWSER_CANDIDATES = [
    "chromium",
    "chromium-browser",
    "google-chrome",
    "google-chrome-stable",
    "chrome",
]


def _find_headless_browser() -> str | None:
    """Return the path of an available headless browser, or None."""
    for candidate in _HEADLESS_BROWSER_CANDIDATES:
        path = shutil.which(candidate)
        if path:
            return path
    return None


async def _render_with_headless_browser(
    url: str,
    timeout: int = 20,
) -> str:
    """Render a URL with a headless Chromium/Chrome and return the full DOM.

    Uses ``chromium --headless --dump-dom`` which renders the page
    (executing JavaScript) and dumps the resulting DOM to stdout.
    This is critical for detecting client-side frameworks like React,
    Emotion, and Material UI whose signatures only appear in the
    rendered DOM after JavaScript execution.

    Parameters
    ----------
    url:
        Target URL to render.
    timeout:
        Maximum seconds to wait for the page to render.

    Returns
    -------
    str
        The rendered HTML DOM, or an empty string on failure.
    """
    browser_path = _find_headless_browser()
    if not browser_path:
        return ""

    try:
        rc, stdout, stderr = await run_tool(
            cmd=[
                browser_path,
                "--headless",
                "--disable-gpu",
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-extensions",
                "--disable-background-networking",
                "--disable-sync",
                "--no-first-run",
                "--disable-translate",
                "--mute-audio",
                f"--timeout={timeout * 1000}",
                "--dump-dom",
                url,
            ],
            timeout=timeout + 10,
        )

        if rc in (0, 1) and stdout.strip():
            # Chromium sometimes exits with code 1 even on success
            # when --dump-dom is used with certain page configurations.
            # What matters is whether we got HTML output.
            if "<" in stdout and ">" in stdout:
                logger.info(
                    "[web_tech] Headless browser rendered %d chars from %s",
                    len(stdout), url,
                )
                return stdout[:200000]

        logger.debug(
            "[web_tech] Headless browser returned rc=%d, stdout=%d chars",
            rc, len(stdout),
        )
    except Exception as exc:
        logger.debug("[web_tech] Headless browser rendering failed: %s", exc)

    return ""


# ---------------------------------------------------------------------------
# OS detection from nmap
# ---------------------------------------------------------------------------


def _detect_os_from_nmap(services: dict[int, Any]) -> list[TechInfo]:
    """Extract operating system information from nmap service detection.

    Nmap often detects the OS from service banners (e.g. 'OpenSSH 9.6p1
    Ubuntu 3ubuntu13.15' reveals Ubuntu).  This function scans all
    services for OS hints and returns them as TechInfo objects.

    Returns
    -------
    list[TechInfo]
        Detected OS technologies (typically one entry).
    """
    techs: list[TechInfo] = []
    detected_os: set[str] = set()

    for _port, svc in services.items():
        # Check product name for OS hints
        combined = f"{svc.product} {svc.version} {svc.extra_info}".lower()

        os_patterns: list[tuple[str, str]] = [
            ("ubuntu", "Ubuntu"),
            ("debian", "Debian"),
            ("centos", "CentOS"),
            ("fedora", "Fedora"),
            ("red hat", "Red Hat"),
            ("amazon linux", "Amazon Linux"),
            ("windows", "Windows"),
            ("microsoft", "Windows"),
            ("freebsd", "FreeBSD"),
        ]

        for pattern, os_name in os_patterns:
            if pattern in combined and os_name not in detected_os:
                # Try to extract version
                version = ""
                ver_match = re.search(
                    re.escape(pattern) + r"\s*([\d.]+)",
                    combined,
                    re.IGNORECASE,
                )
                if ver_match:
                    version = ver_match.group(1)
                # Also check for Ubuntu codename version from nmap OS string
                if os_name == "Ubuntu" and not version:
                    ub_match = re.search(r"ubuntu\s*([\d.]+)", combined, re.IGNORECASE)
                    if ub_match:
                        version = ub_match.group(1)

                detected_os.add(os_name)
                techs.append(TechInfo(
                    name=os_name,
                    version=version,
                    category="os",
                    confidence="probable",
                    source="nmap",
                    port=0,  # OS-level, not port-specific
                ))
                break  # One OS per service is enough

    return techs


def _cross_reference_techs(all_techs: list[TechInfo]) -> list[TechInfo]:
    """Cross-reference detections from multiple sources for confidence scoring.

    If the same technology is detected by both Wappalyzer AND custom rules,
    boost confidence to "certain" and merge the best version/category data.
    If detected by only one engine, keep the original confidence but cap
    at "probable" (unless it's from Wappalyzer which is already reliable).

    Parameters
    ----------
    all_techs:
        All detected technologies (may contain duplicates from different sources).

    Returns
    -------
    list[TechInfo]
        Deduplicated technologies with adjusted confidence levels.
    """
    # Group by (name_lower, port) to find duplicates
    groups: dict[tuple[str, int], list[TechInfo]] = {}
    for tech in all_techs:
        key = (tech.name.lower().strip(), tech.port)
        groups.setdefault(key, []).append(tech)

    merged: list[TechInfo] = []

    for key, tech_list in groups.items():
        if len(tech_list) == 1:
            # Single detection — keep as-is but set reasonable confidence
            tech = tech_list[0]
            if tech.source == "wappalyzer":
                # Wappalyzer alone is reliable enough for "certain"
                tech.confidence = "certain"
            elif tech.confidence == "certain":
                # Custom rules with "certain" confidence (header match, etc.)
                pass
            else:
                tech.confidence = "probable"
            merged.append(tech)
        else:
            # Multiple detections — merge and boost confidence
            # Prefer Wappalyzer data, supplement with custom rules
            wa_techs = [t for t in tech_list if t.source == "wappalyzer"]
            custom_techs = [t for t in tech_list if t.source != "wappalyzer"]

            # Start with best data
            best = wa_techs[0] if wa_techs else tech_list[0]

            # If Wappalyzer didn't get a version but custom rules did, use that
            if not best.version:
                for ct in custom_techs:
                    if ct.version:
                        best = ct
                        break

            # If Wappalyzer didn't get a category but custom rules did, use that
            if not best.category:
                for ct in custom_techs:
                    if ct.category:
                        best.category = ct.category
                        break

            # Merge CVEs from all sources
            all_cves: list[str] = []
            for t in tech_list:
                all_cves.extend(t.cves)
            unique_cves = list(dict.fromkeys(all_cves))  # deduplicate preserving order

            # Boost confidence when confirmed by multiple sources
            sources = {t.source for t in tech_list}
            if len(sources) >= 2:
                confidence = "certain"  # Confirmed by multiple engines
            elif "wappalyzer" in sources:
                confidence = "certain"
            else:
                confidence = "probable"

            # Build merged tech name (prefer the most specific name)
            name = best.name
            for t in tech_list:
                if len(t.name) > len(name):
                    name = t.name

            merged.append(TechInfo(
                name=name,
                version=best.version,
                category=best.category,
                confidence=confidence,
                source="+".join(sorted(sources)),  # e.g. "header+wappalyzer"
                port=best.port,
                cves=unique_cves,
                is_vulnerable=bool(unique_cves) or any(t.is_vulnerable for t in tech_list),
            ))

    return merged


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
    """Deep technology detection sub-module — Wappalyzer-powered.

    Detection layers (in priority order):

    1. **Wappalyzer** (6,000+ fingerprints) — primary engine
    2. **Custom rules** (headers, cookies, HTML) — fallback + confirmation
    3. **External tools** (whatweb, nmap) — additional context
    4. **Cross-referencing** — multiple sources = higher confidence

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
    # 1. Fetch headers via curl (reuse web_core's cached output if available)
    # ------------------------------------------------------------------
    headers: dict[str, str] = {}
    cached_headers = output_dir / "curl_headers.txt"
    header_raw = ""
    if cached_headers.is_file():
        # Reuse headers already fetched by web_core (avoids redundant HTTP round-trip)
        logger.info("[web_tech:%d] Reusing cached headers from web_core", port)
        header_raw = cached_headers.read_text(encoding="utf-8", errors="replace")
    elif shutil.which("curl"):
        curl_out = output_dir / "curl_headers_tech.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["curl", "-sI", "-L", "--max-redirs", "5", url],
            output_file=curl_out,
            timeout=config.default_timeout,
        )
        if rc == 0:
            header_raw = stdout

    if header_raw.strip():
        blocks = re.split(r"\r?\n\r?\n", header_raw.strip())
        last_block = blocks[-1] if blocks else ""
        for line in last_block.splitlines():
            if ":" not in line:
                continue
            name, _, value = line.partition(":")
            key = name.strip().lower()
            val = value.strip()
            if key in headers:
                headers[key] = f"{headers[key]}; {val}"
            else:
                headers[key] = val

        raw_parts.append(f"=== Headers ===\n{last_block}")

        # Custom header detection
        header_techs = _detect_from_headers(headers, port)
        all_techs.extend(header_techs)
        logger.info("[web_tech:%d] Header analysis found %d techs", port, len(header_techs))

        # Custom cookie detection
        cookie_techs = _detect_from_cookies(headers, port)
        all_techs.extend(cookie_techs)
        if cookie_techs:
            logger.info("[web_tech:%d] Cookie analysis found %d techs", port, len(cookie_techs))

    # ------------------------------------------------------------------
    # 2. Fetch HTML page source (not cached by web_core)
    # ------------------------------------------------------------------
    html_source = ""
    cached_html = output_dir / "page_source.html"
    if cached_html.is_file():
        logger.info("[web_tech:%d] Reusing cached HTML source", port)
        html_source = cached_html.read_text(encoding="utf-8", errors="replace")[:100000]
    elif shutil.which("curl"):
        html_out = output_dir / "page_source.html"
        rc, stdout, stderr = await run_tool(
            cmd=["curl", "-sL", "--max-time", "15", url],
            output_file=html_out,
            timeout=20,
        )
        if rc == 0 and stdout.strip():
            html_source = stdout[:100000]

    if html_source:
        raw_parts.append(f"=== HTML Source (first 5KB) ===\n{html_source[:5000]}")
        html_techs = _detect_from_html(html_source, port)
        all_techs.extend(html_techs)
        logger.info("[web_tech:%d] HTML analysis found %d techs", port, len(html_techs))

    # ------------------------------------------------------------------
    # 2b. Headless browser rendering — Layer 0 (JS-rendered DOM)
    # ------------------------------------------------------------------
    # This is the KEY improvement for detecting client-side frameworks
    # like React, Emotion, Material UI, etc.  These technologies are
    # only detectable in the rendered DOM after JavaScript execution.
    # Without this layer, the tool misses them (as seen when comparing
    # with the Wappalyzer browser extension).
    rendered_dom = ""
    headless_browser = _find_headless_browser()
    if headless_browser:
        logger.info("[web_tech:%d] Rendering page with headless browser: %s", port, headless_browser)
        rendered_dom = await _render_with_headless_browser(url, timeout=20)
        if rendered_dom:
            raw_parts.append(f"=== Rendered DOM (first 5KB) ===\n{rendered_dom[:5000]}")
            # Run HTML detection on the rendered DOM too — this catches
            # React data-reactroot, Emotion css- classes, MUI Mui* classes,
            # Google Font links, PWA manifests, etc. that only appear
            # after JavaScript renders the page.
            rendered_techs = _detect_from_html(rendered_dom, port)
            all_techs.extend(rendered_techs)
            logger.info("[web_tech:%d] Rendered DOM analysis found %d techs", port, len(rendered_techs))
        else:
            logger.debug("[web_tech:%d] Headless browser returned empty DOM", port)
    else:
        logger.debug("[web_tech:%d] No headless browser available — skipping JS rendering", port)

    # ------------------------------------------------------------------
    # 3. WAPPALYZER — Primary detection engine (6,000+ fingerprints)
    # ------------------------------------------------------------------
    # When we have a rendered DOM, we feed it to Wappalyzer IN ADDITION
    # to the raw HTML.  This matches the behaviour of the Wappalyzer
    # browser extension which analyses the rendered DOM.
    if _HAS_WAPPALYZER:
        # Primary analysis with raw HTML + headers
        wa_techs = _detect_with_wappalyzer(url, headers, html_source, port)
        all_techs.extend(wa_techs)
        if wa_techs:
            logger.info("[web_tech:%d] Wappalyzer (raw) found %d techs", port, len(wa_techs))
            raw_parts.append(f"=== Wappalyzer (raw) ===\n{json.dumps({t.name: t.version for t in wa_techs}, indent=2)}")

        # Secondary analysis with rendered DOM — catches client-side tech
        if rendered_dom:
            wa_rendered_techs = _detect_with_wappalyzer(url, headers, rendered_dom, port)
            # Only add techs that weren't already detected in raw analysis
            existing_names = {t.name.lower() for t in wa_techs}
            new_wa_techs = [
                t for t in wa_rendered_techs
                if t.name.lower() not in existing_names
            ]
            if new_wa_techs:
                all_techs.extend(new_wa_techs)
                logger.info(
                    "[web_tech:%d] Wappalyzer (rendered) found %d NEW techs",
                    port, len(new_wa_techs),
                )
                raw_parts.append(
                    f"=== Wappalyzer (rendered) ===\n"
                    f"{json.dumps({t.name: t.version for t in new_wa_techs}, indent=2)}"
                )
    else:
        logger.info("[web_tech:%d] Wappalyzer not available — using custom rules only", port)
        raw_parts.append("=== Wappalyzer === SKIPPED (install: pip install python-Wappalyzer)")

    # ------------------------------------------------------------------
    # 4. Whatweb (reuse web_core's cached output if available)
    # ------------------------------------------------------------------
    cached_whatweb = output_dir / "whatweb.txt"
    if cached_whatweb.is_file():
        logger.info("[web_tech:%d] Reusing cached whatweb output from web_core", port)
        whatweb_raw = cached_whatweb.read_text(encoding="utf-8", errors="replace")
        if whatweb_raw.strip():
            raw_parts.append(f"=== Whatweb (cached) ===\n{whatweb_raw}")
            whatweb_techs = _detect_from_whatweb(whatweb_raw, port)
            all_techs.extend(whatweb_techs)
            logger.info("[web_tech:%d] Whatweb found %d techs", port, len(whatweb_techs))
    elif shutil.which("whatweb"):
        whatweb_out = output_dir / "whatweb_tech.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["whatweb", "-a", "3", "--color=never", url],
            output_file=whatweb_out,
            timeout=config.default_timeout,
        )
        if rc == 0 and stdout.strip():
            raw_parts.append(f"=== Whatweb ===\n{stdout}")
            whatweb_techs = _detect_from_whatweb(stdout, port)
            all_techs.extend(whatweb_techs)
            logger.info("[web_tech:%d] Whatweb found %d techs", port, len(whatweb_techs))

    # ------------------------------------------------------------------
    # 5. Nmap service info (from state)
    # ------------------------------------------------------------------
    nmap_techs = _detect_from_nmap(state.services, port)
    all_techs.extend(nmap_techs)
    if nmap_techs:
        logger.info("[web_tech:%d] Nmap service info found %d techs", port, len(nmap_techs))

    # ------------------------------------------------------------------
    # 5b. OS detection from nmap banners
    # ------------------------------------------------------------------
    # Nmap often detects the OS from service banners (e.g. 'Ubuntu' in
    # 'OpenSSH 9.6p1 Ubuntu 3ubuntu13.15').  This surfaces the OS in
    # the tech stack display, matching what Wappalyzer shows.
    os_techs = _detect_os_from_nmap(state.services)
    for os_tech in os_techs:
        # Only add if not already detected (avoid duplicate Ubuntu entries)
        existing_os = {t.name.lower() for t in all_techs if t.category == "os"}
        if os_tech.name.lower() not in existing_os:
            all_techs.append(os_tech)
            # Also add to state with port 0 (OS-level)
            state.add_tech(os_tech)

    # ------------------------------------------------------------------
    # 6. Cross-reference and deduplicate
    # ------------------------------------------------------------------
    merged_techs = _cross_reference_techs(all_techs)

    for tech in merged_techs:
        state.add_tech(tech)

    # ------------------------------------------------------------------
    # 7. Generate findings
    # ------------------------------------------------------------------
    port_techs = state.techs_by_port(port)

    if port_techs:
        # Group techs by category for summary
        categories: dict[str, list[str]] = {}
        for tech in port_techs:
            cat = tech.category or "other"
            label = f"{tech.name}" + (f" {tech.version}" if tech.version else "")
            conf_icon = "+" if tech.confidence == "certain" else "~"
            categories.setdefault(cat, []).append(f"{label} [{conf_icon}]")

        tech_summary_parts = []
        for cat, items in sorted(categories.items()):
            tech_summary_parts.append(f"  {cat.upper()}: {', '.join(items)}")

        tech_summary = "\n".join(tech_summary_parts)

        engine_label = "Wappalyzer + custom" if _HAS_WAPPALYZER else "custom rules"
        findings.append(Finding(
            severity=Severity.INFO,
            title=f"Tech stack detected on port {port} ({len(port_techs)} technologies)",
            description=f"Detected technologies on {url} [{engine_label}]:\n{tech_summary}",
            module="web_tech",
            evidence=json.dumps([t.to_dict() for t in port_techs], indent=2)[:2000],
        ))

    # Vulnerable techs findings
    vulnerable = [t for t in port_techs if t.is_vulnerable]
    for vtech in vulnerable:
        cve_list = ", ".join(vtech.cves)
        is_eol = "EOL" in vtech.cves or "CVE-EOL" in vtech.cves

        if is_eol:
            title = f"End-of-Life software detected: {vtech.name} {vtech.version}"
            description = (
                f"{vtech.name} {vtech.version} on port {port} is End-of-Life (EOL) and no longer supported. "
                f"Detected via {vtech.source}."
            )
            severity = Severity.MEDIUM
        else:
            title = f"Vulnerable tech: {vtech.name} {vtech.version} ({cve_list})"
            description = (
                f"{vtech.name} {vtech.version} on port {port} has known vulnerabilities: {cve_list}. "
                f"Detected via {vtech.source}."
            )
            severity = Severity.HIGH

        findings.append(Finding(
            severity=severity,
            title=title,
            description=description,
            module="web_tech",
            evidence=f"{vtech.name} {vtech.version} → {cve_list}",
            cve=vtech.cves[0] if (len(vtech.cves) == 1 and not is_eol) else None,
            suggested_commands=[
                f"searchsploit {vtech.name} {vtech.version}",
                f"nuclei -u {url} -t cves/",
            ] if not is_eol else [],
        ))

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    combined_raw = "\n\n".join(raw_parts)

    logger.info(
        "[web_tech:%d] Detection complete: %d techs, %d vulnerable (engine: %s)",
        port, len(port_techs), len(vulnerable),
        "wappalyzer+custom" if _HAS_WAPPALYZER else "custom-only",
    )

    return ModuleResult(
        module_name="web_tech",
        status="done",
        findings=findings,
        raw_output=combined_raw[:10000],
        duration_seconds=time.monotonic() - t0,
    )
