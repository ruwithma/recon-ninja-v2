"""CMS-specific scanning and API discovery sub-module.

Implements Steps 5 and 6 of the web module specification:

**CMS scanning** (based on CMS detected by web_core):

* WordPress → ``wpscan`` (user + plugin enumeration)
* Drupal    → ``droopescan``
* Joomla    → ``joomscan``

**Application-server detection**:

* Tomcat     (``/manager/html``)
* Jenkins    (``/script``)
* Spring Boot (``/actuator``)

For each, specific ``suggested_commands`` are attached to the findings.

**API discovery**:

* Check ``/api/``, ``/api/v1/``, ``/swagger.json``, ``/openapi.json``,
  ``/graphql``
* For ``/graphql``: send an introspection query to confirm the endpoint
  and extract schema information.
* Check ``/.git/`` exposure (suggest ``git-dumper`` if found).
* Check ``/.env``, ``/config.php.bak``, ``/web.config`` for sensitive
  file leaks.
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

#: GraphQL introspection query payload.
GRAPHQL_INTROSPECTION_QUERY: str = json.dumps(
    {
        "query": (
            "{ __schema { queryType { name } "
            "mutationType { name } "
            "types { name kind description } } }"
        ),
    },
)

#: API endpoints to probe.
API_ENDPOINTS: list[tuple[str, Severity, str]] = [
    # (path, default_severity, description)
    ("/api/", Severity.INFO, "API root"),
    ("/api/v1/", Severity.INFO, "API v1 root"),
    ("/swagger.json", Severity.MEDIUM, "Swagger/OpenAPI specification"),
    ("/openapi.json", Severity.MEDIUM, "OpenAPI specification"),
    ("/graphql", Severity.MEDIUM, "GraphQL endpoint"),
    ("/graphiql", Severity.MEDIUM, "GraphiQL IDE"),
    ("/api-docs", Severity.INFO, "API documentation"),
    ("/redoc", Severity.INFO, "ReDoc API docs"),
]

#: Sensitive file paths to check (duplicated from dirfuzz but kept here
#: for CMS-specific context and suggested_commands).
SENSITIVE_FILES: list[tuple[str, Severity, str]] = [
    ("/.git/HEAD", Severity.HIGH, "Git repository HEAD"),
    ("/.git/config", Severity.HIGH, "Git repository config"),
    ("/.env", Severity.CRITICAL, "Environment variables file"),
    ("/config.php.bak", Severity.HIGH, "PHP configuration backup"),
    ("/web.config", Severity.MEDIUM, "IIS web configuration"),
]

#: Application-server indicator paths.
APP_SERVER_PATHS: dict[str, tuple[str, Severity, list[str]]] = {
    # path → (server_name, severity, suggested_commands)
    "/manager/html": (
        "Apache Tomcat Manager",
        Severity.HIGH,
        [
            "hydra -L users.txt -P pass.txt {url} http-get /manager/html",
            "curl -u admin:admin {url}/manager/html",
        ],
    ),
    "/script": (
        "Jenkins Script Console",
        Severity.CRITICAL,
        [
            "curl {url}/script — check for unauthenticated access",
            "groovy script execution: println 'id'.execute().text",
        ],
    ),
    "/actuator": (
        "Spring Boot Actuator",
        Severity.MEDIUM,
        [
            "curl {url}/actuator/env",
            "curl {url}/actuator/health",
            "curl {url}/actuator/mappings",
        ],
    ),
    "/actuator/env": (
        "Spring Boot Actuator — Environment",
        Severity.HIGH,
        [
            "curl {url}/actuator/env — may expose secrets",
        ],
    ),
}


# ---------------------------------------------------------------------------
# CMS detection from state
# ---------------------------------------------------------------------------


def _detect_cms(state: ScanState) -> str | None:
    """Determine the CMS from web_core findings in the scan state.

    Parameters
    ----------
    state:
        Shared scan state with accumulated findings.

    Returns
    -------
    str | None
        Lowercase CMS name (``"wordpress"``, ``"drupal"``, ``"joomla"``)
        or ``None`` if no CMS was detected.
    """
    for finding in state.all_findings:
        if finding.module != "web_core":
            continue
        title_lower = finding.title.lower()
        if "wordpress" in title_lower:
            return "wordpress"
        if "drupal" in title_lower:
            return "drupal"
        if "joomla" in title_lower:
            return "joomla"
    return None


# ---------------------------------------------------------------------------
# CMS-specific scanners
# ---------------------------------------------------------------------------


async def _scan_wordpress(
    url: str,
    output_dir: Path,
    config: ReconConfig,
) -> list[Finding]:
    """Run wpscan for WordPress user and plugin enumeration.

    Parameters
    ----------
    url:
        Target URL.
    output_dir:
        Per-port output directory.
    config:
        Scan configuration.

    Returns
    -------
    list[Finding]
        Findings from wpscan.
    """
    findings: list[Finding] = []

    if not shutil.which("wpscan"):
        logger.debug("wpscan not found — skipping WordPress scan")
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="wpscan not available",
                description="Install wpscan for WordPress enumeration",
                module="web_cms",
                suggested_commands=[
                    "sudo apt install wpscan",
                    f"wpscan --url {url} --enumerate u,p,t",
                ],
            )
        )
        return findings

    wpscan_out = output_dir / "wpscan.txt"
    rc, stdout, stderr = await run_tool(
        cmd=[
            "wpscan",
            "--url", url,
            "--enumerate", "u,p,t",
            "--output", str(wpscan_out),
            "--no-banner",
        ],
        output_file=wpscan_out,
        timeout=config.default_timeout,
    )

    if rc in (0, 1, 2, 3, 4, 5) and stdout.strip():
        # wpscan returns various RCs; any output is useful
        # Parse for users
        user_pattern = re.compile(r"\|\s+(\S+)\s+\|\s+(.*)", re.IGNORECASE)
        users_found: list[str] = []
        plugins_found: list[str] = []
        vulns_found: list[str] = []

        in_users = False
        in_plugins = False
        for line in stdout.splitlines():
            line_lower = line.lower()
            if "user(s) identified" in line_lower or "found user" in line_lower:
                in_users = True
                in_plugins = False
            elif "plugin(s) identified" in line_lower or "found plugin" in line_lower:
                in_plugins = True
                in_users = False
            else:
                if in_users:
                    match = user_pattern.search(line)
                    if match:
                        users_found.append(match.group(1))
                if in_plugins:
                    match = user_pattern.search(line)
                    if match:
                        plugins_found.append(match.group(1))

            # Check for vulnerability lines
            if "[!]" in line or "vulnerability" in line_lower:
                vulns_found.append(line.strip())

        if users_found:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f"WordPress users found: {', '.join(users_found[:10])}",
                    description=f"Usernames enumerated via wpscan on {url}",
                    module="web_cms",
                    evidence=", ".join(users_found[:20]),
                    suggested_commands=[
                        f"wpscan --url {url} --enumerate u --passwords /usr/share/wordlists/rockyou.txt",
                    ],
                )
            )

        if plugins_found:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"WordPress plugins found: {', '.join(plugins_found[:10])}",
                    description=f"Plugins enumerated via wpscan on {url}",
                    module="web_cms",
                    evidence=", ".join(plugins_found[:20]),
                )
            )

        for vuln_line in vulns_found[:5]:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title=f"WordPress vulnerability: {vuln_line[:100]}",
                    description=f"wpscan vulnerability finding on {url}",
                    module="web_cms",
                    evidence=vuln_line[:500],
                )
            )

    return findings


async def _scan_drupal(
    url: str,
    output_dir: Path,
    config: ReconConfig,
) -> list[Finding]:
    """Run droopescan for Drupal scanning.

    Parameters
    ----------
    url:
        Target URL.
    output_dir:
        Per-port output directory.
    config:
        Scan configuration.

    Returns
    -------
    list[Finding]
        Findings from droopescan.
    """
    findings: list[Finding] = []

    if not shutil.which("droopescan"):
        logger.debug("droopescan not found — skipping Drupal scan")
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="droopescan not available",
                description="Install droopescan for Drupal enumeration",
                module="web_cms",
                suggested_commands=[
                    "pip install droopescan",
                    f"droopescan scan drupal -u {url}",
                ],
            )
        )
        return findings

    drop_out = output_dir / "droopescan.txt"
    rc, stdout, stderr = await run_tool(
        cmd=["droopescan", "scan", "drupal", "-u", url],
        output_file=drop_out,
        timeout=config.default_timeout,
    )

    if rc in (0, 1) and stdout.strip():
        # Parse interesting lines
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            if "+" in line or "[+]" in line:
                severity = Severity.INFO
                if "vulnerability" in line.lower() or "error" in line.lower():
                    severity = Severity.MEDIUM
                findings.append(
                    Finding(
                        severity=severity,
                        title=f"Drupal: {line[:120]}",
                        description=f"droopescan finding on {url}",
                        module="web_cms",
                        evidence=line[:500],
                    )
                )

    return findings


async def _scan_joomla(
    url: str,
    output_dir: Path,
    config: ReconConfig,
) -> list[Finding]:
    """Run joomscan for Joomla scanning.

    Parameters
    ----------
    url:
        Target URL.
    output_dir:
        Per-port output directory.
    config:
        Scan configuration.

    Returns
    -------
    list[Finding]
        Findings from joomscan.
    """
    findings: list[Finding] = []

    if not shutil.which("joomscan"):
        logger.debug("joomscan not found — skipping Joomla scan")
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="joomscan not available",
                description="Install joomscan for Joomla enumeration",
                module="web_cms",
                suggested_commands=[
                    "sudo apt install joomscan",
                    f"joomscan -u {url}",
                ],
            )
        )
        return findings

    joom_out = output_dir / "joomscan.txt"
    rc, stdout, stderr = await run_tool(
        cmd=["joomscan", "-u", url],
        output_file=joom_out,
        timeout=config.default_timeout,
    )

    if rc in (0, 1) and stdout.strip():
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("[+]"):
                severity = Severity.INFO
                if "vulnerability" in line.lower():
                    severity = Severity.MEDIUM
                findings.append(
                    Finding(
                        severity=severity,
                        title=f"Joomla: {line.lstrip('[+] ').strip()[:120]}",
                        description=f"joomscan finding on {url}",
                        module="web_cms",
                        evidence=line[:500],
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# Application-server detection
# ---------------------------------------------------------------------------


async def _detect_app_servers(
    url: str,
    output_dir: Path,
) -> list[Finding]:
    """Probe for Tomcat, Jenkins, and Spring Boot actuator endpoints.

    Parameters
    ----------
    url:
        Target URL.
    output_dir:
        Per-port output directory.

    Returns
    -------
    list[Finding]
        Findings for each detected application server.
    """
    findings: list[Finding] = []

    async def _check_app_path(
        path: str,
        server_name: str,
        severity: Severity,
        suggested_cmds: list[str],
    ) -> Finding | None:
        """Check a single application-server path via curl."""
        full_url = f"{url}{path}"
        try:
            rc, stdout, stderr = await run_tool(
                cmd=["curl", "-sI", "-L", "--max-time", "10", full_url],
                timeout=15,
            )
            if not stdout.strip():
                return None

            # Parse status code from first line
            first_line = stdout.splitlines()[0] if stdout.splitlines() else ""
            status_match = re.search(r"(\d{3})", first_line)
            status = int(status_match.group(1)) if status_match else 0

            if status == 0 or status == 404:
                return None

            # Path responded — flag it
            resolved_cmds = [cmd.format(url=url) for cmd in suggested_cmds]
            return Finding(
                severity=severity,
                title=f"App server detected: {server_name} (HTTP {status})",
                description=f"{server_name} detected at {full_url}",
                module="web_cms",
                evidence=f"HEAD {full_url} → HTTP {status}",
                suggested_commands=resolved_cmds,
            )
        except Exception as exc:
            logger.debug("Error checking %s: %s", full_url, exc)
            return None

    # Probe all paths concurrently
    tasks = [
        asyncio.create_task(
            _check_app_path(path, info[0], info[1], info[2]),
        )
        for path, info in APP_SERVER_PATHS.items()
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Finding):
            findings.append(result)
        elif isinstance(result, Exception):
            logger.debug("App-server check raised: %s", result)

    return findings


# ---------------------------------------------------------------------------
# API discovery
# ---------------------------------------------------------------------------


async def _discover_apis(
    url: str,
    output_dir: Path,
) -> list[Finding]:
    """Probe for API endpoints and test GraphQL introspection.

    Parameters
    ----------
    url:
        Target URL.
    output_dir:
        Per-port output directory.

    Returns
    -------
    list[Finding]
        Findings for each discovered API endpoint.
    """
    findings: list[Finding] = []
    graphql_url: str | None = None

    async def _probe_endpoint(
        path: str,
        default_sev: Severity,
        description: str,
    ) -> Finding | None:
        """Send a GET/HEAD to an API endpoint and return a Finding if it exists."""
        full_url = f"{url}{path}"
        try:
            rc, stdout, stderr = await run_tool(
                cmd=["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", full_url],
                timeout=10,
            )
            status_str = stdout.strip()
            if not status_str:
                return None
            status = int(status_str)
            if status == 0 or status == 404:
                return None

            return Finding(
                severity=default_sev,
                title=f"API endpoint: {path} (HTTP {status})",
                description=f"{description} found at {full_url}",
                module="web_cms",
                evidence=f"GET {full_url} → HTTP {status}",
            )
        except Exception as exc:
            logger.debug("Error probing %s: %s", full_url, exc)
            return None

    # Probe all API endpoints concurrently
    probe_tasks = [
        asyncio.create_task(
            _probe_endpoint(path, sev, desc),
        )
        for path, sev, desc in API_ENDPOINTS
    ]
    probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

    for result in probe_results:
        if isinstance(result, Finding):
            findings.append(result)
            # Track GraphQL URL for introspection
            if "/graphql" in result.title:
                graphql_url = f"{url}/graphql"
        elif isinstance(result, Exception):
            logger.debug("API probe raised: %s", result)

    # ------------------------------------------------------------------
    # GraphQL introspection
    # ------------------------------------------------------------------
    if graphql_url:
        try:
            rc, stdout, stderr = await run_tool(
                cmd=[
                    "curl", "-s",
                    "-X", "POST",
                    "-H", "Content-Type: application/json",
                    "-d", GRAPHQL_INTROSPECTION_QUERY,
                    graphql_url,
                ],
                timeout=15,
            )

            if rc == 0 and stdout.strip():
                # Try to parse as JSON
                try:
                    data = json.loads(stdout)
                    if "data" in data and "__schema" in data.get("data", {}):
                        schema = data["data"]["__schema"]
                        types_count = len(schema.get("types", []))
                        query_type = schema.get("queryType", {})
                        mutation_type = schema.get("mutationType", {})

                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                title="GraphQL introspection enabled",
                                description=(
                                    f"GraphQL schema is publicly queryable at {graphql_url}. "
                                    f"{types_count} types, query: {query_type}, "
                                    f"mutation: {mutation_type}"
                                ),
                                module="web_cms",
                                evidence=stdout[:1000],
                                suggested_commands=[
                                    f"curl -s -X POST -H 'Content-Type: application/json' "
                                    f"-d '{{\"query\":\"{{ __schema {{ types {{ name }} }} }}\"}}' "
                                    f"{graphql_url}",
                                ],
                            )
                        )
                    else:
                        # GraphQL responded but introspection may be disabled
                        findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                title="GraphQL endpoint responds (introspection may be disabled)",
                                description=f"GraphQL at {graphql_url} responded to POST",
                                module="web_cms",
                                evidence=stdout[:500],
                            )
                        )
                except json.JSONDecodeError:
                    # Not JSON — might still be a valid endpoint
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title="GraphQL endpoint found (non-JSON response)",
                            description=f"GraphQL at {graphql_url} returned non-JSON",
                            module="web_cms",
                            evidence=stdout[:300],
                        )
                    )
        except Exception as exc:
            logger.debug("GraphQL introspection failed: %s", exc)

    return findings


# ---------------------------------------------------------------------------
# Sensitive file checks
# ---------------------------------------------------------------------------


async def _check_sensitive_files(
    url: str,
    output_dir: Path,
) -> list[Finding]:
    """Check for sensitive file exposures (`.git`, `.env`, config backups).

    Parameters
    ----------
    url:
        Target URL.
    output_dir:
        Per-port output directory.

    Returns
    -------
    list[Finding]
        Findings for each discovered sensitive file.
    """
    findings: list[Finding] = []

    async def _check_file(
        path: str,
        severity: Severity,
        description: str,
    ) -> Finding | None:
        """Check a single sensitive file path."""
        full_url = f"{url}{path}"
        try:
            rc, stdout, stderr = await run_tool(
                cmd=["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", full_url],
                timeout=10,
            )
            status_str = stdout.strip()
            if not status_str:
                return None
            status = int(status_str)
            if status == 0 or status == 404:
                return None

            # Build suggested commands based on the path
            suggested: list[str] = []
            if ".git" in path:
                suggested.append(f"git-dumper {url}/.git {output_dir / 'git_dump'}")
                suggested.append(f"curl {url}/.git/HEAD")
            if ".env" in path:
                suggested.append(f"curl {url}/.env")
            if "config" in path.lower():
                suggested.append(f"curl {full_url}")

            return Finding(
                severity=severity,
                title=f"Sensitive file exposed: {path} (HTTP {status})",
                description=f"{description} accessible at {full_url}",
                module="web_cms",
                evidence=f"GET {full_url} → HTTP {status}",
                suggested_commands=suggested,
            )
        except Exception as exc:
            logger.debug("Error checking %s: %s", full_url, exc)
            return None

    tasks = [
        asyncio.create_task(_check_file(path, sev, desc))
        for path, sev, desc in SENSITIVE_FILES
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Finding):
            findings.append(result)
        elif isinstance(result, Exception):
            logger.debug("Sensitive-file check raised: %s", result)

    return findings


# ---------------------------------------------------------------------------
# Main sub-module function
# ---------------------------------------------------------------------------


@module_guard()
async def run_web_cms(
    target: str,
    port: int,
    url: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """CMS-specific scanning and API discovery sub-module.

    Detects the CMS from prior web_core findings and runs the
    appropriate scanner.  Also probes for application-server endpoints,
    API surfaces, and sensitive file exposures.

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
        Result with all CMS/API/sensitive-file findings.
    """
    t0 = time.monotonic()
    findings: list[Finding] = []
    raw_parts: list[str] = []

    # ------------------------------------------------------------------
    # 1. CMS-specific scanning
    # ------------------------------------------------------------------
    cms = _detect_cms(state)
    logger.info("[web_cms] Detected CMS: %s (port %d)", cms or "none", port)

    if cms == "wordpress":
        wp_findings = await _scan_wordpress(url, output_dir, config)
        findings.extend(wp_findings)
        raw_parts.append(f"=== WordPress scan === {len(wp_findings)} findings")

    elif cms == "drupal":
        drupal_findings = await _scan_drupal(url, output_dir, config)
        findings.extend(drupal_findings)
        raw_parts.append(f"=== Drupal scan === {len(drupal_findings)} findings")

    elif cms == "joomla":
        joomla_findings = await _scan_joomla(url, output_dir, config)
        findings.extend(joomla_findings)
        raw_parts.append(f"=== Joomla scan === {len(joomla_findings)} findings")

    else:
        raw_parts.append("=== CMS scan === No known CMS detected")

    # ------------------------------------------------------------------
    # 2. Application-server detection
    # ------------------------------------------------------------------
    app_findings = await _detect_app_servers(url, output_dir)
    findings.extend(app_findings)
    raw_parts.append(f"=== App-server detection === {len(app_findings)} findings")

    # ------------------------------------------------------------------
    # 3. API discovery
    # ------------------------------------------------------------------
    api_findings = await _discover_apis(url, output_dir)
    findings.extend(api_findings)
    raw_parts.append(f"=== API discovery === {len(api_findings)} findings")

    # ------------------------------------------------------------------
    # 4. Sensitive file exposure
    # ------------------------------------------------------------------
    sensitive_findings = await _check_sensitive_files(url, output_dir)
    findings.extend(sensitive_findings)
    raw_parts.append(f"=== Sensitive files === {len(sensitive_findings)} findings")

    # ------------------------------------------------------------------
    # Done
    # ------------------------------------------------------------------
    combined_raw = "\n\n".join(raw_parts)

    return ModuleResult(
        module_name="web_cms",
        status="done",
        findings=findings,
        raw_output=combined_raw[:8000],
        duration_seconds=time.monotonic() - t0,
    )
