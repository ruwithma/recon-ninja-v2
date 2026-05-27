"""OSINT (Open-Source Intelligence) module for ReconNinja v2.

Gathers passive intelligence about a domain target using multiple
open-source sources. Discovers subdomains, WHOIS registration data,
certificate transparency logs, and Shodan host information.

This module only runs for domain targets (not raw IP addresses).

Tools and sources used:
    - whois: registrar, organisation, dates, ASN
    - crt.sh API: certificate transparency subdomain enumeration
    - theHarvester: multi-source OSINT aggregation (optional)
    - subfinder: passive subdomain discovery (optional)
    - amass: passive subdomain enumeration (optional)
    - shodan: host intelligence (optional, requires API key)
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

import requests

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

MODULE_NAME = "osint"

# Timeout for HTTP requests to OSINT APIs (seconds)
_API_TIMEOUT = 30


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_domain(target: str, state: ScanState) -> str | None:
    """Determine the domain to use for OSINT queries.

    Prefers a hostname already discovered in the scan state, falling back
    to the raw *target* if it looks like a domain name (not a bare IP).

    Args:
        target: The primary target string from the CLI.
        state: Current scan state with discovered hostnames.

    Returns:
        A domain string suitable for OSINT queries, or ``None`` if the
        target appears to be a raw IP address with no domain information.
    """
    # If we already have hostnames, use the first one
    if state.hostnames:
        return state.hostnames[0]

    # Check if target itself looks like a domain (not an IP)
    ipv4_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    ipv6_pattern = r"^\[?[0-9a-fA-F:]+\]?$"
    if not re.match(ipv4_pattern, target) and not re.match(ipv6_pattern, target):
        return target

    return None


def _is_ip_address(value: str) -> bool:
    """Check whether *value* looks like an IP address.

    Args:
        value: String to test.

    Returns:
        ``True`` if *value* resembles an IPv4 or IPv6 address.
    """
    ipv4_pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(ipv4_pattern, value))


def _parse_whois_findings(stdout: str, domain: str) -> list[Finding]:
    """Parse whois output for relevant registration details.

    Extracts registrar, organisation, creation date, expiry date, and
    ASN information from raw whois output.

    Args:
        stdout: Raw whois command output.
        domain: The domain being queried.

    Returns:
        List of INFO-level Findings summarising WHOIS data.
    """
    findings: list[Finding] = []

    # Registrar
    registrar_match = re.search(
        r"Registrar:\s*(.+)", stdout, re.IGNORECASE
    )
    if registrar_match:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"WHOIS registrar for {domain}",
                description=f"Domain is registered through: {registrar_match.group(1).strip()}",
                module=MODULE_NAME,
                evidence=registrar_match.group(0).strip(),
            )
        )

    # Organisation
    org_match = re.search(
        r"Registrant\s+Organization:\s*(.+)", stdout, re.IGNORECASE
    ) or re.search(r"Organisation:\s*(.+)", stdout, re.IGNORECASE)
    if org_match:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"WHOIS organisation for {domain}",
                description=f"Registrant organisation: {org_match.group(1).strip()}",
                module=MODULE_NAME,
                evidence=org_match.group(0).strip(),
            )
        )

    # Creation date
    created_match = re.search(
        r"Creation\s+Date:\s*(.+)", stdout, re.IGNORECASE
    ) or re.search(r"created:\s*(.+)", stdout, re.IGNORECASE)
    if created_match:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"WHOIS creation date for {domain}",
                description=f"Domain created: {created_match.group(1).strip()}",
                module=MODULE_NAME,
                evidence=created_match.group(0).strip(),
            )
        )

    # Expiry date
    expiry_match = re.search(
        r"Registry\s+Expiry\s+Date:\s*(.+)", stdout, re.IGNORECASE
    ) or re.search(r"Expiry\s+Date:\s*(.+)", stdout, re.IGNORECASE)
    if expiry_match:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"WHOIS expiry date for {domain}",
                description=f"Domain expires: {expiry_match.group(1).strip()}",
                module=MODULE_NAME,
                evidence=expiry_match.group(0).strip(),
            )
        )

    # ASN (sometimes present in whois)
    asn_match = re.search(r"ASN:\s*(\d+)", stdout, re.IGNORECASE)
    if asn_match:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"WHOIS ASN for {domain}",
                description=f"ASN: {asn_match.group(1)}",
                module=MODULE_NAME,
                evidence=asn_match.group(0).strip(),
            )
        )

    return findings


def _query_crtsh(domain: str) -> list[str]:
    """Query the crt.sh certificate transparency log for subdomains.

    Uses the JSON API endpoint for structured parsing. Falls back to
    regex extraction from HTML if the JSON endpoint fails.

    Args:
        domain: Base domain to search (e.g. ``example.com``).

    Returns:
        Deduplicated list of subdomain names discovered via CT logs.
    """
    subdomains: list[str] = []
    url = f"https://crt.sh/?q={domain}&output=json"

    try:
        resp = requests.get(url, timeout=_API_TIMEOUT, headers={
            "User-Agent": "ReconNinja/2.0 OSINT Module"
        })
        resp.raise_for_status()

        data: list[dict[str, Any]] = resp.json()
        for entry in data:
            name_value = entry.get("name_value", "")
            # crt.sh can return multiple names separated by newlines
            for name in name_value.split("\n"):
                name = name.strip().lower()
                if name and domain in name:
                    subdomains.append(name)

    except requests.exceptions.JSONDecodeError:
        # Fallback: parse HTML response
        logger.debug("crt.sh JSON parse failed, trying HTML extraction")
        try:
            text = resp.text if "resp" in dir() else ""
            if text:
                # Look for domain-like patterns in the response
                found = re.findall(
                    rf"([a-zA-Z0-9*.\-]+\.{re.escape(domain)})", text
                )
                subdomains.extend(found)
        except Exception as exc:
            logger.warning("crt.sh HTML fallback also failed: %s", exc)

    except requests.exceptions.RequestException as exc:
        logger.warning("crt.sh request failed: %s", exc)

    # Deduplicate
    return list(dict.fromkeys(subdomains))


def _parse_subfinder_output(stdout: str, domain: str) -> list[str]:
    """Parse subfinder output, one subdomain per line.

    Args:
        stdout: Raw subfinder output.
        domain: Base domain to filter results against.

    Returns:
        List of unique subdomains containing *domain*.
    """
    subdomains: list[str] = []
    for line in stdout.splitlines():
        line = line.strip().lower()
        if line and domain in line:
            subdomains.append(line)
    return list(dict.fromkeys(subdomains))


def _parse_amass_output(stdout: str, domain: str) -> list[str]:
    """Parse amass passive enumeration output.

    Args:
        stdout: Raw amass output.
        domain: Base domain to filter results against.

    Returns:
        List of unique subdomains containing *domain*.
    """
    subdomains: list[str] = []
    for line in stdout.splitlines():
        line = line.strip().lower()
        if line and domain in line and not line.startswith("#"):
            subdomains.append(line)
    return list(dict.fromkeys(subdomains))


def _parse_harvester_output(stdout: str, domain: str) -> list[str]:
    """Parse theHarvester output for subdomains.

    TheHarvester prints subdomains in a section typically labelled
    ``[*] Subdomains:`` followed by one per line.

    Args:
        stdout: Raw theHarvester output.
        domain: Base domain to filter results against.

    Returns:
        List of unique subdomains containing *domain*.
    """
    subdomains: list[str] = []
    in_subdomain_section = False

    for line in stdout.splitlines():
        stripped = line.strip()

        # Detect subdomain section
        if re.search(r"\[*\]\s*Subdomains", stripped, re.IGNORECASE):
            in_subdomain_section = True
            continue

        # Detect next section (hostnames, IPs, etc.) — stop collecting
        if in_subdomain_section and re.match(r"\[*\]", stripped):
            in_subdomain_section = False
            continue

        if in_subdomain_section and stripped:
            entry = stripped.lower()
            if domain in entry:
                subdomains.append(entry)

    # Also do a broader sweep for any domain-like matches in the full output
    broad_matches = re.findall(
        rf"([a-zA-Z0-9*.\-]+\.{re.escape(domain)})", stdout
    )
    for match in broad_matches:
        entry = match.lower()
        if entry not in subdomains:
            subdomains.append(entry)

    return list(dict.fromkeys(subdomains))


def _parse_shodan_output(stdout: str, target: str) -> list[Finding]:
    """Parse Shodan host output for interesting findings.

    Looks for open ports, technologies, and potential vulnerabilities
    reported by Shodan.

    Args:
        stdout: Raw Shodan CLI output.
        target: The target that was queried.

    Returns:
        List of INFO-level Findings from Shodan data.
    """
    findings: list[Finding] = []

    # Extract port information
    port_matches = re.findall(r"Port:\s*(\d+)", stdout)
    if port_matches:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"Shodan open ports for {target}",
                description=f"Shodan reports {len(port_matches)} open port(s): "
                f"{', '.join(port_matches[:20])}",
                module=MODULE_NAME,
                evidence=f"Ports: {', '.join(port_matches[:20])}",
            )
        )

    # Extract technologies / product information
    product_matches = re.findall(r"Product:\s*(.+)", stdout)
    if product_matches:
        products = [p.strip() for p in product_matches[:10]]
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"Shodan technologies for {target}",
                description=f"Detected technologies: {', '.join(products)}",
                module=MODULE_NAME,
                evidence=f"Products: {', '.join(products)}",
            )
        )

    # Extract vulnerabilities reported by Shodan
    vuln_matches = re.findall(r"CVE-\d{4}-\d{4,}", stdout)
    if vuln_matches:
        unique_cves = list(dict.fromkeys(vuln_matches))
        for cve in unique_cves[:10]:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title=f"Shodan: {cve}",
                    description=f"Shodan reports vulnerability {cve} on {target}.",
                    module=MODULE_NAME,
                    evidence=cve,
                    cve=cve,
                )
            )

    # Generic fallback: if Shodan returned data but we couldn't parse specifics
    if stdout.strip() and not findings:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"Shodan data for {target}",
                description="Shodan returned host data (see raw output).",
                module=MODULE_NAME,
                evidence=stdout[:500],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


@module_guard()
async def run_osint_module(
    target: str, state: ScanState, config: ReconConfig, output_dir: Path
) -> ModuleResult:
    """Run OSINT enumeration against a domain target.

    Gathers WHOIS data, certificate transparency subdomains, and runs
    optional tools (theHarvester, subfinder, amass, Shodan) to discover
    subdomains and intelligence about the target.

    This module is only meaningful for domain targets; if the target is
    a bare IP address with no associated domain, the module skips.

    Args:
        target: The primary target string (IP or domain).
        state: Current scan state with discovered services and hostnames.
        config: Scan configuration (timeouts, toggles, API keys, etc.).
        output_dir: Directory for module output files.

    Returns:
        ModuleResult with OSINT findings, or a skipped/error result if
        the target is not a domain or no tools are available.
    """
    start_time = time.monotonic()
    findings: list[Finding] = []
    raw_outputs: list[str] = []
    all_subdomains: list[str] = []

    # Determine the domain for OSINT queries
    domain = _extract_domain(target, state)
    if not domain:
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            duration_seconds=time.monotonic() - start_time,
            error_message="Target is an IP address with no domain — OSINT skipped",
        )

    # Ensure output directory exists
    osint_output_dir = output_dir / "osint"
    osint_output_dir.mkdir(parents=True, exist_ok=True)

    timeout = config.default_timeout

    # ------------------------------------------------------------------
    # whois
    # ------------------------------------------------------------------
    if shutil.which("whois") is not None:
        whois_output = osint_output_dir / "whois.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["whois", domain],
            output_file=whois_output,
            timeout=timeout,
        )
        raw_outputs.append(f"=== whois {domain} ===\n{stdout}")

        if rc >= 0 and stdout:
            whois_findings = _parse_whois_findings(stdout, domain)
            findings.extend(whois_findings)
    else:
        logger.info("whois not available — skipping WHOIS lookup")

    # ------------------------------------------------------------------
    # crt.sh (certificate transparency)
    # ------------------------------------------------------------------
    logger.info("Querying crt.sh for %s", domain)
    crtsh_subdomains = _query_crtsh(domain)
    if crtsh_subdomains:
        raw_outputs.append(
            "=== crt.sh subdomains ===\n" + "\n".join(crtsh_subdomains)
        )
        all_subdomains.extend(crtsh_subdomains)

        # Save crt.sh results
        crtsh_file = osint_output_dir / "crtsh_subdomains.txt"
        try:
            crtsh_file.write_text("\n".join(crtsh_subdomains), encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to write crt.sh results: %s", exc)

    # ------------------------------------------------------------------
    # theHarvester (optional)
    # ------------------------------------------------------------------
    if shutil.which("theHarvester") is not None:
        harvester_output = osint_output_dir / "harvester.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["theHarvester", "-d", domain, "-b", "google,bing,crtsh,dnsdumpster"],
            output_file=harvester_output,
            timeout=timeout * 2,  # theHarvester can be slow
        )
        raw_outputs.append(f"=== theHarvester {domain} ===\n{stdout}")

        if rc >= 0 and stdout:
            harvester_subs = _parse_harvester_output(stdout, domain)
            all_subdomains.extend(harvester_subs)
    else:
        logger.info("theHarvester not available — skipping")

    # ------------------------------------------------------------------
    # subfinder (optional)
    # ------------------------------------------------------------------
    if shutil.which("subfinder") is not None:
        subfinder_result_file = osint_output_dir / "subfinder.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["subfinder", "-d", domain, "-o", str(subfinder_result_file)],
            timeout=timeout,
        )
        # subfinder writes directly to the -o file; also capture stdout
        raw_outputs.append(f"=== subfinder {domain} ===\n{stdout}")

        # Read subfinder output file (it writes there directly)
        if subfinder_result_file.is_file():
            try:
                subfinder_content = subfinder_result_file.read_text(
                    encoding="utf-8"
                )
                subfinder_subs = _parse_subfinder_output(subfinder_content, domain)
                all_subdomains.extend(subfinder_subs)
            except OSError as exc:
                logger.warning("Failed to read subfinder output file: %s", exc)
        elif stdout:
            subfinder_subs = _parse_subfinder_output(stdout, domain)
            all_subdomains.extend(subfinder_subs)
    else:
        logger.info("subfinder not available — skipping")

    # ------------------------------------------------------------------
    # amass (optional)
    # ------------------------------------------------------------------
    if shutil.which("amass") is not None:
        amass_output = osint_output_dir / "amass.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["amass", "enum", "-passive", "-d", domain],
            output_file=amass_output,
            timeout=timeout * 2,  # amass can be slow
        )
        raw_outputs.append(f"=== amass {domain} ===\n{stdout}")

        if rc >= 0 and stdout:
            amass_subs = _parse_amass_output(stdout, domain)
            all_subdomains.extend(amass_subs)
    else:
        logger.info("amass not available — skipping")

    # ------------------------------------------------------------------
    # Shodan (optional — requires API key)
    # ------------------------------------------------------------------
    has_shodan = shutil.which("shodan") is not None
    shodan_api_key: str | None = None

    # Try to get API key from config attribute, then environment
    api_keys = getattr(config, "api_keys", None)
    if api_keys and hasattr(api_keys, "shodan") and api_keys.shodan:
        shodan_api_key = api_keys.shodan
    else:
        shodan_api_key = os.environ.get("SHODAN_API_KEY")

    if has_shodan and shodan_api_key:
        shodan_output = osint_output_dir / "shodan.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["shodan", "host", target],
            output_file=shodan_output,
            timeout=timeout,
            env={"SHODAN_API_KEY": shodan_api_key},
        )
        raw_outputs.append(f"=== shodan host {target} ===\n{stdout}")

        if rc >= 0 and stdout:
            shodan_findings = _parse_shodan_output(stdout, target)
            findings.extend(shodan_findings)
    else:
        if not has_shodan:
            logger.info("shodan CLI not available — skipping")
        if not shodan_api_key:
            logger.info("Shodan API key not configured — skipping")

    # ------------------------------------------------------------------
    # Deduplicate and record subdomains
    # ------------------------------------------------------------------
    # Normalise subdomains: lowercase, strip wildcards, strip trailing dots
    normalised: list[str] = []
    for sub in all_subdomains:
        sub = sub.lower().strip().rstrip(".")
        # Remove leading wildcard
        sub = re.sub(r"^\*\.", "", sub)
        if sub and domain in sub:
            normalised.append(sub)

    unique_subdomains = list(dict.fromkeys(normalised))

    # Add to scan state
    new_count = 0
    for sub in unique_subdomains:
        if sub not in state.hostnames:
            state.hostnames.append(sub)
            new_count += 1

    if unique_subdomains:
        # Save complete subdomain list
        subs_file = osint_output_dir / "all_subdomains.txt"
        try:
            subs_file.write_text("\n".join(sorted(unique_subdomains)), encoding="utf-8")
        except OSError as exc:
            logger.warning("Failed to write subdomain list: %s", exc)

        # Create a finding summarising the subdomain discovery
        findings.append(
            Finding(
                severity=Severity.INFO,
                title=f"OSINT: {len(unique_subdomains)} unique subdomains discovered for {domain}",
                description=f"Discovered {len(unique_subdomains)} unique subdomains "
                f"({new_count} new) via crt.sh, theHarvester, subfinder, and/or amass.",
                module=MODULE_NAME,
                evidence=", ".join(sorted(unique_subdomains)[:50]),
                suggested_commands=[
                    f"dig +short {sub}" for sub in sorted(unique_subdomains)[:10]
                ],
            )
        )

    # Deduplicate findings by (title, module)
    seen: set[tuple[str, str]] = set()
    unique_findings: list[Finding] = []
    for f in findings:
        key = (f.title, f.module)
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    duration = time.monotonic() - start_time

    return ModuleResult(
        module_name=MODULE_NAME,
        status="done",
        findings=unique_findings,
        raw_output="\n\n".join(raw_outputs)[:10000],
        output_file=osint_output_dir,
        duration_seconds=duration,
    )
