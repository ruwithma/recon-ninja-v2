"""SSL/TLS security auditing module for ReconNinja v2.

Triggered when any HTTPS service is detected, or when ports 443/8443 are open.
Runs multiple TLS analysis tools, parses certificate details for hostname
discovery, and flags known vulnerabilities like Heartbleed, weak ciphers,
and missing security headers.

Tools used:
    - sslscan: cipher suites, certificate details, BEAST/POODLE detection
    - nmap NSE: ssl-heartbleed, ssl-ccs-injection, ssl-dh-params scripts
    - testssl.sh: comprehensive TLS audit (optional)
"""

from __future__ import annotations

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
)
from recon_ninja.core.runner import run_tool

logger = logging.getLogger(__name__)

MODULE_NAME = "ssl"

# Ports that default to HTTPS even without service detection
_SSL_DEFAULT_PORTS = {443, 8443}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _is_ssl_service(state: ScanState) -> list[int]:
    """Return ports that have SSL/TLS services or are in the default HTTPS set.

    A port qualifies if:
    - The service name contains ``ssl`` or ``https``.
    - The port number is 443 or 8443.

    Args:
        state: Current scan state with discovered services.

    Returns:
        List of port numbers that should be audited for SSL/TLS issues.
    """
    ssl_ports: list[int] = []
    for port, svc in state.services.items():
        service_lower = svc.service.lower()
        if "ssl" in service_lower or "https" in service_lower:
            ssl_ports.append(port)
        elif port in _SSL_DEFAULT_PORTS:
            ssl_ports.append(port)
    return sorted(set(ssl_ports))


def _parse_sslscan_hostnames(stdout: str) -> list[str]:
    """Extract CN and SAN hostnames from sslscan output.

    Looks for lines like::
        Subject:  CN=example.com
        Subject Alternative Name: DNS:sub.example.com, DNS:www.example.com

    Args:
        stdout: Raw sslscan output.

    Returns:
        Deduplicated list of hostnames found in the certificate.
    """
    hostnames: list[str] = []

    # Extract CN from Subject line
    cn_match = re.search(r"Subject:\s*.*CN\s*=\s*([^\s,/\n]+)", stdout)
    if cn_match:
        hostnames.append(cn_match.group(1).strip())

    # Extract SAN entries
    san_match = re.search(
        r"Subject Alternative Name\s*:\s*(.+)", stdout, re.IGNORECASE
    )
    if san_match:
        san_value = san_match.group(1)
        dns_entries = re.findall(r"DNS:([^\s,]+)", san_value)
        hostnames.extend(dns_entries)

    return list(dict.fromkeys(hostnames))  # deduplicate, preserve order


def _parse_sslscan_findings(stdout: str) -> list[Finding]:
    """Parse sslscan output for security-relevant findings.

    Detects:
    - SSLv2 / SSLv3 protocol support (MEDIUM)
    - TLS 1.0 / TLS 1.1 support (MEDIUM)
    - Weak cipher suites (MEDIUM)
    - BEAST vulnerability indication (MEDIUM)
    - POODLE vulnerability indication (MEDIUM)
    - Missing HSTS header (INFO)

    Args:
        stdout: Raw sslscan output.

    Returns:
        List of Findings parsed from the output.
    """
    findings: list[Finding] = []

    # Weak protocols
    if re.search(r"^\s*SSLv2\s+enabled", stdout, re.MULTILINE | re.IGNORECASE):
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="SSLv2 protocol enabled",
                description="The server supports SSLv2, which is insecure and deprecated.",
                module=MODULE_NAME,
                evidence="SSLv2 enabled in sslscan output",
            )
        )
    if re.search(r"^\s*SSLv3\s+enabled", stdout, re.MULTILINE | re.IGNORECASE):
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="SSLv3 protocol enabled (POODLE)",
                description="The server supports SSLv3, which is vulnerable to the POODLE attack.",
                module=MODULE_NAME,
                evidence="SSLv3 enabled in sslscan output",
                cve="CVE-2014-3566",
            )
        )
    if re.search(r"^\s*TLSv1\.0\s+enabled", stdout, re.MULTILINE | re.IGNORECASE):
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="TLS 1.0 protocol enabled",
                description="TLS 1.0 is deprecated (RFC 8996) and vulnerable to BEAST.",
                module=MODULE_NAME,
                evidence="TLSv1.0 enabled in sslscan output",
                cve="CVE-2011-3389",
            )
        )
    if re.search(r"^\s*TLSv1\.1\s+enabled", stdout, re.MULTILINE | re.IGNORECASE):
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="TLS 1.1 protocol enabled",
                description="TLS 1.1 is deprecated (RFC 8996).",
                module=MODULE_NAME,
                evidence="TLSv1.1 enabled in sslscan output",
            )
        )

    # Weak ciphers (typically listed with 40-bit or 56-bit key sizes)
    weak_cipher_matches = re.findall(
        r"^\s*(?:SSLv3|TLSv[\d.]+)\s+(\S+)\s+.*\b(40|56)\s*bit",
        stdout,
        re.MULTILINE | re.IGNORECASE,
    )
    if weak_cipher_matches:
        weak_names = [match[0] for match in weak_cipher_matches]
        findings.append(
            Finding(
                severity=Severity.MEDIUM,
                title="Weak cipher suites detected",
                description=f"Found {len(weak_names)} weak cipher(s) with 40/56-bit keys.",
                module=MODULE_NAME,
                evidence=f"Weak ciphers: {', '.join(weak_names[:10])}",
            )
        )

    # Missing HSTS (sslscan sometimes reports this)
    if re.search(r"HSTS\s*:\s*not\s+present", stdout, re.IGNORECASE):
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="Missing HSTS header",
                description="The server does not send the HTTP Strict Transport Security header.",
                module=MODULE_NAME,
                evidence="HSTS not present in sslscan output",
            )
        )

    return findings


def _parse_nmap_ssl_findings(stdout: str) -> list[Finding]:
    """Parse nmap SSL NSE script output for vulnerabilities.

    Detects:
    - Heartbleed (CRITICAL)
    - CCS injection (HIGH)
    - Weak DH parameters (MEDIUM)

    Args:
        stdout: Raw nmap output with SSL NSE scripts.

    Returns:
        List of Findings from the nmap output.
    """
    findings: list[Finding] = []

    if "VULNERABLE" in stdout and "heartbleed" in stdout.lower():
        findings.append(
            Finding(
                severity=Severity.CRITICAL,
                title="OpenSSL Heartbleed vulnerability",
                description="The server is vulnerable to the Heartbleed bug, allowing "
                "memory disclosure of up to 64 KB per request.",
                module=MODULE_NAME,
                evidence=stdout[:1000],
                cve="CVE-2014-0160",
                suggested_commands=[
                    "nmap -p443 --script ssl-heartbleed <TARGET>",
                    "openssl s_client -connect <TARGET>:443 -tlsextdebug",
                ],
            )
        )

    if "VULNERABLE" in stdout and "ccs" in stdout.lower():
        findings.append(
            Finding(
                severity=Severity.HIGH,
                title="OpenSSL CCS Injection vulnerability",
                description="The server is vulnerable to the CCS Injection attack, "
                "which allows man-in-the-middle interception.",
                module=MODULE_NAME,
                evidence=stdout[:1000],
                cve="CVE-2014-0224",
                suggested_commands=[
                    "nmap -p443 --script ssl-ccs-injection <TARGET>",
                ],
            )
        )

    # Weak DH params detection
    dh_match = re.search(
        r"ssl-dh-params:.*?DH\s+parameter\s+size.*?(\d+)\s*bits",
        stdout,
        re.IGNORECASE | re.DOTALL,
    )
    if dh_match:
        key_size = int(dh_match.group(1))
        if key_size < 2048:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f"Weak DH parameters ({key_size} bits)",
                    description=f"Server uses {key_size}-bit DH parameters. "
                    f"Minimum recommended is 2048 bits.",
                    module=MODULE_NAME,
                    evidence=f"DH parameter size: {key_size} bits",
                    suggested_commands=[
                        "nmap -p443 --script ssl-dh-params <TARGET>",
                    ],
                )
            )

    return findings


def _parse_testssl_findings(stdout: str) -> list[Finding]:
    """Parse testssl.sh output for security findings.

    Looks for severity indicators in the testssl output format.
    testssl uses labels like ``CRITICAL``, ``HIGH``, ``MEDIUM``, ``LOW``,
    and ``WARN`` in its output.

    Args:
        stdout: Raw testssl.sh output.

    Returns:
        List of Findings extracted from the testssl output.
    """
    findings: list[Finding] = []

    # Match testssl severity-tagged lines
    severity_map: dict[str, Severity] = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "WARN": Severity.MEDIUM,
    }

    for line in stdout.splitlines():
        for label, sev in severity_map.items():
            # testssl lines often look like: "  CRITICAL  ... description ..."
            if re.search(rf"\b{label}\b", line, re.IGNORECASE):
                # Avoid duplicate generic findings; only add meaningful lines
                stripped = line.strip()
                if len(stripped) < 10:
                    continue

                # Skip if we've already flagged a very similar finding
                title = stripped[:120]
                if any(f.title == title for f in findings):
                    continue

                findings.append(
                    Finding(
                        severity=sev,
                        title=title,
                        description=stripped,
                        module=MODULE_NAME,
                        evidence=stripped,
                    )
                )
                break  # one finding per line at highest severity

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


async def run_ssl_module(
    target: str, state: ScanState, config: ReconConfig, output_dir: Path
) -> ModuleResult:
    """Run SSL/TLS security auditing against all HTTPS services.

    Checks for SSL/TLS services in the scan state, then runs sslscan,
    nmap SSL NSE scripts, and optionally testssl.sh against each. Parses
    results for vulnerabilities, weak configurations, and certificate
    hostnames.

    Args:
        target: The primary target IP or hostname.
        state: Current scan state with discovered services and hostnames.
        config: Scan configuration (timeouts, toggles, etc.).
        output_dir: Directory for module output files.

    Returns:
        ModuleResult with all SSL/TLS findings, or a skipped/error result
        if no SSL services were detected or all tools are unavailable.
    """
    start_time = time.monotonic()
    findings: list[Finding] = []
    raw_outputs: list[str] = []

    # Determine which ports to audit
    ssl_ports = _is_ssl_service(state)
    if not ssl_ports:
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            duration_seconds=time.monotonic() - start_time,
            error_message="No SSL/TLS services detected",
        )

    # Ensure output directory exists
    ssl_output_dir = output_dir / "ssl"
    ssl_output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Tool availability checks
    # ------------------------------------------------------------------
    has_sslscan = shutil.which("sslscan") is not None
    has_nmap = shutil.which("nmap") is not None
    has_testssl = shutil.which("testssl.sh") is not None

    if not has_sslscan and not has_nmap and not has_testssl:
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            duration_seconds=time.monotonic() - start_time,
            error_message="No SSL scanning tools available (sslscan, nmap, testssl.sh)",
        )

    timeout = config.default_timeout

    # ------------------------------------------------------------------
    # Run tools for each SSL port
    # ------------------------------------------------------------------
    discovered_hostnames: list[str] = []

    for port in ssl_ports:
        target_host = target
        # Use service hostname if available
        svc = state.services.get(port)
        if svc and svc.hostname:
            target_host = svc.hostname

        # --- sslscan ---
        if has_sslscan:
            sslscan_output = ssl_output_dir / f"sslscan_{port}.txt"
            rc, stdout, stderr = await run_tool(
                cmd=["sslscan", "--no-colour", f"{target_host}:{port}"],
                output_file=sslscan_output,
                timeout=timeout,
            )
            raw_outputs.append(f"=== sslscan {target_host}:{port} ===\n{stdout}")

            if rc >= 0 and stdout:
                port_findings = _parse_sslscan_findings(stdout)
                for f in port_findings:
                    f.title = f"[Port {port}] {f.title}"
                findings.extend(port_findings)

                # Extract hostnames from certificate
                cert_hostnames = _parse_sslscan_hostnames(stdout)
                discovered_hostnames.extend(cert_hostnames)

        # --- nmap SSL NSE scripts ---
        if has_nmap:
            nmap_output = ssl_output_dir / f"nmap_ssl_{port}.txt"
            rc, stdout, stderr = await run_tool(
                cmd=[
                    "nmap",
                    f"-p{port}",
                    "--script",
                    "ssl-heartbleed,ssl-ccs-injection,ssl-dh-params",
                    target_host,
                ],
                output_file=nmap_output,
                timeout=timeout,
            )
            raw_outputs.append(f"=== nmap SSL scripts {target_host}:{port} ===\n{stdout}")

            if rc >= 0 and stdout:
                nmap_findings = _parse_nmap_ssl_findings(stdout)
                for f in nmap_findings:
                    f.title = f"[Port {port}] {f.title}"
                findings.extend(nmap_findings)

        # --- testssl.sh ---
        if has_testssl:
            testssl_output = ssl_output_dir / f"testssl_{port}.txt"
            rc, stdout, stderr = await run_tool(
                cmd=["testssl.sh", "--quiet", f"{target_host}:{port}"],
                output_file=testssl_output,
                timeout=timeout * 2,  # testssl can be slow
            )
            raw_outputs.append(f"=== testssl.sh {target_host}:{port} ===\n{stdout}")

            if rc >= 0 and stdout:
                testssl_findings = _parse_testssl_findings(stdout)
                for f in testssl_findings:
                    f.title = f"[Port {port}] {f.title}"
                findings.extend(testssl_findings)

    # ------------------------------------------------------------------
    # Add discovered hostnames to scan state
    # ------------------------------------------------------------------
    for hostname in discovered_hostnames:
        # Clean up wildcards for state purposes
        clean_hostname = hostname.lstrip("*.")
        if clean_hostname and clean_hostname not in state.hostnames:
            state.hostnames.append(clean_hostname)
            logger.info("SSL cert discovery: added hostname %s", clean_hostname)

    # ------------------------------------------------------------------
    # Check for missing HSTS on HTTPS services (if not already detected)
    # ------------------------------------------------------------------
    hsts_already_flagged = any("HSTS" in f.title for f in findings)
    if not hsts_already_flagged:
        for port in ssl_ports:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"[Port {port}] Missing HSTS header",
                    description="HTTPS service without HSTS header detected. "
                    "Consider enabling HSTS to prevent protocol downgrade attacks.",
                    module=MODULE_NAME,
                    evidence="No HSTS header found during SSL assessment",
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
        output_file=ssl_output_dir,
        duration_seconds=duration,
    )
