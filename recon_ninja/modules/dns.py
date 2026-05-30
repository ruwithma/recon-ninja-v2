"""DNS reconnaissance module for ReconNinja v2.

Triggered when port 53 is open or the service is identified as ``domain``
(DNS).  Attempts zone transfers, brute-forces subdomains, and enumerates
SRV records.  A successful zone transfer is flagged as CRITICAL.
"""

from __future__ import annotations

import logging
import re
import shutil
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

MODULE_NAME = "dns"


def _is_dns_port(state: ScanState) -> bool:
    """Return ``True`` if port 53 is open or the service is DNS."""
    if 53 in state.open_ports or 53 in state.udp_ports:
        return True
    for _port, svc in state.services.items():
        if svc.service.lower() in ("domain", "dns"):
            return True
    return False


def _resolve_domain(target: str, state: ScanState) -> str | None:
    """Determine the domain to query from the target or scan state.

    Uses the first hostname from *state* if available; otherwise
    returns ``None`` (zone transfer requires a domain, not an IP).
    """
    if state.hostnames:
        return state.hostnames[0]
    # If target itself looks like a domain (not an IP), use it directly
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target):
        return target
    return None


@module_guard()
async def run_dns_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run DNS enumeration against *target*.

    Args:
        target: IP address or hostname of the target.
        state: Current scan state with port/service information.
        config: Scan configuration.
        output_dir: Base directory for module output files.

    Returns:
        A :class:`ModuleResult` containing findings and raw output.
    """
    findings: list[Finding] = []
    raw_outputs: list[str] = []

    if not _is_dns_port(state):
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            error_message="No DNS port (53) or DNS service found.",
        )

    # Prepare output subdirectory
    dns_dir = output_dir / "dns"
    dns_dir.mkdir(parents=True, exist_ok=True)

    timeout = config.default_timeout

    # Determine the domain to use for DNS queries
    domain = _resolve_domain(target, state)
    if domain is None:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="DNS — No Domain Resolved",
                description=(
                    "DNS port is open but no domain name was discovered. "
                    "Zone transfer and subdomain enumeration require a domain."
                ),
                module=MODULE_NAME,
                evidence=f"Target IP: {target}",
            )
        )
        # We can still do basic dig queries against the IP
        domain = target

    # ------------------------------------------------------------------
    # 1. dig axfr — zone transfer attempt
    # ------------------------------------------------------------------
    if shutil.which("dig"):
        logger.info("[%s] Attempting DNS zone transfer for %s @ %s", MODULE_NAME, domain, target)
        axfr_out = dns_dir / "dig_axfr.txt"
        cmd = ["dig", "axfr", domain, f"@{target}"]
        rc, stdout, stderr = await run_tool(
            cmd, output_file=axfr_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        if stdout:
            zone_records = _parse_axfr_output(stdout)
            if zone_records:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        title=f"DNS Zone Transfer Successful — {len(zone_records)} Record(s)",
                        description=(
                            f"The DNS server allows zone transfers (AXFR) for '{domain}', "
                            f"exposing {len(zone_records)} DNS record(s). This reveals the "
                            f"entire internal network topology."
                        ),
                        module=MODULE_NAME,
                        evidence="\n".join(zone_records[:30]),
                        suggested_commands=[
                            f"dig axfr {domain} @{target}",
                        ],
                    )
                )
            else:
                # Check if transfer was refused / failed
                if "Transfer failed" in stdout or "XFR size: 0" in stdout:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title="DNS Zone Transfer Denied",
                            description=(
                                f"Zone transfer for '{domain}' was denied — the server "
                                f"is correctly configured to restrict AXFR."
                            ),
                            module=MODULE_NAME,
                            evidence=_extract_line(stdout, "Transfer") or _extract_line(stdout, "XFR"),
                        )
                    )
    else:
        logger.info("[%s] dig not found — skipping zone transfer", MODULE_NAME)

    # ------------------------------------------------------------------
    # 2. dnsrecon — zone transfer, brute force, SRV records
    # ------------------------------------------------------------------
    if shutil.which("dnsrecon") and domain != target:
        logger.info("[%s] Running dnsrecon against %s", MODULE_NAME, domain)
        dnsrecon_out = dns_dir / "dnsrecon.txt"

        # Locate subdomain wordlist
        use_adaptive_dns = config.adaptive_fuzz and not config.fast_mode
        passive_subdomains_found = any(
            f.module == "osint" and "subdomain" in f.title.lower()
            for f in state.all_findings
        )

        subdomain_wordlist = Path(
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        )
        if not subdomain_wordlist.is_file():
            subdomain_wordlist = config.dns_wordlist
        if not subdomain_wordlist.is_file():
            subdomain_wordlist = Path("/usr/share/wordlists/dirb/big.txt")

        # Determine stage 1 wordlist
        stage1_wl = subdomain_wordlist
        if use_adaptive_dns and not passive_subdomains_found:
            # Probe with a smaller wordlist first if available
            from recon_ninja.utils.wordlists import resolve_wordlist
            seclists_base = config.module_toggles.get("_seclists_base")
            custom_dir = config.module_toggles.get("_custom_dir")
            small_dns = resolve_wordlist("Discovery/DNS/subdomains-top1million-5000.txt", seclists_base, custom_dir) if seclists_base else None
            if small_dns and small_dns.is_file():
                stage1_wl = small_dns

        dnsrecon_args: list[str] = ["-d", domain, "-t", "axfr,srv"]
        if stage1_wl.is_file():
            dnsrecon_args.extend(["-t", "brt", "-D", str(stage1_wl)])

        cmd = ["dnsrecon"] + dnsrecon_args
        rc, stdout, stderr = await run_tool(
            cmd, output_file=dnsrecon_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        # Stage 2 escalation
        if stdout:
            subdomains_stage1 = _parse_dnsrecon_subdomains(stdout)
            # If we used a smaller list, and found subdomains, upgrade to the full/dns_wordlist
            if use_adaptive_dns and subdomains_stage1 and stage1_wl != config.dns_wordlist and config.dns_wordlist.is_file():
                logger.info("[dns] Stage 1 found active subdomains. Upgrading to Stage 2 (large list: %s)", config.dns_wordlist)
                dnsrecon_args2 = ["-d", domain, "-t", "brt", "-D", str(config.dns_wordlist)]
                cmd2 = ["dnsrecon"] + dnsrecon_args2
                rc2, stdout2, stderr2 = await run_tool(
                    cmd2, output_file=dns_dir / "dnsrecon_stage2.txt", timeout=timeout
                )
                raw_outputs.append(stdout2 or stderr2)
                if stdout2:
                    stdout = stdout + "\n" + stdout2

        if stdout:
            subdomains = _parse_dnsrecon_subdomains(stdout)
            if subdomains:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title=f"DNS Subdomains Discovered — {len(subdomains)} Found",
                        description=(
                            f"dnsrecon found {len(subdomains)} subdomain(s) for '{domain}'."
                        ),
                        module=MODULE_NAME,
                        evidence="\n".join(subdomains[:30]),
                        suggested_commands=[
                            f"dig {sd} @{target}" for sd in subdomains[:10]
                        ],
                    )
                )

            srv_records = _parse_dnsrecon_srv(stdout)
            if srv_records:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title=f"DNS SRV Records — {len(srv_records)} Found",
                        description="dnsrecon discovered SRV records that reveal internal services.",
                        module=MODULE_NAME,
                        evidence="\n".join(srv_records[:15]),
                    )
                )
    else:
        if not shutil.which("dnsrecon"):
            logger.info("[%s] dnsrecon not found — skipping", MODULE_NAME)
        elif domain == target:
            logger.info("[%s] No domain resolved — skipping dnsrecon", MODULE_NAME)

    # ------------------------------------------------------------------
    # 3. dnsenum — comprehensive DNS enumeration
    # ------------------------------------------------------------------
    if shutil.which("dnsenum") and domain != target:
        logger.info("[%s] Running dnsenum against %s", MODULE_NAME, domain)
        dnsenum_out = dns_dir / "dnsenum.txt"
        cmd = ["dnsenum", domain]
        rc, stdout, stderr = await run_tool(
            cmd, output_file=dnsenum_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        if stdout:
            # Extract additional subdomains from dnsenum
            dnsenum_subs = _parse_dnsenum_subdomains(stdout)
            if dnsenum_subs:
                # Avoid duplicating subdomains already found by dnsrecon
                existing_subdomains: set[str] = set()
                for f in findings:
                    if "Subdomains" in f.title:
                        existing_subdomains = set(f.evidence.splitlines())

                new_subs = [s for s in dnsenum_subs if s not in existing_subdomains]
                if new_subs:
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            title=f"DNS Additional Subdomains (dnsenum) — {len(new_subs)} Found",
                            description=(
                                f"dnsenum found {len(new_subs)} additional subdomain(s) "
                                f"for '{domain}'."
                            ),
                            module=MODULE_NAME,
                            evidence="\n".join(new_subs[:30]),
                        )
                    )

            # Extract MX / NS records
            mx_records = _parse_dnsenum_mx(stdout)
            if mx_records:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title=f"DNS MX Records — {len(mx_records)} Found",
                        description="Mail exchange records discovered via dnsenum.",
                        module=MODULE_NAME,
                        evidence="\n".join(mx_records),
                    )
                )
    else:
        if not shutil.which("dnsenum"):
            logger.info("[%s] dnsenum not found — skipping", MODULE_NAME)
        elif domain == target:
            logger.info("[%s] No domain resolved — skipping dnsenum", MODULE_NAME)

    # ------------------------------------------------------------------
    # If domain was resolved only as IP, try basic dig queries
    # ------------------------------------------------------------------
    if domain == target and shutil.which("dig"):
        # Basic ANY query
        logger.info("[%s] Running basic dig queries against %s", MODULE_NAME, target)
        basic_out = dns_dir / "dig_basic.txt"
        cmd = ["dig", "ANY", target, f"@{target}"]
        rc, stdout, stderr = await run_tool(
            cmd, output_file=basic_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

    # ------------------------------------------------------------------
    # Build result
    # ------------------------------------------------------------------
    combined_output = "\n\n".join(raw_outputs)

    return ModuleResult(
        module_name=MODULE_NAME,
        status="done",
        findings=findings,
        raw_output=combined_output[:10000],
        output_file=dns_dir,
        error_message="",
    )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _extract_line(text: str, keyword: str) -> str:
    """Return the first line from *text* containing *keyword*."""
    for line in text.splitlines():
        if keyword in line:
            return line.strip()
    return ""


def _parse_axfr_output(output: str) -> list[str]:
    """Parse dig AXFR output for DNS records.

    Returns a list of record lines (non-comment, non-empty).
    A successful zone transfer contains lines like::

        example.com.  3600  IN  A  10.10.10.1
    """
    records: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        # Skip comments, blank lines, and status lines
        if not stripped or stripped.startswith(";") or stripped.startswith("<<>>"):
            continue
        # A valid zone record should contain "IN" as the class
        if " IN " in stripped:
            records.append(stripped)
    return records


def _parse_dnsrecon_subdomains(output: str) -> list[str]:
    """Parse dnsrecon output for discovered subdomains.

    Looks for lines like::

        [+] A example.example.com 10.10.10.1
        [+] CNAME www.example.com example.com
    """
    subdomains: list[str] = []
    seen: set[str] = set()
    for line in output.splitlines():
        if line.strip().startswith("[+]"):
            # Extract the hostname portion
            match = re.search(r"\[\+\]\s+\w+\s+(\S+)", line)
            if match:
                hostname = match.group(1)
                if hostname not in seen:
                    seen.add(hostname)
                    subdomains.append(hostname)
    return subdomains


def _parse_dnsrecon_srv(output: str) -> list[str]:
    """Parse dnsrecon output for SRV records.

    Looks for lines like::

        [+] SRV _ldap._tcp.example.com example.com 389
    """
    srv_records: list[str] = []
    for line in output.splitlines():
        if "SRV" in line and line.strip().startswith("[+]"):
            srv_records.append(line.strip())
    return srv_records


def _parse_dnsenum_subdomains(output: str) -> list[str]:
    """Parse dnsenum output for discovered subdomains.

    dnsenum outputs subdomains under a section typically starting
    with a header like "Name Servers" or listing IPs.
    """
    subdomains: list[str] = []
    seen: set[str] = set()
    # Look for host entries — dnsenum prints discovered hosts with IPs
    for line in output.splitlines():
        stripped = line.strip()
        # dnsenum lines for found hosts often have the format: hostname IP
        match = re.match(r"^([\w.-]+\.[\w.-]+)\s+([\d.]+)$", stripped)
        if match:
            hostname = match.group(1)
            if hostname not in seen:
                seen.add(hostname)
                subdomains.append(hostname)
    return subdomains


def _parse_dnsenum_mx(output: str) -> list[str]:
    """Parse dnsenum output for MX records.

    Looks for lines in the MX section.
    """
    mx_records: list[str] = []
    in_mx = False
    for line in output.splitlines():
        stripped = line.strip()
        if "Mail" in stripped and "exchange" in stripped.lower():
            in_mx = True
            continue
        if in_mx:
            if not stripped or stripped.startswith("==="):
                in_mx = False
                continue
            mx_records.append(stripped)
    return mx_records
