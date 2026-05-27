"""SNMP reconnaissance module for ReconNinja v2.

Triggered when UDP port 161 is detected.  Brute-forces community
strings, performs full MIB walks on valid communities, and extracts
usernames, running processes, network information, and installed
software.
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

logger = logging.getLogger(__name__)

MODULE_NAME = "snmp"


def _is_snmp_port(state: ScanState) -> bool:
    """Return ``True`` if UDP port 161 was detected."""
    return 161 in state.udp_ports


async def run_snmp_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run SNMP enumeration against *target*.

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

    if not _is_snmp_port(state):
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            error_message="No SNMP port (UDP 161) found.",
        )

    # Prepare output subdirectory
    snmp_dir = output_dir / "snmp"
    snmp_dir.mkdir(parents=True, exist_ok=True)

    timeout = config.default_timeout

    # ------------------------------------------------------------------
    # 1. onesixtyone — community string brute force
    # ------------------------------------------------------------------
    valid_communities: list[str] = []
    if shutil.which("onesixtyone"):
        # Locate SNMP wordlist
        snmp_wordlist = Path("/usr/share/seclists/Discovery/SNMP/snmp.txt")
        if not snmp_wordlist.is_file():
            snmp_wordlist = Path("/usr/share/wordlists/seclists/Discovery/SNMP/snmp.txt")
        if not snmp_wordlist.is_file():
            # Fallback: use a minimal built-in list
            snmp_wordlist = Path("/tmp/recon_ninja_snmp_wordlist.txt")
            snmp_wordlist.write_text("public\nprivate\ncommunity\n", encoding="utf-8")

        logger.info("[%s] Running onesixtyone against %s", MODULE_NAME, target)
        onesixtyone_out = snmp_dir / "onesixtyone.txt"
        cmd = ["onesixtyone", "-c", str(snmp_wordlist), target]
        rc, stdout, stderr = await run_tool(
            cmd, output_file=onesixtyone_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        if stdout:
            valid_communities = _parse_onesixtyone(stdout)
            if valid_communities:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title=f"SNMP Community String(s) Found: {', '.join(valid_communities)}",
                        description=(
                            f"Discovered {len(valid_communities)} valid SNMP community "
                            f"string(s): {', '.join(valid_communities)}. This allows "
                            f"unauthenticated information disclosure."
                        ),
                        module=MODULE_NAME,
                        evidence="\n".join(valid_communities),
                        suggested_commands=[
                            f"snmpwalk -v2c -c {c} {target}" for c in valid_communities
                        ],
                    )
                )
    else:
        logger.info("[%s] onesixtyone not found — skipping community brute", MODULE_NAME)
        # Default to trying 'public' if we can't brute force
        valid_communities = ["public"]

    # ------------------------------------------------------------------
    # 2. snmpwalk — full MIB walk for each valid community
    # ------------------------------------------------------------------
    if shutil.which("snmpwalk") and valid_communities:
        for community in valid_communities:
            logger.info(
                "[%s] Running snmpwalk -c %s against %s",
                MODULE_NAME, community, target,
            )
            walk_out = snmp_dir / f"snmpwalk_{community}.txt"
            cmd = ["snmpwalk", "-v2c", "-c", community, target]
            rc, stdout, stderr = await run_tool(
                cmd, output_file=walk_out, timeout=timeout
            )
            raw_outputs.append(stdout or stderr)

            if stdout and rc == 0:
                # --- Usernames ---
                usernames = _extract_snmp_usernames(stdout)
                if usernames:
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            title=f"SNMP Usernames Discovered ({community})",
                            description=(
                                f"Extracted {len(usernames)} username(s) via SNMP walk "
                                f"with community '{community}'."
                            ),
                            module=MODULE_NAME,
                            evidence="\n".join(usernames[:30]),
                            suggested_commands=[
                                f"hydra -L /tmp/snmp_users.txt -P /usr/share/wordlists/rockyou.txt {target} ssh",
                            ],
                        )
                    )

                # --- Running processes ---
                processes = _extract_snmp_processes(stdout)
                if processes:
                    # Check for interesting processes
                    interesting_procs = _find_interesting_processes(processes)
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title=f"SNMP Running Processes ({community})",
                            description=(
                                f"Discovered {len(processes)} running process(es) via SNMP. "
                                f"{len(interesting_procs)} appear interesting."
                            ),
                            module=MODULE_NAME,
                            evidence="\n".join(processes[:30]),
                        )
                    )
                    for proc in interesting_procs:
                        findings.append(
                            Finding(
                                severity=Severity.MEDIUM,
                                title=f"Interesting Process: {proc}",
                                description=(
                                    f"Potentially interesting process detected via SNMP: {proc}"
                                ),
                                module=MODULE_NAME,
                                evidence=proc,
                            )
                        )

                # --- Network information ---
                network_info = _extract_snmp_network(stdout)
                if network_info:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title=f"SNMP Network Information ({community})",
                            description=(
                                f"Extracted {len(network_info)} network interface/route entries."
                            ),
                            module=MODULE_NAME,
                            evidence="\n".join(network_info[:20]),
                        )
                    )

                # --- Software / installed packages ---
                software = _extract_snmp_software(stdout)
                if software:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title=f"SNMP Installed Software ({community})",
                            description=(
                                f"Discovered {len(software)} installed software item(s) via SNMP."
                            ),
                            module=MODULE_NAME,
                            evidence="\n".join(software[:30]),
                        )
                    )
            elif stdout and "Timeout" in stdout:
                logger.info(
                    "[%s] snmpwalk timed out for community '%s' — skipping further walks",
                    MODULE_NAME, community,
                )
                # Remove invalid community
                if community in valid_communities:
                    valid_communities.remove(community)
    else:
        if not shutil.which("snmpwalk"):
            logger.info("[%s] snmpwalk not found — skipping MIB walk", MODULE_NAME)
        if not valid_communities:
            logger.info("[%s] No valid community strings — skipping MIB walk", MODULE_NAME)

    # If no findings at all, add an info note
    if not findings:
        findings.append(
            Finding(
                severity=Severity.INFO,
                title="SNMP — No Information Extracted",
                description="SNMP enumeration completed but no useful information was extracted.",
                module=MODULE_NAME,
                evidence="",
                suggested_commands=[
                    f"snmpwalk -v2c -c public {target}",
                    f"snmpwalk -v1 -c public {target}",
                ],
            )
        )

    # ------------------------------------------------------------------
    # Build result
    # ------------------------------------------------------------------
    combined_output = "\n\n".join(raw_outputs)

    return ModuleResult(
        module_name=MODULE_NAME,
        status="done",
        findings=findings,
        raw_output=combined_output[:10000],
        output_file=snmp_dir,
        error_message="",
    )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_onesixtyone(output: str) -> list[str]:
    """Parse onesixtyone output for valid community strings.

    Looks for lines like::

        10.10.10.1 [public] Linux 4.15.0-112-generic ...
    """
    communities: list[str] = []
    for line in output.splitlines():
        match = re.search(r"\[(\S+)\]", line)
        if match:
            community = match.group(1)
            if community not in communities:
                communities.append(community)
    return communities


def _extract_snmp_usernames(output: str) -> list[str]:
    """Extract usernames from snmpwalk output.

    Searches OIDs commonly associated with user accounts:
    - 1.3.6.1.4.1.77.1.2.25 (Windows user accounts)
    - 1.3.6.1.2.1.25.1.5.0 (hrSystemNumUsers)
    - STRING entries that look like usernames
    """
    usernames: list[str] = []
    seen: set[str] = set()

    # Windows user OID
    for line in output.splitlines():
        if "1.3.6.1.4.1.77.1.2.25" in line:
            match = re.search(r'STRING:\s*"([^"]+)"', line)
            if match:
                username = match.group(1)
                if username not in seen:
                    seen.add(username)
                    usernames.append(username)

    # Linux/Unix user OID (hrSWRunName / hrSWRunPath)
    for line in output.splitlines():
        if "1.3.6.1.2.1.25.4.2.1" in line:
            match = re.search(r'STRING:\s*"([^"]+)"', line)
            if match:
                proc_name = match.group(1)
                # Some process names indicate user sessions
                if proc_name not in seen and not proc_name.startswith("/"):
                    # Filter obvious non-usernames
                    if not any(kw in proc_name.lower() for kw in ("daemon", "system", "kernel")):
                        seen.add(proc_name)
                        usernames.append(proc_name)

    return usernames


def _extract_snmp_processes(output: str) -> list[str]:
    """Extract running process names from snmpwalk output.

    Searches OID 1.3.6.1.2.1.25.4.2.1 (hrSWRunName).
    """
    processes: list[str] = []
    for line in output.splitlines():
        if "1.3.6.1.2.1.25.4.2.1.2" in line or "hrSWRunName" in line:
            match = re.search(r'STRING:\s*"([^"]+)"', line)
            if match:
                proc = match.group(1)
                if proc not in processes:
                    processes.append(proc)
    return processes


def _find_interesting_processes(processes: list[str]) -> list[str]:
    """Filter process names for potentially interesting services.

    Looks for keywords that suggest vulnerable or high-value services.
    """
    interesting_keywords = {
        "apache", "nginx", "httpd", "tomcat", "iis",
        "mysql", "postgres", "mssql", "oracle", "redis", "mongo",
        "ssh", "sshd", "telnet", "ftp", "vsftpd", "proftpd",
        "smb", "samba", "nmbd", "winbindd",
        "vnc", "x11", "xorg",
        "java", "python", "node", "ruby",
        "docker", "containerd",
    }
    interesting: list[str] = []
    for proc in processes:
        proc_lower = proc.lower()
        if any(kw in proc_lower for kw in interesting_keywords):
            interesting.append(proc)
    return interesting


def _extract_snmp_network(output: str) -> list[str]:
    """Extract network interface and routing information from snmpwalk.

    Searches OIDs related to:
    - 1.3.6.1.2.1.4.20.1 (ipAddrTable)
    - 1.3.6.1.2.1.2.2.1 (ifTable)
    - 1.3.6.1.2.1.4.24.4 (ipCidrRouteTable)
    """
    network_info: list[str] = []
    for line in output.splitlines():
        if any(oid in line for oid in ("1.3.6.1.2.1.4.20.1", "1.3.6.1.2.1.2.2.1", "1.3.6.1.2.1.4.24.4")):
            network_info.append(line.strip())
    return network_info


def _extract_snmp_software(output: str) -> list[str]:
    """Extract installed software information from snmpwalk.

    Searches OID 1.3.6.1.2.1.25.6.3.1.2 (hrSWInstalledName).
    """
    software: list[str] = []
    for line in output.splitlines():
        if "1.3.6.1.2.1.25.6.3.1.2" in line or "hrSWInstalledName" in line:
            match = re.search(r'STRING:\s*"([^"]+)"', line)
            if match:
                sw = match.group(1)
                if sw not in software:
                    software.append(sw)
    return software
