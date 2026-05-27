"""SMB reconnaissance module for Recon Ninja v2.

Triggered when ports 139 or 445 are open, or when the service is
identified as ``netbios-ssn`` / ``microsoft-ds``.  Enumerates shares,
checks for anonymous/guest access, and tests for critical SMB
vulnerabilities (EternalBlue, SMBGhost).
"""

from __future__ import annotations

import logging
import re
import shutil
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

MODULE_NAME = "smb"


def _is_smb_port(state: ScanState) -> bool:
    """Return ``True`` if any SMB-related port (139, 445) is open."""
    return any(p in state.open_ports for p in (139, 445))


async def run_smb_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run SMB enumeration against *target*.

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
    suggested_cmds: list[str] = []

    # Quick check — if no SMB ports, skip
    if not _is_smb_port(state):
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            error_message="No SMB ports (139/445) found open.",
        )

    # Prepare output subdirectory
    smb_dir = output_dir / "smb"
    smb_dir.mkdir(parents=True, exist_ok=True)

    timeout = config.default_timeout

    # ------------------------------------------------------------------
    # 1. enum4linux-ng / enum4linux — full enumeration
    # ------------------------------------------------------------------
    enum_tool: str | None = None
    if shutil.which("enum4linux-ng"):
        enum_tool = "enum4linux-ng"
    elif shutil.which("enum4linux"):
        enum_tool = "enum4linux"

    if enum_tool:
        logger.info("[%s] Running %s against %s", MODULE_NAME, enum_tool, target)
        enum_out = smb_dir / "enum4linux.txt"
        if enum_tool == "enum4linux-ng":
            cmd = ["enum4linux-ng", "-A", target, "-oA", str(smb_dir / "enum4linux")]
        else:
            cmd = ["enum4linux", "-a", target]

        rc, stdout, stderr = await run_tool(
            cmd, output_file=enum_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        # Parse anonymous / guest access
        if stdout:
            if re.search(r"Anonymous access.*(?:OK|SUCCESS|allowed|enabled)", stdout, re.IGNORECASE):
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title="SMB Anonymous Access Enabled",
                        description="The SMB server allows anonymous (null session) access.",
                        module=MODULE_NAME,
                        evidence=_extract_line(stdout, "Anonymous"),
                        suggested_commands=[f"smbclient -L //{target}/ -N"],
                    )
                )

            if re.search(r"Guest access.*(?:OK|SUCCESS|allowed|enabled)", stdout, re.IGNORECASE):
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title="SMB Guest Access Enabled",
                        description="The SMB server allows guest access without authentication.",
                        module=MODULE_NAME,
                        evidence=_extract_line(stdout, "Guest"),
                        suggested_commands=[f"smbclient -L //{target}/ -U 'guest%'"],
                    )
                )

            # Extract OS / domain info
            os_match = re.search(r"OS:\s*(.+)", stdout)
            domain_match = re.search(r"Domain:\s*(.+)", stdout)
            if os_match or domain_match:
                info_parts: list[str] = []
                if os_match:
                    info_parts.append(f"OS: {os_match.group(1).strip()}")
                if domain_match:
                    info_parts.append(f"Domain: {domain_match.group(1).strip()}")
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title="SMB OS/Domain Information",
                        description="SMB enumeration revealed OS and domain details.",
                        module=MODULE_NAME,
                        evidence=" | ".join(info_parts),
                    )
                )
    else:
        logger.info("[%s] enum4linux-ng / enum4linux not found — skipping", MODULE_NAME)

    # ------------------------------------------------------------------
    # 2. smbclient — null session share listing
    # ------------------------------------------------------------------
    if shutil.which("smbclient"):
        logger.info("[%s] Running smbclient share listing against %s", MODULE_NAME, target)
        smb_out = smb_dir / "smbclient_shares.txt"
        cmd = ["smbclient", "-L", f"//{target}/", "-N"]
        rc, stdout, stderr = await run_tool(
            cmd, output_file=smb_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        if stdout and rc == 0:
            shares = _parse_smbclient_shares(stdout)
            if shares:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title="SMB Shares Discovered (Null Session)",
                        description=f"Found {len(shares)} share(s) via null session enumeration.",
                        module=MODULE_NAME,
                        evidence="\n".join(shares),
                        suggested_commands=[
                            f"smbclient //{target}/{s} -N" for s in shares
                        ],
                    )
                )
    else:
        logger.info("[%s] smbclient not found — skipping share listing", MODULE_NAME)

    # ------------------------------------------------------------------
    # 3. smbmap — share permissions
    # ------------------------------------------------------------------
    if shutil.which("smbmap"):
        logger.info("[%s] Running smbmap against %s", MODULE_NAME, target)
        smbmap_out = smb_dir / "smbmap.txt"

        # Null session
        cmd = ["smbmap", "-H", target, "-u", "", "-p", ""]
        rc, stdout, stderr = await run_tool(
            cmd, output_file=smbmap_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        readable_shares: list[str] = []
        writable_shares: list[str] = []

        if stdout:
            readable_shares, writable_shares = _parse_smbmap_permissions(stdout)

        # Retry with guest if null session found nothing
        if not readable_shares and not writable_shares:
            cmd_guest = ["smbmap", "-H", target, "-u", "guest", "-p", ""]
            rc2, stdout2, stderr2 = await run_tool(
                cmd_guest, timeout=timeout
            )
            raw_outputs.append(stdout2 or stderr2)
            if stdout2:
                readable_shares, writable_shares = _parse_smbmap_permissions(stdout2)

        if writable_shares:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Writable SMB Shares Found",
                    description=f"Found {len(writable_shares)} writable share(s) — potential for file drop / lateral movement.",
                    module=MODULE_NAME,
                    evidence="\n".join(writable_shares),
                    suggested_commands=[
                        f"smbclient //{target}/{s} -N" for s in writable_shares
                    ],
                )
            )

        if readable_shares:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="Readable SMB Shares Found",
                    description=f"Found {len(readable_shares)} readable share(s) — data exfiltration risk.",
                    module=MODULE_NAME,
                    evidence="\n".join(readable_shares),
                    suggested_commands=[
                        f"smbclient //{target}/{s} -N" for s in readable_shares
                    ],
                )
            )
    else:
        logger.info("[%s] smbmap not found — skipping", MODULE_NAME)

    # ------------------------------------------------------------------
    # 4. nmap SMB vulnerability scripts (EternalBlue, SMBGhost)
    # ------------------------------------------------------------------
    if shutil.which("nmap"):
        logger.info("[%s] Running nmap SMB vuln scripts against %s", MODULE_NAME, target)
        nmap_vuln_out = smb_dir / "nmap_smb_vulns.txt"
        cmd = [
            "nmap",
            "-p445",
            "--script", "smb-vuln-ms17-010,smb-vuln-cve-2020-0796",
            target,
        ]
        rc, stdout, stderr = await run_tool(
            cmd, output_file=nmap_vuln_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        if stdout:
            if "VULNERABLE" in stdout and "ms17-010" in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        title="MS17-010 EternalBlue Vulnerable",
                        description="The target is vulnerable to MS17-010 EternalBlue — unauthenticated RCE.",
                        module=MODULE_NAME,
                        evidence=_extract_line(stdout, "VULNERABLE"),
                        cve="CVE-2017-0144",
                        suggested_commands=["msfconsole -q -x 'use exploit/windows/smb/ms17_010_eternalblue'"],
                    )
                )

            if "VULNERABLE" in stdout and "cve-2020-0796" in stdout.lower():
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        title="CVE-2020-0796 SMBGhost Vulnerable",
                        description="The target is vulnerable to SMBGhost (CVE-2020-0796) — SMBv3 compression RCE.",
                        module=MODULE_NAME,
                        evidence=_extract_line(stdout, "VULNERABLE"),
                        cve="CVE-2020-0796",
                        suggested_commands=[
                            "msfconsole -q -x 'use exploit/windows/smb/cve_2020_0796_smbghost'"
                        ],
                    )
                )
    else:
        logger.info("[%s] nmap not found — skipping SMB vuln scripts", MODULE_NAME)

    # ------------------------------------------------------------------
    # 5. crackmapexec — signing status, null session
    # ------------------------------------------------------------------
    if shutil.which("crackmapexec"):
        logger.info("[%s] Running crackmapexec smb against %s", MODULE_NAME, target)
        cme_out = smb_dir / "crackmapexec.txt"
        cmd = ["crackmapexec", "smb", target, "-u", "", "-p", ""]
        rc, stdout, stderr = await run_tool(
            cmd, output_file=cme_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        if stdout:
            # Signing status — capture multi-word values like "not required"
            signing_match = re.search(r"signing:?\s+(.+?)(?:\s{2,}|\n|$)", stdout, re.IGNORECASE)
            if signing_match:
                signing_val = signing_match.group(1).strip()
                if signing_val.lower() in ("not required", "false", "disabled", "(not required)"):
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            title="SMB Signing Not Required",
                            description="SMB signing is not required — susceptible to relay attacks.",
                            module=MODULE_NAME,
                            evidence=signing_match.group(0).strip(),
                            suggested_commands=[
                                "ntlmrelayx.py -tf targets.txt -smb2support"
                            ],
                        )
                    )

            # Null session from CME
            if "(pwless)" in stdout.lower() or "null" in stdout.lower():
                if not any("Anonymous Access" in f.title for f in findings):
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title="SMB Null Session (CME)",
                            description="CrackMapExec confirmed null session access.",
                            module=MODULE_NAME,
                            evidence=_extract_line(stdout, "(pwless)") or _extract_line(stdout, "null"),
                        )
                    )
    else:
        logger.info("[%s] crackmapexec not found — skipping", MODULE_NAME)

    # ------------------------------------------------------------------
    # Build result
    # ------------------------------------------------------------------
    combined_output = "\n\n".join(raw_outputs)

    return ModuleResult(
        module_name=MODULE_NAME,
        status="done",
        findings=findings,
        raw_output=combined_output[:10000],
        output_file=smb_dir,
        error_message="",
    )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _extract_line(text: str, keyword: str) -> str:
    """Return the first line from *text* containing *keyword* (case-insensitive)."""
    for line in text.splitlines():
        if keyword.lower() in line.lower():
            return line.strip()
    return ""


def _parse_smbclient_shares(output: str) -> list[str]:
    """Extract share names from ``smbclient -L`` output.

    Looks for lines like::

        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share

    Returns a list of share names (trailing ``$`` included).
    """
    shares: list[str] = []
    # Share block starts after a header line containing "Sharename"
    in_shares = False
    for line in output.splitlines():
        if "Sharename" in line or "sharename" in line.lower():
            in_shares = True
            continue
        if in_shares:
            # Skip separator lines like "--------- ------- -------"
            if line.strip().startswith("---"):
                continue
            # End of share section — a blank line or a different section header
            if not line.strip() or line.startswith("Server") or line.startswith("Workgroup"):
                break
            parts = line.split()
            if len(parts) >= 2 and parts[1] in ("Disk", "IPC", "Printer"):
                shares.append(parts[0])
    return shares


def _parse_smbmap_permissions(output: str) -> tuple[list[str], list[str]]:
    """Parse smbmap output for readable and writable shares.

    Returns:
        A tuple of ``(readable_shares, writable_shares)``.
    """
    readable: list[str] = []
    writable: list[str] = []
    for line in output.splitlines():
        # smbmap lines look like:
        # disk    READ, WRITE    /path/share
        lower = line.lower()
        parts = line.split()
        if not parts:
            continue
        # Detect share name + permission columns
        if "read" in lower and "write" in lower:
            # Writable share
            for p in parts:
                if p not in ("READ,", "READ", "WRITE", "NO", "ACCESS", "disk", "print", "IPC"):
                    if p not in writable:
                        writable.append(p)
                    break
        elif "read" in lower:
            for p in parts:
                if p not in ("READ,", "READ", "NO", "ACCESS", "disk", "print", "IPC"):
                    if p not in readable:
                        readable.append(p)
                    break
    return readable, writable
