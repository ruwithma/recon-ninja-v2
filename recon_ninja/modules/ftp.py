"""FTP reconnaissance module for ReconNinja v2.

Triggered when port 21 is open or the service is identified as ``ftp``.
Checks for anonymous login, banner information, FTP bounce attacks,
and system type enumeration.
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

MODULE_NAME = "ftp"


def _is_ftp_port(state: ScanState) -> bool:
    """Return ``True`` if port 21 is open or the service is FTP."""
    if 21 in state.open_ports:
        return True
    for _port, svc in state.services.items():
        if "ftp" in svc.service.lower():
            return True
    return False


async def run_ftp_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run FTP enumeration against *target*.

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

    if not _is_ftp_port(state):
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            error_message="No FTP port (21) or FTP service found.",
        )

    # Prepare output subdirectory
    ftp_dir = output_dir / "ftp"
    ftp_dir.mkdir(parents=True, exist_ok=True)

    timeout = config.default_timeout

    # ------------------------------------------------------------------
    # 1. nmap FTP scripts — anonymous login, syst, bounce
    # ------------------------------------------------------------------
    if shutil.which("nmap"):
        logger.info("[%s] Running nmap FTP scripts against %s", MODULE_NAME, target)
        nmap_out = ftp_dir / "nmap_ftp.txt"
        cmd = [
            "nmap",
            "-p21",
            "--script", "ftp-anon,ftp-syst,ftp-bounce",
            target,
        ]
        rc, stdout, stderr = await run_tool(
            cmd, output_file=nmap_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        if stdout:
            # --- Banner ---
            banner_match = re.search(
                r"21/tcp\s+open\s+ftp\s+(.*)", stdout, re.IGNORECASE
            )
            banner = banner_match.group(1).strip() if banner_match else ""

            if banner:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title="FTP Banner",
                        description=f"FTP server banner: {banner}",
                        module=MODULE_NAME,
                        evidence=banner,
                    )
                )

                # Check for known vulnerable FTP servers
                vulnerable_keywords = ["vsftpd 2.3.4", "proftpd 1.3.5", "proftpd 1.3.3c"]
                for vk in vulnerable_keywords:
                    if vk in banner.lower():
                        findings.append(
                            Finding(
                                severity=Severity.CRITICAL,
                                title=f"Known Vulnerable FTP Server: {vk}",
                                description=(
                                    f"FTP server banner indicates {vk} — known to have "
                                    f"a backdoor or critical vulnerability."
                                ),
                                module=MODULE_NAME,
                                evidence=banner,
                                suggested_commands=[
                                    f"msfconsole -q -x 'search {vk}'"
                                ],
                            )
                        )
                        break

            # --- Anonymous login ---
            anon_match = re.search(
                r"ftp-anon:.*Anonymous FTP login allowed",
                stdout,
                re.IGNORECASE,
            )
            if anon_match:
                # Try to extract the anonymous login details
                anon_detail = anon_match.group(0).strip()
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title="FTP Anonymous Login Allowed",
                        description=(
                            "The FTP server permits anonymous login — sensitive files "
                            "may be accessible without authentication."
                        ),
                        module=MODULE_NAME,
                        evidence=anon_detail,
                        suggested_commands=[
                            f"ftp {target}",
                            f"lftp -e 'set ftp:passive-mode on; ls; bye' ftp://{target}",
                        ],
                    )
                )
            else:
                # Double-check with a looser pattern
                if "anonymous" in stdout.lower() and "login" in stdout.lower():
                    # nmap ftp-anon can output in different formats
                    for line in stdout.splitlines():
                        if "anonymous" in line.lower() and ("allowed" in line.lower() or "ok" in line.lower()):
                            findings.append(
                                Finding(
                                    severity=Severity.HIGH,
                                    title="FTP Anonymous Login Allowed",
                                    description=(
                                        "The FTP server permits anonymous login — sensitive files "
                                        "may be accessible without authentication."
                                    ),
                                    module=MODULE_NAME,
                                    evidence=line.strip(),
                                    suggested_commands=[
                                        f"ftp {target}",
                                    ],
                                )
                            )
                            break

            # --- FTP system type ---
            syst_match = re.search(r"ftp-syst:.*?\n(.*?)(?:\n\n|\n\||\Z)", stdout, re.DOTALL)
            if syst_match:
                syst_info = syst_match.group(1).strip().strip("|_ ").strip()
                if syst_info:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title="FTP System Type",
                            description="FTP SYST command revealed system information.",
                            module=MODULE_NAME,
                            evidence=syst_info,
                        )
                    )

            # --- FTP bounce ---
            bounce_match = re.search(
                r"ftp-bounce:.*?(open|vulnerable|working)",
                stdout,
                re.IGNORECASE,
            )
            if bounce_match:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title="FTP Bounce Attack Possible",
                        description=(
                            "The FTP server may be vulnerable to FTP bounce / port "
                            "scanning via the PORT command."
                        ),
                        module=MODULE_NAME,
                        evidence=bounce_match.group(0).strip(),
                        suggested_commands=[
                            f"nmap -b anonymous:{target} <victim_ip>",
                        ],
                    )
                )
    else:
        logger.info("[%s] nmap not found — skipping FTP scripts", MODULE_NAME)

    # ------------------------------------------------------------------
    # Build result
    # ------------------------------------------------------------------
    combined_output = "\n\n".join(raw_outputs)

    return ModuleResult(
        module_name=MODULE_NAME,
        status="done",
        findings=findings,
        raw_output=combined_output[:10000],
        output_file=ftp_dir,
        error_message="",
    )
