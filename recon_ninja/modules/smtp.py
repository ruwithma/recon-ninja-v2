"""SMTP reconnaissance module for ReconNinja v2.

Triggered when ports 25, 465, or 587 are open or the service is
identified as ``smtp``.  Enumerates supported commands, tests for
open relay, attempts user enumeration via VRFY, and extracts NTLM
domain information.
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

MODULE_NAME = "smtp"

# Ports commonly associated with SMTP
SMTP_PORTS = {25, 465, 587}


def _get_smtp_port(state: ScanState) -> int | None:
    """Return the first SMTP port from scan state, or ``None``."""
    for port in SMTP_PORTS:
        if port in state.open_ports:
            return port
    # Fallback: check by service name
    for port, svc in state.services.items():
        if "smtp" in svc.service.lower():
            return port
    return None


@module_guard()
async def run_smtp_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run SMTP enumeration against *target*.

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

    smtp_port = _get_smtp_port(state)
    if smtp_port is None:
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            error_message="No SMTP port (25/465/587) or SMTP service found.",
        )

    # Prepare output subdirectory
    smtp_dir = output_dir / "smtp"
    smtp_dir.mkdir(parents=True, exist_ok=True)

    timeout = config.default_timeout

    # ------------------------------------------------------------------
    # 1. nmap SMTP scripts — commands, open relay, NTLM info
    # ------------------------------------------------------------------
    if shutil.which("nmap"):
        logger.info(
            "[%s] Running nmap SMTP scripts against %s:%d",
            MODULE_NAME, target, smtp_port,
        )
        nmap_out = smtp_dir / "nmap_smtp.txt"
        cmd = [
            "nmap",
            f"-p{smtp_port}",
            "--script", "smtp-commands,smtp-open-relay,smtp-ntlm-info",
            target,
        ]
        rc, stdout, stderr = await run_tool(
            cmd, output_file=nmap_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        if stdout:
            # --- Banner ---
            banner_match = re.search(
                rf"{smtp_port}/tcp\s+open\s+smtp\s+(.*)",
                stdout,
                re.IGNORECASE,
            )
            banner = banner_match.group(1).strip() if banner_match else ""
            if banner:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title="SMTP Banner",
                        description=f"SMTP server banner: {banner}",
                        module=MODULE_NAME,
                        evidence=banner,
                    )
                )

            # --- Supported commands ---
            commands_match = re.search(
                r"smtp-commands:.*?\n(.*?)(?:\n\n|\n\||\Z)",
                stdout,
                re.DOTALL,
            )
            if commands_match:
                commands_raw = commands_match.group(0).strip()
                # Extract the actual command list
                cmd_line_match = re.search(
                    r"smtp-commands:\s*(.+?)(?:\n|$)", stdout, re.DOTALL
                )
                if cmd_line_match:
                    cmd_list = cmd_line_match.group(1).strip()
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title="SMTP Supported Commands",
                            description="The SMTP server advertised the following commands.",
                            module=MODULE_NAME,
                            evidence=cmd_list,
                        )
                    )

                # Check for VRFY/EXPN/RCPT which enable user enumeration
                if re.search(r"\bVRFY\b", commands_raw, re.IGNORECASE):
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            title="SMTP VRFY Command Enabled",
                            description=(
                                "The VRFY command is enabled — can be used to "
                                "enumerate valid user accounts."
                            ),
                            module=MODULE_NAME,
                            evidence=_extract_command_line(commands_raw, "VRFY"),
                            suggested_commands=[
                                f"smtp-user-enum -M VRFY -U /usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt -t {target} -p {smtp_port}",
                            ],
                        )
                    )

                if re.search(r"\bEXPN\b", commands_raw, re.IGNORECASE):
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            title="SMTP EXPN Command Enabled",
                            description=(
                                "The EXPN command is enabled — can be used to "
                                "expand mailing lists and enumerate users."
                            ),
                            module=MODULE_NAME,
                            evidence=_extract_command_line(commands_raw, "EXPN"),
                        )
                    )

            # --- Open relay ---
            relay_match = re.search(
                r"smtp-open-relay:.*?(open relay|relay is open|Server is an open relay)",
                stdout,
                re.IGNORECASE,
            )
            if relay_match:
                findings.append(
                    Finding(
                        severity=Severity.CRITICAL,
                        title="SMTP Open Relay Detected",
                        description=(
                            "The SMTP server is configured as an open relay — "
                            "unauthenticated attackers can send emails through it, "
                            "enabling spam and phishing."
                        ),
                        module=MODULE_NAME,
                        evidence=relay_match.group(0).strip(),
                        suggested_commands=[
                            (
                                f"swaks --to victim@example.com --from attacker@evil.com "
                                f"--server {target} --port {smtp_port}"
                            ),
                        ],
                    )
                )

            # --- NTLM info ---
            ntlm_match = re.search(
                r"smtp-ntlm-info:.*?\n(.*?)(?:\n\n|\n\||\Z)",
                stdout,
                re.DOTALL,
            )
            if ntlm_match:
                ntlm_info = ntlm_match.group(0).strip()
                # Extract domain and NetBIOS name
                domain_match = re.search(r"Domain_Name:\s*(\S+)", ntlm_info)
                netbios_match = re.search(r"NetBIOS_Computer_Name:\s*(\S+)", ntlm_info)

                ntlm_parts: list[str] = []
                if domain_match:
                    ntlm_parts.append(f"Domain: {domain_match.group(1)}")
                if netbios_match:
                    ntlm_parts.append(f"NetBIOS: {netbios_match.group(1)}")

                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title="SMTP NTLM Information",
                        description="NTLM authentication revealed domain and computer name.",
                        module=MODULE_NAME,
                        evidence=" | ".join(ntlm_parts) if ntlm_parts else ntlm_info,
                    )
                )
    else:
        logger.info("[%s] nmap not found — skipping SMTP scripts", MODULE_NAME)

    # ------------------------------------------------------------------
    # 2. smtp-user-enum — user enumeration via VRFY
    # ------------------------------------------------------------------
    if shutil.which("smtp-user-enum"):
        # Locate wordlist
        wordlist_path = Path(
            "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
        )
        if not wordlist_path.is_file():
            # Try smaller wordlist
            wordlist_path = Path("/usr/share/seclists/Usernames/names.txt")
        if not wordlist_path.is_file():
            wordlist_path = Path("/usr/share/wordlists/dirb/big.txt")

        if wordlist_path.is_file():
            logger.info(
                "[%s] Running smtp-user-enum against %s:%d",
                MODULE_NAME, target, smtp_port,
            )
            enum_out = smtp_dir / "smtp_user_enum.txt"
            cmd = [
                "smtp-user-enum",
                "-M", "VRFY",
                "-U", str(wordlist_path),
                "-t", target,
                "-p", str(smtp_port),
            ]
            rc, stdout, stderr = await run_tool(
                cmd, output_file=enum_out, timeout=timeout
            )
            raw_outputs.append(stdout or stderr)

            if stdout:
                # Count valid users found
                valid_users = _parse_smtp_user_enum(stdout)
                if valid_users:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title=f"SMTP User Enumeration — {len(valid_users)} User(s) Found",
                            description=(
                                f"smtp-user-enum identified {len(valid_users)} valid "
                                f"user account(s) via VRFY."
                            ),
                            module=MODULE_NAME,
                            evidence="\n".join(valid_users[:20]),  # cap at 20 lines
                            suggested_commands=[
                                f"hydra -L {wordlist_path} -P /usr/share/wordlists/rockyou.txt {target} smtp -s {smtp_port}",
                            ],
                        )
                    )
        else:
            logger.info("[%s] No username wordlist found — skipping smtp-user-enum", MODULE_NAME)
    else:
        logger.info("[%s] smtp-user-enum not found — skipping", MODULE_NAME)

    # ------------------------------------------------------------------
    # Build result
    # ------------------------------------------------------------------
    combined_output = "\n\n".join(raw_outputs)

    return ModuleResult(
        module_name=MODULE_NAME,
        status="done",
        findings=findings,
        raw_output=combined_output[:10000],
        output_file=smtp_dir,
        error_message="",
    )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _extract_command_line(text: str, command: str) -> str:
    """Return the line from *text* that mentions *command*."""
    for line in text.splitlines():
        if command in line:
            return line.strip()
    return ""


def _parse_smtp_user_enum(output: str) -> list[str]:
    """Parse smtp-user-enum output for valid usernames.

    Looks for lines indicating a successful VRFY/RCPT response such as::

        252 admin
        250 2.1.5 user@domain.com
    """
    valid: list[str] = []
    for line in output.splitlines():
        stripped = line.strip()
        # smtp-user-enum marks found users with 252 or 250 response codes
        if re.match(r"^(252|250)\s", stripped):
            # Extract the username part
            parts = stripped.split(None, 1)
            if len(parts) > 1:
                valid.append(parts[1].strip())
    return valid
