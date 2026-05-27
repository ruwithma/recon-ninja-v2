"""RDP reconnaissance module for ReconNinja v2.

Triggered when port 3389 (RDP) is detected open.  Checks encryption
level, NLA (Network Level Authentication) status, and tests for
critical vulnerabilities including BlueKeep (CVE-2019-0708).

Key findings
------------
- NLA disabled (HIGH) — no pre-auth required
- BlueKeep vulnerability (CRITICAL) — CVE-2019-0708
- MS12-020 vulnerability (HIGH)
- RDP encryption level (INFO)
"""

from __future__ import annotations

import logging
import re
import shutil
import time
from pathlib import Path

from recon_ninja.core.models import Finding, ModuleResult, ReconConfig, ScanState, Severity
from recon_ninja.core.runner import run_tool
from recon_ninja.core.utils import module_guard

logger = logging.getLogger(__name__)

MODULE_NAME = "rdp"


@module_guard()
async def run_rdp_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run RDP enumeration against *target*.

    Triggered when port 3389 is open.

    Parameters
    ----------
    target:
        IP address or hostname of the target.
    state:
        Current scan state with discovered services and hostnames.
    config:
        Active reconnaissance configuration.
    output_dir:
        Directory to write raw tool output files.

    Returns
    -------
    ModuleResult
        Aggregated findings from RDP enumeration.
    """
    start = time.monotonic()
    findings: list[Finding] = []
    raw_outputs: list[str] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Check trigger port ───────────────────────────────────────────────
    if 3389 not in state.open_ports:
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            duration_seconds=time.monotonic() - start,
            error_message="Port 3389 (RDP) not found open",
        )

    # ── 1. nmap RDP encryption & MS12-020 check ─────────────────────────
    if shutil.which("nmap"):
        nmap_enc_out = output_dir / "rdp_nmap_encryption.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "nmap",
                "-p3389",
                "--script", "rdp-enum-encryption,rdp-vuln-ms12-020",
                target,
            ],
            output_file=nmap_enc_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout:
            # ── Check NLA status ─────────────────────────────────────────
            # rdp-enum-encryption typically reports:
            #   "Security layer: CredSSP (NLA)"
            #   or "Security layer: RDSTLS" / "RDP" (no NLA)
            if "rdp-enum-encryption" in stdout:
                if re.search(r"CredSSP.*NLA", stdout, re.IGNORECASE):
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title="RDP NLA Enabled",
                            description=(
                                f"RDP on {target}:3389 requires Network Level "
                                f"Authentication (NLA / CredSSP). This is the "
                                f"recommended configuration."
                            ),
                            module=MODULE_NAME,
                            evidence=re.search(
                                r"rdp-enum-encryption:.*?(?:\n\n|\Z)",
                                stdout,
                                re.DOTALL,
                            )
                            .group(0)
                            .strip()[:1000],
                        )
                    )
                else:
                    # No NLA detected — could be vulnerable to pre-auth attacks
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title="RDP NLA Disabled",
                            description=(
                                f"RDP on {target}:3389 does NOT require Network "
                                f"Level Authentication. Without NLA, the server "
                                f"is vulnerable to pre-authentication attacks "
                                f"and credential stuffing."
                            ),
                            module=MODULE_NAME,
                            evidence=re.search(
                                r"rdp-enum-encryption:.*?(?:\n\n|\Z)",
                                stdout,
                                re.DOTALL,
                            )
                            .group(0)
                            .strip()[:1000],
                            suggested_commands=[
                                f"xfreerdp /v:{target} /u:admin /p:password +auth-only",
                                f"rdesktop {target}",
                            ],
                        )
                    )

            # ── Check encryption level ───────────────────────────────────
            enc_match = re.search(r"Encryption level:\s*(.+)", stdout, re.IGNORECASE)
            if enc_match:
                enc_level = enc_match.group(1).strip()
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title="RDP Encryption Level",
                        description=f"RDP encryption level on {target}: {enc_level}",
                        module=MODULE_NAME,
                        evidence=enc_level,
                    )
                )

            # ── Check MS12-020 ──────────────────────────────────────────
            if "ms12-020" in stdout.lower():
                if re.search(r"VULNERABLE", stdout, re.IGNORECASE):
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title="RDP Vulnerable to MS12-020",
                            description=(
                                f"RDP on {target}:3389 is vulnerable to "
                                f"MS12-020 (CVE-2012-0152), a remote code "
                                f"execution vulnerability in the Remote "
                                f"Desktop Protocol."
                            ),
                            module=MODULE_NAME,
                            evidence=re.search(
                                r"rdp-vuln-ms12-020:.*?(?:\n\n|\Z)",
                                stdout,
                                re.DOTALL,
                            )
                            .group(0)
                            .strip()[:1000],
                            cve="CVE-2012-0152",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title="RDP Not Vulnerable to MS12-020",
                            description=f"RDP on {target}:3389 does not appear vulnerable to MS12-020.",
                            module=MODULE_NAME,
                        )
                    )
    else:
        logger.warning("nmap not found — skipping RDP encryption & MS12-020 checks")

    # ── 2. nmap BlueKeep check (CVE-2019-0708) ─────────────────────────
    if shutil.which("nmap"):
        bluekeep_out = output_dir / "rdp_nmap_bluekeep.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "nmap",
                "-p3389",
                "--script", "rdp-vuln-ms19-0708",
                target,
            ],
            output_file=bluekeep_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout:
            if "ms19-0708" in stdout.lower() or "bluekeep" in stdout.lower():
                if re.search(r"VULNERABLE", stdout, re.IGNORECASE):
                    findings.append(
                        Finding(
                            severity=Severity.CRITICAL,
                            title="RDP Vulnerable to BlueKeep (CVE-2019-0708)",
                            description=(
                                f"RDP on {target}:3389 is VULNERABLE to "
                                f"BlueKeep (CVE-2019-0708). This is a "
                                f"wormable, unauthenticated remote code "
                                f"execution vulnerability affecting Windows "
                                f"XP through Server 2008 R2. PATCH IMMEDIATELY."
                            ),
                            module=MODULE_NAME,
                            evidence=re.search(
                                r"rdp-vuln-ms19-0708:.*?(?:\n\n|\Z)",
                                stdout,
                                re.DOTALL,
                            )
                            .group(0)
                            .strip()[:1000],
                            cve="CVE-2019-0708",
                            suggested_commands=[
                                f"nmap -p3389 --script rdp-vuln-ms19-0708 {target}",
                                "msfconsole -x 'use exploit/windows/rdp/cve_2019_0708_bluekeep_rce'",
                            ],
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title="RDP Not Vulnerable to BlueKeep",
                            description=(
                                f"RDP on {target}:3389 does not appear "
                                f"vulnerable to BlueKeep (CVE-2019-0708)."
                            ),
                            module=MODULE_NAME,
                        )
                    )
    # No else needed — already warned about nmap above

    # ── 3. Suggested RDP tools ──────────────────────────────────────────
    tool_suggestions: list[str] = []
    if shutil.which("xfreerdp"):
        tool_suggestions.append(f"xfreerdp /v:{target} /u:<USER> /p:<PASS> /cert:ignore")
    else:
        tool_suggestions.append(f"xfreerdp /v:{target} /u:<USER> /p:<PASS> /cert:ignore")

    if shutil.which("rdesktop"):
        tool_suggestions.append(f"rdesktop {target}")
    else:
        tool_suggestions.append(f"rdesktop {target}")

    findings.append(
        Finding(
            severity=Severity.INFO,
            title="RDP Connection Tools",
            description=(
                "RDP service is open. Use the following tools to attempt "
                "authentication and connection."
            ),
            module=MODULE_NAME,
            evidence=f"Port 3389 open on {target}",
            suggested_commands=tool_suggestions,
        )
    )

    # ── Build result ─────────────────────────────────────────────────────
    combined_output = "\n\n".join(raw_outputs)
    elapsed = time.monotonic() - start

    return ModuleResult(
        module_name=MODULE_NAME,
        status="done",
        findings=findings,
        raw_output=combined_output[:5000],
        output_file=output_dir / "rdp_summary.txt",
        duration_seconds=elapsed,
    )
