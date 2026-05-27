"""WinRM reconnaissance module for Recon Ninja v2.

Triggered when ports 5985 (WinRM HTTP) or 5986 (WinRM HTTPS) are
detected open.  Enumerates the WinRM service and authentication
mechanism using nmap NSE scripts.

WinRM (Windows Remote Management) provides remote shell access on
Windows hosts.  An open WinRM port often means ``evil-winrm`` or
PowerShell Remoting can be used for lateral movement once credentials
are obtained.

Key findings
------------
- WinRM open with suggested attack command (HIGH)
- WinRM over HTTP vs HTTPS (INFO)
"""

from __future__ import annotations

import logging
import re
import shutil
import time
from pathlib import Path

from recon_ninja.core.models import Finding, ModuleResult, ReconConfig, ScanState, Severity
from recon_ninja.core.runner import run_tool

logger = logging.getLogger(__name__)

MODULE_NAME = "winrm"

# Well-known WinRM ports
WINRM_HTTP_PORT = 5985
WINRM_HTTPS_PORT = 5986


async def run_winrm_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run WinRM enumeration against *target*.

    Triggered when port 5985 (HTTP) or 5986 (HTTPS) is open.

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
        Aggregated findings from WinRM enumeration.
    """
    start = time.monotonic()
    findings: list[Finding] = []
    raw_outputs: list[str] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Check trigger ports ──────────────────────────────────────────────
    open_ports = set(state.open_ports)
    winrm_ports = {WINRM_HTTP_PORT, WINRM_HTTPS_PORT}
    active_winrm_ports = winrm_ports.intersection(open_ports)
    if not active_winrm_ports:
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            duration_seconds=time.monotonic() - start,
            error_message="No WinRM ports (5985/5986) found open",
        )

    # ── 1. nmap http-auth-finder on WinRM HTTP port ─────────────────────
    if shutil.which("nmap"):
        # Enumerate each active WinRM port
        for port in sorted(active_winrm_ports):
            nmap_out = output_dir / f"winrm_nmap_{port}.txt"
            rc, stdout, stderr = await run_tool(
                cmd=[
                    "nmap",
                    f"-p{port}",
                    "--script", "http-auth-finder",
                    target,
                ],
                output_file=nmap_out,
                timeout=config.default_timeout,
            )
            raw_outputs.append(stdout or stderr)

            if rc == 0 and stdout:
                # Determine the transport protocol
                transport = "HTTPS" if port == WINRM_HTTPS_PORT else "HTTP"
                scheme = "https" if port == WINRM_HTTPS_PORT else "http"

                # Extract auth type from nmap output
                auth_match = re.search(
                    r"(?:auth|authentication)\s*(?:scheme|type|method)?\s*:\s*(.+)",
                    stdout,
                    re.IGNORECASE,
                )
                auth_type = auth_match.group(1).strip() if auth_match else "unknown"

                # ── WinRM open finding ──────────────────────────────────
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title=f"WinRM Open ({transport}) on Port {port}",
                        description=(
                            f"WinRM is accessible on {target}:{port} "
                            f"over {transport}. Authentication type detected: "
                            f"{auth_type}. If valid credentials are obtained, "
                            f"an attacker can execute arbitrary commands on the "
                            f"target via a remote shell."
                        ),
                        module=MODULE_NAME,
                        evidence=stdout[:2000],
                        suggested_commands=[
                            f"evil-winrm -i {target} -u <USER> -p <PASS>",
                            f"evil-winrm -i {target} -u <USER> -H <NTLM_HASH>",
                            f"crackmapexec winrm {target} -u <USER> -p <PASS>",
                        ],
                    )
                )

                # ── HTTP vs HTTPS note ──────────────────────────────────
                if port == WINRM_HTTPS_PORT:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title="WinRM over HTTPS (Port 5986)",
                            description=(
                                f"WinRM on {target}:5986 uses HTTPS/TLS. "
                                f"This encrypts the transport but does not "
                                f"reduce the risk if credentials are compromised. "
                                f"Note: self-signed certificates may cause "
                                f"connection errors — use -S or --no-ssl-verify."
                            ),
                            module=MODULE_NAME,
                            evidence=f"Port 5986 (HTTPS) open",
                            suggested_commands=[
                                f"evil-winrm -i {target} -u <USER> -p <PASS> -S",
                            ],
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            title="WinRM over Unencrypted HTTP (Port 5985)",
                            description=(
                                f"WinRM on {target}:5985 uses plain HTTP. "
                                f"All data including credentials is transmitted "
                                f"in cleartext and can be sniffed on the network."
                            ),
                            module=MODULE_NAME,
                            evidence=f"Port 5985 (HTTP) open",
                            suggested_commands=[
                                f"evil-winrm -i {target} -u <USER> -p <PASS>",
                            ],
                        )
                    )
    else:
        logger.warning("nmap not found — skipping WinRM http-auth-finder scan")

        # Even without nmap, flag open WinRM ports based on portscan data
        for port in sorted(active_winrm_ports):
            transport = "HTTPS" if port == WINRM_HTTPS_PORT else "HTTP"
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title=f"WinRM Port {port} ({transport}) Open",
                    description=(
                        f"Port {port} ({transport}) is open on {target}, "
                        f"which is the default WinRM port. Remote shell "
                        f"access may be possible with valid credentials."
                    ),
                    module=MODULE_NAME,
                    evidence=f"Port {port} open",
                    suggested_commands=[
                        f"evil-winrm -i {target} -u <USER> -p <PASS>",
                        f"crackmapexec winrm {target} -u <USER> -p <PASS>",
                    ],
                )
            )

    # ── 2. Additional suggested tools ───────────────────────────────────
    tool_suggestions: list[str] = []

    if shutil.which("evil-winrm"):
        tool_suggestions.append(
            f"evil-winrm -i {target} -u <USER> -p <PASS>"
        )
    else:
        tool_suggestions.append(
            f"evil-winrm -i {target} -u <USER> -p <PASS>  # install: gem install evil-winrm"
        )

    if shutil.which("crackmapexec"):
        tool_suggestions.append(
            f"crackmapexec winrm {target} -u <USER> -p <PASS>"
        )
    else:
        tool_suggestions.append(
            f"crackmapexec winrm {target} -u <USER> -p <PASS>  # install: pipx install crackmapexec"
        )

    findings.append(
        Finding(
            severity=Severity.INFO,
            title="WinRM Suggested Attack Tools",
            description=(
                "The following tools can be used to authenticate to WinRM "
                "and obtain a remote shell."
            ),
            module=MODULE_NAME,
            evidence=f"WinRM ports open: {', '.join(str(p) for p in sorted(active_winrm_ports))}",
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
        output_file=output_dir / "winrm_summary.txt",
        duration_seconds=elapsed,
    )
