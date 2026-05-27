"""VNC reconnaissance module for ReconNinja v2.

Triggered when ports 5900–5910 (VNC) are detected open.  Uses nmap's
``vnc-info`` NSE script to determine the authentication type and VNC
protocol version.

Key findings
------------
- VNC with no authentication (CRITICAL)
- VNC with weak authentication (HIGH)
- VNC version and auth type (INFO)
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

MODULE_NAME = "vnc"

# VNC display ports range: 5900 (display :0) through 5910 (display :10)
VNC_PORT_RANGE = range(5900, 5911)

# Auth types considered weak (easily brute-forced or bypassed)
_WEAK_AUTH_TYPES = {"vnc authentication", "none", "ultravnc", "realvnc"}

# Auth types indicating no authentication at all
_NO_AUTH_TYPES = {"none", "no auth", "no authentication"}


def _find_vnc_ports(open_ports: list[int]) -> list[int]:
    """Return the subset of open ports that fall in the VNC range.

    Parameters
    ----------
    open_ports:
        All open ports discovered so far.

    Returns
    -------
    list[int]
        VNC-relevant ports sorted ascending.
    """
    return sorted(p for p in open_ports if p in VNC_PORT_RANGE)


async def run_vnc_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run VNC enumeration against *target*.

    Triggered when any port in the 5900–5910 range is open.

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
        Aggregated findings from VNC enumeration.
    """
    start = time.monotonic()
    findings: list[Finding] = []
    raw_outputs: list[str] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Check trigger ports ──────────────────────────────────────────────
    vnc_ports = _find_vnc_ports(state.open_ports)
    if not vnc_ports:
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            duration_seconds=time.monotonic() - start,
            error_message="No VNC ports (5900-5910) found open",
        )

    # ── Enumerate each VNC port ─────────────────────────────────────────
    if not shutil.which("nmap"):
        logger.warning("nmap not found — skipping VNC NSE scripts")
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            duration_seconds=time.monotonic() - start,
            error_message="nmap not available for VNC enumeration",
        )

    for port in vnc_ports:
        nmap_out = output_dir / f"vnc_nmap_{port}.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "nmap",
                f"-p{port}",
                "--script", "vnc-info",
                target,
            ],
            output_file=nmap_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc != 0 or not stdout:
            continue

        # ── Extract VNC protocol version ────────────────────────────────
        version_match = re.search(
            r"(?:RFB|VNC)\s*Protocol\s*version\s*:\s*(.+)",
            stdout,
            re.IGNORECASE,
        )
        vnc_version = version_match.group(1).strip() if version_match else "unknown"

        # ── Extract authentication type ─────────────────────────────────
        auth_match = re.search(
            r"Authentication\s*(?:schemes|method|type)\s*:\s*(.+)",
            stdout,
            re.IGNORECASE,
        )
        auth_type = auth_match.group(1).strip().lower() if auth_match else "unknown"

        # ── Determine severity based on auth type ───────────────────────
        is_no_auth = any(
            no_auth in auth_type for no_auth in _NO_AUTH_TYPES
        )
        is_weak_auth = any(
            weak in auth_type for weak in _WEAK_AUTH_TYPES
        )

        if is_no_auth:
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    title=f"VNC No Authentication on Port {port}",
                    description=(
                        f"VNC on {target}:{port} requires NO authentication. "
                        f"An attacker can connect and take full control of "
                        f"the desktop session without any credentials."
                    ),
                    module=MODULE_NAME,
                    evidence=stdout[:2000],
                    suggested_commands=[
                        f"vncviewer {target}::{port - 5900}",
                        f"nmap -p{port} --script vnc-info {target}",
                    ],
                )
            )
        elif is_weak_auth:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title=f"VNC Weak Authentication on Port {port}",
                    description=(
                        f"VNC on {target}:{port} uses weak authentication "
                        f"({auth_type}). VNC passwords are typically short "
                        f"and can be brute-forced or sniffed off the network."
                    ),
                    module=MODULE_NAME,
                    evidence=stdout[:2000],
                    suggested_commands=[
                        f"vncviewer {target}::{port - 5900}",
                        f"nmap -p{port} --script vnc-brute {target}",
                    ],
                )
            )
        else:
            # Standard VNC auth — informational
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"VNC Service Detected on Port {port}",
                    description=(
                        f"VNC is running on {target}:{port} with "
                        f"authentication type '{auth_type}' and "
                        f"protocol version {vnc_version}."
                    ),
                    module=MODULE_NAME,
                    evidence=stdout[:2000],
                )
            )

        # ── Record VNC version as informational finding ─────────────────
        if vnc_version != "unknown":
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"VNC Version on Port {port}",
                    description=f"VNC protocol version: {vnc_version}",
                    module=MODULE_NAME,
                    evidence=f"Port {port}: {vnc_version}",
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
        output_file=output_dir / "vnc_summary.txt",
        duration_seconds=elapsed,
    )
