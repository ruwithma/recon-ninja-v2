"""NFS reconnaissance module for ReconNinja v2.

Triggered when port 2049 (NFS) is detected open.  Enumerates exported
NFS shares via ``showmount -e`` and nmap NSE scripts, then suggests
mount commands for any accessible shares.

Key findings
------------
- Accessible NFS shares (MEDIUM)
- NFS share listing exposed (INFO)
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

MODULE_NAME = "nfs"


def _parse_showmount_shares(output: str) -> list[str]:
    """Extract NFS export paths from showmount -e output.

    The typical format is::

        Export list for 10.10.10.1:
        /home           *
        /var/www        10.10.10.0/24
        /               *

    Parameters
    ----------
    output:
        Raw stdout from ``showmount -e <target>``.

    Returns
    -------
    list[str]
        List of exported share paths.
    """
    shares: list[str] = []
    for line in output.splitlines():
        line = line.strip()
        # Skip header lines
        if not line or line.startswith("Export list") or line.startswith("Host"):
            continue
        # Lines are: "/path  access_list"
        match = re.match(r"^(/\S*)", line)
        if match:
            shares.append(match.group(1))
    return shares


def _is_nfs_port(state: ScanState) -> bool:
    """Return ``True`` if port 2049 is open or the service is NFS."""
    if 2049 in state.open_ports:
        return True
    for _port, svc in state.services.items():
        if "nfs" in svc.service.lower():
            return True
    return False


def _get_nfs_port(state: ScanState) -> int:
    """Return the open NFS port, defaulting to 2049."""
    if 2049 in state.open_ports:
        return 2049
    for port, svc in state.services.items():
        if "nfs" in svc.service.lower():
            return port
    return 2049


@module_guard()
async def run_nfs_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run NFS enumeration against *target*.

    Triggered when port 2049 is open or the service is NFS.

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
        Aggregated findings from NFS enumeration.
    """
    start = time.monotonic()
    findings: list[Finding] = []
    raw_outputs: list[str] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Check trigger port ───────────────────────────────────────────────
    if not _is_nfs_port(state):
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            duration_seconds=time.monotonic() - start,
            error_message="No NFS port (2049) or NFS service found open",
        )

    nfs_port = _get_nfs_port(state)

    # ── 1. showmount -e — list exported shares ──────────────────────────
    discovered_shares: list[str] = []

    if shutil.which("showmount"):
        showmount_out = output_dir / "nfs_showmount.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["showmount", "-e", target],
            output_file=showmount_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout:
            discovered_shares = _parse_showmount_shares(stdout)

            if discovered_shares:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title="NFS Exported Shares Accessible",
                        description=(
                            f"showmount discovered {len(discovered_shares)} "
                            f"exported NFS shares on {target}. These shares may "
                            f"contain sensitive files accessible without "
                            f"authentication."
                        ),
                        module=MODULE_NAME,
                        evidence="\n".join(discovered_shares),
                        suggested_commands=[
                            f"sudo mount -t nfs {target}:/{share} /tmp/nfs_mount"
                            for share in discovered_shares
                        ],
                    )
                )
            else:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title="NFS Service Detected — No Exported Shares",
                        description=(
                            f"NFS is running on {target}:{nfs_port} but no exported "
                            f"shares were listed by showmount."
                        ),
                        module=MODULE_NAME,
                        evidence=stdout[:1000],
                    )
                )
        elif stderr and "rpc" in stderr.lower():
            logger.debug("showmount failed with RPC error: %s", stderr[:200])
    else:
        logger.warning("showmount not found — skipping NFS share enumeration")

    # ── 2. nmap NFS NSE scripts ─────────────────────────────────────────
    if shutil.which("nmap"):
        nmap_out = output_dir / "nfs_nmap.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "nmap",
                f"-p{nfs_port}",
                "--script", "nfs-ls,nfs-showmount,nfs-statfs",
                target,
            ],
            output_file=nmap_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout:
            # Parse nfs-ls output for file listings
            if "nfs-ls" in stdout:
                ls_match = re.search(
                    r"nfs-ls:.*?\n(.*?)(?:\n\n|\Z)", stdout, re.DOTALL
                )
                if ls_match:
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            title="NFS Directory Listing via nmap",
                            description=(
                                f"nmap nfs-ls script was able to list files "
                                f"in an NFS share on {target}."
                            ),
                            module=MODULE_NAME,
                            evidence=ls_match.group(1).strip()[:2000],
                        )
                    )

            # Parse nfs-showmount output
            if "nfs-showmount" in stdout:
                nmap_shares = _parse_showmount_shares(stdout)
                # Add any shares not already discovered
                new_shares = [s for s in nmap_shares if s not in discovered_shares]
                if new_shares:
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            title="Additional NFS Shares via nmap nfs-showmount",
                            description=(
                                f"nmap nfs-showmount found {len(new_shares)} "
                                f"additional exported shares."
                            ),
                            module=MODULE_NAME,
                            evidence="\n".join(new_shares),
                            suggested_commands=[
                                f"sudo mount -t nfs {target}:{share} /tmp/nfs_mount"
                                for share in new_shares
                            ],
                        )
                    )

            # Parse nfs-statfs output
            if "nfs-statfs" in stdout:
                statfs_match = re.search(
                    r"nfs-statfs:.*?\n(.*?)(?:\n\n|\Z)", stdout, re.DOTALL
                )
                if statfs_match:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title="NFS Filesystem Statistics",
                            description="nmap nfs-statfs retrieved filesystem statistics from an NFS share.",
                            module=MODULE_NAME,
                            evidence=statfs_match.group(1).strip()[:1000],
                        )
                    )
    else:
        logger.warning("nmap not found — skipping NFS NSE scripts")

    # ── 3. Suggested mount commands for discovered shares ───────────────
    if discovered_shares:
        mount_commands: list[str] = []
        for share in discovered_shares:
            mount_commands.append(
                f"sudo mkdir -p /tmp/nfs_mount && "
                f"sudo mount -t nfs {target}:{share} /tmp/nfs_mount"
            )

        findings.append(
            Finding(
                severity=Severity.INFO,
                title="NFS Mount Commands",
                description=(
                    "Use the following commands to mount the discovered "
                    "NFS shares and inspect their contents."
                ),
                module=MODULE_NAME,
                evidence=f"Shares: {', '.join(discovered_shares)}",
                suggested_commands=mount_commands,
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
        output_file=output_dir / "nfs_summary.txt",
        duration_seconds=elapsed,
    )
