"""RPC reconnaissance module for ReconNinja v2.

Triggered when ports 111 (rpcbind) or 135 (MSRPC) are detected open.
Performs null-session enumeration with ``rpcclient``, queries registered
RPC programs via ``rpcinfo``, and optionally runs nmap NSE scripts and
Impacket's ``rpcdump``.

Key findings
------------
- Null session access (HIGH)
- Domain users / groups extracted via null session (HIGH)
- Registered RPC services (INFO)
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

MODULE_NAME = "rpc"


def _parse_rpcclient_users(output: str) -> list[str]:
    """Extract usernames from rpcclient enumdomusers output.

    The typical format is::

        user:[administrator] rid:[0x1f4]
        user:[guest] rid:[0x1f5]

    Parameters
    ----------
    output:
        Raw stdout from ``rpcclient -c 'enumdomusers'``.

    Returns
    -------
    list[str]
        List of discovered usernames.
    """
    users: list[str] = []
    for match in re.finditer(r"user:\[(\S+?)\]", output, re.IGNORECASE):
        users.append(match.group(1))
    return list(set(users))


def _parse_rpcclient_groups(output: str) -> list[str]:
    """Extract group names from rpcclient enumdomgroups output.

    The typical format is::

        group:[Domain Admins] rid:[0x200]

    Parameters
    ----------
    output:
        Raw stdout from ``rpcclient -c 'enumdomgroups'``.

    Returns
    -------
    list[str]
        List of discovered group names.
    """
    groups: list[str] = []
    for match in re.finditer(r"group:\[(\S+?)\]", output, re.IGNORECASE):
        groups.append(match.group(1))
    return list(set(groups))


async def run_rpc_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run RPC enumeration against *target*.

    Triggered when port 111 (rpcbind) or 135 (MSRPC) is open.

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
        Aggregated findings from RPC enumeration.
    """
    start = time.monotonic()
    findings: list[Finding] = []
    raw_outputs: list[str] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Check trigger ports ──────────────────────────────────────────────
    open_ports = set(state.open_ports)
    rpc_ports = {111, 135}
    if not rpc_ports.intersection(open_ports):
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            duration_seconds=time.monotonic() - start,
            error_message="No RPC ports (111/135) found open",
        )

    # ── 1. rpcclient null-session enumeration (port 135 / SMB) ──────────
    if shutil.which("rpcclient"):
        rpcclient_out = output_dir / "rpc_rpcclient.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "rpcclient",
                "-U", "",
                "-N",
                target,
                "-c", "enumdomusers;enumdomgroups;querydominfo",
            ],
            output_file=rpcclient_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout:
            # Null session succeeded
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="RPC Null Session Access",
                    description=(
                        f"rpcclient connected to {target} with a null session "
                        f"(empty username, no password). This allows "
                        f"unauthenticated enumeration of domain users, groups, "
                        f"and shares."
                    ),
                    module=MODULE_NAME,
                    evidence=stdout[:2000],
                    suggested_commands=[
                        f"rpcclient -U '' -N {target} -c 'enumdomusers;enumdomgroups;querydominfo'",
                        f"rpcclient -U '' -N {target} -c 'enumalsgroups dom;lookupnames administrator'",
                    ],
                )
            )

            # Parse users
            users = _parse_rpcclient_users(stdout)
            if users:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title="Domain Users Enumerated via Null Session",
                        description=(
                            f"{len(users)} domain users discovered through "
                            f"rpcclient null-session enumeration."
                        ),
                        module=MODULE_NAME,
                        evidence="\n".join(users[:50]),
                    )
                )

            # Parse groups
            groups = _parse_rpcclient_groups(stdout)
            if groups:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title="Domain Groups Enumerated via Null Session",
                        description=(
                            f"{len(groups)} domain groups discovered through "
                            f"rpcclient null-session enumeration."
                        ),
                        module=MODULE_NAME,
                        evidence="\n".join(groups[:50]),
                    )
                )

            # Check for domain info
            dominfo_match = re.search(
                r"Domain:.*?Comment:.*?(?:\n|$)", stdout, re.DOTALL | re.IGNORECASE
            )
            if dominfo_match:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title="Domain Information via querydominfo",
                        description="Domain information was retrieved via rpcclient querydominfo.",
                        module=MODULE_NAME,
                        evidence=dominfo_match.group(0).strip()[:500],
                    )
                )
        elif "NT_STATUS_ACCESS_DENIED" in (stderr or "") or "NT_STATUS_ACCESS_DENIED" in (stdout or ""):
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="RPC Null Session Denied",
                    description=(
                        f"rpcclient null session was denied on {target}. "
                        f"The host may restrict unauthenticated access."
                    ),
                    module=MODULE_NAME,
                    evidence=(stderr or stdout)[:500],
                )
            )
    else:
        logger.warning("rpcclient not found — skipping null-session enumeration")

    # ── 2. rpcinfo — registered RPC services (port 111) ─────────────────
    if 111 in open_ports and shutil.which("rpcinfo"):
        rpcinfo_out = output_dir / "rpc_rpcinfo.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["rpcinfo", "-p", target],
            output_file=rpcinfo_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout:
            # Count registered services
            service_lines = [
                line for line in stdout.splitlines()
                if line.strip() and not line.startswith("program")
            ]
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="RPC Services Registered",
                    description=(
                        f"rpcinfo found {len(service_lines)} registered RPC "
                        f"services on {target}."
                    ),
                    module=MODULE_NAME,
                    evidence=stdout[:2000],
                )
            )
    else:
        if 111 in open_ports:
            logger.debug("rpcinfo not available — skipping registered RPC service query")

    # ── 3. nmap msrpc-enum NSE script (port 135) ────────────────────────
    if 135 in open_ports and shutil.which("nmap"):
        nmap_out = output_dir / "rpc_nmap.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "nmap",
                "-p135",
                "--script", "msrpc-enum",
                target,
            ],
            output_file=nmap_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout and "msrpc-enum" in stdout:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title="MSRPC Endpoints Enumerated",
                    description=(
                        f"nmap msrpc-enum script discovered RPC endpoints "
                        f"on {target} port 135."
                    ),
                    module=MODULE_NAME,
                    evidence=stdout[:2000],
                )
            )
    else:
        if 135 in open_ports:
            logger.debug("nmap not available — skipping msrpc-enum NSE script")

    # ── 4. impacket-rpcdump (optional) ──────────────────────────────────
    if shutil.which("impacket-rpcdump"):
        rpcdump_out = output_dir / "rpc_rpcdump.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["impacket-rpcdump", target],
            output_file=rpcdump_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout:
            # Count discovered endpoints
            endpoint_count = len(re.findall(r"Protocol:\s*\[", stdout))
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title="RPC Endpoints via impacket-rpcdump",
                    description=(
                        f"impacket-rpcdump enumerated {endpoint_count} "
                        f"RPC endpoints on {target}."
                    ),
                    module=MODULE_NAME,
                    evidence=stdout[:2000],
                )
            )
    else:
        logger.debug("impacket-rpcdump not available — skipping")

    # ── Build result ─────────────────────────────────────────────────────
    combined_output = "\n\n".join(raw_outputs)
    elapsed = time.monotonic() - start

    return ModuleResult(
        module_name=MODULE_NAME,
        status="done",
        findings=findings,
        raw_output=combined_output[:5000],
        output_file=output_dir / "rpc_summary.txt",
        duration_seconds=elapsed,
    )
