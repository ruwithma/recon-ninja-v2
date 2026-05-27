"""LDAP reconnaissance module for Recon Ninja v2.

Triggered when ports 389 (LDAP) or 636 (LDAPS) are detected open.
Enumerates the LDAP directory service via nmap NSE scripts, anonymous
bind tests with ``ldapsearch``, and optional ``windapsearch`` for
deep Active Directory enumeration.

Key findings
------------
- Anonymous bind access (HIGH)
- Base DN extraction (INFO)
- User and group enumeration (MEDIUM / HIGH depending on data exposed)
"""

from __future__ import annotations

import logging
import re
import shutil
import time
from pathlib import Path
from typing import Any

from recon_ninja.core.models import Finding, ModuleResult, ReconConfig, ScanState, Severity
from recon_ninja.core.runner import run_tool

logger = logging.getLogger(__name__)

MODULE_NAME = "ldap"


def _extract_base_dn(naming_contexts_output: str) -> str | None:
    """Extract the first namingContext from ldapsearch output.

    Parameters
    ----------
    naming_contexts_output:
        Raw stdout from ``ldapsearch -b '' -s base namingContexts``.

    Returns
    -------
    str | None
        The first base DN found, or ``None`` if parsing fails.
    """
    match = re.search(r"namingContexts:\s*(.+)", naming_contexts_output, re.IGNORECASE)
    if match:
        return match.group(1).strip()
    return None


def _extract_entries(ldap_output: str) -> dict[str, list[str]]:
    """Extract users and groups from ldapsearch LDIF output.

    Parameters
    ----------
    ldap_output:
        Raw stdout from an ldapsearch query.

    Returns
    -------
    dict[str, list[str]]
        Dictionary with ``"users"`` and ``"groups"`` keys containing
        lists of distinguished names or common names.
    """
    users: list[str] = []
    groups: list[str] = []

    for line in ldap_output.splitlines():
        # Match common user-related objectClass indicators
        if re.match(r"^(dn|cn|sn):\s*", line, re.IGNORECASE):
            value_match = re.match(r"^(?:dn|cn):\s*(.+)", line, re.IGNORECASE)
            if value_match:
                val = value_match.group(1).strip()
                if "ou=users" in val.lower() or "ou=people" in val.lower():
                    users.append(val)
                elif "ou=groups" in val.lower() or "ou=group" in val.lower():
                    groups.append(val)

    # Also grab objectClass=person / organizationalPerson entries
    user_match = re.findall(r"cn:\s*(.+)", ldap_output, re.IGNORECASE)
    if not users and user_match:
        users = list(set(user_match))

    group_match = re.findall(r"cn:\s*(.+)", ldap_output, re.IGNORECASE)
    if not groups and group_match:
        # Heuristic: if we found user CNs, treat remaining as groups
        pass

    return {"users": users, "groups": groups}


async def run_ldap_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run LDAP enumeration against *target*.

    Triggered when port 389 (LDAP) or 636 (LDAPS) is open.

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
        Aggregated findings from LDAP enumeration.
    """
    start = time.monotonic()
    findings: list[Finding] = []
    raw_outputs: list[str] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Check trigger ports ──────────────────────────────────────────────
    open_ports = set(state.open_ports)
    ldap_ports = {389, 636}
    if not ldap_ports.intersection(open_ports):
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            duration_seconds=time.monotonic() - start,
            error_message="No LDAP ports (389/636) found open",
        )

    # ── 1. Nmap LDAP NSE scripts ────────────────────────────────────────
    if shutil.which("nmap"):
        nmap_out = output_dir / "ldap_nmap.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["nmap", "-p389", "--script", "ldap-rootdse,ldap-search", target],
            output_file=nmap_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout:
            # Extract root DSE information
            if "ldap-rootdse" in stdout:
                rootdse_match = re.search(
                    r"ldap-rootdse:.*?\n(.*?)(?:\n\n|\Z)", stdout, re.DOTALL
                )
                if rootdse_match:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title="LDAP Root DSE Information",
                            description="LDAP Root DSE was enumerated via nmap NSE script.",
                            module=MODULE_NAME,
                            evidence=rootdse_match.group(1).strip()[:2000],
                        )
                    )

            # Check for ldap-search results with user data
            if "ldap-search" in stdout:
                findings.append(
                    Finding(
                        severity=Severity.MEDIUM,
                        title="LDAP Search Results Exposed",
                        description="LDAP directory data was retrieved via nmap ldap-search script.",
                        module=MODULE_NAME,
                        evidence=stdout[:2000],
                    )
                )
    else:
        logger.warning("nmap not found — skipping LDAP NSE scripts")

    # ── 2. ldapsearch anonymous bind test ───────────────────────────────
    base_dn: str | None = None
    if shutil.which("ldapsearch"):
        anon_out = output_dir / "ldap_anon_bind.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "ldapsearch",
                "-x",
                "-H", f"ldap://{target}",
                "-b", "",
                "-s", "base",
                "namingContexts",
            ],
            output_file=anon_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout and "namingContexts" in stdout:
            base_dn = _extract_base_dn(stdout)
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title="LDAP Anonymous Bind Access",
                    description=(
                        "The LDAP server allows anonymous bind. An unauthenticated "
                        "attacker can query the directory for naming contexts and "
                        "potentially enumerate users, groups, and other objects."
                    ),
                    module=MODULE_NAME,
                    evidence=stdout[:2000],
                    suggested_commands=[
                        f"ldapsearch -x -H ldap://{target} -b '' -s base namingContexts",
                    ],
                )
            )

            # Record base DN as an informational finding
            if base_dn:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title="LDAP Base DN Discovered",
                        description=f"Base DN extracted from namingContexts: {base_dn}",
                        module=MODULE_NAME,
                        evidence=f"namingContexts: {base_dn}",
                    )
                )

        # ── 3. ldapsearch user/object enumeration ───────────────────────
        if base_dn and shutil.which("ldapsearch"):
            enum_out = output_dir / "ldap_enum.txt"
            rc, stdout, stderr = await run_tool(
                cmd=[
                    "ldapsearch",
                    "-x",
                    "-H", f"ldap://{target}",
                    "-b", base_dn,
                    "(objectClass=*)",
                ],
                output_file=enum_out,
                timeout=config.default_timeout,
            )
            raw_outputs.append(stdout or stderr)

            if rc == 0 and stdout:
                entries = _extract_entries(stdout)
                if entries["users"]:
                    user_list = entries["users"][:20]  # cap for evidence
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title="LDAP User Objects Enumerated",
                            description=(
                                f"{len(entries['users'])} user entries discovered "
                                f"via anonymous LDAP query."
                            ),
                            module=MODULE_NAME,
                            evidence="\n".join(user_list),
                            suggested_commands=[
                                f"ldapsearch -x -H ldap://{target} -b '{base_dn}' "
                                f"'(objectClass=user)'",
                            ],
                        )
                    )
                if entries["groups"]:
                    group_list = entries["groups"][:20]
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            title="LDAP Group Objects Enumerated",
                            description=(
                                f"{len(entries['groups'])} group entries discovered "
                                f"via anonymous LDAP query."
                            ),
                            module=MODULE_NAME,
                            evidence="\n".join(group_list),
                        )
                    )
    else:
        logger.warning("ldapsearch not found — skipping anonymous bind test")

    # ── 4. windapsearch (optional) ──────────────────────────────────────
    if shutil.which("windapsearch"):
        windap_out = output_dir / "ldap_windapsearch.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "windapsearch",
                "-m", "users",
                "--dc", target,
                "--full",
            ],
            output_file=windap_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout:
            # Count user entries in windapsearch output
            user_count = stdout.count("userPrincipalName:")
            if user_count > 0:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title="AD Users Enumerated via windapsearch",
                        description=(
                            f"windapsearch enumerated {user_count} Active Directory "
                            f"user accounts from {target}."
                        ),
                        module=MODULE_NAME,
                        evidence=stdout[:2000],
                        suggested_commands=[
                            f"windapsearch -m users --dc {target} --full",
                            f"windapsearch -m groups --dc {target} --full",
                            f"windapsearch -m computers --dc {target} --full",
                        ],
                    )
                )
    else:
        logger.debug("windapsearch not available — skipping AD deep enumeration")

    # ── Build result ─────────────────────────────────────────────────────
    combined_output = "\n\n".join(raw_outputs)
    elapsed = time.monotonic() - start

    return ModuleResult(
        module_name=MODULE_NAME,
        status="done",
        findings=findings,
        raw_output=combined_output[:5000],
        output_file=output_dir / "ldap_summary.txt",
        duration_seconds=elapsed,
    )
