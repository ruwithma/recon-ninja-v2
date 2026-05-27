"""Kerberos reconnaissance module for Recon Ninja v2.

Triggered when port 88 (Kerberos) is detected open.  Enumerates valid
usernames via ``kerbrute`` and nmap's ``krb5-enum-users`` NSE script,
then suggests Impacket attack commands for AS-REP roasting and
Kerberoasting.

Key findings
------------
- Valid Kerberos usernames (HIGH)
- Kerberos service detected (INFO)
- Suggested post-exploitation commands (INFO)
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

MODULE_NAME = "kerberos"

# Default username wordlist for kerbrute
_DEFAULT_USER_WORDLIST = Path(
    "/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt"
)


def _derive_domain(state: ScanState, config: ReconConfig) -> str | None:
    """Derive the Active Directory domain from scan state or config.

    Checks hostnames first (FQDN format), then falls back to
    ``config.is_domain`` treating the target itself as the domain.

    Parameters
    ----------
    state:
        Current scan state with discovered hostnames.
    config:
        Active reconnaissance configuration.

    Returns
    -------
    str | None
        Best-guess domain string (uppercase) or ``None``.
    """
    # Try to extract domain from FQDN hostnames
    for hostname in state.hostnames:
        parts = hostname.split(".")
        if len(parts) >= 3:
            # e.g. dc01.corp.local → corp.local
            domain = ".".join(parts[1:]).upper()
            return domain
        if len(parts) == 2:
            # e.g. dc01.corp → corp
            domain = ".".join(parts[1:]).upper()
            return domain

    # If the target itself looks like a domain
    if config.is_domain and "." in state.target:
        return state.target.upper()

    return None


def _parse_valid_users(kerbrute_output: str) -> list[str]:
    """Parse valid usernames from kerbrute output.

    Parameters
    ----------
    kerbrute_output:
        Raw stdout from ``kerbrute userenum``.

    Returns
    -------
    list[str]
        List of confirmed valid usernames.
    """
    users: list[str] = []
    # kerbrute lines look like: [+] VALID USERNAME: admin@DOMAIN.LOCAL
    for match in re.finditer(
        r"VALID USERNAME:\s*(\S+?)(?:@|\s)", kerbrute_output, re.IGNORECASE
    ):
        users.append(match.group(1))
    # Also try: [+] admin@DOMAIN.LOCAL
    if not users:
        for match in re.finditer(r"\[\+\]\s+(\w+)@", kerbrute_output):
            users.append(match.group(1))
    return list(set(users))


def _parse_nmap_krb_users(nmap_output: str) -> list[str]:
    """Parse valid usernames from nmap krb5-enum-users output.

    Parameters
    ----------
    nmap_output:
        Raw stdout from nmap with krb5-enum-users NSE script.

    Returns
    -------
    list[str]
        List of confirmed valid usernames.
    """
    users: list[str] = []
    # nmap output typically: krb5-enum-users: ... username ...
    for match in re.finditer(r"Valid:\s*(\S+)", nmap_output, re.IGNORECASE):
        users.append(match.group(1))
    # Alternate pattern: "user <name> is valid"
    for match in re.finditer(r"user\s+(\w+)\s+is\s+valid", nmap_output, re.IGNORECASE):
        users.append(match.group(1))
    return list(set(users))


async def run_kerberos_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run Kerberos enumeration against *target*.

    Triggered when port 88 is open.

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
        Aggregated findings from Kerberos enumeration.
    """
    start = time.monotonic()
    findings: list[Finding] = []
    raw_outputs: list[str] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Check trigger port ───────────────────────────────────────────────
    if 88 not in state.open_ports:
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            duration_seconds=time.monotonic() - start,
            error_message="Port 88 (Kerberos) not found open",
        )

    # ── Derive domain ────────────────────────────────────────────────────
    domain = _derive_domain(state, config)
    if not domain:
        logger.warning(
            "Could not determine domain from state — Kerberos enumeration "
            "may be limited. Consider specifying --domain."
        )

    # ── 1. kerbrute user enumeration ────────────────────────────────────
    valid_users: list[str] = []
    wordlist = _DEFAULT_USER_WORDLIST

    if shutil.which("kerbrute") and wordlist.is_file():
        kerbrute_out = output_dir / "kerberos_kerbrute.txt"
        kerbrute_cmd = [
            "kerbrute",
            "userenum",
            str(wordlist),
            "--dc", target,
        ]
        if domain:
            kerbrute_cmd.extend(["-d", domain])

        rc, stdout, stderr = await run_tool(
            cmd=kerbrute_cmd,
            output_file=kerbrute_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if stdout:
            valid_users = _parse_valid_users(stdout)
            if valid_users:
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title="Valid Kerberos Usernames Discovered",
                        description=(
                            f"kerbrute confirmed {len(valid_users)} valid "
                            f"usernames against {target}."
                        ),
                        module=MODULE_NAME,
                        evidence="\n".join(valid_users[:50]),
                        suggested_commands=[
                            f"kerbrute userenum {wordlist} --dc {target}"
                            + (f" -d {domain}" if domain else ""),
                        ],
                    )
                )
    elif not shutil.which("kerbrute"):
        logger.debug("kerbrute not available — skipping username enumeration")
    else:
        logger.warning("Username wordlist not found at %s — skipping kerbrute", wordlist)

    # ── 2. nmap krb5-enum-users NSE script ──────────────────────────────
    if shutil.which("nmap"):
        nmap_out = output_dir / "kerberos_nmap.txt"
        nmap_cmd: list[str] = [
            "nmap",
            "-p88",
            "--script", "krb5-enum-users",
        ]
        if domain:
            nmap_cmd.extend([
                "--script-args",
                f"krb5-enum-users.realm='{domain}'",
            ])
        nmap_cmd.append(target)

        rc, stdout, stderr = await run_tool(
            cmd=nmap_cmd,
            output_file=nmap_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout:
            nmap_users = _parse_nmap_krb_users(stdout)
            if nmap_users:
                # Merge with kerbrute results
                new_users = [u for u in nmap_users if u not in valid_users]
                valid_users.extend(new_users)
                findings.append(
                    Finding(
                        severity=Severity.HIGH,
                        title="Kerberos Users via NSE Script",
                        description=(
                            f"nmap krb5-enum-users discovered {len(nmap_users)} "
                            f"usernames on {target}."
                        ),
                        module=MODULE_NAME,
                        evidence="\n".join(nmap_users[:50]),
                    )
                )
    else:
        logger.warning("nmap not found — skipping krb5-enum-users NSE script")

    # ── 3. Informational finding — Kerberos service detected ────────────
    findings.append(
        Finding(
            severity=Severity.INFO,
            title="Kerberos Service Detected",
            description=(
                f"Kerberos (port 88) is open on {target}. This indicates "
                f"an Active Directory environment which may be vulnerable "
                f"to AS-REP roasting and Kerberoasting."
            ),
            module=MODULE_NAME,
            evidence=f"Port 88 open on {target}",
        )
    )

    # ── 4. Suggested Impacket commands ──────────────────────────────────
    if domain:
        suggested: list[str] = []

        # AS-REP roasting — no password required
        suggested.append(
            f"GetNPUsers.py {domain}/ -usersfile loot/usernames.txt -no-pass"
        )

        # Kerberoasting — requires credentials
        suggested.append(
            f"GetUserSPNs.py {domain}/<USER>:<PASS> -request"
        )

        # Additional useful commands
        suggested.append(
            f"GetTGT.py {domain}/<USER>:<PASS>"
        )
        suggested.append(
            f"GetADUsers.py {domain}/ -all -dc-ip {target}"
        )

        findings.append(
            Finding(
                severity=Severity.INFO,
                title="Suggested Kerberos Attack Commands",
                description=(
                    "Active Directory Kerberos is present. The following "
                    "Impacket commands may be useful for further exploitation."
                ),
                module=MODULE_NAME,
                evidence=f"Domain: {domain}, Target: {target}",
                suggested_commands=suggested,
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
        output_file=output_dir / "kerberos_summary.txt",
        duration_seconds=elapsed,
    )
