"""SSH reconnaissance module for ReconNinja v2.

Triggered when port 22 is open or the service is identified as ``ssh``.
Enumerates authentication methods, supported algorithms, host keys,
and checks for weak configurations such as password-based auth.
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

MODULE_NAME = "ssh"


def _get_ssh_port(state: ScanState) -> int | None:
    """Return the SSH port from scan state, or ``None`` if not found."""
    # Check port 22 explicitly
    if 22 in state.open_ports:
        return 22
    # Check service identification on all open ports
    for port, svc in state.services.items():
        if "ssh" in svc.service.lower():
            return port
    return None


@module_guard()
async def run_ssh_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run SSH enumeration against *target*.

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

    ssh_port = _get_ssh_port(state)
    if ssh_port is None:
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            error_message="No SSH port (22) or SSH service found.",
        )

    # Prepare output subdirectory
    ssh_dir = output_dir / "ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)

    timeout = config.default_timeout

    # ------------------------------------------------------------------
    # 1. nmap SSH scripts — auth methods, algorithms, host key
    # ------------------------------------------------------------------
    if shutil.which("nmap"):
        logger.info(
            "[%s] Running nmap SSH scripts against %s:%d",
            MODULE_NAME, target, ssh_port,
        )
        nmap_out = ssh_dir / "nmap_ssh.txt"
        cmd = [
            "nmap",
            f"-p{ssh_port}",
            "--script", "ssh-auth-methods,ssh2-enum-algos,ssh-hostkey",
            target,
        ]
        rc, stdout, stderr = await run_tool(
            cmd, output_file=nmap_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        if stdout:
            # Parse SSH version / banner from nmap output
            banner_match = re.search(
                r"22/tcp\s+open\s+ssh\s+(.*)", stdout, re.IGNORECASE
            )
            if not banner_match:
                banner_match = re.search(
                    rf"{ssh_port}/tcp\s+open\s+ssh\s+(.*)", stdout, re.IGNORECASE
                )
            banner = banner_match.group(1).strip() if banner_match else ""

            if banner:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title="SSH Banner / Version",
                        description=f"SSH server banner: {banner}",
                        module=MODULE_NAME,
                        evidence=banner,
                        suggested_commands=[
                            f"searchsploit '{banner}'",
                            f"ssh {target} -p {ssh_port}  # Try default creds",
                        ],
                    )
                )

            # Parse auth methods
            auth_methods = _parse_auth_methods(stdout)
            if auth_methods:
                if "password" in auth_methods:
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title="SSH Password Authentication Enabled",
                            description=(
                                "SSH allows password-based authentication — "
                                "susceptible to brute-force attacks."
                            ),
                            module=MODULE_NAME,
                            evidence=f"Auth methods: {', '.join(auth_methods)}",
                            suggested_commands=[
                                f"hydra -l root -P /usr/share/wordlists/rockyou.txt {target} ssh -s {ssh_port}",
                                f"medusa -h {target} -u root -P /usr/share/wordlists/rockyou.txt -M ssh -n {ssh_port}",
                            ],
                        )
                    )
                elif "publickey" in auth_methods and "password" not in auth_methods:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title="SSH Key-Only Authentication",
                            description=(
                                "SSH is configured for public-key authentication only — "
                                "brute-force is not viable."
                            ),
                            module=MODULE_NAME,
                            evidence=f"Auth methods: {', '.join(auth_methods)}",
                        )
                    )

            # Parse algorithms
            algos = _parse_algorithms(stdout)
            if algos:
                weak_algos = _identify_weak_algos(algos)
                if weak_algos:
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            title="Weak SSH Algorithms Detected",
                            description=(
                                f"The SSH server supports weak/deprecated algorithms: "
                                f"{', '.join(weak_algos)}"
                            ),
                            module=MODULE_NAME,
                            evidence="\n".join(weak_algos),
                        )
                    )

            # Parse host key
            hostkey_match = re.search(r"ssh-hostkey:.*?\n(.*?)(?:\n\n|\Z)", stdout, re.DOTALL)
            if hostkey_match:
                key_info = hostkey_match.group(1).strip()
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title="SSH Host Key",
                        description="SSH host key fingerprint information.",
                        module=MODULE_NAME,
                        evidence=key_info,
                    )
                )
    else:
        logger.info("[%s] nmap not found — skipping SSH scripts", MODULE_NAME)

    # ------------------------------------------------------------------
    # 2. ssh-audit — detailed algorithm and configuration audit
    # ------------------------------------------------------------------
    if shutil.which("ssh-audit"):
        logger.info("[%s] Running ssh-audit against %s:%d", MODULE_NAME, target, ssh_port)
        audit_out = ssh_dir / "ssh_audit.txt"
        cmd = ["ssh-audit", f"{target}:{ssh_port}"]
        rc, stdout, stderr = await run_tool(
            cmd, output_file=audit_out, timeout=timeout
        )
        raw_outputs.append(stdout or stderr)

        if stdout:
            # Check for algorithm warnings / failures
            for line in stdout.splitlines():
                line_stripped = line.strip()
                if "(fail)" in line_stripped.lower():
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title="SSH Audit: Failed Check",
                            description=f"ssh-audit reported a failure: {line_stripped}",
                            module=MODULE_NAME,
                            evidence=line_stripped,
                        )
                    )
                elif "(warn)" in line_stripped.lower():
                    findings.append(
                        Finding(
                            severity=Severity.MEDIUM,
                            title="SSH Audit: Warning",
                            description=f"ssh-audit reported a warning: {line_stripped}",
                            module=MODULE_NAME,
                            evidence=line_stripped,
                        )
                    )
    else:
        logger.info("[%s] ssh-audit not found — skipping", MODULE_NAME)

    # ------------------------------------------------------------------
    # Build result
    # ------------------------------------------------------------------
    combined_output = "\n\n".join(raw_outputs)

    return ModuleResult(
        module_name=MODULE_NAME,
        status="done",
        findings=findings,
        raw_output=combined_output[:10000],
        output_file=ssh_dir,
        error_message="",
    )


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_auth_methods(output: str) -> list[str]:
    """Extract SSH authentication methods from nmap ``ssh-auth-methods`` output.

    Looks for lines like::

        |   auth methods: publickey, password
    """
    match = re.search(r"auth(?:entication)?\s*methods?:\s*(.+)", output, re.IGNORECASE)
    if match:
        methods_str = match.group(1).strip()
        return [m.strip().lower() for m in methods_str.split(",")]
    return []


def _parse_algorithms(output: str) -> dict[str, list[str]]:
    """Extract SSH algorithms grouped by category from ``ssh2-enum-algos`` output.

    Returns a dict mapping category names (e.g. ``kex_algorithms``) to
    lists of algorithm names.
    """
    algos: dict[str, list[str]] = {}
    current_category: str | None = None
    in_algo_section = False

    for line in output.splitlines():
        stripped = line.strip()
        # Detect the start of the algorithm enumeration
        if "ssh2-enum-algos" in stripped or "SSH algorithms" in stripped:
            in_algo_section = True
            continue
        if not in_algo_section:
            continue
        # End of nmap script section — standalone "|_" with nothing after
        if stripped == "|_":
            in_algo_section = False
            continue
        # Remove leading nmap formatting: | or |_  followed by spaces
        content = re.sub(r'^\|_\s*', '', stripped)
        content = re.sub(r'^\|\s*', '', content)
        content = content.strip()
        if not content:
            continue
        # Category header (e.g., "kex_algorithms (3)")
        cat_match = re.match(r"(\w+)\s+\(\d+\)$", content)
        if cat_match:
            current_category = cat_match.group(1)
            algos[current_category] = []
            continue
        # Algorithm entry
        if current_category and content:
            algos[current_category].append(content)

    return algos


def _identify_weak_algos(algos: dict[str, list[str]]) -> list[str]:
    """Return a list of weak/deprecated algorithm names from the parsed dict.

    Checks against a known set of insecure algorithms.
    """
    weak_set = {
        # Weak key exchange
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        # Weak ciphers
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "3des-cbc",
        "blowfish-cbc",
        "cast128-cbc",
        "arcfour",
        "arcfour128",
        "arcfour256",
        # Weak MACs
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1-96",
        "hmac-sha1",
        # Weak host keys
        "ssh-rsa",
        "ssh-dss",
    }
    weak_found: list[str] = []
    for _category, algo_list in algos.items():
        for algo in algo_list:
            if algo.lower() in weak_set:
                weak_found.append(algo)
    return weak_found
