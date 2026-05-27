"""Database reconnaissance module for ReconNinja v2.

Triggered when well-known database ports are detected open.  Supports
MySQL, MSSQL, PostgreSQL, Redis, MongoDB, and Oracle — each with
port-specific nmap NSE scripts, tool checks, and appropriate severity
ratings.

Key findings by database type
------------------------------
- MySQL (3306):   empty root password → CRITICAL
- MSSQL (1433):   empty sa password  → CRITICAL
- PostgreSQL (5432): brute-force results → HIGH
- Redis (6379):   unauthenticated access → CRITICAL
- MongoDB (27017): no authentication → CRITICAL
- Oracle (1521):  TNS version exposed → INFO
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

MODULE_NAME = "database"

# ── Database port → type mapping ────────────────────────────────────────
DB_PORT_MAP: dict[int, str] = {
    3306: "mysql",
    1433: "mssql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    1521: "oracle",
}


# ── MySQL enumeration ───────────────────────────────────────────────────


async def _enum_mysql(
    target: str,
    port: int,
    config: ReconConfig,
    output_dir: Path,
    findings: list[Finding],
    raw_outputs: list[str],
) -> None:
    """Enumerate MySQL service on *target*:*port*.

    Parameters
    ----------
    target:
        Target IP or hostname.
    port:
        MySQL port (typically 3306).
    config:
        Active reconnaissance configuration.
    output_dir:
        Directory for raw output files.
    findings:
        Mutable list to append findings to.
    raw_outputs:
        Mutable list to append raw tool outputs to.
    """
    if not shutil.which("nmap"):
        logger.warning("nmap not found — skipping MySQL NSE scripts")
        return

    nmap_out = output_dir / f"db_mysql_{port}.txt"
    rc, stdout, stderr = await run_tool(
        cmd=[
            "nmap",
            f"-p{port}",
            "--script", "mysql-info,mysql-empty-password,mysql-enum",
            target,
        ],
        output_file=nmap_out,
        timeout=config.default_timeout,
    )
    raw_outputs.append(stdout or stderr)

    if rc != 0 or not stdout:
        return

    # ── mysql-info ──────────────────────────────────────────────────────
    if "mysql-info" in stdout:
        info_match = re.search(
            r"mysql-info:.*?(?:\n\n|\Z)", stdout, re.DOTALL
        )
        if info_match:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"MySQL Server Info on Port {port}",
                    description=f"MySQL server information enumerated on {target}:{port}.",
                    module=MODULE_NAME,
                    evidence=info_match.group(0).strip()[:2000],
                )
            )

    # ── mysql-empty-password ────────────────────────────────────────────
    if "mysql-empty-password" in stdout:
        if re.search(r"empty password|account is using empty password", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    title=f"MySQL Empty Root Password on Port {port}",
                    description=(
                        f"MySQL on {target}:{port} has an account with an "
                        f"empty password. An attacker can log in without "
                        f"any credentials and access all databases."
                    ),
                    module=MODULE_NAME,
                    evidence=re.search(
                        r"mysql-empty-password:.*?(?:\n\n|\Z)", stdout, re.DOTALL
                    )
                    .group(0)
                    .strip()[:2000],
                    suggested_commands=[
                        f"mysql -h {target} -P {port} -u root -p''",
                        f"mysqldump -h {target} -P {port} -u root --all-databases",
                    ],
                )
            )
        else:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"MySQL No Empty Password on Port {port}",
                    description=f"MySQL on {target}:{port} does not appear to have accounts with empty passwords.",
                    module=MODULE_NAME,
                )
            )

    # ── mysql-enum ──────────────────────────────────────────────────────
    if "mysql-enum" in stdout:
        enum_match = re.search(
            r"mysql-enum:.*?(?:\n\n|\Z)", stdout, re.DOTALL
        )
        if enum_match:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    title=f"MySQL User Enumeration on Port {port}",
                    description=f"MySQL user accounts were enumerated via nmap mysql-enum script.",
                    module=MODULE_NAME,
                    evidence=enum_match.group(0).strip()[:2000],
                )
            )

    # ── Suggested manual commands ───────────────────────────────────────
    findings.append(
        Finding(
            severity=Severity.INFO,
            title="MySQL Suggested Commands",
            description="Manual commands for further MySQL enumeration.",
            module=MODULE_NAME,
            evidence=f"MySQL on {target}:{port}",
            suggested_commands=[
                f"mysql -h {target} -P {port} -u root -p",
                f"nmap -p{port} --script mysql-brute {target}",
                f"nmap -p{port} --script mysql-databases {target}",
            ],
        )
    )


# ── MSSQL enumeration ───────────────────────────────────────────────────


async def _enum_mssql(
    target: str,
    port: int,
    config: ReconConfig,
    output_dir: Path,
    findings: list[Finding],
    raw_outputs: list[str],
) -> None:
    """Enumerate MSSQL service on *target*:*port*.

    Parameters
    ----------
    target:
        Target IP or hostname.
    port:
        MSSQL port (typically 1433).
    config:
        Active reconnaissance configuration.
    output_dir:
        Directory for raw output files.
    findings:
        Mutable list to append findings to.
    raw_outputs:
        Mutable list to append raw tool outputs to.
    """
    if not shutil.which("nmap"):
        logger.warning("nmap not found — skipping MSSQL NSE scripts")
        return

    nmap_out = output_dir / f"db_mssql_{port}.txt"
    rc, stdout, stderr = await run_tool(
        cmd=[
            "nmap",
            f"-p{port}",
            "--script", "ms-sql-info,ms-sql-empty-password,ms-sql-config",
            target,
        ],
        output_file=nmap_out,
        timeout=config.default_timeout,
    )
    raw_outputs.append(stdout or stderr)

    if rc != 0 or not stdout:
        return

    # ── ms-sql-info ─────────────────────────────────────────────────────
    if "ms-sql-info" in stdout:
        info_match = re.search(
            r"ms-sql-info:.*?(?:\n\n|\Z)", stdout, re.DOTALL
        )
        if info_match:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"MSSQL Server Info on Port {port}",
                    description=f"MSSQL server information enumerated on {target}:{port}.",
                    module=MODULE_NAME,
                    evidence=info_match.group(0).strip()[:2000],
                )
            )

    # ── ms-sql-empty-password ───────────────────────────────────────────
    if "ms-sql-empty-password" in stdout:
        if re.search(r"empty password|sa.*empty", stdout, re.IGNORECASE):
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    title=f"MSSQL Empty SA Password on Port {port}",
                    description=(
                        f"MSSQL on {target}:{port} has the 'sa' (system "
                        f"administrator) account with an empty password. "
                        f"An attacker can gain full database and potentially "
                        f"OS-level access via xp_cmdshell."
                    ),
                    module=MODULE_NAME,
                    evidence=re.search(
                        r"ms-sql-empty-password:.*?(?:\n\n|\Z)", stdout, re.DOTALL
                    )
                    .group(0)
                    .strip()[:2000],
                    suggested_commands=[
                        f"mssqlclient.py sa@{target} -port {port}",
                        f"sqsh -S {target} -U sa -P ''",
                        f"nmap -p{port} --script ms-sql-xp-cmdshell {target}",
                    ],
                )
            )
        else:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"MSSQL No Empty SA Password on Port {port}",
                    description=f"MSSQL on {target}:{port} does not appear to have an empty SA password.",
                    module=MODULE_NAME,
                )
            )

    # ── ms-sql-config ──────────────────────────────────────────────────
    if "ms-sql-config" in stdout:
        config_match = re.search(
            r"ms-sql-config:.*?(?:\n\n|\Z)", stdout, re.DOTALL
        )
        if config_match:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"MSSQL Configuration on Port {port}",
                    description="MSSQL configuration settings retrieved via nmap ms-sql-config.",
                    module=MODULE_NAME,
                    evidence=config_match.group(0).strip()[:2000],
                )
            )

    # ── Suggested manual commands ───────────────────────────────────────
    findings.append(
        Finding(
            severity=Severity.INFO,
            title="MSSQL Suggested Commands",
            description="Manual commands for further MSSQL enumeration.",
            module=MODULE_NAME,
            evidence=f"MSSQL on {target}:{port}",
            suggested_commands=[
                f"mssqlclient.py <USER>:<PASS>@{target} -port {port}",
                f"impacket-mssqlclient <USER>:<PASS>@{target}",
                f"nmap -p{port} --script ms-sql-brute {target}",
                f"nmap -p{port} --script ms-sql-dump-hashes {target}",
            ],
        )
    )


# ── PostgreSQL enumeration ──────────────────────────────────────────────


async def _enum_postgresql(
    target: str,
    port: int,
    config: ReconConfig,
    output_dir: Path,
    findings: list[Finding],
    raw_outputs: list[str],
) -> None:
    """Enumerate PostgreSQL service on *target*:*port*.

    Parameters
    ----------
    target:
        Target IP or hostname.
    port:
        PostgreSQL port (typically 5432).
    config:
        Active reconnaissance configuration.
    output_dir:
        Directory for raw output files.
    findings:
        Mutable list to append findings to.
    raw_outputs:
        Mutable list to append raw tool outputs to.
    """
    if shutil.which("nmap"):
        nmap_out = output_dir / f"db_postgresql_{port}.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "nmap",
                f"-p{port}",
                "--script", "pgsql-brute",
                target,
            ],
            output_file=nmap_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout:
            if "pgsql-brute" in stdout:
                # Check for valid credentials
                if re.search(r"Valid credentials", stdout, re.IGNORECASE):
                    creds_match = re.search(
                        r"pgsql-brute:.*?(?:\n\n|\Z)", stdout, re.DOTALL
                    )
                    findings.append(
                        Finding(
                            severity=Severity.HIGH,
                            title=f"PostgreSQL Valid Credentials on Port {port}",
                            description=(
                                f"nmap pgsql-brute found valid credentials for "
                                f"PostgreSQL on {target}:{port}."
                            ),
                            module=MODULE_NAME,
                            evidence=creds_match.group(0).strip()[:2000] if creds_match else stdout[:2000],
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title=f"PostgreSQL Brute-Force No Hits on Port {port}",
                            description=(
                                f"nmap pgsql-brute did not find valid credentials "
                                f"for PostgreSQL on {target}:{port}."
                            ),
                            module=MODULE_NAME,
                        )
                    )

    # ── Suggested psql connection ───────────────────────────────────────
    findings.append(
        Finding(
            severity=Severity.INFO,
            title="PostgreSQL Suggested Commands",
            description="Manual commands for further PostgreSQL enumeration.",
            module=MODULE_NAME,
            evidence=f"PostgreSQL on {target}:{port}",
            suggested_commands=[
                f"psql -h {target} -p {port} -U postgres -W",
                f"psql -h {target} -p {port} -U postgres --no-password",
                f"nmap -p{port} --script pgsql-brute {target}",
                f"pg_dump -h {target} -p {port} -U postgres -d <DB>",
            ],
        )
    )


# ── Redis enumeration ───────────────────────────────────────────────────


async def _enum_redis(
    target: str,
    port: int,
    config: ReconConfig,
    output_dir: Path,
    findings: list[Finding],
    raw_outputs: list[str],
) -> None:
    """Enumerate Redis service on *target*:*port*.

    Checks for unauthenticated access using ``redis-cli ping``.

    Parameters
    ----------
    target:
        Target IP or hostname.
    port:
        Redis port (typically 6379).
    config:
        Active reconnaissance configuration.
    output_dir:
        Directory for raw output files.
    findings:
        Mutable list to append findings to.
    raw_outputs:
        Mutable list to append raw tool outputs to.
    """
    # ── redis-cli ping test ─────────────────────────────────────────────
    if shutil.which("redis-cli"):
        redis_out = output_dir / f"db_redis_{port}.txt"
        rc, stdout, stderr = await run_tool(
            cmd=["redis-cli", "-h", target, "-p", str(port), "ping"],
            output_file=redis_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and "PONG" in (stdout or "").upper():
            # Unauthenticated access confirmed
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    title=f"Redis Unauthenticated Access on Port {port}",
                    description=(
                        f"Redis on {target}:{port} responds to PING without "
                        f"authentication. An attacker can read and modify all "
                        f"data, write SSH authorized_keys, or achieve RCE "
                        f"via module loading."
                    ),
                    module=MODULE_NAME,
                    evidence=f"redis-cli -h {target} -p {port} ping → PONG",
                    suggested_commands=[
                        f"redis-cli -h {target} -p {port} info",
                        f"redis-cli -h {target} -p {port} config get dir",
                        f"redis-cli -h {target} -p {port} keys '*'",
                        f"redis-cli -h {target} -p {port} get <KEY>",
                    ],
                )
            )

            # ── Try to get server info ──────────────────────────────────
            info_out = output_dir / f"db_redis_{port}_info.txt"
            rc2, stdout2, stderr2 = await run_tool(
                cmd=["redis-cli", "-h", target, "-p", str(port), "info", "server"],
                output_file=info_out,
                timeout=config.default_timeout,
            )
            raw_outputs.append(stdout2 or stderr2)

            if rc2 == 0 and stdout2:
                redis_version_match = re.search(
                    r"redis_version:(\S+)", stdout2
                )
                os_match = re.search(r"os:(\S+)", stdout2)
                version = redis_version_match.group(1) if redis_version_match else "unknown"
                os_info = os_match.group(1) if os_match else "unknown"
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title=f"Redis Server Info on Port {port}",
                        description=(
                            f"Redis version {version} running on {os_info}."
                        ),
                        module=MODULE_NAME,
                        evidence=stdout2[:2000],
                    )
                )
        elif "NOAUTH" in (stdout or "") or "Authentication required" in (stdout or stderr or ""):
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"Redis Requires Authentication on Port {port}",
                    description=(
                        f"Redis on {target}:{port} requires a password. "
                        f"Brute-force may be feasible."
                    ),
                    module=MODULE_NAME,
                    evidence=(stdout or stderr)[:500],
                    suggested_commands=[
                        f"redis-cli -h {target} -p {port} -a <PASSWORD> ping",
                        f"nmap -p{port} --script redis-brute {target}",
                    ],
                )
            )
    else:
        logger.warning("redis-cli not found — skipping Redis unauthenticated access check")

    # ── Fallback to nmap if available ───────────────────────────────────
    if shutil.which("nmap"):
        nmap_out = output_dir / f"db_redis_nmap_{port}.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "nmap",
                f"-p{port}",
                "--script", "redis-info",
                target,
            ],
            output_file=nmap_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout and "redis-info" in stdout:
            info_match = re.search(
                r"redis-info:.*?(?:\n\n|\Z)", stdout, re.DOTALL
            )
            if info_match:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        title=f"Redis Info via nmap on Port {port}",
                        description="Redis server info retrieved via nmap redis-info script.",
                        module=MODULE_NAME,
                        evidence=info_match.group(0).strip()[:2000],
                    )
                )


# ── MongoDB enumeration ─────────────────────────────────────────────────


async def _enum_mongodb(
    target: str,
    port: int,
    config: ReconConfig,
    output_dir: Path,
    findings: list[Finding],
    raw_outputs: list[str],
) -> None:
    """Enumerate MongoDB service on *target*:*port*.

    Parameters
    ----------
    target:
        Target IP or hostname.
    port:
        MongoDB port (typically 27017).
    config:
        Active reconnaissance configuration.
    output_dir:
        Directory for raw output files.
    findings:
        Mutable list to append findings to.
    raw_outputs:
        Mutable list to append raw tool outputs to.
    """
    if not shutil.which("nmap"):
        logger.warning("nmap not found — skipping MongoDB NSE scripts")
        return

    nmap_out = output_dir / f"db_mongodb_{port}.txt"
    rc, stdout, stderr = await run_tool(
        cmd=[
            "nmap",
            f"-p{port}",
            "--script", "mongodb-info,mongodb-databases",
            target,
        ],
        output_file=nmap_out,
        timeout=config.default_timeout,
    )
    raw_outputs.append(stdout or stderr)

    if rc != 0 or not stdout:
        return

    # ── mongodb-info ────────────────────────────────────────────────────
    if "mongodb-info" in stdout:
        info_match = re.search(
            r"mongodb-info:.*?(?:\n\n|\Z)", stdout, re.DOTALL
        )
        if info_match:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"MongoDB Server Info on Port {port}",
                    description=f"MongoDB server information enumerated on {target}:{port}.",
                    module=MODULE_NAME,
                    evidence=info_match.group(0).strip()[:2000],
                )
            )

        # If mongodb-info succeeds without auth, no-auth is likely enabled
        findings.append(
            Finding(
                severity=Severity.CRITICAL,
                title=f"MongoDB No Authentication on Port {port}",
                description=(
                    f"MongoDB on {target}:{port} appears to have "
                    f"authentication disabled. The nmap mongodb-info script "
                    f"was able to retrieve server information without "
                    f"credentials. An attacker can read, modify, or delete "
                    f"all data."
                ),
                module=MODULE_NAME,
                evidence=re.search(
                    r"mongodb-info:.*?(?:\n\n|\Z)", stdout, re.DOTALL
                )
                .group(0)
                .strip()[:2000],
                suggested_commands=[
                    f"mongosh --host {target} --port {port}",
                    f"mongo --host {target} --port {port}",
                    f"nmap -p{port} --script mongodb-databases {target}",
                ],
            )
        )

    # ── mongodb-databases ───────────────────────────────────────────────
    if "mongodb-databases" in stdout:
        db_match = re.search(
            r"mongodb-databases:.*?(?:\n\n|\Z)", stdout, re.DOTALL
        )
        if db_match:
            findings.append(
                Finding(
                    severity=Severity.HIGH,
                    title=f"MongoDB Databases Listed on Port {port}",
                    description=(
                        f"MongoDB databases were enumerated on {target}:{port} "
                        f"without authentication."
                    ),
                    module=MODULE_NAME,
                    evidence=db_match.group(0).strip()[:2000],
                    suggested_commands=[
                        f"mongosh --host {target} --port {port} --eval 'show dbs'",
                    ],
                )
            )


# ── Oracle enumeration ──────────────────────────────────────────────────


async def _enum_oracle(
    target: str,
    port: int,
    config: ReconConfig,
    output_dir: Path,
    findings: list[Finding],
    raw_outputs: list[str],
) -> None:
    """Enumerate Oracle TNS service on *target*:*port*.

    Parameters
    ----------
    target:
        Target IP or hostname.
    port:
        Oracle port (typically 1521).
    config:
        Active reconnaissance configuration.
    output_dir:
        Directory for raw output files.
    findings:
        Mutable list to append findings to.
    raw_outputs:
        Mutable list to append raw tool outputs to.
    """
    if shutil.which("nmap"):
        nmap_out = output_dir / f"db_oracle_{port}.txt"
        rc, stdout, stderr = await run_tool(
            cmd=[
                "nmap",
                f"-p{port}",
                "--script", "oracle-tns-version",
                target,
            ],
            output_file=nmap_out,
            timeout=config.default_timeout,
        )
        raw_outputs.append(stdout or stderr)

        if rc == 0 and stdout:
            if "oracle-tns-version" in stdout:
                tns_match = re.search(
                    r"oracle-tns-version:.*?(?:\n\n|\Z)", stdout, re.DOTALL
                )
                if tns_match:
                    findings.append(
                        Finding(
                            severity=Severity.INFO,
                            title=f"Oracle TNS Version on Port {port}",
                            description=(
                                f"Oracle TNS listener version information "
                                f"retrieved from {target}:{port}."
                            ),
                            module=MODULE_NAME,
                            evidence=tns_match.group(0).strip()[:2000],
                        )
                    )

    # ── Suggested tools ─────────────────────────────────────────────────
    suggested: list[str] = []

    if shutil.which("tnscmd10g"):
        suggested.append(f"tnscmd10g version -h {target} -p {port}")
    else:
        suggested.append(
            f"tnscmd10g version -h {target} -p {port}  # install: pipx install tnscmd10g"
        )

    suggested.extend([
        f"nmap -p{port} --script oracle-sid-brute {target}",
        f"nmap -p{port} --script oracle-brute {target}",
        f"odat all -s {target} -p {port}",
    ])

    findings.append(
        Finding(
            severity=Severity.INFO,
            title="Oracle Suggested Commands",
            description="Manual commands for further Oracle enumeration.",
            module=MODULE_NAME,
            evidence=f"Oracle on {target}:{port}",
            suggested_commands=suggested,
        )
    )


# ── Database type → enum function mapping ───────────────────────────────

_DB_ENUM_FUNCS: dict[str, object] = {
    "mysql": _enum_mysql,
    "mssql": _enum_mssql,
    "postgresql": _enum_postgresql,
    "redis": _enum_redis,
    "mongodb": _enum_mongodb,
    "oracle": _enum_oracle,
}


# ── Main entry point ────────────────────────────────────────────────────


async def run_database_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult:
    """Run database enumeration against *target*.

    Triggered when any well-known database port (3306, 1433, 5432,
    6379, 27017, 1521) is open.  Dispatches to the appropriate
    sub-enumerator based on the port.

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
        Aggregated findings from database enumeration.
    """
    start = time.monotonic()
    findings: list[Finding] = []
    raw_outputs: list[str] = []
    output_dir.mkdir(parents=True, exist_ok=True)

    # ── Identify which database ports are open ───────────────────────────
    open_ports = set(state.open_ports)
    active_db_ports: dict[int, str] = {
        port: db_type
        for port, db_type in DB_PORT_MAP.items()
        if port in open_ports
    }

    if not active_db_ports:
        return ModuleResult(
            module_name=MODULE_NAME,
            status="skipped",
            duration_seconds=time.monotonic() - start,
            error_message="No database ports found open",
        )

    # ── Dispatch to per-database enumerators ─────────────────────────────
    for port, db_type in sorted(active_db_ports.items()):
        enum_func = _DB_ENUM_FUNCS.get(db_type)
        if enum_func is None:
            logger.warning("No enumerator for database type '%s'", db_type)
            continue

        try:
            await enum_func(  # type: ignore[misc]
                target=target,
                port=port,
                config=config,
                output_dir=output_dir,
                findings=findings,
                raw_outputs=raw_outputs,
            )
        except Exception as exc:
            logger.error(
                "Error enumerating %s on port %d: %s", db_type, port, exc
            )
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    title=f"{db_type.upper()} Enumeration Error on Port {port}",
                    description=f"An error occurred while enumerating {db_type}: {exc}",
                    module=MODULE_NAME,
                    evidence=str(exc)[:500],
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
        output_file=output_dir / "database_summary.txt",
        duration_seconds=elapsed,
    )
