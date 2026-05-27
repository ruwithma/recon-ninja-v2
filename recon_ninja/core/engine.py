"""Main async orchestrator for ReconNinja.

Runs all reconnaissance phases in order, supports resume from checkpoint,
and manages concurrent module execution with graceful error handling.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

from recon_ninja.core.models import (
    Finding,
    ModuleResult,
    ReconConfig,
    ScanState,
    ServiceInfo,
    Severity,
)
from recon_ninja.core.runner import run_multiple, run_tool

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Phase names for logging
# ---------------------------------------------------------------------------

PHASE_NAMES: dict[int, str] = {
    0: "Pre-flight",
    1: "Port Discovery",
    2: "Deep Service Enumeration",
    3: "Service-Specific Modules",
    4: "OSINT",
    5: "Vulnerability Correlation",
    6: "Loot Extraction",
    7: "Report Generation",
}


# ---------------------------------------------------------------------------
# Nmap XML parser (standalone — no external dependency)
# ---------------------------------------------------------------------------


def parse_nmap_xml(xml_path: Path) -> dict[int, ServiceInfo]:
    """Parse nmap XML output into a ``{port: ServiceInfo}`` mapping.

    Handles both regular and greppable (-oX) nmap XML output.

    Args:
        xml_path: Path to the nmap XML output file.

    Returns:
        Dictionary mapping port numbers to ``ServiceInfo`` instances.
    """
    services: dict[int, ServiceInfo] = {}

    try:
        tree = ET.parse(str(xml_path))
    except ET.ParseError as exc:
        logger.error("Failed to parse nmap XML %s: %s", xml_path, exc)
        return services

    root = tree.getroot()

    for host_elem in root.iter("host"):
        # Skip hosts that are not "up"
        status = host_elem.find("status")
        if status is not None and status.get("state") != "up":
            continue

        # Determine hostname
        hostname: str | None = None
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hname in hostnames_elem.findall("hostname"):
                name = hname.get("name")
                if name:
                    hostname = name
                    break

        ports_elem = host_elem.find("ports")
        if ports_elem is None:
            continue

        for port_elem in ports_elem.findall("port"):
            port_id = int(port_elem.get("portid", "0"))
            proto = port_elem.get("protocol", "tcp")

            state_elem = port_elem.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

            svc_elem = port_elem.find("service")
            service = svc_elem.get("name", "unknown") if svc_elem is not None else "unknown"
            product = svc_elem.get("product", "") if svc_elem is not None else ""
            version = svc_elem.get("version", "") if svc_elem is not None else ""
            extra_info = svc_elem.get("extrainfo", "") if svc_elem is not None else ""

            scripts: dict[str, str] = {}
            for script_elem in port_elem.findall("script"):
                sid = script_elem.get("id", "unknown")
                soutput = script_elem.get("output", "")
                scripts[sid] = soutput

            services[port_id] = ServiceInfo(
                port=port_id,
                proto=proto,
                state=state,
                service=service,
                product=product,
                version=version,
                extra_info=extra_info,
                scripts=scripts,
                hostname=hostname,
            )

    return services


# ---------------------------------------------------------------------------
# ReconEngine
# ---------------------------------------------------------------------------


class ReconEngine:
    """Async orchestrator — runs all reconnaissance phases in order.

    Usage::

        engine = ReconEngine(target="10.10.10.1", config=cfg, state=state)
        final_state = await engine.run()
    """

    def __init__(self, target: str, config: ReconConfig, state: ScanState) -> None:
        self.target = target
        self.config = config
        self.state = state

        # Convenience
        self.output_dir = state.output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Set up file logger for this scan
        self._setup_file_logger()

    # ------------------------------------------------------------------
    # Logging setup
    # ------------------------------------------------------------------

    def _setup_file_logger(self) -> None:
        """Attach a FileHandler writing to ``<output_dir>/reconninja.log``."""
        log_path = self.output_dir / "reconninja.log"
        handler = logging.FileHandler(str(log_path), encoding="utf-8")
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            "%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)

        # Avoid adding duplicate handlers on resume / re-creation
        root_logger = logging.getLogger("recon_ninja")
        if not any(
            isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", "") == str(log_path)
            for h in root_logger.handlers
        ):
            root_logger.addHandler(handler)

        logger.info("File logging initialised → %s", log_path)

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    async def run(self) -> ScanState:
        """Run all phases from current state (supports resume).

        Phases that have already completed (``state.current_phase``) are
        skipped, enabling checkpoint-and-resume behaviour.

        Returns:
            The final ``ScanState`` after all phases complete.
        """
        logger.info(
            "=== ReconEngine starting for %s (resume from phase %d: %s) ===",
            self.target,
            self.state.current_phase,
            PHASE_NAMES.get(self.state.current_phase, "???"),
        )

        phase_methods: list[tuple[int, Callable[..., Any]]] = [
            (1, self.phase1_port_discovery),
            (2, self.phase2_deep_scan),
            (3, self.phase3_modules),
            (4, self.phase4_osint),
            (5, self.phase5_vuln_correlate),
            (6, self.phase6_loot),
            (7, self.phase7_report),
        ]

        for phase_num, phase_func in phase_methods:
            if self.state.current_phase > phase_num:
                logger.info("Skipping phase %d (%s) — already completed", phase_num, PHASE_NAMES[phase_num])
                continue

            phase_name = PHASE_NAMES.get(phase_num, f"Phase {phase_num}")
            logger.info(">>> Phase %d: %s <<<", phase_num, phase_name)

            t0 = time.monotonic()
            try:
                await phase_func()
            except Exception as exc:
                logger.exception("Phase %d (%s) failed: %s", phase_num, phase_name, exc)
                # Record the failure but continue to next phase
                self.state.add_finding(
                    Finding(
                        severity=Severity.HIGH,
                        title=f"Phase {phase_num} ({phase_name}) crashed",
                        description=str(exc),
                        module="engine",
                    )
                )

            elapsed = time.monotonic() - t0
            logger.info(
                "<<< Phase %d (%s) completed in %.1fs >>>",
                phase_num,
                phase_name,
                elapsed,
            )

            self.state.current_phase = phase_num + 1
            self.state.save()
            logger.debug("State saved after phase %d", phase_num)

        self.state.end_time = self.state.end_time or __import__("datetime").datetime.now()
        self.state.save()
        logger.info("=== ReconEngine finished for %s ===", self.target)
        return self.state

    # ------------------------------------------------------------------
    # Phase 1 — Port Discovery
    # ------------------------------------------------------------------

    async def phase1_port_discovery(self) -> None:
        """Run RustScan or nmap fast scan to find open ports.

        Strategy:
            * If ``rustscan`` is available on PATH, use it for fast SYN scan.
            * Otherwise fall back to ``nmap -sS --top-ports 10000``.
            * In fast mode, only scan top-1000 ports.
            * Optionally run a UDP scan on top ports if ``config.udp_scan``.
            * Parsed ports are stored in ``state.open_ports``.
        """
        ports_file = self.output_dir / "ports.txt"

        # --- RustScan path ---
        if shutil.which("rustscan"):
            logger.info("Using RustScan for port discovery")
            top_ports = "1000" if self.config.fast_mode else "10000"
            cmd = [
                "rustscan",
                "--addresses", self.target,
                "--top-ports", top_ports,
                "--ulimit", "5000",
                "--",
                "-Pn",
            ]
            rc, stdout, stderr = await run_tool(
                cmd,
                output_file=self.output_dir / "rustscan.txt",
                timeout=self.config.default_timeout,
            )

            if rc == 0:
                # RustScan prints "Open <ip>:<port>" lines
                open_ports = self._parse_rustscan_ports(stdout)
                self.state.open_ports = sorted(set(open_ports))
                logger.info("RustScan found %d open ports: %s", len(self.state.open_ports), self.state.open_ports)
            else:
                logger.warning("RustScan failed (rc=%d), falling back to nmap", rc)
                await self._nmap_fast_scan()
        else:
            logger.info("RustScan not found, using nmap for port discovery")
            await self._nmap_fast_scan()

        # --- Optional UDP scan ---
        if self.config.udp_scan:
            await self._nmap_udp_scan()

        # Persist port list for other phases
        ports_file.write_text(",".join(str(p) for p in self.state.open_ports), encoding="utf-8")
        logger.info("Open ports written to %s", ports_file)

    async def _nmap_fast_scan(self) -> None:
        """Fast SYN scan using nmap as fallback."""
        top_ports = "1000" if self.config.fast_mode else "10000"
        cmd = [
            "nmap",
            "-Pn",
            "-sS",
            "--top-ports", top_ports,
            "-T4",
            *self.config.extra_nmap_flags,
            self.target,
        ]
        outfile = self.output_dir / "nmap_fast.txt"
        rc, stdout, stderr = await run_tool(
            cmd,
            output_file=outfile,
            timeout=self.config.default_timeout,
        )

        if rc == 0:
            ports = self._parse_nmap_grep_ports(stdout)
            self.state.open_ports = sorted(set(ports))
            logger.info("nmap fast scan found %d open ports", len(self.state.open_ports))
        else:
            logger.error("nmap fast scan failed (rc=%d): %s", rc, stderr.strip())

    async def _nmap_udp_scan(self) -> None:
        """Top-20 UDP port scan."""
        cmd = [
            "nmap",
            "-Pn",
            "-sU",
            "--top-ports", "20",
            "-T4",
            *self.config.extra_nmap_flags,
            self.target,
        ]
        outfile = self.output_dir / "nmap_udp.txt"
        rc, stdout, stderr = await run_tool(
            cmd,
            output_file=outfile,
            timeout=self.config.default_timeout,
        )

        if rc == 0:
            udp_ports = self._parse_nmap_grep_ports(stdout)
            self.state.udp_ports = sorted(set(udp_ports))
            logger.info("UDP scan found %d open/filtered ports", len(self.state.udp_ports))
        else:
            logger.warning("UDP scan failed (rc=%d): %s", rc, stderr.strip())

    # ------------------------------------------------------------------
    # Phase 2 — Deep Service Enumeration
    # ------------------------------------------------------------------

    async def phase2_deep_scan(self) -> None:
        """Run deep nmap scan with -sC -sV -O on discovered ports.

        Parses the XML output using :func:`parse_nmap_xml`, detects
        hostnames, and classifies the box profile.
        """
        if not self.state.open_ports:
            logger.warning("No open ports discovered — skipping deep scan")
            return

        ports_str = ",".join(str(p) for p in self.state.open_ports)
        xml_out = self.output_dir / "nmap_deep.xml"

        cmd = [
            "nmap",
            "-Pn",
            "-sC", "-sV", "-O",
            "-p", ports_str,
            "-oX", str(xml_out),
            *self.config.extra_nmap_flags,
            self.target,
        ]

        rc, stdout, stderr = await run_tool(
            cmd,
            output_file=self.output_dir / "nmap_deep.txt",
            timeout=max(self.config.default_timeout, 600),
        )

        if rc != 0 and not xml_out.exists():
            logger.error("Deep scan failed (rc=%d) and no XML output", rc)
            return

        if xml_out.exists():
            services = parse_nmap_xml(xml_out)
            self.state.services.update(services)
            logger.info("Parsed %d services from deep scan XML", len(services))
        else:
            logger.warning("XML output file not found after deep scan")

        # Detect hostnames from service info
        for svc in self.state.services.values():
            if svc.hostname and svc.hostname not in self.state.hostnames:
                self.state.hostnames.append(svc.hostname)

        # Classify the box
        self.state.box_profile = self._classify_box()
        logger.info("Box profile: %s", self.state.box_profile)

    # ------------------------------------------------------------------
    # Phase 3 — Service-Specific Modules
    # ------------------------------------------------------------------

    async def phase3_modules(self) -> None:
        """Launch service-specific modules concurrently.

        Modules are determined by :meth:`_determine_modules` based on the
        services discovered in Phase 2.  They run under a semaphore
        (controlled by ``config.max_concurrent``) and each module's errors
        are caught so that a single failure does not block others.
        """
        modules = self._determine_modules()

        if not modules:
            logger.info("No applicable modules for detected services")
            return

        # Filter out disabled modules
        enabled_modules = [
            (name, func)
            for name, func in modules
            if self.config.is_module_enabled(name)
            and name not in self.state.completed_modules
        ]

        if not enabled_modules:
            logger.info("All applicable modules are disabled or already completed")
            return

        logger.info("Running %d modules: %s", len(enabled_modules), [n for n, _ in enabled_modules])

        semaphore = asyncio.Semaphore(self.config.max_concurrent)
        results: list[ModuleResult] = []

        async def _run_module(name: str, func: Callable[..., Any]) -> ModuleResult:
            """Execute a single module inside the semaphore, catching errors."""
            async with semaphore:
                logger.info("[module:%s] Starting", name)
                t0 = time.monotonic()
                try:
                    result: ModuleResult = await func(
                        target=self.target,
                        state=self.state,
                        config=self.config,
                        output_dir=self.output_dir,
                    )
                except asyncio.TimeoutError:
                    result = ModuleResult(
                        module_name=name,
                        status="timeout",
                        error_message=f"Module {name} timed out",
                        duration_seconds=time.monotonic() - t0,
                    )
                except Exception as exc:
                    logger.exception("[module:%s] Error: %s", name, exc)
                    result = ModuleResult(
                        module_name=name,
                        status="error",
                        error_message=str(exc),
                        duration_seconds=time.monotonic() - t0,
                    )

                # Some module implementations may return None to indicate
                # a skipped action; normalize that into a ModuleResult so
                # the engine records completion and doesn't repeatedly
                # re-run the module on resume.
                if result is None:
                    logger.debug("[module:%s] Module returned None — treating as skipped", name)
                    result = ModuleResult(
                        module_name=name,
                        status="skipped",
                        error_message="Module returned None",
                    )

                result.duration_seconds = time.monotonic() - t0
                logger.info(
                    "[module:%s] Finished — status=%s duration=%.1fs",
                    name,
                    result.status,
                    result.duration_seconds,
                )
                return result

        tasks = [
            asyncio.create_task(_run_module(name, func))
            for name, func in enabled_modules
        ]

        module_results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in module_results:
            if isinstance(result, Exception):
                logger.error("Module task raised unexpectedly: %s", result)
                continue
            if not isinstance(result, ModuleResult):
                continue

            self.state.module_results.append(result)
            self.state.completed_modules.append(result.module_name)

            for finding in result.findings:
                self.state.add_finding(finding)

        logger.info(
            "Phase 3 complete: %d module results, %d total findings",
            len(self.state.module_results),
            len(self.state.all_findings),
        )

    # ------------------------------------------------------------------
    # Phase 4 — OSINT
    # ------------------------------------------------------------------

    async def phase4_osint(self) -> None:
        """Run OSINT modules for domain targets.

        Skipped entirely when ``config.osint_enabled`` is ``False`` or when
        the target does not appear to be a domain.
        """
        if not self.config.osint_enabled:
            logger.info("OSINT phase disabled in config")
            return

        if not self.config.is_domain and not self.state.hostnames:
            logger.info("Target is an IP with no hostname — skipping OSINT")
            return

        osint_target = self.state.primary_hostname or self.target
        logger.info("Running OSINT for %s", osint_target)

        # --- DNS enumeration ---
        if shutil.which("dnsrecon"):
            cmd = [
                "dnsrecon",
                "-d", osint_target,
                "-t", "std",
                "-o", str(self.output_dir / "dnsrecon.json"),
            ]
            await run_tool(
                cmd,
                output_file=self.output_dir / "dnsrecon.txt",
                timeout=self.config.default_timeout,
            )
        else:
            logger.debug("dnsrecon not found — skipping DNS OSINT")

        # --- Subfinder ---
        if shutil.which("subfinder"):
            cmd = [
                "subfinder",
                "-d", osint_target,
                "-o", str(self.output_dir / "subfinder.txt"),
                "-silent",
            ]
            await run_tool(
                cmd,
                output_file=self.output_dir / "subfinder.txt",
                timeout=self.config.default_timeout,
            )
        else:
            logger.debug("subfinder not found — skipping subdomain enum")

        # --- theHarvester ---
        if shutil.which("theHarvester"):
            cmd = [
                "theHarvester",
                "-d", osint_target,
                "-b", "all",
                "-f", str(self.output_dir / "harvester"),
            ]
            await run_tool(
                cmd,
                timeout=self.config.default_timeout,
            )
        else:
            logger.debug("theHarvester not found — skipping")

    # ------------------------------------------------------------------
    # Phase 5 — Vulnerability Correlation
    # ------------------------------------------------------------------

    async def phase5_vuln_correlate(self) -> None:
        """Run searchsploit and nuclei against all detected versions.

        Skipped when ``config.skip_vuln_correlate`` is ``True``.
        """
        if self.config.skip_vuln_correlate:
            logger.info("Vulnerability correlation phase skipped by config")
            return

        commands: list[tuple[str, list[str], Path | None]] = []

        # --- searchsploit ---
        if shutil.which("searchsploit"):
            # Build a query from every product+version we found
            for svc in self.state.services.values():
                if svc.product and svc.version:
                    query = f"{svc.product} {svc.version}"
                    outfile = self.output_dir / f"searchsploit_{svc.port}.txt"
                    commands.append((
                        f"searchsploit-{svc.port}",
                        ["searchsploit", "--json", query],
                        outfile,
                    ))

        # --- nuclei ---
        if shutil.which("nuclei"):
            nuclei_cmd = ["nuclei", "-u", self.target, "-o", str(self.output_dir / "nuclei.txt")]
            if self.config.nuclei_templates:
                nuclei_cmd.extend(["-t", self.config.nuclei_templates])
            commands.append(("nuclei", nuclei_cmd, self.output_dir / "nuclei.txt"))

        if not commands:
            logger.info("No vulnerability correlation tools available")
            return

        results = await run_multiple(
            commands,
            max_concurrent=self.config.max_concurrent,
            timeout=self.config.default_timeout,
        )

        # Convert searchsploit results into findings
        for name, (rc, stdout, stderr) in results.items():
            if rc != 0:
                logger.warning("Vuln correlation task %s failed (rc=%d)", name, rc)
                continue
            if "searchsploit" in name and stdout.strip():
                self.state.add_finding(
                    Finding(
                        severity=Severity.MEDIUM,
                        title=f"Searchsploit results for {name}",
                        description="Potential exploits found — see output file",
                        evidence=stdout[:2000],
                        module="vuln_correlate",
                    )
                )
            if name == "nuclei" and stdout.strip():
                self.state.add_finding(
                    Finding(
                        severity=Severity.HIGH,
                        title="Nuclei vulnerability scan results",
                        description="Vulnerabilities detected by nuclei — see output file",
                        evidence=stdout[:2000],
                        module="vuln_correlate",
                    )
                )

    # ------------------------------------------------------------------
    # Phase 6 — Loot Extraction
    # ------------------------------------------------------------------

    async def phase6_loot(self) -> None:
        """Extract loot from all output files.

        Scans output files for common CTF/pentest loot patterns: credentials,
        flags, keys, hashes, and interesting strings.
        """
        if self.config.skip_loot:
            logger.info("Loot extraction phase skipped by config")
            return

        loot_dir = self.output_dir / "loot"
        loot_dir.mkdir(parents=True, exist_ok=True)

        loot_patterns: dict[str, list[str]] = {
            "credentials": [
                r"password", r"passwd", r"pwd", r"login", r"credential",
                r"secret", r"apikey", r"api_key", r"token",
            ],
            "flags": [
                r"flag\{", r"HTB\{", r"THM\{", r"CTF\{", r"picoCTF\{",
            ],
            "hashes": [
                r"\$[0-9a-z]\$", r"[a-f0-9]{32}", r"[a-f0-9]{40}",
                r"[a-f0-9]{64}",
            ],
            "keys": [
                r"BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY",
                r"ssh-rsa ", r"ssh-ed25519 ",
            ],
        }

        import re

        for pattern_category, patterns in loot_patterns.items():
            combined_re = re.compile("|".join(patterns), re.IGNORECASE)
            loot_lines: list[str] = []

            for outfile in self.output_dir.rglob("*.txt"):
                try:
                    text = outfile.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                for line in text.splitlines():
                    if combined_re.search(line):
                        loot_lines.append(f"[{outfile.name}] {line.strip()}")

            if loot_lines:
                loot_file = loot_dir / f"{pattern_category}.txt"
                loot_file.write_text("\n".join(loot_lines), encoding="utf-8")
                logger.info(
                    "Loot [%s]: %d matches → %s",
                    pattern_category,
                    len(loot_lines),
                    loot_file,
                )

                self.state.add_finding(
                    Finding(
                        severity=Severity.INFO,
                        title=f"Loot: {pattern_category}",
                        description=f"Extracted {len(loot_lines)} potential {pattern_category} matches",
                        evidence="\n".join(loot_lines[:10]),
                        module="loot",
                    )
                )

    # ------------------------------------------------------------------
    # Phase 7 — Report Generation
    # ------------------------------------------------------------------

    async def phase7_report(self) -> None:
        """Generate final reports in multiple formats.

        Delegates to :func:`recon_ninja.core.report.generate_reports` for
        comprehensive Markdown, HTML (opt-in), and JSON output.  Also
        writes a raw ``state.json`` for checkpoint / resume purposes.
        """
        from recon_ninja.core.report import generate_reports

        # Determine whether HTML report was requested
        html = self.config.module_toggles.get("_html_report", False)
        json_output = self.config.module_toggles.get("_json_report", True)

        generated = await generate_reports(
            state=self.state,
            output_dir=self.output_dir,
            html=html,
            json_output=json_output,
        )
        for fmt_name, path in generated.items():
            logger.info("%s report → %s", fmt_name.capitalize(), path)

        # Always write raw state.json for checkpoint / resume
        state_file = self.output_dir / "state.json"
        state_file.write_text(
            __import__("json").dumps(self.state.to_dict(), indent=2),
            encoding="utf-8",
        )
        logger.info("State checkpoint → %s", state_file)

    def _build_markdown_report(self) -> list[str]:
        """Build a Markdown report as a list of lines."""
        lines: list[str] = [
            "# ReconNinja — Scan Report",
            "",
            f"**Target:** {self.target}",
            f"**Box Profile:** {self.state.box_profile}",
            f"**Duration:** {self.state.duration:.1f}s",
            f"**Open Ports:** {', '.join(str(p) for p in self.state.open_ports) or 'None'}",
            f"**Hostnames:** {', '.join(self.state.hostnames) or 'None'}",
            "",
            "## Services",
            "",
        ]

        for port, svc in sorted(self.state.services.items()):
            lines.append(
                f"- **Port {port}/{svc.proto}** — {svc.service} "
                f"| {svc.display_product} "
                f"| State: {svc.state}"
            )
            if svc.scripts:
                for script_id, output in svc.scripts.items():
                    lines.append(f"  - Script `{script_id}`: {output[:200]}")

        lines.append("")
        lines.append("## Findings")
        lines.append("")

        by_sev = self.state.findings_by_severity()
        for sev in Severity:
            findings = by_sev.get(sev, [])
            if not findings:
                continue
            lines.append(f"### {sev.value} ({len(findings)})")
            lines.append("")
            for f in findings:
                lines.append(f"- **[{f.module}]** {f.title}")
                if f.description:
                    lines.append(f"  > {f.description[:300]}")
            lines.append("")

        if self.state.module_results:
            lines.append("## Module Results")
            lines.append("")
            for mr in self.state.module_results:
                lines.append(
                    f"- **{mr.module_name}** — {mr.status} "
                    f"({mr.duration_seconds:.1f}s)"
                )
                if mr.error_message:
                    lines.append(f"  > Error: {mr.error_message[:200]}")
            lines.append("")

        return lines

    # ------------------------------------------------------------------
    # Module determination
    # ------------------------------------------------------------------

    def _determine_modules(self) -> list[tuple[str, Callable[..., Any]]]:
        """Based on services, return list of ``(name, module_func)`` to run.

        Each module function is an async callable with the signature::

            async def module_func(
                target: str,
                state: ScanState,
                config: ReconConfig,
                output_dir: Path,
            ) -> ModuleResult: ...

        Module availability is checked lazily — if a required external tool
        is not installed, the module function itself should return a
        ``ModuleResult(status="skipped")``.
        """
        modules: list[tuple[str, Callable[..., Any]]] = []

        # Import modules lazily so that missing sub-packages don't crash
        # the engine at import time.
        try:
            from recon_ninja.modules.web import run_web_module
            modules.append(("web", run_web_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.smb import run_smb_module
            modules.append(("smb", run_smb_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.ssh import run_ssh_module
            modules.append(("ssh", run_ssh_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.ftp import run_ftp_module
            modules.append(("ftp", run_ftp_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.smtp import run_smtp_module
            modules.append(("smtp", run_smtp_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.snmp import run_snmp_module
            modules.append(("snmp", run_snmp_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.dns import run_dns_module
            modules.append(("dns", run_dns_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.ldap import run_ldap_module
            modules.append(("ldap", run_ldap_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.kerberos import run_kerberos_module
            modules.append(("kerberos", run_kerberos_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.rpc import run_rpc_module
            modules.append(("rpc", run_rpc_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.nfs import run_nfs_module
            modules.append(("nfs", run_nfs_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.rdp import run_rdp_module
            modules.append(("rdp", run_rdp_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.vnc import run_vnc_module
            modules.append(("vnc", run_vnc_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.winrm import run_winrm_module
            modules.append(("winrm", run_winrm_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.database import run_database_module
            modules.append(("database", run_database_module))
        except ImportError:
            pass

        try:
            from recon_ninja.modules.ssl import run_ssl_module
            modules.append(("ssl", run_ssl_module))
        except ImportError:
            pass

        # Now filter: only keep modules that are relevant to detected services
        relevant = self._filter_relevant_modules(modules)
        return relevant

    def _filter_relevant_modules(
        self, all_modules: list[tuple[str, Callable[..., Any]]]
    ) -> list[tuple[str, Callable[..., Any]]]:
        """Keep only modules whose service is present on the target.

        The mapping of module name → detection criteria follows the spec.
        """
        module_name_to_func: dict[str, Callable[..., Any]] = dict(all_modules)
        relevant: list[tuple[str, Callable[..., Any]]] = []

        port_set = set(self.state.open_ports)
        service_names = {svc.service.lower() for svc in self.state.services.values()}

        # Helper predicates
        def has_port(*ports: int) -> bool:
            return bool(port_set.intersection(ports))

        def has_service(name: str) -> bool:
            return any(name in sn for sn in service_names)

        # Web: any port with "http" service
        if has_service("http"):
            if "web" in module_name_to_func:
                relevant.append(("web", module_name_to_func["web"]))

        # SMB: port 139 or 445
        if has_port(139, 445):
            if "smb" in module_name_to_func:
                relevant.append(("smb", module_name_to_func["smb"]))

        # SSH: port 22 or service "ssh"
        if has_port(22) or has_service("ssh"):
            if "ssh" in module_name_to_func:
                relevant.append(("ssh", module_name_to_func["ssh"]))

        # FTP: port 21
        if has_port(21):
            if "ftp" in module_name_to_func:
                relevant.append(("ftp", module_name_to_func["ftp"]))

        # SMTP: ports 25, 465, 587
        if has_port(25, 465, 587):
            if "smtp" in module_name_to_func:
                relevant.append(("smtp", module_name_to_func["smtp"]))

        # SNMP: UDP port 161
        if 161 in set(self.state.udp_ports):
            if "snmp" in module_name_to_func:
                relevant.append(("snmp", module_name_to_func["snmp"]))

        # DNS: port 53
        if has_port(53):
            if "dns" in module_name_to_func:
                relevant.append(("dns", module_name_to_func["dns"]))

        # LDAP: ports 389, 636
        if has_port(389, 636):
            if "ldap" in module_name_to_func:
                relevant.append(("ldap", module_name_to_func["ldap"]))

        # Kerberos: port 88
        if has_port(88):
            if "kerberos" in module_name_to_func:
                relevant.append(("kerberos", module_name_to_func["kerberos"]))

        # RPC: ports 111 or 135
        if has_port(111, 135):
            if "rpc" in module_name_to_func:
                relevant.append(("rpc", module_name_to_func["rpc"]))

        # NFS: port 2049
        if has_port(2049):
            if "nfs" in module_name_to_func:
                relevant.append(("nfs", module_name_to_func["nfs"]))

        # RDP: port 3389
        if has_port(3389):
            if "rdp" in module_name_to_func:
                relevant.append(("rdp", module_name_to_func["rdp"]))

        # VNC: ports 5900-5910
        if port_set.intersection(range(5900, 5911)):
            if "vnc" in module_name_to_func:
                relevant.append(("vnc", module_name_to_func["vnc"]))

        # WinRM: ports 5985, 5986
        if has_port(5985, 5986):
            if "winrm" in module_name_to_func:
                relevant.append(("winrm", module_name_to_func["winrm"]))

        # Database: ports 3306, 1433, 5432, 6379, 27017, 1521
        if has_port(3306, 1433, 5432, 6379, 27017, 1521):
            if "database" in module_name_to_func:
                relevant.append(("database", module_name_to_func["database"]))

        # SSL: any HTTPS service
        if has_service("ssl") or has_service("https"):
            if "ssl" in module_name_to_func:
                relevant.append(("ssl", module_name_to_func["ssl"]))

        return relevant

    # ------------------------------------------------------------------
    # Box classification
    # ------------------------------------------------------------------

    def _classify_box(self) -> str:
        """Classify the target based on detected services.

        Returns one of:
            ``WINDOWS_AD``, ``WINDOWS_WEB``, ``LINUX_WEB``,
            ``LINUX_AD``, ``LINUX_SERVER``, ``UNKNOWN``.
        """
        port_set = set(self.state.open_ports)
        service_products = {
            svc.product.lower() for svc in self.state.services.values()
        }
        service_names = {
            svc.service.lower() for svc in self.state.services.values()
        }

        has_kerberos = 88 in port_set
        has_ldap = bool(port_set.intersection({389, 636}))
        has_smb = bool(port_set.intersection({139, 445}))
        has_winrm = bool(port_set.intersection({5985, 5986}))
        has_ssh = 22 in port_set
        has_http = bool(port_set.intersection({80, 443, 8080, 8443})) or "http" in service_names
        has_iis = any("iis" in p for p in service_products)

        # WINDOWS_AD: ports 88 + 389 + 445 + (5985 or 139)
        if has_kerberos and has_ldap and has_smb and (has_winrm or 139 in port_set):
            return "WINDOWS_AD"

        # WINDOWS_WEB: IIS detected, no Kerberos
        if has_iis and not has_kerberos:
            return "WINDOWS_WEB"

        # LINUX_WEB: port 22 + 80/443, no SMB
        if has_ssh and has_http and not has_smb:
            return "LINUX_WEB"

        # LINUX_AD: Samba + LDAP, no Kerberos
        if has_smb and has_ldap and not has_kerberos:
            return "LINUX_AD"

        # LINUX_SERVER: port 22, no web
        if has_ssh and not has_http:
            return "LINUX_SERVER"

        return "UNKNOWN"

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_rustscan_ports(output: str) -> list[int]:
        """Extract open port numbers from RustScan output.

        RustScan prints lines like ``Open 10.10.10.1:22``.
        """
        import re

        ports: list[int] = []
        pattern = re.compile(r"Open\s+\S+:(\d+)")
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                ports.append(int(match.group(1)))
        return ports

    @staticmethod
    def _parse_nmap_grep_ports(output: str) -> list[int]:
        """Extract open port numbers from normal nmap output.

        Matches lines like ``22/tcp  open  ssh``.
        """
        import re

        ports: list[int] = []
        pattern = re.compile(r"^(\d+)/(tcp|udp)\s+open\s+", re.MULTILINE)
        for match in pattern.finditer(output):
            ports.append(int(match.group(1)))
        return ports
