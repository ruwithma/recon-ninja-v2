"""Main async orchestrator for ReconNinja.

Runs all reconnaissance phases in order, supports resume from checkpoint,
and manages concurrent module execution with graceful error handling.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shutil
import time
import datetime as _dt
from pathlib import Path
from typing import Any, Callable

from recon_ninja.core.display import (
    display_phase_header,
    display_port_table,
    display_box_profile,
    display_loot_summary,
    get_console,
)
from recon_ninja.core.models import (
    Finding,
    KNOWN_WEB_PORTS,
    ModuleResult,
    ReconConfig,
    ScanState,
    ServiceInfo,
    Severity,
)
from recon_ninja.core.runner import run_multiple, run_tool
from recon_ninja.utils.network import is_root
from recon_ninja.utils.nmap_parser import parse_nmap_xml

logger = logging.getLogger(__name__)


def _is_valid_hostname(name: str) -> bool:
    """Check if a string looks like a valid hostname.

    Filters out garbage like ``"Did not follow redirect to http://X/"``
    that nmap's http-title script sometimes produces.
    """
    if not name:
        return False
    if " " in name or "/" in name or ":" in name:
        return False
    if "." not in name:
        return False
    if name.replace(".", "").isdigit():
        return False
    return True

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
# Nmap XML parser — imported from utils.nmap_parser
# ---------------------------------------------------------------------------

# parse_nmap_xml is now imported from recon_ninja.utils.nmap_parser at the
# top of this file.  It returns a tuple of (services, hostnames).


# ---------------------------------------------------------------------------
# ReconEngine
# ---------------------------------------------------------------------------


class ReconEngine:
    """Async orchestrator — runs all reconnaissance phases in order.

    Usage::

        engine = ReconEngine(target="10.10.10.1", config=cfg, state=state)
        final_state = await engine.run()
    """

    def __init__(self, target: str, config: ReconConfig, state: ScanState, quiet: bool = False) -> None:
        self.target = target
        self.config = config
        self.state = state
        self.quiet = quiet

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

            if not self.quiet:
                display_phase_header(phase_num, phase_name)

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

        self.state.end_time = self.state.end_time or _dt.datetime.now()
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
        rustscan_path = shutil.which("rustscan")
        if not rustscan_path:
            # Check extra search paths
            from recon_ninja.utils.checker import EXTRA_SEARCH_PATHS
            import os
            for p in EXTRA_SEARCH_PATHS:
                cand = p / "rustscan"
                if cand.is_file() and os.access(cand, os.X_OK):
                    rustscan_path = str(cand)
                    break

        if rustscan_path:
            logger.info("Using RustScan for port discovery (path: %s)", rustscan_path)
            if not self.quiet:
                console = get_console()
                console.print("  [dim]Using RustScan for fast port discovery...[/]")
            top_ports = "1000" if self.config.fast_mode else "10000"

            # Dynamically calculate ulimit and batch size to prevent OS permission/resource errors
            try:
                import resource
                soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            except Exception:
                soft, hard = 1024, 1024

            ulimit_val = min(5000, hard)
            cmd = [
                rustscan_path,
                "-a", self.target,
                "-r", f"1-{top_ports}",
                "-u", str(ulimit_val),
                "--scripts", "none",
            ]

            if ulimit_val < 4500:
                batch_size = max(100, ulimit_val - 100)
                cmd.extend(["-b", str(batch_size)])

            rc, stdout, stderr = await run_tool(
                cmd,
                output_file=self.output_dir / "rustscan.txt",
                timeout=self.config.default_timeout,
            )

            if rc == 0:
                # RustScan prints "Open <ip>:<port>" lines or raw port numbers
                open_ports = self._parse_rustscan_ports(stdout)
                self.state.open_ports = sorted(set(open_ports))
                logger.info("RustScan found %d open ports: %s", len(self.state.open_ports), self.state.open_ports)
            else:
                logger.warning("RustScan failed (rc=%d), falling back to nmap", rc)
                await self._nmap_fast_scan()
        else:
            logger.info("RustScan not found, using nmap for port discovery")
            if not self.quiet:
                console = get_console()
                console.print("  [dim]Using nmap for port discovery...[/]")
            await self._nmap_fast_scan()

        # --- Optional UDP scan ---
        if self.config.udp_scan:
            await self._nmap_udp_scan()

        # Persist port list for other phases
        ports_file.write_text(",".join(str(p) for p in self.state.open_ports), encoding="utf-8")
        logger.info("Open ports written to %s", ports_file)

        if not self.quiet:
            console = get_console()
            console.print(f"  [bold green][+][/] Found [bold]{len(self.state.open_ports)}[/] open ports: [cyan]{', '.join(str(p) for p in self.state.open_ports)}[/]")

    async def _nmap_fast_scan(self) -> None:
        """Fast SYN/TCP Connect scan using nmap as fallback."""
        top_ports = "1000" if self.config.fast_mode else "10000"
        scan_type = "-sS" if is_root() else "-sT"
        cmd = [
            "nmap",
            "-Pn",
            scan_type,
            "--top-ports", top_ports,
            "-T4",
            "--min-rate", "5000",
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
        ]
        if is_root():
            cmd.append("-O")
        cmd.extend([
            "-sC", "-sV",
            "--version-intensity", "5",
            "-p", ports_str,
            "-oX", str(xml_out),
            *self.config.extra_nmap_flags,
            self.target,
        ])

        rc, stdout, stderr = await run_tool(
            cmd,
            output_file=self.output_dir / "nmap_deep.txt",
            timeout=max(self.config.default_timeout, 600),
        )

        if rc != 0 and not xml_out.exists():
            logger.error("Deep scan failed (rc=%d) and no XML output", rc)
            return

        if xml_out.exists():
            services, parsed_hostnames = parse_nmap_xml(xml_out)
            self.state.services.update(services)
            logger.info("Parsed %d services from deep scan XML", len(services))

            # Supplement product/version from nmap script output when
            # nmap -sV couldn't determine them (common for filtered ports).
            self._supplement_scripts(services)
        else:
            logger.warning("XML output file not found after deep scan")
            parsed_hostnames = []

        # Detect hostnames from service info
        for svc in self.state.services.values():
            if svc.hostname:
                # Validate hostname — skip garbage like
                # "Did not follow redirect to http://X/"
                if not _is_valid_hostname(svc.hostname):
                    logger.warning(
                        "Ignoring invalid hostname from nmap: %r",
                        svc.hostname,
                    )
                    # Clear the garbage hostname so it doesn't
                    # propagate into URL construction later
                    svc.hostname = None
                    continue
                is_new = svc.hostname not in self.state.hostnames
                self.state.add_hostname(svc.hostname)
                if is_new:
                    # Auto-add to hosts if enabled OR running as root
                    auto_add = (
                        self.config.module_toggles.get("_add_hosts", False)
                        or self.config.module_toggles.get("_htb", False)
                    )
                    if not auto_add:
                        auto_add = is_root()
                    from recon_ninja.utils.hosts import get_ip_for_hostname, add_to_hosts
                    if auto_add and get_ip_for_hostname(
                        svc.hostname
                    ) != self.target:
                        if add_to_hosts(
                            self.target, svc.hostname,
                        ):
                            logger.info(
                                "Auto-updated %s -> %s"
                                " in /etc/hosts (nmap)",
                                self.target, svc.hostname,
                            )
                            if not self.quiet:
                                get_console().print(
                                    f"  [bold green][+][/] Auto-added"
                                    f" [bold cyan]{svc.hostname}[/]"
                                    f" to /etc/hosts"
                                )

        # Also register hostnames extracted from <hostname> elements and
        # http-title script output by the parser
        for hname in parsed_hostnames:
            if not hname or not _is_valid_hostname(hname):
                logger.warning("Ignoring invalid hostname from parser: %r", hname)
                continue
            if hname not in self.state.hostnames:
                self.state.add_hostname(hname)
                auto_add = (
                    self.config.module_toggles.get("_add_hosts", False)
                    or self.config.module_toggles.get("_htb", False)
                )
                if not auto_add:
                    auto_add = is_root()
                from recon_ninja.utils.hosts import get_ip_for_hostname, add_to_hosts
                if auto_add and get_ip_for_hostname(hname) != self.target:
                    if add_to_hosts(self.target, hname):
                        logger.info(
                            "Auto-updated %s -> %s in /etc/hosts",
                            self.target, hname,
                        )
                        if not self.quiet:
                            get_console().print(
                                f"  [bold green][+][/] Auto-added"
                                f" [bold cyan]{hname}[/]"
                                f" to /etc/hosts"
                            )

        # Classify the box
        self.state.box_profile = self._classify_box()
        logger.info("Box profile: %s", self.state.box_profile)

        if not self.quiet:
            display_port_table(self.state.services)
            display_box_profile(self.state.box_profile)

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

        if not self.quiet:
            console = get_console()
            for name, _func in enabled_modules:
                console.print(f"  [dim]▸[/] Running [bold]{name}[/] module...")

        semaphore = asyncio.Semaphore(self.config.max_concurrent)
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

        if not self.quiet:
            console = get_console()
            for result in module_results:
                if isinstance(result, Exception) or not isinstance(result, ModuleResult):
                    continue
                name = result.module_name
                if result.status == "done":
                    console.print(f"  [bold green][+][/] {name} [dim]({result.duration_seconds:.1f}s)[/]")
                elif result.status == "error":
                    console.print(f"  [bold red][x][/] {name} [dim]— {result.error_message[:80]}[/]")
                elif result.status == "skipped":
                    console.print(f"  [yellow][-][/] {name} [dim]— skipped[/]")
                elif result.status == "timeout":
                    console.print(f"  [red][!][/] {name} [dim]— timed out[/]")

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

        # Display discovered paths and vhosts PROMINENTLY — before the
        # findings panel collapses them into INFO summary.  CTF players
        # need to see directories and vhosts first, not buried in a
        # generic findings list.
        if not self.quiet:
            from recon_ninja.core.display import display_discovered_paths
            dirfuzz_findings = []
            vhost_findings = []
            for result in module_results:
                if not isinstance(result, ModuleResult):
                    continue
                for f in result.findings:
                    if f.module == "web_dirfuzz":
                        if f.title.startswith("Vhost found:"):
                            vhost_findings.append(f)
                        elif f.title.startswith("Fuzz:") or f.title.startswith("Path found:") or f.title.startswith("[") and "Path found:" in f.title:
                            dirfuzz_findings.append(f)
            if dirfuzz_findings or vhost_findings:
                display_discovered_paths(dirfuzz_findings, vhost_findings)

        # Show a quick findings summary after Phase 3 so the user gets
        # immediate feedback without waiting for Phases 4-7 to complete.
        if not self.quiet and self.state.all_findings:
            from recon_ninja.core.display import display_findings_panel
            display_findings_panel(self.state.all_findings)

        # Re-display the port table with tech-enriched data now that
        # Phase 3 has run technology detection.  When nmap -sV fails to
        # detect product/version (shows "—"), the tech data from
        # Wappalyzer/headers supplements the table.
        if not self.quiet and self.state.detected_techs:
            console = get_console()
            console.print()
            console.print(
                "  [bold cyan][*][/] Updated service info with detected technologies:"
            )
            display_port_table(self.state.services, techs=self.state.detected_techs)

        # Phase 3.5: Recursively scan discovered vhosts for technologies.
        # Vhosts found by web_dirfuzz may have different tech stacks from
        # the primary host.  The web module already does in-scan vhost
        # tech detection, but this catches vhosts discovered through other
        # channels (OSINT, DNS) or ensures complete coverage.
        await self._scan_vhost_techs()

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
        the target does not appear to be a domain.  All OSINT tools run
        concurrently via :func:`run_multiple`.
        """
        if not self.config.osint_enabled:
            logger.info("OSINT phase disabled in config")
            return

        if not self.config.is_domain and not self.state.hostnames:
            logger.info("Target is an IP with no hostname — skipping OSINT")
            return

        osint_target = self.state.primary_hostname or self.target
        logger.info("Running OSINT for %s", osint_target)

        # Build concurrent command list — all OSINT tools are independent
        commands: list[tuple[str, list[str], Path | None]] = []

        if shutil.which("dnsrecon"):
            commands.append((
                "dnsrecon",
                [
                    "dnsrecon",
                    "-d", osint_target,
                    "-t", "std",
                    "-o", str(self.output_dir / "dnsrecon.json"),
                ],
                self.output_dir / "dnsrecon.txt",
            ))
        else:
            logger.debug("dnsrecon not found — skipping DNS OSINT")

        if shutil.which("subfinder"):
            commands.append((
                "subfinder",
                [
                    "subfinder",
                    "-d", osint_target,
                    "-o", str(self.output_dir / "subfinder.txt"),
                    "-silent",
                ],
                self.output_dir / "subfinder.txt",
            ))
        else:
            logger.debug("subfinder not found — skipping subdomain enum")

        if shutil.which("theHarvester"):
            commands.append((
                "theHarvester",
                [
                    "theHarvester",
                    "-d", osint_target,
                    "-b", "all",
                    "-f", str(self.output_dir / "harvester"),
                ],
                None,
            ))
        else:
            logger.debug("theHarvester not found — skipping")

        if commands:
            results = await run_multiple(
                commands,
                max_concurrent=3,
                timeout=self.config.default_timeout,
            )

            # Parse discovered subdomains
            subdomains: set[str] = set()

            # 1. Parse subfinder output
            subfinder_out = self.output_dir / "subfinder.txt"
            if subfinder_out.is_file():
                try:
                    content = subfinder_out.read_text(encoding="utf-8", errors="replace")
                    for line in content.splitlines():
                        sub = line.strip().lower()
                        if sub and "." in sub:
                            subdomains.add(sub)
                except Exception as exc:
                    logger.debug("Failed to parse subfinder output: %s", exc)

            # 2. Parse dnsrecon output (JSON)
            dnsrecon_out = self.output_dir / "dnsrecon.json"
            if dnsrecon_out.is_file():
                try:
                    content = dnsrecon_out.read_text(encoding="utf-8", errors="replace")
                    if content.strip():
                        records = json.loads(content)
                        for rec in records:
                            if isinstance(rec, dict):
                                name = rec.get("name", "").strip().lower()
                                if name and "." in name:
                                    subdomains.add(name)
                                target_host = rec.get("target", "").strip().lower()
                                if target_host and "." in target_host:
                                    subdomains.add(target_host)
                except Exception as exc:
                    logger.debug("Failed to parse dnsrecon JSON: %s", exc)

            # 3. Parse theHarvester output (JSON)
            harvester_out = self.output_dir / "harvester.json"
            if harvester_out.is_file():
                try:
                    content = harvester_out.read_text(encoding="utf-8", errors="replace")
                    if content.strip():
                        data = json.loads(content)
                        for host in data.get("hosts", []):
                            if isinstance(host, str):
                                sub = host.strip().lower()
                                if sub and "." in sub:
                                    subdomains.add(sub)
                except Exception as exc:
                    logger.debug("Failed to parse harvester JSON: %s", exc)

            # Add discovered subdomains to state and findings
            if subdomains:
                for sub in subdomains:
                    self.state.add_hostname(sub)

                sublist = sorted(list(subdomains))
                self.state.add_finding(
                    Finding(
                        severity=Severity.INFO,
                        title=f"OSINT subdomains discovered ({len(sublist)} subdomains)",
                        description=(
                            f"Passive and active DNS/OSINT tools discovered {len(sublist)} subdomains:\n"
                            + "\n".join(f"  - {sub}" for sub in sublist[:50])
                            + (f"\n  ... and {len(sublist) - 50} more" if len(sublist) > 50 else "")
                        ),
                        evidence="\n".join(sublist),
                        module="osint",
                    )
                )

    # ------------------------------------------------------------------
    # Phase 5 — Vulnerability Correlation
    # ------------------------------------------------------------------

    async def phase5_vuln_correlate(self) -> None:
        """Run searchsploit against all detected versions.

        Also runs searchsploit against technologies detected by the
        web_tech module (stored in ``state.detected_techs``).
        Deep scanners (nuclei, nikto) are excluded to keep scans fast.

        Skipped when ``config.skip_vuln_correlate`` is ``True``.
        """
        if self.config.skip_vuln_correlate:
            logger.info("Vulnerability correlation phase skipped by config")
            return

        commands: list[tuple[str, list[str], Path | None]] = []
        query_map: dict[str, str] = {}

        # --- searchsploit from nmap services ---
        if shutil.which("searchsploit"):
            # Build a query from every product+version we found via nmap
            for svc in self.state.services.values():
                if svc.product and svc.version:
                    query = f"{svc.product} {svc.version}"
                    outfile = self.output_dir / f"searchsploit_{svc.port}.txt"
                    cmd_name = f"searchsploit-{svc.port}"
                    commands.append((
                        cmd_name,
                        ["searchsploit", "--json", query],
                        outfile,
                    ))
                    query_map[cmd_name] = query

            # Build queries from detected web technologies
            for tech in self.state.detected_techs:
                if tech.version and tech.name:
                    # Skip if already covered by nmap service detection
                    already_covered = any(
                        svc.product.lower() == tech.name.lower() and svc.version == tech.version
                        for svc in self.state.services.values()
                    )
                    if not already_covered:
                        query = f"{tech.name} {tech.version}"
                        safe_name = tech.name.lower().replace(" ", "_").replace("/", "_")
                        outfile = self.output_dir / f"searchsploit_tech_{safe_name}_{tech.port}.txt"
                        cmd_name = f"searchsploit-tech-{safe_name}-{tech.port}"
                        commands.append((
                            cmd_name,
                            ["searchsploit", "--json", query],
                            outfile,
                        ))
                        query_map[cmd_name] = query

        if not commands:
            logger.info("No vulnerability correlation tools available")
            return

        if not self.quiet:
            console = get_console()
            for name, _cmd_list, _outfile in commands:
                console.print(f"  [dim]▸[/] Running [bold]{name}[/]...")

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
                # Try to parse JSON output for better findings
                exploits_found = self._parse_searchsploit_json(stdout, name)
                query = query_map.get(name, "")
                if exploits_found:
                    self.state.add_finding(
                        Finding(
                            severity=Severity.MEDIUM,
                            title=f"Exploits found: {name} ({len(exploits_found)} results)",
                            description=(
                                f"searchsploit found {len(exploits_found)} potential exploits"
                                f" for '{query}'. "
                                f"Top results: {', '.join(exploits_found[:5])}"
                            ),
                            evidence=stdout[:2000],
                            module="vuln_correlate",
                            suggested_commands=[
                                f"searchsploit {query}" if query else "searchsploit",
                            ],
                        )
                    )
                else:
                    # No results for specific query — try broad fallback
                    # e.g. "Nginx 1.18.0" → try "Nginx"
                    if query and " " in query.strip():
                        broad_query = query.strip().split()[0]
                        # Only try if the broad query is different from the specific
                        if broad_query.lower() != query.lower() and shutil.which("searchsploit"):
                            broad_name = f"{name}-broad"
                            broad_outfile = self.output_dir / f"searchsploit_{name}_broad.txt"
                            try:
                                brc, bstdout, bstderr = await run_tool(
                                    cmd=["searchsploit", "--json", broad_query],
                                    output_file=broad_outfile,
                                    timeout=self.config.default_timeout,
                                )
                                if brc in (0, 1) and bstdout.strip():
                                    broad_exploits = self._parse_searchsploit_json(bstdout, broad_name)
                                    if broad_exploits:
                                        self.state.add_finding(
                                            Finding(
                                                severity=Severity.INFO,
                                                title=f"Exploits (broad): {broad_query} ({len(broad_exploits)} results)",
                                                description=(
                                                    f"No exploits found for '{query}', but"
                                                    f" {len(broad_exploits)} found for broader"
                                                    f" query '{broad_query}'. "
                                                    f"Top: {', '.join(broad_exploits[:5])}"
                                                ),
                                                evidence=bstdout[:2000],
                                                module="vuln_correlate",
                                                suggested_commands=[
                                                    f"searchsploit {broad_query}",
                                                ],
                                            )
                                        )
                            except Exception:
                                logger.debug("Broad searchsploit fallback failed for %s", broad_query)
                    logger.info("searchsploit ran: %s (no exploits found)", name)

        # Display exploit results prominently
        if not self.quiet:
            exploit_findings = [f for f in self.state.all_findings if f.module == "vuln_correlate"]
            if exploit_findings:
                from recon_ninja.core.display import display_exploit_results
                display_exploit_results(exploit_findings)

    @staticmethod
    def _parse_searchsploit_json(stdout: str, name: str) -> list[str]:
        """Parse searchsploit JSON output for exploit titles.

        Parameters
        ----------
        stdout:
            The stdout from ``searchsploit --json <query>``.
        name:
            The task name for context.

        Returns
        -------
        list[str]
            List of exploit titles found.
        """
        exploits: list[str] = []
        try:
            data = json.loads(stdout)
            results = (
                data.get("RESULTS_EXPLOIT", [])
                or data.get("RESULTS_SEARCH", [])
                or data.get("RESULTS", [])
                or data.get("results", [])
            )
            if isinstance(results, list):
                for entry in results[:10]:
                    if isinstance(entry, dict):
                        title = entry.get("Title", entry.get("title", ""))
                        if title:
                            exploits.append(title)
                    elif isinstance(entry, str):
                        exploits.append(entry)
        except (json.JSONDecodeError, KeyError, TypeError):
            # Fallback: parse text output
            for line in stdout.splitlines():
                line = line.strip()
                if line and not line.startswith("{") and not line.startswith("["):
                    if "|" in line:
                        parts = line.split("|")
                        if len(parts) >= 2:
                            exploits.append(parts[1].strip())
        return exploits

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
                r"password\s*[:=]", r"passwd\s*[:=]", r"pwd\s*[:=]",
                r"login\s*[:=]", r"credential\s*[:=]",
                r"secret\s*[:=]", r"apikey\s*[:=]", r"api_key\s*[:=]",
                r"token\s*[:=]",
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

        if not self.quiet:
            loot_counts = {}
            for f in self.state.all_findings:
                if f.module == "loot" and f.title.startswith("Loot: "):
                    category = f.title.replace("Loot: ", "")
                    try:
                        count = int(f.description.split()[1])
                    except (IndexError, ValueError):
                        count = 0
                    loot_counts[category] = count
            if loot_counts:
                display_loot_summary(loot_counts)

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

        if not self.quiet:
            console = get_console()
            console.print("  [dim]Generating reports...[/]")

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
            json.dumps(self.state.to_dict(), indent=2),
            encoding="utf-8",
        )
        logger.info("State checkpoint → %s", state_file)

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

        has_web_port = bool(port_set.intersection(KNOWN_WEB_PORTS))

        # Web: any port with "http" service OR a known web port number
        if has_service("http") or has_web_port:
            if "web" in module_name_to_func:
                relevant.append(("web", module_name_to_func["web"]))

        # SMB: port 139 or 445, or SMB services
        if has_port(139, 445) or has_service("microsoft-ds") or has_service("netbios-ssn") or has_service("smb"):
            if "smb" in module_name_to_func:
                relevant.append(("smb", module_name_to_func["smb"]))

        # SSH: port 22 or service "ssh"
        if has_port(22) or has_service("ssh"):
            if "ssh" in module_name_to_func:
                relevant.append(("ssh", module_name_to_func["ssh"]))

        # FTP: port 21 or service "ftp"
        if has_port(21) or has_service("ftp"):
            if "ftp" in module_name_to_func:
                relevant.append(("ftp", module_name_to_func["ftp"]))

        # SMTP: ports 25, 465, 587, or service "smtp"
        if has_port(25, 465, 587) or has_service("smtp") or has_service("ssmtp"):
            if "smtp" in module_name_to_func:
                relevant.append(("smtp", module_name_to_func["smtp"]))

        # SNMP: UDP port 161, or service "snmp"
        if (161 in set(self.state.udp_ports)) or has_service("snmp"):
            if "snmp" in module_name_to_func:
                relevant.append(("snmp", module_name_to_func["snmp"]))

        # DNS: port 53 or service "dns"
        if has_port(53) or has_service("dns") or has_service("domain"):
            if "dns" in module_name_to_func:
                relevant.append(("dns", module_name_to_func["dns"]))

        # LDAP: ports 389, 636, or service "ldap"
        if has_port(389, 636) or has_service("ldap"):
            if "ldap" in module_name_to_func:
                relevant.append(("ldap", module_name_to_func["ldap"]))

        # Kerberos: port 88 or service "kerberos"
        if has_port(88) or has_service("kerberos") or has_service("kdc"):
            if "kerberos" in module_name_to_func:
                relevant.append(("kerberos", module_name_to_func["kerberos"]))

        # RPC: ports 111 or 135, or service matching RPC
        if has_port(111, 135) or has_service("rpcbind") or has_service("portmapper") or has_service("msrpc") or has_service("rpc"):
            if "rpc" in module_name_to_func:
                relevant.append(("rpc", module_name_to_func["rpc"]))

        # NFS: port 2049 or service "nfs"
        if has_port(2049) or has_service("nfs"):
            if "nfs" in module_name_to_func:
                relevant.append(("nfs", module_name_to_func["nfs"]))

        # RDP: port 3389 or service "rdp"
        if has_port(3389) or has_service("rdp") or has_service("ms-wbt-server"):
            if "rdp" in module_name_to_func:
                relevant.append(("rdp", module_name_to_func["rdp"]))

        # VNC: ports 5900-5910, or service "vnc"
        if port_set.intersection(range(5900, 5911)) or has_service("vnc"):
            if "vnc" in module_name_to_func:
                relevant.append(("vnc", module_name_to_func["vnc"]))

        # WinRM: ports 5985, 5986, or service "winrm"
        if has_port(5985, 5986) or has_service("winrm") or has_service("wsman"):
            if "winrm" in module_name_to_func:
                relevant.append(("winrm", module_name_to_func["winrm"]))

        # Database: ports 3306, 1433, 5432, 6379, 27017, 1521, or DB services
        if (
            has_port(3306, 1433, 5432, 6379, 27017, 1521)
            or has_service("mysql")
            or has_service("mssql")
            or has_service("postgresql")
            or has_service("redis")
            or has_service("mongodb")
            or has_service("oracle")
        ):
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
        has_http = bool(port_set.intersection(KNOWN_WEB_PORTS)) or "http" in service_names
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
    # Script-based service supplementation
    # ------------------------------------------------------------------

    @staticmethod
    def _supplement_scripts(services: dict[int, ServiceInfo]) -> None:
        """Fill in missing product/version from nmap script output.

        When nmap -sV can't probe deeply enough (filtered ports), the
        script output often contains useful version information that we
        can extract.
        """
        import re as _re

        for svc in services.values():
            if not isinstance(svc, ServiceInfo):
                continue
            # http-server-header → e.g. "nginx/1.18.0 (Ubuntu)"
            if "http-server-header" in svc.scripts and not svc.product:
                header = svc.scripts["http-server-header"].strip()
                # Parse "nginx/1.18.0 (Ubuntu)" or "Apache/2.4.52"
                match = _re.match(r"(\w+)[/\s]*(\S+)?", header)
                if match:
                    svc.product = match.group(1)
                    ver = match.group(2)
                    if ver and not svc.version:
                        svc.version = ver.strip("()")

            # ssh-hostkey → indicates OpenSSH
            if "ssh-hostkey" in svc.scripts and not svc.product:
                output = svc.scripts["ssh-hostkey"].lower()
                if "ssh" in output:
                    # Try to extract version from the key output
                    ver_match = _re.search(r"ssh[- ](\d+[\.\d]*)", output)
                    if ver_match:
                        svc.product = "OpenSSH"
                        svc.version = ver_match.group(1)
                    else:
                        svc.product = "OpenSSH"

    # ------------------------------------------------------------------
    # Vhost tech scanning (Phase 3.5)
    # ------------------------------------------------------------------

    async def _scan_vhost_techs(self) -> None:
        """Scan discovered vhosts for technologies.

        Checks ``state.hostnames`` for hostnames that differ from the
        primary hostname and runs web_tech against them.  This ensures
        that vhosts discovered by dirfuzz or other modules are fully
        profiled even if the in-scan vhost detection missed some.
        """
        primary = self.state.primary_hostname
        web_ports = self.state.web_ports
        if not web_ports or not self.state.hostnames:
            return

        # Identify vhosts we haven't scanned yet — a vhost is considered
        # "already scanned" if we have detected techs for it on any port.
        scanned_vhost_techs: set[str] = set()
        for tech in self.state.detected_techs:
            # tech names associated with non-primary hostnames indicate
            # those vhosts have been scanned
            pass  # We check differently below

        # Actually, check which hostnames appear in evidence/description
        # of existing techs.  Simpler: just track which vhost:port combos
        # we've already scanned by looking at existing tech entries.
        existing_tech_names = {(t.name, t.port) for t in self.state.detected_techs}

        new_vhosts = [
            h for h in self.state.hostnames
            if h != primary and h != self.target
        ]

        if not new_vhosts:
            return

        logger.info("Scanning %d vhost(s) for technologies: %s", len(new_vhosts), new_vhosts)

        if not self.quiet:
            console = get_console()
            console.print()
            console.print(
                "  [bold cyan][*][/] Scanning discovered vhosts for technologies..."
            )

        try:
            from recon_ninja.modules.web.web_tech import run_web_tech
        except ImportError:
            logger.debug("web_tech module not available — skipping vhost tech scan")
            return

        for vhost in new_vhosts:
            for port in web_ports:
                svc = self.state.services.get(port)
                if svc is None:
                    continue
                scheme = "https" if (port in (443, 8443) or "ssl" in svc.service.lower()) else "http"
                vhost_url = f"{scheme}://{vhost}:{port}"
                # Omit default ports for clean URLs
                if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
                    vhost_url = f"{scheme}://{vhost}"

                # Skip if we already have tech results for this vhost on this port
                # (the web module may have already scanned it)
                vhost_port_dir = self.output_dir / f"port_{port}_{vhost}"
                tech_marker = vhost_port_dir / "web_tech_done.txt"
                if tech_marker.exists():
                    continue

                logger.info("[vhost_tech] Scanning %s on port %d", vhost, port)

                try:
                    vhost_port_dir.mkdir(parents=True, exist_ok=True)
                    result = await run_web_tech(
                        target=self.target,
                        port=port,
                        url=vhost_url,
                        state=self.state,
                        config=self.config,
                        output_dir=vhost_port_dir,
                    )

                    # Mark as done to avoid re-scanning
                    tech_marker.write_text("done", encoding="utf-8")

                    # Add any new findings
                    for finding in result.findings:
                        self.state.add_finding(finding)

                    # Report new techs discovered on the vhost
                    if not self.quiet and result.findings:
                        new_techs = [
                            t for t in self.state.detected_techs
                            if t.port == port
                            and (t.name, port) not in existing_tech_names
                        ]
                        if new_techs:
                            for t in new_techs:
                                ver_tag = f" {t.version}" if t.version else ""
                                console.print(
                                    f"    [bold green][+][/] [bold]{vhost}[/]:"
                                    f" {t.name}{ver_tag} [{t.category}]"
                                )

                except Exception as exc:
                    logger.debug("[vhost_tech] Failed for %s:%d: %s", vhost, port, exc)

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_rustscan_ports(output: str) -> list[int]:
        """Extract open port numbers from RustScan output.

        Supports standard ``Open 10.10.10.1:22`` lines and quiet raw port formats.
        """
        import re

        ports: list[int] = []
        pattern = re.compile(r"Open\s+\S+:(\d+)")
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            match = pattern.search(line)
            if match:
                ports.append(int(match.group(1)))
            elif line.isdigit():
                ports.append(int(line))
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
