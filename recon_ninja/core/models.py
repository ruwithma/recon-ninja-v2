"""Data models for ReconNinja — all core dataclasses used throughout the application."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    """Finding severity levels, ordered from most to least critical."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting (lower = more severe)."""
        return {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }[self.value]

    @property
    def icon(self) -> str:
        """Rich-compatible icon for display."""
        return {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🔵",
            "INFO": "⚪",
        }[self.value]

    @property
    def rich_style(self) -> str:
        """Rich style string for colored output."""
        return {
            "CRITICAL": "bold red",
            "HIGH": "bold yellow",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }[self.value]


@dataclass
class Finding:
    """A single security finding from any module."""

    severity: Severity
    title: str
    description: str
    module: str
    evidence: str = ""
    cve: str | None = None
    suggested_commands: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dictionary."""
        return {
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "module": self.module,
            "evidence": self.evidence,
            "cve": self.cve,
            "suggested_commands": self.suggested_commands,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Deserialize from a dictionary."""
        data = dict(data)
        data["severity"] = Severity(data["severity"])
        if isinstance(data.get("timestamp"), str):
            data["timestamp"] = datetime.fromisoformat(data["timestamp"])
        return cls(**data)


@dataclass
class TechInfo:
    """Detected technology on a web service."""

    name: str
    version: str = ""
    category: str = ""       # "language", "framework", "cms", "server", "os", "library", "waf"
    confidence: str = "certain"  # "certain", "probable", "possible"
    source: str = ""          # "header", "cookie", "html", "whatweb", "nmap", "wappalyzer"
    port: int = 0
    cves: list[str] = field(default_factory=list)
    is_vulnerable: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dictionary."""
        return {
            "name": self.name,
            "version": self.version,
            "category": self.category,
            "confidence": self.confidence,
            "source": self.source,
            "port": self.port,
            "cves": self.cves,
            "is_vulnerable": self.is_vulnerable,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TechInfo:
        """Deserialize from a dictionary."""
        return cls(**data)


@dataclass
class ServiceInfo:
    """Information about a single service discovered on a port."""

    port: int
    proto: str  # tcp / udp
    state: str  # open / filtered / closed
    service: str  # http / ssh / smb ...
    product: str = ""  # Apache httpd / OpenSSH ...
    version: str = ""  # 2.4.52 / 8.9p1 ...
    extra_info: str = ""
    scripts: dict[str, str] = field(default_factory=dict)  # script_name → output
    hostname: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dictionary."""
        return {
            "port": self.port,
            "proto": self.proto,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extra_info": self.extra_info,
            "scripts": self.scripts,
            "hostname": self.hostname,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServiceInfo:
        """Deserialize from a dictionary."""
        return cls(**data)

    @property
    def url(self) -> str | None:
        """Construct a URL for web services.

        Detects web services both by nmap service name (http/https/ssl/http)
        and by common web port numbers that nmap sometimes misidentifies.
        """
        # Known web service name patterns
        if any(p in self.service.lower() for p in ("http", "ssl/http", "https")):
            scheme = "https" if "ssl" in self.service or self.port in (443, 8443) else "http"
            return f"{scheme}://{self.hostname or 'TARGET'}:{self.port}"

        # Common web ports that nmap sometimes misidentifies (e.g. port 3000 → "ppp")
        _KNOWN_WEB_PORTS = {
            80, 443, 8080, 8443,  # standard
            3000, 3001, 4000, 5000, 8000, 8001, 8081, 8082, 8088,  # dev/app servers
            8888, 9000, 9090, 4443,  # other common web ports
        }
        if self.port in _KNOWN_WEB_PORTS:
            scheme = "https" if self.port in (443, 8443, 4443) else "http"
            return f"{scheme}://{self.hostname or 'TARGET'}:{self.port}"

        return None

    @property
    def display_product(self) -> str:
        """Product string for display, with version if available."""
        if self.product and self.version:
            return f"{self.product} {self.version}"
        return self.product or self.service


@dataclass
class ModuleResult:
    """Result from a single reconnaissance module execution."""

    module_name: str
    status: str  # "done" | "skipped" | "error" | "timeout"
    findings: list[Finding] = field(default_factory=list)
    raw_output: str = ""
    output_file: Path | None = None
    duration_seconds: float = 0.0
    error_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dictionary."""
        return {
            "module_name": self.module_name,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "raw_output": self.raw_output[:5000],  # truncate for JSON
            "output_file": str(self.output_file) if self.output_file else None,
            "duration_seconds": self.duration_seconds,
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModuleResult":
        """Deserialize from a dictionary."""
        findings_raw = data.get("findings", [])
        findings = [Finding.from_dict(f) for f in findings_raw]
        output_file = data.get("output_file")
        if isinstance(output_file, str):
            output_file = Path(output_file)
        return cls(
            module_name=data.get("module_name", ""),
            status=data.get("status", ""),
            findings=findings,
            raw_output=data.get("raw_output", ""),
            output_file=output_file,
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            error_message=data.get("error_message", ""),
        )


@dataclass
class ScanState:
    """Complete state of a reconnaissance scan — used for checkpointing and resume."""

    target: str
    start_time: datetime
    output_dir: Path
    open_ports: list[int] = field(default_factory=list)
    udp_ports: list[int] = field(default_factory=list)
    services: dict[int, ServiceInfo] = field(default_factory=dict)
    hostnames: list[str] = field(default_factory=list)
    box_profile: str = "UNKNOWN"
    completed_modules: list[str] = field(default_factory=list)
    all_findings: list[Finding] = field(default_factory=list)
    module_results: list[ModuleResult] = field(default_factory=list)
    detected_techs: list[TechInfo] = field(default_factory=list)
    available_tools: dict[str, bool] = field(default_factory=dict)
    current_phase: int = 0
    end_time: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-friendly dictionary."""
        return {
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "output_dir": str(self.output_dir),
            "open_ports": self.open_ports,
            "udp_ports": self.udp_ports,
            "services": {str(k): v.to_dict() for k, v in self.services.items()},
            "hostnames": self.hostnames,
            "box_profile": self.box_profile,
            "completed_modules": self.completed_modules,
            "all_findings": [f.to_dict() for f in self.all_findings],
            "module_results": [m.to_dict() for m in self.module_results],
            "detected_techs": [t.to_dict() for t in self.detected_techs],
            "available_tools": self.available_tools,
            "current_phase": self.current_phase,
            "end_time": self.end_time.isoformat() if self.end_time else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScanState:
        """Deserialize from a dictionary."""
        data = dict(data)
        if isinstance(data.get("start_time"), str):
            data["start_time"] = datetime.fromisoformat(data["start_time"])
        if isinstance(data.get("end_time"), str):
            data["end_time"] = datetime.fromisoformat(data["end_time"])
        if isinstance(data.get("output_dir"), str):
            data["output_dir"] = Path(data["output_dir"])
        services_raw = data.pop("services", {})
        data["services"] = {
            int(k): ServiceInfo.from_dict(v) for k, v in services_raw.items()
        }
        findings_raw = data.pop("all_findings", [])
        data["all_findings"] = [Finding.from_dict(f) for f in findings_raw]
        techs_raw = data.pop("detected_techs", [])
        data["detected_techs"] = [TechInfo.from_dict(t) for t in techs_raw]
        results_raw = data.pop("module_results", [])
        # Reconstruct ModuleResult objects if present in the payload.
        from_path_results = []
        for mr in results_raw:
            try:
                from_path_results.append(ModuleResult.from_dict(mr))
            except Exception:
                # If deserialisation fails for some entries, skip them
                # but preserve the rest of the state load instead of crashing.
                continue
        data["module_results"] = from_path_results
        return cls(**data)

    def add_finding(self, finding: Finding) -> None:
        """Add a finding, preventing duplicates by title+module."""
        existing_titles = {(f.title, f.module) for f in self.all_findings}
        if (finding.title, finding.module) not in existing_titles:
            self.all_findings.append(finding)

    def add_tech(self, tech: TechInfo) -> None:
        """Add a detected technology, preventing duplicates by name+version+port."""
        existing_keys = {(t.name, t.version, t.port) for t in self.detected_techs}
        if (tech.name, tech.version, tech.port) not in existing_keys:
            self.detected_techs.append(tech)

    def techs_by_port(self, port: int) -> list[TechInfo]:
        """Return detected technologies for a specific port."""
        return [t for t in self.detected_techs if t.port == port]

    def vulnerable_techs(self) -> list[TechInfo]:
        """Return only technologies flagged as vulnerable."""
        return [t for t in self.detected_techs if t.is_vulnerable]

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        """Group findings by severity level."""
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.all_findings:
            result[f.severity].append(f)
        return result

    @property
    def duration(self) -> float:
        """Total scan duration in seconds."""
        end = self.end_time or datetime.now()
        return (end - self.start_time).total_seconds()

    @property
    def web_ports(self) -> list[int]:
        """Ports with HTTP/HTTPS services.

        Includes ports detected as HTTP by nmap service name AND
        common web ports that nmap sometimes misidentifies.
        """
        # Common web ports that nmap may misidentify
        _KNOWN_WEB_PORTS = {
            80, 443, 8080, 8443,  # standard
            3000, 3001, 4000, 5000, 8000, 8001, 8081, 8082, 8088,  # dev/app servers
            8888, 9000, 9090, 4443,  # other common web ports
        }
        return [
            port
            for port, svc in self.services.items()
            if "http" in svc.service.lower() or port in _KNOWN_WEB_PORTS
        ]

    @property
    def primary_hostname(self) -> str | None:
        """First hostname detected, or None."""
        return self.hostnames[0] if self.hostnames else None

    def save(self) -> Path:
        """Serialize current state to <output_dir>/state.json and return the path."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        state_file = self.output_dir / "state.json"
        state_file.write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
        return state_file

    @classmethod
    def load(cls, path: Path) -> ScanState:
        """Load a ScanState from a JSON file."""
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.from_dict(data)


@dataclass
class ReconConfig:
    """Configuration for a reconnaissance scan."""

    # Scan mode
    fast_mode: bool = False
    # UDP scanning
    udp_scan: bool = False
    # OSINT phase
    osint_enabled: bool = True
    # Maximum concurrent module tasks
    max_concurrent: int = 10
    # Default timeout per tool (seconds)
    default_timeout: int = 300
    # Per-module toggles: module_name → enabled
    module_toggles: dict[str, bool] = field(default_factory=dict)
    # Custom nmap flags appended to every nmap call
    extra_nmap_flags: list[str] = field(default_factory=list)
    # Whether to skip vulnerability correlation phase
    skip_vuln_correlate: bool = False
    # Whether to skip loot extraction phase
    skip_loot: bool = False
    # Wordlist paths
    web_wordlist: Path = Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")
    dns_wordlist: Path = Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
    # Nuclei templates path (empty = default)
    nuclei_templates: str = ""
    # Target is a domain (vs IP)
    is_domain: bool = False

    def is_module_enabled(self, module_name: str) -> bool:
        """Check whether a specific module is enabled.

        If the module is not present in module_toggles it defaults to enabled.
        """
        return self.module_toggles.get(module_name, True)
