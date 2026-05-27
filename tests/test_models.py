"""Tests for recon_ninja.core.models data models.

Covers:
- Severity enum values and ranking
- Finding.to_dict() and Finding.from_dict() roundtrip
- ServiceInfo.url property
- ModuleResult construction
- ScanState.add_finding() deduplication
- ScanState.findings_by_severity()
- ScanState.web_ports property
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path


from recon_ninja.core.models import Finding, ModuleResult, ScanState, ServiceInfo, Severity


# ===================================================================
# Severity enum tests
# ===================================================================

class TestSeverity:
    """Tests for Severity enum values and ranking."""

    def test_all_values_exist(self) -> None:
        expected = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
        actual = {s.value for s in Severity}
        assert actual == expected

    def test_rank_ordering(self) -> None:
        """CRITICAL < HIGH < MEDIUM < LOW < INFO (lower rank = more severe)."""
        assert Severity.CRITICAL.rank < Severity.HIGH.rank
        assert Severity.HIGH.rank < Severity.MEDIUM.rank
        assert Severity.MEDIUM.rank < Severity.LOW.rank
        assert Severity.LOW.rank < Severity.INFO.rank

    def test_rank_specific_values(self) -> None:
        assert Severity.CRITICAL.rank == 0
        assert Severity.HIGH.rank == 1
        assert Severity.MEDIUM.rank == 2
        assert Severity.LOW.rank == 3
        assert Severity.INFO.rank == 4

    def test_severity_is_str(self) -> None:
        """Severity is a str enum — comparing with plain strings should work."""
        assert Severity.CRITICAL == "CRITICAL"
        assert Severity.HIGH == "HIGH"

    def test_icon_property(self) -> None:
        for sev in Severity:
            assert isinstance(sev.icon, str)
            assert len(sev.icon) > 0

    def test_rich_style_property(self) -> None:
        for sev in Severity:
            assert isinstance(sev.rich_style, str)


# ===================================================================
# Finding tests
# ===================================================================

class TestFinding:
    """Tests for Finding.to_dict() and Finding.from_dict() roundtrip."""

    def test_to_dict_keys(self) -> None:
        f = Finding(
            severity=Severity.HIGH,
            title="Test Finding",
            description="Something found",
            module="test",
        )
        d = f.to_dict()
        expected_keys = {
            "severity", "title", "description", "module",
            "evidence", "cve", "suggested_commands", "timestamp",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_from_dict_roundtrip(self) -> None:
        f = Finding(
            severity=Severity.CRITICAL,
            title="RCE in Apache",
            description="Apache 2.4.52 is vulnerable to path traversal",
            module="web_vuln",
            evidence="curl -s http://target/cgi-bin/.%2e/",
            cve="CVE-2021-41773",
            suggested_commands=["nmap --script http-path-traversal", "searchsploit apache 2.4.52"],
        )
        d = f.to_dict()
        f2 = Finding.from_dict(d)

        assert f2.severity == f.severity
        assert f2.title == f.title
        assert f2.description == f.description
        assert f2.module == f.module
        assert f2.evidence == f.evidence
        assert f2.cve == f.cve
        assert f2.suggested_commands == f.suggested_commands
        assert f2.timestamp == f.timestamp

    def test_from_dict_converts_severity_string(self) -> None:
        d = {
            "severity": "HIGH",
            "title": "Test",
            "description": "Desc",
            "module": "test",
        }
        f = Finding.from_dict(d)
        assert f.severity == Severity.HIGH

    def test_from_dict_converts_timestamp_string(self) -> None:
        ts = "2024-06-15T10:30:00"
        d = {
            "severity": "INFO",
            "title": "Test",
            "description": "Desc",
            "module": "test",
            "timestamp": ts,
        }
        f = Finding.from_dict(d)
        assert isinstance(f.timestamp, datetime)
        assert f.timestamp.year == 2024
        assert f.timestamp.month == 6

    def test_default_optional_fields(self) -> None:
        f = Finding(
            severity=Severity.LOW,
            title="Info",
            description="Info desc",
            module="scanner",
        )
        assert f.evidence == ""
        assert f.cve is None
        assert f.suggested_commands == []


# ===================================================================
# ServiceInfo.url property tests
# ===================================================================

class TestServiceInfoUrl:
    """Tests for ServiceInfo.url property."""

    def test_http_service_url(self) -> None:
        svc = ServiceInfo(
            port=80, proto="tcp", state="open",
            service="http", hostname="target.local",
        )
        assert svc.url == "http://target.local:80"

    def test_https_service_url(self) -> None:
        svc = ServiceInfo(
            port=443, proto="tcp", state="open",
            service="ssl/http", hostname="target.local",
        )
        assert svc.url == "https://target.local:443"

    def test_http_on_443_gets_https(self) -> None:
        """Port 443 should default to https even if service doesn't say ssl."""
        svc = ServiceInfo(
            port=443, proto="tcp", state="open",
            service="http", hostname="target.local",
        )
        assert svc.url == "https://target.local:443"

    def test_http_on_8443_gets_https(self) -> None:
        svc = ServiceInfo(
            port=8443, proto="tcp", state="open",
            service="http", hostname="target.local",
        )
        assert svc.url == "https://target.local:8443"

    def test_non_web_service_returns_none(self) -> None:
        svc = ServiceInfo(
            port=22, proto="tcp", state="open",
            service="ssh",
        )
        assert svc.url is None

    def test_no_hostname_uses_target(self) -> None:
        svc = ServiceInfo(
            port=80, proto="tcp", state="open",
            service="http", hostname=None,
        )
        assert svc.url == "http://TARGET:80"

    def test_http_alt_service(self) -> None:
        """Service name containing 'http' (e.g. 'http-alt') should produce a URL."""
        svc = ServiceInfo(
            port=8080, proto="tcp", state="open",
            service="http-alt", hostname="host",
        )
        assert svc.url == "http://host:8080"


# ===================================================================
# ModuleResult tests
# ===================================================================

class TestModuleResult:
    """Tests for ModuleResult construction."""

    def test_basic_construction(self) -> None:
        mr = ModuleResult(
            module_name="smb",
            status="done",
            duration_seconds=12.5,
        )
        assert mr.module_name == "smb"
        assert mr.status == "done"
        assert mr.findings == []
        assert mr.raw_output == ""
        assert mr.output_file is None
        assert mr.duration_seconds == 12.5
        assert mr.error_message == ""

    def test_with_findings(self) -> None:
        finding = Finding(
            severity=Severity.HIGH,
            title="SMB signing disabled",
            description="SMB signing is not required",
            module="smb",
        )
        mr = ModuleResult(
            module_name="smb",
            status="done",
            findings=[finding],
        )
        assert len(mr.findings) == 1
        assert mr.findings[0].title == "SMB signing disabled"

    def test_error_status(self) -> None:
        mr = ModuleResult(
            module_name="ssl",
            status="error",
            error_message="sslscan not found",
        )
        assert mr.status == "error"
        assert mr.error_message == "sslscan not found"

    def test_to_dict(self) -> None:
        mr = ModuleResult(
            module_name="dns",
            status="done",
            raw_output="DNS lookup complete",
            output_file=Path("/tmp/dns.txt"),
            duration_seconds=5.0,
        )
        d = mr.to_dict()
        assert d["module_name"] == "dns"
        assert d["status"] == "done"
        assert d["output_file"] == "/tmp/dns.txt"
        assert d["duration_seconds"] == 5.0

    def test_to_dict_truncates_raw_output(self) -> None:
        mr = ModuleResult(
            module_name="nmap",
            status="done",
            raw_output="x" * 10000,
        )
        d = mr.to_dict()
        assert len(d["raw_output"]) <= 5000


# ===================================================================
# ScanState.add_finding() deduplication tests
# ===================================================================

class TestScanStateAddFinding:
    """Tests for ScanState.add_finding() deduplication."""

    def test_add_finding_appends(self) -> None:
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=Path("/tmp/results"),
        )
        f = Finding(
            severity=Severity.HIGH,
            title="Open SSH",
            description="SSH exposed",
            module="portscan",
        )
        state.add_finding(f)
        assert len(state.all_findings) == 1
        assert state.all_findings[0].title == "Open SSH"

    def test_dedup_same_title_and_module(self) -> None:
        """Duplicate findings (same title + module) should not be added."""
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=Path("/tmp/results"),
        )
        f1 = Finding(
            severity=Severity.HIGH,
            title="Open SSH",
            description="SSH exposed",
            module="portscan",
        )
        f2 = Finding(
            severity=Severity.HIGH,
            title="Open SSH",
            description="SSH exposed (duplicate)",
            module="portscan",
        )
        state.add_finding(f1)
        state.add_finding(f2)
        assert len(state.all_findings) == 1

    def test_same_title_different_module_allowed(self) -> None:
        """Same title but different module should be treated as distinct."""
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=Path("/tmp/results"),
        )
        f1 = Finding(
            severity=Severity.HIGH,
            title="Vulnerable service",
            description="Found via nmap",
            module="portscan",
        )
        f2 = Finding(
            severity=Severity.HIGH,
            title="Vulnerable service",
            description="Found via nuclei",
            module="web_vuln",
        )
        state.add_finding(f1)
        state.add_finding(f2)
        assert len(state.all_findings) == 2

    def test_different_title_same_module_allowed(self) -> None:
        """Different title with same module should be treated as distinct."""
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=Path("/tmp/results"),
        )
        f1 = Finding(
            severity=Severity.HIGH,
            title="Open SSH",
            description="SSH on 22",
            module="portscan",
        )
        f2 = Finding(
            severity=Severity.MEDIUM,
            title="Open HTTP",
            description="HTTP on 80",
            module="portscan",
        )
        state.add_finding(f1)
        state.add_finding(f2)
        assert len(state.all_findings) == 2


# ===================================================================
# ScanState.findings_by_severity() tests
# ===================================================================

class TestScanStateFindingsBySeverity:
    """Tests for ScanState.findings_by_severity()."""

    def test_empty_findings(self) -> None:
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=Path("/tmp/results"),
        )
        grouped = state.findings_by_severity()
        assert all(len(v) == 0 for v in grouped.values())
        assert set(grouped.keys()) == set(Severity)

    def test_grouped_correctly(self) -> None:
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=Path("/tmp/results"),
        )
        state.add_finding(Finding(
            severity=Severity.CRITICAL, title="C1", description="", module="m1",
        ))
        state.add_finding(Finding(
            severity=Severity.HIGH, title="H1", description="", module="m1",
        ))
        state.add_finding(Finding(
            severity=Severity.HIGH, title="H2", description="", module="m1",
        ))
        state.add_finding(Finding(
            severity=Severity.INFO, title="I1", description="", module="m1",
        ))

        grouped = state.findings_by_severity()
        assert len(grouped[Severity.CRITICAL]) == 1
        assert len(grouped[Severity.HIGH]) == 2
        assert len(grouped[Severity.INFO]) == 1
        assert len(grouped[Severity.MEDIUM]) == 0
        assert len(grouped[Severity.LOW]) == 0

    def test_all_severity_keys_present(self) -> None:
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=Path("/tmp/results"),
        )
        grouped = state.findings_by_severity()
        for sev in Severity:
            assert sev in grouped


# ===================================================================
# ScanState.web_ports property tests
# ===================================================================

class TestScanStateWebPorts:
    """Tests for ScanState.web_ports property."""

    def test_no_services_returns_empty(self) -> None:
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=Path("/tmp/results"),
        )
        assert state.web_ports == []

    def test_http_services_returned(self) -> None:
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=Path("/tmp/results"),
        )
        state.services[80] = ServiceInfo(
            port=80, proto="tcp", state="open", service="http",
        )
        state.services[443] = ServiceInfo(
            port=443, proto="tcp", state="open", service="ssl/http",
        )
        state.services[22] = ServiceInfo(
            port=22, proto="tcp", state="open", service="ssh",
        )
        web = state.web_ports
        assert 80 in web
        assert 443 in web
        assert 22 not in web

    def test_http_alt_included(self) -> None:
        """Service names containing 'http' should be included."""
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=Path("/tmp/results"),
        )
        state.services[8080] = ServiceInfo(
            port=8080, proto="tcp", state="open", service="http-alt",
        )
        state.services[8443] = ServiceInfo(
            port=8443, proto="tcp", state="open", service="https-alt",
        )
        assert 8080 in state.web_ports
        assert 8443 in state.web_ports

    def test_only_non_web_services(self) -> None:
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=Path("/tmp/results"),
        )
        state.services[22] = ServiceInfo(
            port=22, proto="tcp", state="open", service="ssh",
        )
        state.services[445] = ServiceInfo(
            port=445, proto="tcp", state="open", service="microsoft-ds",
        )
        assert state.web_ports == []

    def test_case_insensitive_match(self) -> None:
        """The web_ports property uses .lower() for matching."""
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=Path("/tmp/results"),
        )
        state.services[80] = ServiceInfo(
            port=80, proto="tcp", state="open", service="HTTP",
        )
        # ServiceInfo.service is stored as-is; web_ports checks .lower()
        assert 80 in state.web_ports
