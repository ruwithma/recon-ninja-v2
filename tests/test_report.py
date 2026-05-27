"""Tests for recon_ninja.core.report — report generation in JSON, Markdown, and HTML.

Covers:
- File creation for JSON, Markdown, and HTML reports
- JSON report structure and findings schema
- Markdown section headers, services listing, and findings by severity
- HTML structural validity and severity CSS classes
- Edge cases: empty state, multiple findings, multiple services
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime

import pytest

from recon_ninja.core.report import generate_reports
from recon_ninja.core.models import ScanState, ServiceInfo, Finding, Severity


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def make_sample_state(
    target: str = "10.10.11.58",
    output_dir: Path | None = None,
) -> ScanState:
    """Build a sample ScanState with services and findings for report tests.

    Returns a state with three services (SSH, HTTP, SMB), two findings
    (HIGH + INFO), one hostname, and a LINUX_WEB box profile.
    """
    state = ScanState(
        target=target,
        start_time=datetime(2025, 5, 27, 14, 30, 0),
        end_time=datetime(2025, 5, 27, 14, 35, 0),
        output_dir=output_dir or Path("/tmp/test"),
        open_ports=[22, 80, 445],
        services={
            22: ServiceInfo(
                port=22, proto="tcp", state="open",
                service="ssh", product="OpenSSH", version="8.9p1",
            ),
            80: ServiceInfo(
                port=80, proto="tcp", state="open",
                service="http", product="Apache httpd", version="2.4.52",
            ),
            445: ServiceInfo(
                port=445, proto="tcp", state="open",
                service="microsoft-ds", product="Samba", version="4.15.13",
            ),
        },
        hostnames=["dog.htb"],
        box_profile="LINUX_WEB",
    )
    state.add_finding(
        Finding(
            severity=Severity.HIGH,
            title="SSH Password Auth",
            description="Password auth enabled",
            module="ssh",
        )
    )
    state.add_finding(
        Finding(
            severity=Severity.INFO,
            title="Web Server Detected",
            description="Apache detected",
            module="web",
        )
    )
    return state


# ===================================================================
# Report generation tests
# ===================================================================


class TestGenerateReports:
    """Tests for the async generate_reports() function."""

    # --- File creation ---------------------------------------------------

    async def test_generate_json_report(self, tmp_path: Path) -> None:
        """generate_reports with json_output=True creates a .json file."""
        state = make_sample_state(output_dir=tmp_path)
        paths = await generate_reports(state, tmp_path, html=False, json_output=True)

        assert "json" in paths
        assert paths["json"].exists()
        assert paths["json"].name == "00_findings.json"

    async def test_generate_markdown_report(self, tmp_path: Path) -> None:
        """generate_reports always creates a .md file."""
        state = make_sample_state(output_dir=tmp_path)
        paths = await generate_reports(state, tmp_path, html=False, json_output=False)

        assert "markdown" in paths
        assert paths["markdown"].exists()
        assert paths["markdown"].name == "00_SUMMARY.md"

    async def test_generate_html_report(self, tmp_path: Path) -> None:
        """generate_reports with html=True creates an .html file."""
        state = make_sample_state(output_dir=tmp_path)
        paths = await generate_reports(state, tmp_path, html=True, json_output=False)

        assert "html" in paths
        assert paths["html"].exists()
        assert paths["html"].name == "00_SUMMARY.html"

    # --- JSON content ----------------------------------------------------

    async def test_json_report_structure(self, tmp_path: Path) -> None:
        """JSON has target, scan_time, box_profile, open_ports, services, findings keys."""
        state = make_sample_state(output_dir=tmp_path)
        paths = await generate_reports(state, tmp_path, html=False, json_output=True)

        data = json.loads(paths["json"].read_text(encoding="utf-8"))
        for key in ("target", "scan_time", "box_profile", "open_ports", "services", "findings"):
            assert key in data, f"Missing key: {key}"

    async def test_json_report_findings(self, tmp_path: Path) -> None:
        """JSON findings array has correct structure (severity, title, description, module)."""
        state = make_sample_state(output_dir=tmp_path)
        paths = await generate_reports(state, tmp_path, html=False, json_output=True)

        data = json.loads(paths["json"].read_text(encoding="utf-8"))
        assert len(data["findings"]) == 2
        for finding in data["findings"]:
            assert "severity" in finding
            assert "title" in finding
            assert "description" in finding
            assert "module" in finding

    # --- Markdown content ------------------------------------------------

    async def test_markdown_has_headers(self, tmp_path: Path) -> None:
        """Markdown contains # Recon Ninja and ## sections."""
        state = make_sample_state(output_dir=tmp_path)
        paths = await generate_reports(state, tmp_path, html=False, json_output=False)

        content = paths["markdown"].read_text(encoding="utf-8")
        assert "Recon Ninja" in content
        assert "## Target Information" in content
        assert "## Open Ports" in content

    async def test_markdown_has_services(self, tmp_path: Path) -> None:
        """Markdown lists services found."""
        state = make_sample_state(output_dir=tmp_path)
        paths = await generate_reports(state, tmp_path, html=False, json_output=False)

        content = paths["markdown"].read_text(encoding="utf-8")
        # Services table should contain the service names
        assert "ssh" in content.lower()
        assert "http" in content.lower()
        assert "microsoft-ds" in content.lower()

    async def test_markdown_has_findings(self, tmp_path: Path) -> None:
        """Markdown lists findings by severity."""
        state = make_sample_state(output_dir=tmp_path)
        paths = await generate_reports(state, tmp_path, html=False, json_output=False)

        content = paths["markdown"].read_text(encoding="utf-8")
        assert "## Key Findings" in content
        assert "SSH Password Auth" in content
        assert "Web Server Detected" in content

    # --- HTML content ----------------------------------------------------

    async def test_html_is_valid(self, tmp_path: Path) -> None:
        """HTML contains <html>, <head>, <body> tags."""
        state = make_sample_state(output_dir=tmp_path)
        paths = await generate_reports(state, tmp_path, html=True, json_output=False)

        content = paths["html"].read_text(encoding="utf-8")
        assert "<html" in content
        assert "<head>" in content
        assert "<body>" in content
        assert "</html>" in content

    async def test_html_severity_colors(self, tmp_path: Path) -> None:
        """HTML contains severity class names for styling findings."""
        state = make_sample_state(output_dir=tmp_path)
        paths = await generate_reports(state, tmp_path, html=True, json_output=False)

        content = paths["html"].read_text(encoding="utf-8")
        # The template renders severity-based CSS classes
        assert "sev-badge" in content
        assert "finding-card" in content
        # make_sample_state includes HIGH and INFO findings
        assert "finding-card high" in content or "sev-badge high" in content
        assert "finding-card info" in content or "sev-badge info" in content

    # --- Edge cases ------------------------------------------------------

    async def test_report_empty_state(self, tmp_path: Path) -> None:
        """Report with no findings/services doesn't crash."""
        state = ScanState(
            target="10.10.10.1",
            start_time=datetime(2025, 5, 27, 14, 30, 0),
            end_time=datetime(2025, 5, 27, 14, 35, 0),
            output_dir=tmp_path,
        )
        paths = await generate_reports(state, tmp_path, html=True, json_output=True)

        assert "markdown" in paths
        assert "html" in paths
        assert "json" in paths
        # Verify JSON is valid and empty
        data = json.loads(paths["json"].read_text(encoding="utf-8"))
        assert data["findings"] == []
        assert data["open_ports"] == []

    async def test_report_with_findings(self, tmp_path: Path) -> None:
        """Report correctly includes multiple findings sorted by severity."""
        state = ScanState(
            target="10.10.10.1",
            start_time=datetime(2025, 5, 27, 14, 30, 0),
            end_time=datetime(2025, 5, 27, 14, 35, 0),
            output_dir=tmp_path,
        )
        state.add_finding(
            Finding(
                severity=Severity.CRITICAL,
                title="RCE Found",
                description="Remote code execution",
                module="web",
            )
        )
        state.add_finding(
            Finding(
                severity=Severity.HIGH,
                title="SQL Injection",
                description="SQLi in login form",
                module="web",
            )
        )
        state.add_finding(
            Finding(
                severity=Severity.MEDIUM,
                title="Info Disclosure",
                description="Server version leaked",
                module="web",
            )
        )

        paths = await generate_reports(state, tmp_path, html=False, json_output=True)
        data = json.loads(paths["json"].read_text(encoding="utf-8"))

        assert len(data["findings"]) == 3
        # Findings should be sorted by severity rank (CRITICAL < HIGH < MEDIUM)
        severities = [f["severity"] for f in data["findings"]]
        assert severities == ["CRITICAL", "HIGH", "MEDIUM"]

    async def test_report_with_multiple_services(self, tmp_path: Path) -> None:
        """Report lists all services across JSON and Markdown."""
        state = ScanState(
            target="10.10.10.1",
            start_time=datetime(2025, 5, 27, 14, 30, 0),
            end_time=datetime(2025, 5, 27, 14, 35, 0),
            output_dir=tmp_path,
            open_ports=[22, 80, 443, 3306],
        )
        state.services[22] = ServiceInfo(
            port=22, proto="tcp", state="open", service="ssh",
        )
        state.services[80] = ServiceInfo(
            port=80, proto="tcp", state="open", service="http",
        )
        state.services[443] = ServiceInfo(
            port=443, proto="tcp", state="open", service="https",
        )
        state.services[3306] = ServiceInfo(
            port=3306, proto="tcp", state="open", service="mysql",
        )

        paths = await generate_reports(state, tmp_path, json_output=True, html=True)

        # JSON: all four services in open_ports array
        data = json.loads(paths["json"].read_text(encoding="utf-8"))
        assert len(data["open_ports"]) == 4
        json_ports = {svc["port"] for svc in data["open_ports"]}
        assert json_ports == {22, 80, 443, 3306}

        # Markdown: service table should reference all port numbers
        md_content = paths["markdown"].read_text(encoding="utf-8")
        for port in (22, 80, 443, 3306):
            assert str(port) in md_content
