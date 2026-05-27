"""Tests for recon_ninja.utils.nmap_parser and core.models.

Covers:
- parse_nmap_xml with inline XML fixture
- ServiceInfo construction + to_dict / from_dict roundtrip
- Finding construction and severity ranking
- ScanState serialization / deserialization
- parse_rustscan_output with sample output
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest

from recon_ninja.core.models import Finding, ScanState, ServiceInfo, Severity
from recon_ninja.utils.nmap_parser import parse_nmap_xml, parse_rustscan_output


# ---------------------------------------------------------------------------
# Inline Nmap XML fixture
# ---------------------------------------------------------------------------

NMAP_XML_SAMPLE = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sC -sV -oX scan.xml 10.10.11.42" start="1700000000" startstr="Tue Nov 14 2023" version="7.94" xmloutputversion="1.05">
  <host starttime="1700000000" endtime="1700000100">
    <status state="up" reason="echo-reply" reason_ttl="63"/>
    <address addr="10.10.11.42" addrtype="ipv4"/>
    <hostnames>
      <hostname name="dc01.recon.local" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="63"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" extrainfo="Ubuntu 3ubuntu0.6" method="probed" conf="10"/>
        <script id="ssh-hostkey" output="&lt;key&gt;ssh-rsa AAAAB3...&lt;/key&gt;"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack" reason_ttl="63"/>
        <service name="http" product="Apache httpd" version="2.4.52" extrainfo="" method="probed" conf="10"/>
        <script id="http-title" output="ReconNinja Dashboard"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" reason_ttl="63"/>
        <service name="ssl/http" product="nginx" version="1.18.0" extrainfo="" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="closed" reason="reset" reason_ttl="63"/>
        <service name="microsoft-ds" product="" version="" extrainfo="" method="probed" conf="10"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


# ===================================================================
# parse_nmap_xml tests
# ===================================================================

class TestParseNmapXml:
    """Tests for parse_nmap_xml with the inline XML fixture."""

    @pytest.fixture()
    def xml_file(self, tmp_path: Path) -> Path:
        """Write the sample XML to a temp file and return its path."""
        p = tmp_path / "scan.xml"
        p.write_text(NMAP_XML_SAMPLE, encoding="utf-8")
        return p

    def test_parse_returns_services_and_hostnames(self, xml_file: Path) -> None:
        services, hostnames = parse_nmap_xml(xml_file)
        assert isinstance(services, dict)
        assert isinstance(hostnames, list)

    def test_open_ports_extracted(self, xml_file: Path) -> None:
        services, _ = parse_nmap_xml(xml_file)
        # Port 22, 80, 443 are open; port 445 is closed and should be excluded
        assert 22 in services
        assert 80 in services
        assert 443 in services
        assert 445 not in services

    def test_service_details(self, xml_file: Path) -> None:
        services, _ = parse_nmap_xml(xml_file)
        ssh = services[22]
        assert ssh.service == "ssh"
        assert ssh.product == "OpenSSH"
        assert ssh.version == "8.9p1"
        assert ssh.proto == "tcp"
        assert ssh.state == "open"
        assert ssh.extra_info == "Ubuntu 3ubuntu0.6"

    def test_scripts_extracted(self, xml_file: Path) -> None:
        services, _ = parse_nmap_xml(xml_file)
        ssh = services[22]
        assert "ssh-hostkey" in ssh.scripts
        assert "AAAAB3" in ssh.scripts["ssh-hostkey"]

    def test_http_title_hostname(self, xml_file: Path) -> None:
        _, hostnames = parse_nmap_xml(xml_file)
        assert "ReconNinja Dashboard" in hostnames

    def test_hostname_element(self, xml_file: Path) -> None:
        _, hostnames = parse_nmap_xml(xml_file)
        assert "dc01.recon.local" in hostnames

    def test_ssl_http_service(self, xml_file: Path) -> None:
        services, _ = parse_nmap_xml(xml_file)
        assert services[443].service == "ssl/http"
        assert services[443].product == "nginx"

    def test_malformed_xml_returns_empty(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.xml"
        bad.write_text("this is not xml at all", encoding="utf-8")
        services, hostnames = parse_nmap_xml(bad)
        assert services == {}
        assert hostnames == []

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.xml"
        services, hostnames = parse_nmap_xml(missing)
        assert services == {}
        assert hostnames == []


# ===================================================================
# ServiceInfo tests
# ===================================================================

class TestServiceInfo:
    """Tests for ServiceInfo construction and roundtrip."""

    def test_construction(self) -> None:
        svc = ServiceInfo(
            port=80, proto="tcp", state="open",
            service="http", product="Apache", version="2.4.52",
        )
        assert svc.port == 80
        assert svc.service == "http"
        assert svc.product == "Apache"

    def test_to_dict_from_dict_roundtrip(self) -> None:
        svc = ServiceInfo(
            port=22, proto="tcp", state="open",
            service="ssh", product="OpenSSH", version="8.9p1",
            extra_info="Ubuntu", scripts={"ssh-hostkey": "some key"},
            hostname="target.local",
        )
        d = svc.to_dict()
        svc2 = ServiceInfo.from_dict(d)
        assert svc2.port == svc.port
        assert svc2.service == svc.service
        assert svc2.product == svc.product
        assert svc2.version == svc.version
        assert svc2.scripts == svc.scripts
        assert svc2.hostname == svc.hostname

    def test_url_http_service(self) -> None:
        svc = ServiceInfo(
            port=80, proto="tcp", state="open",
            service="http", hostname="example.com",
        )
        assert svc.url == "http://example.com:80"

    def test_url_https_service(self) -> None:
        svc = ServiceInfo(
            port=443, proto="tcp", state="open",
            service="ssl/http", hostname="example.com",
        )
        assert svc.url == "https://example.com:443"

    def test_url_non_web_service(self) -> None:
        svc = ServiceInfo(
            port=22, proto="tcp", state="open",
            service="ssh",
        )
        assert svc.url is None

    def test_url_no_hostname_uses_target(self) -> None:
        svc = ServiceInfo(
            port=8080, proto="tcp", state="open",
            service="http", hostname=None,
        )
        assert svc.url == "http://TARGET:8080"


# ===================================================================
# Finding tests
# ===================================================================

class TestFinding:
    """Tests for Finding construction and severity ranking."""

    def test_construction(self) -> None:
        f = Finding(
            severity=Severity.HIGH,
            title="Open SSH",
            description="SSH is exposed",
            module="portscan",
        )
        assert f.severity == Severity.HIGH
        assert f.title == "Open SSH"

    def test_to_dict_from_dict_roundtrip(self) -> None:
        f = Finding(
            severity=Severity.CRITICAL,
            title="RCE found",
            description="Remote code execution",
            module="web_vuln",
            evidence="curl output",
            cve="CVE-2024-1234",
            suggested_commands=["nmap --script vuln"],
        )
        d = f.to_dict()
        f2 = Finding.from_dict(d)
        assert f2.severity == f.severity
        assert f2.title == f.title
        assert f2.cve == f.cve
        assert f2.suggested_commands == f.suggested_commands

    def test_severity_ranking(self) -> None:
        assert Severity.CRITICAL.rank < Severity.HIGH.rank
        assert Severity.HIGH.rank < Severity.MEDIUM.rank
        assert Severity.MEDIUM.rank < Severity.LOW.rank
        assert Severity.LOW.rank < Severity.INFO.rank

    def test_default_fields(self) -> None:
        f = Finding(
            severity=Severity.INFO,
            title="Test",
            description="Test desc",
            module="test",
        )
        assert f.evidence == ""
        assert f.cve is None
        assert f.suggested_commands == []


# ===================================================================
# ScanState tests
# ===================================================================

class TestScanState:
    """Tests for ScanState serialization/deserialization."""

    def _make_state(self) -> ScanState:
        return ScanState(
            target="10.10.11.42",
            start_time=datetime(2024, 1, 1, 12, 0, 0),
            output_dir=Path("/tmp/results/10.10.11.42"),
            open_ports=[22, 80, 443],
            hostnames=["dc01.recon.local"],
            available_tools={"nmap": True, "ffuf": False},
        )

    def test_to_dict_from_dict_roundtrip(self) -> None:
        state = self._make_state()
        d = state.to_dict()
        state2 = ScanState.from_dict(d)
        assert state2.target == state.target
        assert state2.open_ports == state.open_ports
        assert state2.hostnames == state.hostnames
        assert state2.available_tools == state.available_tools

    def test_services_roundtrip(self) -> None:
        state = self._make_state()
        state.services[22] = ServiceInfo(
            port=22, proto="tcp", state="open",
            service="ssh", product="OpenSSH",
        )
        d = state.to_dict()
        state2 = ScanState.from_dict(d)
        assert 22 in state2.services
        assert state2.services[22].service == "ssh"

    def test_save_and_load(self, tmp_path: Path) -> None:
        state = ScanState(
            target="10.10.10.5",
            start_time=datetime.now(),
            output_dir=tmp_path,
            open_ports=[80],
        )
        path = state.save()
        assert path.is_file()
        loaded = ScanState.load(path)
        assert loaded.target == "10.10.10.5"
        assert loaded.open_ports == [80]


# ===================================================================
# parse_rustscan_output tests
# ===================================================================

class TestParseRustscanOutput:
    """Tests for parse_rustscan_output."""

    def test_basic_open_ports(self) -> None:
        output = "Open 22\nOpen 80\nOpen 443\n"
        ports = parse_rustscan_output(output)
        assert ports == [22, 80, 443]

    def test_nmap_style_ports(self) -> None:
        output = "22/tcp open ssh\n80/tcp open http\n"
        ports = parse_rustscan_output(output)
        assert 22 in ports
        assert 80 in ports

    def test_dedup_and_sort(self) -> None:
        output = "Open 443\nOpen 22\nOpen 22\n443/tcp open https\n"
        ports = parse_rustscan_output(output)
        assert ports == [22, 443]

    def test_empty_input(self) -> None:
        assert parse_rustscan_output("") == []

    def test_no_matching_ports(self) -> None:
        output = "Starting RustScan...\nNo open ports found.\n"
        assert parse_rustscan_output(output) == []

    def test_mixed_formats(self) -> None:
        output = "Open 22\nOpen 80\nAlso found: 443/tcp and 8080/tcp\n"
        ports = parse_rustscan_output(output)
        assert ports == [22, 80, 443, 8080]
