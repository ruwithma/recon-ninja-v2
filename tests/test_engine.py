"""Tests for recon_ninja.core.engine — orchestration, classification, and parsing.

Covers:
- Box classification (_classify_box) for WINDOWS_AD, LINUX_WEB, WINDOWS_WEB, etc.
- Nmap XML parsing (parse_nmap_xml) with basic, scripts, hostname, and malformed input
- Module determination (_filter_relevant_modules) for web, smb, ssh, multi, and no services
- Phase names constant
- Parsing helpers (_parse_rustscan_ports, _parse_nmap_grep_ports)
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock
from datetime import datetime

from recon_ninja.core.engine import ReconEngine, parse_nmap_xml, PHASE_NAMES
from recon_ninja.core.models import ScanState, ServiceInfo, ReconConfig


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engine(
    tmp_path: Path,
    open_ports: list[int] | None = None,
    services: dict[int, ServiceInfo] | None = None,
    hostnames: list[str] | None = None,
) -> ReconEngine:
    """Create a ReconEngine with a configured ScanState for testing.

    The *tmp_path* is used as the output directory so that the engine's
    ``_setup_file_logger`` and ``mkdir`` calls succeed without side-effects.
    """
    state = ScanState(
        target="10.10.10.1",
        start_time=datetime(2025, 5, 27, 14, 30, 0),
        output_dir=tmp_path,
        open_ports=open_ports or [],
        services=services or {},
        hostnames=hostnames or [],
    )
    config = ReconConfig()
    return ReconEngine(target="10.10.10.1", config=config, state=state)


# A complete set of mock module functions for _filter_relevant_modules tests.
# This avoids depending on whether the real modules can be imported.
_MOCK_MODULES: list[tuple[str, AsyncMock]] = [
    ("web", AsyncMock()),
    ("smb", AsyncMock()),
    ("ssh", AsyncMock()),
    ("ftp", AsyncMock()),
    ("smtp", AsyncMock()),
    ("snmp", AsyncMock()),
    ("dns", AsyncMock()),
    ("ldap", AsyncMock()),
    ("kerberos", AsyncMock()),
    ("rpc", AsyncMock()),
    ("nfs", AsyncMock()),
    ("rdp", AsyncMock()),
    ("vnc", AsyncMock()),
    ("winrm", AsyncMock()),
    ("database", AsyncMock()),
    ("ssl", AsyncMock()),
]


# ===================================================================
# Box classification tests
# ===================================================================


class TestClassifyBox:
    """Tests for ReconEngine._classify_box()."""

    def test_classify_windows_ad(self, tmp_path: Path) -> None:
        """Ports 88+389+445+5985 → WINDOWS_AD."""
        services = {
            88: ServiceInfo(port=88, proto="tcp", state="open", service="kerberos"),
            389: ServiceInfo(port=389, proto="tcp", state="open", service="ldap"),
            445: ServiceInfo(port=445, proto="tcp", state="open", service="microsoft-ds"),
            5985: ServiceInfo(port=5985, proto="tcp", state="open", service="wsman"),
        }
        engine = _make_engine(tmp_path, [88, 389, 445, 5985], services)
        assert engine._classify_box() == "WINDOWS_AD"

    def test_classify_linux_web(self, tmp_path: Path) -> None:
        """Ports 22+80, no SMB → LINUX_WEB."""
        services = {
            22: ServiceInfo(port=22, proto="tcp", state="open", service="ssh"),
            80: ServiceInfo(port=80, proto="tcp", state="open", service="http"),
        }
        engine = _make_engine(tmp_path, [22, 80], services)
        assert engine._classify_box() == "LINUX_WEB"

    def test_classify_windows_web(self, tmp_path: Path) -> None:
        """IIS product + port 80, no Kerberos → WINDOWS_WEB."""
        services = {
            80: ServiceInfo(
                port=80, proto="tcp", state="open",
                service="http", product="Microsoft IIS httpd", version="10.0",
            ),
        }
        engine = _make_engine(tmp_path, [80], services)
        assert engine._classify_box() == "WINDOWS_WEB"

    def test_classify_linux_ad(self, tmp_path: Path) -> None:
        """Samba + LDAP (ports 389+445), no Kerberos → LINUX_AD."""
        services = {
            389: ServiceInfo(
                port=389, proto="tcp", state="open",
                service="ldap", product="OpenLDAP",
            ),
            445: ServiceInfo(
                port=445, proto="tcp", state="open",
                service="microsoft-ds", product="Samba",
            ),
        }
        engine = _make_engine(tmp_path, [389, 445], services)
        assert engine._classify_box() == "LINUX_AD"

    def test_classify_linux_server(self, tmp_path: Path) -> None:
        """Port 22 only, no web → LINUX_SERVER."""
        services = {
            22: ServiceInfo(port=22, proto="tcp", state="open", service="ssh"),
        }
        engine = _make_engine(tmp_path, [22], services)
        assert engine._classify_box() == "LINUX_SERVER"

    def test_classify_unknown(self, tmp_path: Path) -> None:
        """Just port 8080 with no SSH/IIS/SMB/LDAP → UNKNOWN.

        Port 8080 makes has_http=True but without SSH, IIS, SMB, or
        Kerberos no classification matches, falling through to UNKNOWN.
        """
        engine = _make_engine(tmp_path, [8080], {})
        assert engine._classify_box() == "UNKNOWN"


# ===================================================================
# Nmap XML parsing tests
# ===================================================================


class TestParseNmapXml:
    """Tests for the standalone parse_nmap_xml() function."""

    def test_parse_nmap_xml_basic(self, tmp_path: Path) -> None:
        """Parse XML string with 2 open ports."""
        xml = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9p1"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.52"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        xml_file = tmp_path / "nmap_basic.xml"
        xml_file.write_text(xml, encoding="utf-8")

        services = parse_nmap_xml(xml_file)
        assert len(services) == 2
        assert 22 in services
        assert 80 in services
        assert services[22].service == "ssh"
        assert services[22].product == "OpenSSH"
        assert services[22].version == "8.9p1"
        assert services[80].service == "http"
        assert services[80].product == "Apache httpd"

    def test_parse_nmap_xml_scripts(self, tmp_path: Path) -> None:
        """Parse XML with NSE script output."""
        xml = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
        <script id="http-title" output="Welcome to Apache"/>
        <script id="http-headers" output="Server: Apache"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        xml_file = tmp_path / "nmap_scripts.xml"
        xml_file.write_text(xml, encoding="utf-8")

        services = parse_nmap_xml(xml_file)
        assert 80 in services
        assert "http-title" in services[80].scripts
        assert services[80].scripts["http-title"] == "Welcome to Apache"
        assert "http-headers" in services[80].scripts
        assert services[80].scripts["http-headers"] == "Server: Apache"

    def test_parse_nmap_xml_hostname(self, tmp_path: Path) -> None:
        """Parse XML with hostname element."""
        xml = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <status state="up"/>
    <hostnames>
      <hostname name="dog.htb"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        xml_file = tmp_path / "nmap_hostname.xml"
        xml_file.write_text(xml, encoding="utf-8")

        services = parse_nmap_xml(xml_file)
        assert 80 in services
        assert services[80].hostname == "dog.htb"

    def test_parse_nmap_xml_malformed(self, tmp_path: Path) -> None:
        """Malformed XML returns empty dict."""
        xml_file = tmp_path / "bad.xml"
        xml_file.write_text("this is not xml <<<<>", encoding="utf-8")

        services = parse_nmap_xml(xml_file)
        assert services == {}


# ===================================================================
# Module determination tests
# ===================================================================


class TestDetermineModules:
    """Tests for ReconEngine._filter_relevant_modules().

    Uses a fixed set of mock module callables so that tests are
    deterministic regardless of which real modules are importable.
    """

    def test_determine_modules_web(self, tmp_path: Path) -> None:
        """HTTP service → web module in list."""
        services = {
            80: ServiceInfo(port=80, proto="tcp", state="open", service="http"),
        }
        engine = _make_engine(tmp_path, [80], services)
        result = engine._filter_relevant_modules(_MOCK_MODULES)
        names = [name for name, _ in result]
        assert "web" in names

    def test_determine_modules_smb(self, tmp_path: Path) -> None:
        """Port 445 → smb module in list."""
        services = {
            445: ServiceInfo(port=445, proto="tcp", state="open", service="microsoft-ds"),
        }
        engine = _make_engine(tmp_path, [445], services)
        result = engine._filter_relevant_modules(_MOCK_MODULES)
        names = [name for name, _ in result]
        assert "smb" in names

    def test_determine_modules_ssh(self, tmp_path: Path) -> None:
        """Port 22 → ssh module in list."""
        services = {
            22: ServiceInfo(port=22, proto="tcp", state="open", service="ssh"),
        }
        engine = _make_engine(tmp_path, [22], services)
        result = engine._filter_relevant_modules(_MOCK_MODULES)
        names = [name for name, _ in result]
        assert "ssh" in names

    def test_determine_modules_multi(self, tmp_path: Path) -> None:
        """Ports 22+80+445 → web+smb+ssh modules."""
        services = {
            22: ServiceInfo(port=22, proto="tcp", state="open", service="ssh"),
            80: ServiceInfo(port=80, proto="tcp", state="open", service="http"),
            445: ServiceInfo(port=445, proto="tcp", state="open", service="microsoft-ds"),
        }
        engine = _make_engine(tmp_path, [22, 80, 445], services)
        result = engine._filter_relevant_modules(_MOCK_MODULES)
        names = [name for name, _ in result]
        assert "web" in names
        assert "smb" in names
        assert "ssh" in names

    def test_determine_modules_no_services(self, tmp_path: Path) -> None:
        """No relevant ports → empty list."""
        engine = _make_engine(tmp_path, [12345], {})
        result = engine._filter_relevant_modules(_MOCK_MODULES)
        names = [name for name, _ in result]
        assert names == []


# ===================================================================
# Phase names test
# ===================================================================


class TestPhaseNames:
    """Tests for the PHASE_NAMES constant."""

    def test_phase_names(self) -> None:
        """PHASE_NAMES has 8 entries (0–7)."""
        assert len(PHASE_NAMES) == 8
        assert set(PHASE_NAMES.keys()) == {0, 1, 2, 3, 4, 5, 6, 7}
        # Verify key phase names
        assert PHASE_NAMES[0] == "Pre-flight"
        assert PHASE_NAMES[7] == "Report Generation"


# ===================================================================
# Parsing helper tests
# ===================================================================


class TestParsingHelpers:
    """Tests for _parse_rustscan_ports and _parse_nmap_grep_ports."""

    def test_parse_rustscan_ports(self) -> None:
        """Parse RustScan 'Open <ip>:<port>' lines → [22, 80]."""
        output = "Open 10.10.10.1:22\nOpen 10.10.10.1:80"
        ports = ReconEngine._parse_rustscan_ports(output)
        assert ports == [22, 80]

    def test_parse_nmap_grep_ports(self) -> None:
        """Parse nmap 'PORT/tcp open service' lines → [22, 80]."""
        output = "22/tcp open ssh\n80/tcp open http"
        ports = ReconEngine._parse_nmap_grep_ports(output)
        assert ports == [22, 80]
