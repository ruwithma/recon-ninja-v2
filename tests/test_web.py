"""Regression tests for web orchestration and redirect handling."""

from __future__ import annotations


from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

import pytest

from recon_ninja.core.models import ModuleResult, ReconConfig, ScanState, ServiceInfo
from recon_ninja.modules.web import run_web_module
from recon_ninja.modules.web.web_core import run_web_core
from recon_ninja.modules.web.web_dirfuzz import run_web_dirfuzz


def _make_web_state(tmp_path: Path, hostname: str | None = None) -> ScanState:
    return ScanState(
        target="10.129.7.81",
        start_time=datetime.now(),
        output_dir=tmp_path,
        services={
            80: ServiceInfo(
                port=80,
                proto="tcp",
                state="open",
                service="http",
                hostname=hostname,
            )
        },
    )


class TestWebModuleOrchestration:
    @pytest.mark.asyncio
    async def test_rebuilds_url_after_core_hostname_discovery(self, tmp_path: Path) -> None:
        state = _make_web_state(tmp_path)
        config = ReconConfig()
        captured: dict[str, str | None] = {}

        async def fake_run_web_core(target, port, url, state, config, output_dir):
            state.hostnames.append("smarthire.htb")
            return ModuleResult(module_name="web_core", status="done")

        async def fake_run_web_tech(target, port, url, state, config, output_dir):
            captured["tech_url"] = url
            return ModuleResult(module_name="web_tech", status="done")

        async def fake_run_web_dirfuzz(target, port, url, hostname, state, config, output_dir):
            captured["dirfuzz_url"] = url
            captured["dirfuzz_hostname"] = hostname
            return ModuleResult(module_name="web_dirfuzz", status="done")

        async def fake_run_web_vuln(target, port, url, state, config, output_dir):
            return ModuleResult(module_name="web_vuln", status="done")

        async def fake_run_web_cms(target, port, url, state, config, output_dir):
            return ModuleResult(module_name="web_cms", status="done")

        with (
            patch("recon_ninja.modules.web.run_web_core", side_effect=fake_run_web_core),
            patch("recon_ninja.modules.web.run_web_tech", side_effect=fake_run_web_tech),
            patch("recon_ninja.modules.web.run_web_dirfuzz", side_effect=fake_run_web_dirfuzz),
            patch("recon_ninja.modules.web.run_web_vuln", side_effect=fake_run_web_vuln),
            patch("recon_ninja.modules.web.run_web_cms", side_effect=fake_run_web_cms),
        ):
            result = await run_web_module("10.129.7.81", state, config, tmp_path)

        assert result.status == "done"
        assert captured["tech_url"] == "http://smarthire.htb:80"
        assert captured["dirfuzz_url"] == "http://smarthire.htb:80"
        assert captured["dirfuzz_hostname"] == "smarthire.htb"


class TestWebCoreRedirectWarning:
    @pytest.mark.asyncio
    async def test_warns_when_redirect_hostname_missing_from_hosts(self, tmp_path: Path) -> None:
        state = _make_web_state(tmp_path)
        config = ReconConfig()
        curl_output = (
            "HTTP/1.1 301 Moved Permanently\n"
            "Location: http://smarthire.htb/\n"
            "Server: nginx\n"
            "\n"
        )

        def which_side_effect(cmd: str):
            return "/usr/bin/curl" if cmd == "curl" else None

        async def run_tool_side_effect(*args, **kwargs):
            return 0, curl_output, ""

        mock_console = AsyncMock()
        mock_console.print = lambda *a, **kw: None  # swallow Rich output

        with (
            patch(
                "recon_ninja.modules.web.web_core.shutil.which",
                side_effect=which_side_effect,
            ),
            patch(
                "recon_ninja.modules.web.web_core.run_tool",
                new_callable=AsyncMock,
                side_effect=run_tool_side_effect,
            ),
            patch(
                "recon_ninja.modules.web.web_core.get_ip_for_hostname",
                return_value=None,
            ),
            patch(
                "recon_ninja.modules.web.web_core.get_console",
                return_value=mock_console,
            ),
        ):
            result = await run_web_core(
                "10.129.7.81", 80, "http://10.129.7.81:80",
                state, config, tmp_path,
            )

        assert result.status == "done"
        assert "smarthire.htb" in state.hostnames
        # The warning now surfaces as a Finding (not a log message)
        host_findings = [f for f in result.findings if "Hostname redirect detected" in f.title]
        assert len(host_findings) == 1
        assert "smarthire.htb" in host_findings[0].title
        assert "/etc/hosts" in host_findings[0].description


class TestWebDirfuzzHeadChecks:
    @pytest.mark.asyncio
    async def test_ignores_baseline_redirect_statuses(self, tmp_path: Path) -> None:
        state = _make_web_state(tmp_path)
        config = ReconConfig()

        def which_side_effect(cmd: str):
            return "/usr/bin/curl" if cmd == "curl" else None

        async def run_tool_side_effect(*args, **kwargs):
            full_url = kwargs["cmd"][-1]
            path = urlsplit(full_url).path
            if path == "/rn_404_baseline_check":
                return 0, "301 http://smarthire.htb/", ""
            if path == "/admin":
                return 0, "200", ""
            return 0, "301 http://smarthire.htb/", ""

        with (
            patch(
                "recon_ninja.modules.web.web_dirfuzz.shutil.which",
                side_effect=which_side_effect,
            ),
            patch(
                "recon_ninja.modules.web.web_dirfuzz.run_tool",
                new_callable=AsyncMock,
                side_effect=run_tool_side_effect,
            ),
        ):
            result = await run_web_dirfuzz(
                "10.129.7.81", 80, "http://10.129.7.81:80",
                None, state, config, tmp_path,
            )

        titles = [finding.title for finding in result.findings]
        assert titles == ["Path found: /admin (HTTP 200)"]


class TestFeroxbusterParser:
    def test_parses_v1_and_v2_formats(self) -> None:
        from recon_ninja.modules.web.web_dirfuzz import _parse_feroxbuster

        # v1.x output style (4 columns)
        v1_raw = "200      GET       48l http://10.129.7.182/admin\n301      GET        5l http://10.129.7.182/dashboard"
        results_v1 = _parse_feroxbuster(v1_raw)
        assert len(results_v1) == 2
        assert results_v1[0] == (200, "http://10.129.7.182/admin", 48)
        assert results_v1[1] == (301, "http://10.129.7.182/dashboard", 5)

        # v2.x output style (6 columns)
        v2_raw = (
            "200      GET       48l      128w     2345c"
            " http://10.129.7.182/admin\n"
            "301      GET        5l       10w      150c"
            " http://10.129.7.182/dashboard"
        )
        results_v2 = _parse_feroxbuster(v2_raw)
        assert len(results_v2) == 2
        assert results_v2[0] == (200, "http://10.129.7.182/admin", 2345)
        assert results_v2[1] == (301, "http://10.129.7.182/dashboard", 150)


class TestWebTechVulnBounds:
    def test_eol_version_boundaries(self) -> None:
        from recon_ninja.modules.web.web_tech import _check_known_vulns

        # nginx EOL prefix "1.1" should NOT match "1.18.0"
        cves_1_18 = _check_known_vulns("nginx", "1.18.0")
        assert "EOL" not in cves_1_18

        # nginx EOL prefix "1.1" should match "1.1.2"
        cves_1_1 = _check_known_vulns("nginx", "1.1.2")
        assert "EOL" in cves_1_1

        # vsftpd exact/prefix "2.3.4" should match "2.3.4"
        cves_vsftpd = _check_known_vulns("vsftpd", "2.3.4")
        assert "CVE-2011-2523" in cves_vsftpd


class TestWhatwebExclusions:
    def test_ignores_metadata_fields(self) -> None:
        from recon_ninja.modules.web.web_tech import _detect_from_whatweb

        raw_whatweb = (
            "http://10.129.7.182 [200 OK] IP[10.129.7.182] Title[SmartHire] "
            "Country[RESERVED] Apache[2.4.41] Nginx[1.18.0]"
        )
        techs = _detect_from_whatweb(raw_whatweb, 80)

        names = {t.name for t in techs}
        # Metadata should be skipped
        assert "IP" not in names
        assert "Title" not in names
        assert "Country" not in names
        # Actual technologies should be parsed
        assert "Apache" in names
        assert "Nginx" in names


class TestAdaptiveWebFuzz:
    @pytest.mark.asyncio
    async def test_adaptive_fuzz_skips_stage2_when_no_meaningful_stage1_findings(
        self, tmp_path: Path,
    ) -> None:
        state = _make_web_state(tmp_path)
        config = ReconConfig(adaptive_fuzz=True)

        def which_side_effect(cmd: str):
            return "/usr/bin/feroxbuster" if cmd == "feroxbuster" else None

        call_count = 0

        # Pre-flight returns 200 (target reachable), Stage 1 returns no output
        async def run_tool_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Pre-flight curl check
                return 0, "200", ""
            # Stage 1 feroxbuster — no findings
            return 0, "", ""

        with (
            patch(
                "recon_ninja.modules.web.web_dirfuzz.shutil.which",
                side_effect=which_side_effect,
            ),
            patch(
                "recon_ninja.modules.web.web_dirfuzz.run_tool",
                new_callable=AsyncMock,
                side_effect=run_tool_side_effect,
            ) as mock_run,
        ):
            result = await run_web_dirfuzz(
                "10.129.7.81", 80, "http://10.129.7.81:80",
                None, state, config, tmp_path,
            )

        # It should run pre-flight + Stage 1 and skip Stage 2
        assert result.status == "done"
        assert mock_run.call_count == 2

    @pytest.mark.asyncio
    async def test_adaptive_fuzz_runs_stage2_when_stage1_finds_directories(
        self, tmp_path: Path,
    ) -> None:
        state = _make_web_state(tmp_path)
        config = ReconConfig(adaptive_fuzz=True)
        # Ensure configured wordlist is distinct from small fallback
        config.web_wordlist = Path("/tmp/configured_wordlist.txt")

        def which_side_effect(cmd: str):
            return "/usr/bin/feroxbuster" if cmd == "feroxbuster" else None

        # Pre-flight returns 200, Stage 1 returns an active directory, Stage 2 returns empty
        stage1_out = "200      GET       48l http://10.129.7.81/dashboard"
        stage2_out = ""

        call_count = 0

        async def run_tool_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Pre-flight curl check
                return 0, "200", ""
            if call_count == 2:
                # Stage 1 feroxbuster — finds /dashboard
                return 0, stage1_out, ""
            # Stage 2 feroxbuster — empty
            return 0, stage2_out, ""

        with (
            patch(
                "recon_ninja.modules.web.web_dirfuzz.shutil.which",
                side_effect=which_side_effect,
            ),
            patch(
                "recon_ninja.modules.web.web_dirfuzz.run_tool",
                new_callable=AsyncMock,
                side_effect=run_tool_side_effect,
            ) as mock_run,
            patch(
                "recon_ninja.modules.web.web_dirfuzz.Path.is_file",
                return_value=True,
            ),
        ):
            result = await run_web_dirfuzz(
                "10.129.7.81", 80, "http://10.129.7.81:80",
                None, state, config, tmp_path,
            )

        assert result.status == "done"
        # It should run pre-flight + Stage 1 + Stage 2
        assert mock_run.call_count == 3
        assert any("dashboard" in f.title for f in result.findings)


class TestNiktoMetadataFiltering:
    def test_filters_noise_lines(self) -> None:
        from recon_ninja.modules.web.web_vuln import _parse_nikto_findings

        raw_nikto = (
            "+ Target IP:          10.129.7.182\n"
            "+ Target Hostname:    smarthire.htb\n"
            "+ Target Port:        80\n"
            "+ Start Time:         2026-05-28 11:21:12\n"
            "+ Server: nginx/1.18.0 (Ubuntu)\n"
            "+ No CGI Directories found\n"
            "+ OSVDB-3092: /admin/: This might be interesting.\n"
            "+ /config.php: PHP config file found."
        )
        findings = _parse_nikto_findings(raw_nikto, "http://smarthire.htb")

        titles = {f.title for f in findings}
        # Metadata / banners should be filtered out
        assert "Nikto [OSVDB-3092]: OSVDB-3092: /admin/: This might be interesting." in titles
        assert "Nikto: /config.php: PHP config file found." in titles
        assert not any("Target IP" in t for t in titles)
        assert not any("Server" in t for t in titles)
        assert not any("No CGI Directories" in t for t in titles)


class TestRecursiveVhostScanQueue:
    @pytest.mark.asyncio
    async def test_dynamically_discovered_vhost_registered_but_not_rescanned(self, tmp_path: Path) -> None:
        """Vhosts discovered during dirfuzz are registered in state but NOT
        re-scanned through the full web pipeline.  This prevents duplicate
        output and long delays — the vhost is already reported as a finding
        and auto-added to /etc/hosts by web_dirfuzz.
        """
        state = _make_web_state(tmp_path)
        config = ReconConfig()

        # Track which hosts are scanned
        scanned_hosts = []

        async def fake_run_web_core(target, port, url, state, config, output_dir):
            return ModuleResult(module_name="web_core", status="done")

        async def fake_run_web_tech(target, port, url, state, config, output_dir):
            return ModuleResult(module_name="web_tech", status="done")

        async def fake_run_web_dirfuzz(target, port, url, hostname, state, config, output_dir):
            scanned_hosts.append(hostname)
            # Simulate discovering a new virtual host on the first run
            if hostname == "10.129.7.81":
                state.hostnames.append("models.smarthire.htb")
            return ModuleResult(module_name="web_dirfuzz", status="done")

        async def fake_run_web_vuln(target, port, url, state, config, output_dir):
            return ModuleResult(module_name="web_vuln", status="done")

        async def fake_run_web_cms(target, port, url, state, config, output_dir):
            return ModuleResult(module_name="web_cms", status="done")

        with (
            patch("recon_ninja.modules.web.run_web_core", side_effect=fake_run_web_core),
            patch("recon_ninja.modules.web.run_web_tech", side_effect=fake_run_web_tech),
            patch("recon_ninja.modules.web.run_web_dirfuzz", side_effect=fake_run_web_dirfuzz),
            patch("recon_ninja.modules.web.run_web_vuln", side_effect=fake_run_web_vuln),
            patch("recon_ninja.modules.web.run_web_cms", side_effect=fake_run_web_cms),
        ):
            result = await run_web_module("10.129.7.81", state, config, tmp_path)

        assert result.status == "done"
        # The vhost is registered in state but NOT re-scanned
        assert "models.smarthire.htb" in state.hostnames
        # Only the primary target IP should be scanned through the pipeline
        assert scanned_hosts == ["10.129.7.81"]


class TestFeroxbusterCommandGen:
    @pytest.mark.asyncio
    async def test_feroxbuster_cmd_adaptive(self, tmp_path: Path) -> None:
        state = _make_web_state(tmp_path)
        config = ReconConfig(adaptive_fuzz=True)
        config.web_wordlist = Path("/tmp/configured_wordlist.txt")

        def which_side_effect(cmd: str):
            return "/usr/bin/feroxbuster" if cmd == "feroxbuster" else None

        captured_cmds = []
        call_count = 0

        async def run_tool_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            captured_cmds.append(kwargs.get("cmd", args[0] if args else []))
            if call_count == 1:
                # Pre-flight curl check — target is reachable
                return 0, "200", ""
            # Stage 1 feroxbuster — no findings
            return 0, "", ""

        with (
            patch(
                "recon_ninja.modules.web.web_dirfuzz.shutil.which",
                side_effect=which_side_effect,
            ),
            patch(
                "recon_ninja.modules.web.web_dirfuzz.run_tool",
                new_callable=AsyncMock,
                side_effect=run_tool_side_effect,
            ),
            patch(
                "recon_ninja.modules.web.web_dirfuzz.Path.is_file",
                return_value=True,
            ),
        ):
            await run_web_dirfuzz(
                "10.129.7.81", 80, "http://10.129.7.81:80",
                None, state, config, tmp_path,
            )

        # First cmd is the pre-flight curl, second is feroxbuster Stage 1
        assert len(captured_cmds) >= 2
        stage1_cmd = captured_cmds[1]
        assert "feroxbuster" in stage1_cmd
        assert "--no-recursion" in stage1_cmd
        assert "--depth" not in stage1_cmd


class TestWhatwebFixes:
    def test_parse_whatweb_excludes_status_and_metadata(self) -> None:
        from recon_ninja.modules.web.web_core import _parse_whatweb
        raw_output = (
            "http://10.129.7.182 [200 OK] Apache[2.4.52], PHP[7.4], WordPress[5.9], "
            "IP[10.129.7.182], Title[Dashboard], Country[RESERVED][ZZ]\n"
            "http://10.129.7.182/login [302 Found] RedirectLocation[http://10.129.7.182/index.php]"
        )
        tech_map = _parse_whatweb(raw_output)

        # Spurious 200 OK status matches should not exist
        assert "200 OK" not in tech_map
        assert "302 Found" not in tech_map
        # Metadata fields should be ignored
        assert "IP" not in tech_map
        assert "Title" not in tech_map
        assert "Country" not in tech_map
        assert "RedirectLocation" not in tech_map

        # Valid technologies should be kept
        assert tech_map["Apache"] == "2.4.52"
        assert tech_map["PHP"] == "7.4"
        assert tech_map["WordPress"] == "5.9"


class TestCurlHeaderHttp2:
    def test_parse_curl_headers_http2_and_standard(self) -> None:
        from recon_ninja.modules.web.web_core import _parse_curl_headers
        raw_http2 = (
            "HTTP/2 200\r\n"
            ":status: 200\r\n"
            ":status 200\r\n"
            "server: nginx/1.18.0\r\n"
            "content-type: text/html\r\n"
        )
        headers = _parse_curl_headers(raw_http2)
        assert headers.get("server") == "nginx/1.18.0"
        assert headers.get("content-type") == "text/html"
        assert headers.get("status") == "200"

        raw_http1 = (
            "HTTP/1.1 200 OK\r\n"
            "Server: Apache\r\n"
            "Content-Type: application/json\r\n"
        )
        headers_http1 = _parse_curl_headers(raw_http1)
        assert headers_http1.get("server") == "Apache"
        assert headers_http1.get("content-type") == "application/json"


class TestExtractHostnamesIPGuard:
    def test_extract_hostnames_ignores_bare_ips(self) -> None:
        from recon_ninja.modules.web.web_core import _extract_hostnames_from_headers
        raw_headers = (
            "HTTP/1.1 301 Moved Permanently\r\n"
            "Location: http://10.10.10.1/index.php\r\n"
            "Set-Cookie: session=xyz; Domain=smarthire.htb\r\n"
            "\r\n"
            "HTTP/1.1 200 OK\r\n"
            "Location: https://sub.smarthire.htb:8443/home\r\n"
            "Set-Cookie: session=xyz; Domain=127.0.0.1\r\n"
        )
        hosts = _extract_hostnames_from_headers(raw_headers)
        assert "smarthire.htb" in hosts
        assert "sub.smarthire.htb" in hosts
        assert "10.10.10.1" not in hosts
        assert "127.0.0.1" not in hosts


class TestScanStateAddHostname:
    def test_add_hostname_duplicate_check(self, tmp_path: Path) -> None:
        state = _make_web_state(tmp_path)
        state.add_hostname("smarthire.htb")
        state.add_hostname("smarthire.htb")
        state.add_hostname("")
        state.add_hostname("another.htb")

        assert state.hostnames == ["smarthire.htb", "another.htb"]
