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
            patch("recon_ninja.modules.web.web_core.shutil.which", side_effect=which_side_effect),
            patch("recon_ninja.modules.web.web_core.run_tool", new_callable=AsyncMock, side_effect=run_tool_side_effect),
            patch("recon_ninja.modules.web.web_core.hostname_exists", return_value=False),
            patch("recon_ninja.modules.web.web_core.get_console", return_value=mock_console),
        ):
            result = await run_web_core("10.129.7.81", 80, "http://10.129.7.81:80", state, config, tmp_path)

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
            patch("recon_ninja.modules.web.web_dirfuzz.shutil.which", side_effect=which_side_effect),
            patch("recon_ninja.modules.web.web_dirfuzz.run_tool", new_callable=AsyncMock, side_effect=run_tool_side_effect),
        ):
            result = await run_web_dirfuzz("10.129.7.81", 80, "http://10.129.7.81:80", None, state, config, tmp_path)

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
        v2_raw = "200      GET       48l      128w     2345c http://10.129.7.182/admin\n301      GET        5l       10w      150c http://10.129.7.182/dashboard"
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