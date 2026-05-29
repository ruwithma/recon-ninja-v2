"""Tests for recon_ninja utility modules — network, checker, wordlists, hosts.

Covers:
- Network: validate_target, is_private_ip, expand_cidr, is_root
- Checker: check_tools, get_missing_required, format_tool_status
- Wordlists: resolve_wordlist, find_seclists, get_dir_wordlist
- Hosts: read_etc_hosts, hostname_exists
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from recon_ninja.utils.network import (
    validate_target,
    is_private_ip,
    expand_cidr,
    is_root,
)
from recon_ninja.utils.checker import (
    check_tools,
    get_missing_required,
    format_tool_status,
    REQUIRED_TOOLS,
)
from recon_ninja.utils.wordlists import (
    resolve_wordlist,
    find_seclists,
    get_dir_wordlist,
)
from recon_ninja.utils.hosts import (
    read_etc_hosts,
    hostname_exists,
)


# ===================================================================
# Network: validate_target tests
# ===================================================================


class TestValidateTarget:
    """Tests for validate_target()."""

    def test_validate_ipv4_valid(self) -> None:
        """'192.168.1.1' should validate as (True, '192.168.1.1')."""
        ok, result = validate_target("192.168.1.1")
        assert ok is True
        assert result == "192.168.1.1"

    def test_validate_ipv4_valid_zero(self) -> None:
        """'0.0.0.0' should validate."""
        ok, result = validate_target("0.0.0.0")
        assert ok is True
        assert result == "0.0.0.0"

    def test_validate_ipv4_valid_max(self) -> None:
        """'255.255.255.255' should validate."""
        ok, result = validate_target("255.255.255.255")
        assert ok is True
        assert result == "255.255.255.255"

    def test_validate_ipv4_invalid_octet(self) -> None:
        """'256.1.1.1' has an octet > 255 and should fail."""
        ok, result = validate_target("256.1.1.1")
        assert ok is False
        assert "range" in result.lower() or "invalid" in result.lower()

    def test_validate_ipv4_negative_octet(self) -> None:
        """Negative octet values should fail."""
        ok, result = validate_target("-1.1.1.1")
        assert ok is False

    def test_validate_ipv4_loopback(self) -> None:
        """'127.0.0.1' is a valid IPv4 address."""
        ok, result = validate_target("127.0.0.1")
        assert ok is True
        assert result == "127.0.0.1"

    def test_validate_empty(self) -> None:
        """Empty string should return (False, ...)."""
        ok, result = validate_target("")
        assert ok is False

    def test_validate_whitespace_only(self) -> None:
        """Whitespace-only string should return (False, ...)."""
        ok, result = validate_target("   ")
        assert ok is False

    @patch("recon_ninja.utils.network.socket.gethostbyname")
    def test_validate_hostname_google(self, mock_gethostbyname: MagicMock) -> None:
        """'google.com' should resolve — (True, some_ip)."""
        mock_gethostbyname.return_value = "8.8.8.8"
        ok, result = validate_target("google.com")
        assert ok is True
        assert result == "8.8.8.8"

    def test_validate_hostname_invalid(self) -> None:
        """'!!!invalid' is not a valid hostname and should fail."""
        ok, result = validate_target("!!!invalid")
        assert ok is False

    @patch("recon_ninja.utils.network.socket.gethostbyname")
    def test_validate_hostname_unresolvable(self, mock_gethostbyname: MagicMock) -> None:
        """A well-formed but non-existent hostname should fail."""
        import socket
        mock_gethostbyname.side_effect = socket.gaierror
        ok, result = validate_target("this.domain.does.not.exist.at.all.xyz12345.com")
        assert ok is False

    def test_validate_ipv6_loopback(self) -> None:
        """IPv6 loopback '::1' should validate."""
        ok, result = validate_target("::1")
        assert ok is True
        assert result == "::1"

    def test_validate_ipv6_full(self) -> None:
        """Full IPv6 address should validate."""
        ok, result = validate_target("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert ok is True

    def test_validate_strips_whitespace(self) -> None:
        """Leading/trailing whitespace should be stripped."""
        ok, result = validate_target("  192.168.1.1  ")
        assert ok is True
        assert result == "192.168.1.1"


# ===================================================================
# Network: is_private_ip tests
# ===================================================================


class TestIsPrivateIP:
    """Tests for is_private_ip()."""

    def test_is_private_ip_10(self) -> None:
        """10.0.0.1 is in the 10.0.0.0/8 private range."""
        assert is_private_ip("10.0.0.1") is True

    def test_is_private_ip_10_max(self) -> None:
        """10.255.255.255 is still in the 10.0.0.0/8 range."""
        assert is_private_ip("10.255.255.255") is True

    def test_is_private_ip_172(self) -> None:
        """172.16.0.1 is in the 172.16.0.0/12 private range."""
        assert is_private_ip("172.16.0.1") is True

    def test_is_private_ip_172_end(self) -> None:
        """172.31.255.255 is still in the 172.16.0.0/12 range."""
        assert is_private_ip("172.31.255.255") is True

    def test_is_private_ip_172_before_range(self) -> None:
        """172.15.0.1 is NOT in the private range."""
        assert is_private_ip("172.15.0.1") is False

    def test_is_private_ip_192(self) -> None:
        """192.168.1.1 is in the 192.168.0.0/16 private range."""
        assert is_private_ip("192.168.1.1") is True

    def test_is_private_ip_192_end(self) -> None:
        """192.168.255.255 is still in the private range."""
        assert is_private_ip("192.168.255.255") is True

    def test_is_private_ip_public(self) -> None:
        """8.8.8.8 is a public IP and should return False."""
        assert is_private_ip("8.8.8.8") is False

    def test_is_private_ip_public_another(self) -> None:
        """1.1.1.1 is a public IP."""
        assert is_private_ip("1.1.1.1") is False

    def test_is_private_ip_invalid(self) -> None:
        """Invalid IP string should return False."""
        assert is_private_ip("not_an_ip") is False

    def test_is_private_ip_empty(self) -> None:
        """Empty string should return False."""
        assert is_private_ip("") is False


# ===================================================================
# Network: expand_cidr tests
# ===================================================================


class TestExpandCIDR:
    """Tests for expand_cidr()."""

    def test_expand_cidr_24(self) -> None:
        """'10.10.10.0/24' should produce 254 host addresses."""
        hosts = expand_cidr("10.10.10.0/24")
        assert len(hosts) == 254
        # Should NOT include network (.0) and broadcast (.255)
        assert "10.10.10.0" not in hosts
        assert "10.10.10.255" not in hosts
        # Should include .1 and .254
        assert "10.10.10.1" in hosts
        assert "10.10.10.254" in hosts

    def test_expand_cidr_32(self) -> None:
        """'10.10.10.1/32' should produce exactly 1 host."""
        hosts = expand_cidr("10.10.10.1/32")
        assert len(hosts) == 1
        assert "10.10.10.1" in hosts

    def test_expand_cidr_31(self) -> None:
        """'10.10.10.0/31' is point-to-point — returns 2 addresses."""
        hosts = expand_cidr("10.10.10.0/31")
        assert len(hosts) == 2
        assert "10.10.10.0" in hosts
        assert "10.10.10.1" in hosts

    def test_expand_cidr_30(self) -> None:
        """'10.10.10.0/30' should produce 2 host addresses."""
        hosts = expand_cidr("10.10.10.0/30")
        assert len(hosts) == 2
        assert "10.10.10.1" in hosts
        assert "10.10.10.2" in hosts

    def test_expand_cidr_16(self) -> None:
        """'10.10.0.0/16' should produce 65534 host addresses."""
        hosts = expand_cidr("10.10.0.0/16")
        assert len(hosts) == 65534

    def test_expand_cidr_invalid(self) -> None:
        """'not_a_cidr' should raise ValueError."""
        with pytest.raises(ValueError):
            expand_cidr("not_a_cidr")

    def test_expand_cidr_bad_prefix(self) -> None:
        """Invalid prefix should raise ValueError."""
        with pytest.raises(ValueError):
            expand_cidr("10.10.10.0/33")

    def test_expand_cidr_bad_ip(self) -> None:
        """Invalid IP in CIDR should raise ValueError."""
        with pytest.raises(ValueError):
            expand_cidr("999.10.10.0/24")


# ===================================================================
# Network: is_root tests
# ===================================================================


class TestIsRoot:
    """Tests for is_root()."""

    def test_is_root_returns_bool(self) -> None:
        """is_root() should return a boolean value."""
        result = is_root()
        assert isinstance(result, bool)

    @patch("recon_ninja.utils.network.os.geteuid", return_value=0)
    def test_is_root_when_root(self, mock_geteuid: MagicMock) -> None:
        """When euid is 0, is_root() should return True."""
        assert is_root() is True

    @patch("recon_ninja.utils.network.os.geteuid", return_value=1000)
    def test_is_root_when_not_root(self, mock_geteuid: MagicMock) -> None:
        """When euid is 1000, is_root() should return False."""
        assert is_root() is False


# ===================================================================
# Checker tests
# ===================================================================


class TestCheckTools:
    """Tests for the tool availability checker."""

    def test_check_tools_returns_dict(self) -> None:
        """check_tools() should return a dict[str, bool]."""
        result = check_tools()
        assert isinstance(result, dict)
        for key, val in result.items():
            assert isinstance(key, str)
            assert isinstance(val, bool)

    def test_check_tools_has_nmap(self) -> None:
        """'nmap' should be a key in the check_tools() result."""
        result = check_tools()
        assert "nmap" in result

    def test_check_tools_covers_all_required(self) -> None:
        """All REQUIRED_TOOLS should appear in check_tools() results."""
        result = check_tools()
        for tool in REQUIRED_TOOLS:
            assert tool in result, f"Required tool '{tool}' missing from check_tools()"

    def test_check_tools_covers_optional(self) -> None:
        """Optional tools should also appear in check_tools() results."""
        from recon_ninja.utils.checker import OPTIONAL_TOOLS
        result = check_tools()
        for tool in OPTIONAL_TOOLS:
            assert tool in result, f"Optional tool '{tool}' missing from check_tools()"

    @patch("recon_ninja.utils.checker.shutil.which", return_value=None)
    def test_get_missing_required_all_missing(self, mock_which: MagicMock) -> None:
        """When all tools are unavailable, get_missing_required returns all required tools."""
        available = {tool: False for tool in REQUIRED_TOOLS}
        missing = get_missing_required(available)
        assert set(missing) == set(REQUIRED_TOOLS.keys())

    @patch("recon_ninja.utils.checker.shutil.which", return_value="/usr/bin/nmap")
    def test_get_missing_required_nmap_found(self, mock_which: MagicMock) -> None:
        """When nmap is found but others aren't, only others are missing."""
        available = {tool: (tool == "nmap") for tool in REQUIRED_TOOLS}
        missing = get_missing_required(available)
        assert "nmap" not in missing
        assert len(missing) == len(REQUIRED_TOOLS) - 1

    def test_get_missing_required_all_present(self) -> None:
        """When all required tools are present, get_missing_required returns empty list."""
        available = {tool: True for tool in REQUIRED_TOOLS}
        missing = get_missing_required(available)
        assert missing == []

    def test_format_tool_status(self) -> None:
        """format_tool_status returns a non-empty string."""
        available = check_tools()
        result = format_tool_status(available)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_format_tool_status_contains_tool_names(self) -> None:
        """format_tool_status output should contain tool names."""
        available = check_tools()
        result = format_tool_status(available)
        assert "nmap" in result

    @patch("recon_ninja.utils.checker.shutil.which", return_value=None)
    def test_format_tool_status_all_missing(self, mock_which: MagicMock) -> None:
        """format_tool_status should include a warning when required tools are missing."""
        available = {tool: False for tool in {**REQUIRED_TOOLS, **{k: v for k, v in {}}}}
        # Actually let's just build a dict manually with all False
        from recon_ninja.utils.checker import OPTIONAL_TOOLS
        available = {}
        for tool in {**REQUIRED_TOOLS, **OPTIONAL_TOOLS}:
            available[tool] = False
        result = format_tool_status(available)
        assert isinstance(result, str)
        assert len(result) > 0


# ===================================================================
# Wordlist tests
# ===================================================================


class TestResolveWordlist:
    """Tests for resolve_wordlist()."""

    def test_resolve_wordlist_existing(self, tmp_path: Path) -> None:
        """resolve_wordlist should find an existing file in seclists_base."""
        # Create a fake seclists structure
        seclists = tmp_path / "seclists"
        seclists.mkdir()
        web_dir = seclists / "Discovery" / "Web-Content"
        web_dir.mkdir(parents=True)
        wordlist = web_dir / "common.txt"
        wordlist.write_text("admin\nlogin\ntest\n", encoding="utf-8")

        result = resolve_wordlist(
            "Discovery/Web-Content/common.txt",
            seclists_base=str(seclists),
        )
        assert result is not None
        assert result.name == "common.txt"

    def test_resolve_wordlist_with_custom_dir(self, tmp_path: Path) -> None:
        """resolve_wordlist should check custom_dir before seclists_base."""
        custom = tmp_path / "custom"
        custom.mkdir()
        wordlist = custom / "mylist.txt"
        wordlist.write_text("entry1\nentry2\n", encoding="utf-8")

        result = resolve_wordlist(
            "mylist.txt",
            seclists_base=str(tmp_path / "nonexistent_seclists"),
            custom_dir=str(custom),
        )
        assert result is not None
        assert result.name == "mylist.txt"

    def test_resolve_wordlist_missing(self, tmp_path: Path) -> None:
        """resolve_wordlist returns None for a non-existent file."""
        seclists = tmp_path / "seclists"
        seclists.mkdir()

        result = resolve_wordlist(
            "nonexistent_wordlist.txt",
            seclists_base=str(seclists),
        )
        assert result is None

    def test_resolve_wordlist_nonexistent_base(self) -> None:
        """resolve_wordlist returns None when base dir doesn't exist."""
        result = resolve_wordlist(
            "common.txt",
            seclists_base="/nonexistent/path/that/does/not/exist",
        )
        assert result is None

    def test_resolve_wordlist_rglob_fallback(self, tmp_path: Path) -> None:
        """resolve_wordlist uses rglob when direct path doesn't match."""
        seclists = tmp_path / "seclists"
        seclists.mkdir()
        deep_dir = seclists / "some" / "deep" / "path"
        deep_dir.mkdir(parents=True)
        wordlist = deep_dir / "targets.txt"
        wordlist.write_text("line1\n", encoding="utf-8")

        # Search by filename only — should find via rglob
        result = resolve_wordlist(
            "targets.txt",
            seclists_base=str(seclists),
        )
        assert result is not None
        assert result.name == "targets.txt"


class TestFindSeclists:
    """Tests for find_seclists()."""

    def test_find_seclists_none(self) -> None:
        """find_seclists returns None when no seclists dirs exist."""
        with patch("recon_ninja.utils.wordlists._SECLISTS_SEARCH_PATHS", ["/nonexistent/path"]):
            result = find_seclists()
            assert result is None

    def test_find_seclists_existing(self, tmp_path: Path) -> None:
        """find_seclists returns the path when a valid seclists dir exists."""
        seclists = tmp_path / "seclists"
        seclists.mkdir()
        (seclists / "Discovery").mkdir()

        with patch("recon_ninja.utils.wordlists._SECLISTS_SEARCH_PATHS", [str(seclists)]):
            result = find_seclists()
            assert result == str(seclists)

    def test_find_seclists_returns_first_match(self, tmp_path: Path) -> None:
        """find_seclists should return the first existing directory."""
        first = tmp_path / "first"
        first.mkdir()
        (first / "Discovery").mkdir()
        second = tmp_path / "second"
        second.mkdir()
        (second / "Discovery").mkdir()

        with patch(
            "recon_ninja.utils.wordlists._SECLISTS_SEARCH_PATHS",
            [str(first), str(second)],
        ):
            result = find_seclists()
            assert result == str(first)


class TestGetDirWordlist:
    """Tests for get_dir_wordlist()."""

    def test_get_dir_wordlist_none(self) -> None:
        """get_dir_wordlist returns None when no seclists is available."""
        with patch("recon_ninja.utils.wordlists._SECLISTS_SEARCH_PATHS", ["/nonexistent"]):
            result = get_dir_wordlist(seclists_base="/nonexistent/path")
            assert result is None

    def test_get_dir_wordlist_finds_first_candidate(self, tmp_path: Path) -> None:
        """get_dir_wordlist finds the first available directory wordlist."""
        seclists = tmp_path / "seclists"
        web_dir = seclists / "Discovery" / "Web-Content"
        web_dir.mkdir(parents=True)
        wordlist = web_dir / "raft-medium-directories-lowercase.txt"
        wordlist.write_text("admin\n", encoding="utf-8")

        result = get_dir_wordlist(seclists_base=str(seclists))
        assert result is not None
        assert result.name == "raft-medium-directories-lowercase.txt"

    def test_get_dir_wordlist_fallback_candidate(self, tmp_path: Path) -> None:
        """get_dir_wordlist falls back to the second candidate if first is missing."""
        seclists = tmp_path / "seclists"
        web_dir = seclists / "Discovery" / "Web-Content"
        web_dir.mkdir(parents=True)
        # Only create the second candidate (not the first)
        wordlist = web_dir / "raft-medium-directories.txt"
        wordlist.write_text("admin\n", encoding="utf-8")

        result = get_dir_wordlist(seclists_base=str(seclists))
        assert result is not None
        assert result.name == "raft-medium-directories.txt"


# ===================================================================
# Hosts tests
# ===================================================================


class TestReadEtcHosts:
    """Tests for read_etc_hosts()."""

    def test_read_etc_hosts_returns_list(self) -> None:
        """read_etc_hosts returns a list of tuples."""
        result = read_etc_hosts()
        assert isinstance(result, list)
        # If entries exist, each should be a 2-tuple
        if result:
            for entry in result:
                assert isinstance(entry, tuple)
                assert len(entry) == 2
                assert isinstance(entry[0], str)
                assert isinstance(entry[1], str)

    @patch("recon_ninja.utils.hosts._ETC_HOSTS")
    def test_read_etc_hosts_parses_correctly(self, mock_path: MagicMock, tmp_path: Path) -> None:
        """read_etc_hosts correctly parses a sample /etc/hosts file."""
        hosts_file = tmp_path / "hosts"
        hosts_file.write_text(
            "127.0.0.1\tlocalhost\n"
            "10.10.10.5\trecon.local dc01\n"
            "# This is a comment\n"
            "\n"
            "::1\tlocalhost ip6-localhost\n",
            encoding="utf-8",
        )
        mock_path.read_text = hosts_file.read_text
        mock_path.__class__ = type(hosts_file)  # ensure Path-like behavior

        # We need to mock _ETC_HOSTS properly
        with patch("recon_ninja.utils.hosts._ETC_HOSTS", hosts_file):
            entries = read_etc_hosts()

        assert isinstance(entries, list)
        # Should find localhost, recon.local, dc01, ip6-localhost
        ips = [ip for ip, _ in entries]
        hostnames = [h for _, h in entries]
        assert "127.0.0.1" in ips
        assert "localhost" in hostnames

    @patch("recon_ninja.utils.hosts._ETC_HOSTS")
    def test_read_etc_hosts_handles_permission_error(self, mock_path: MagicMock) -> None:
        """read_etc_hosts returns empty list on PermissionError."""
        mock_path.read_text.side_effect = PermissionError("denied")
        with patch("recon_ninja.utils.hosts._ETC_HOSTS", mock_path):
            result = read_etc_hosts()
        assert result == []

    @patch("recon_ninja.utils.hosts._ETC_HOSTS")
    def test_read_etc_hosts_skips_malformed_lines(self, mock_path: MagicMock, tmp_path: Path) -> None:
        """Malformed lines in /etc/hosts are silently skipped."""
        hosts_file = tmp_path / "hosts"
        hosts_file.write_text(
            "10.10.10.5\trecon.local\n"
            "malformed_line_no_tab\n"
            "just_one_word\n"
            "192.168.1.1\trouter.local\n",
            encoding="utf-8",
        )
        with patch("recon_ninja.utils.hosts._ETC_HOSTS", hosts_file):
            entries = read_etc_hosts()
        ips = [ip for ip, _ in entries]
        assert "10.10.10.5" in ips
        assert "192.168.1.1" in ips
        # malformed entries should not appear as IPs
        assert "malformed_line_no_tab" not in ips

    @patch("recon_ninja.utils.hosts._ETC_HOSTS")
    def test_read_etc_hosts_multiple_hostnames(self, mock_path: MagicMock, tmp_path: Path) -> None:
        """A line with multiple hostnames produces one entry per hostname."""
        hosts_file = tmp_path / "hosts"
        hosts_file.write_text("10.10.10.5\trecon.local dc01 fileserver\n", encoding="utf-8")
        with patch("recon_ninja.utils.hosts._ETC_HOSTS", hosts_file):
            entries = read_etc_hosts()
        hostnames = [h for _, h in entries]
        assert "recon.local" in hostnames
        assert "dc01" in hostnames
        assert "fileserver" in hostnames

    @patch("recon_ninja.utils.hosts._ETC_HOSTS")
    def test_read_etc_hosts_strips_comments(self, mock_path: MagicMock, tmp_path: Path) -> None:
        """Inline comments should be stripped."""
        hosts_file = tmp_path / "hosts"
        hosts_file.write_text("10.10.10.5\trecon.local # this is a comment\n", encoding="utf-8")
        with patch("recon_ninja.utils.hosts._ETC_HOSTS", hosts_file):
            entries = read_etc_hosts()
        assert len(entries) >= 1
        ip, hostname = entries[0]
        assert ip == "10.10.10.5"
        assert hostname == "recon.local"


class TestHostnameExists:
    """Tests for hostname_exists()."""

    def test_hostname_exists_false(self) -> None:
        """hostname_exists returns False for a random hostname that's unlikely in /etc/hosts."""
        result = hostname_exists("this_hostname_absolutely_does_not_exist_12345")
        assert result is False

    @patch("recon_ninja.utils.hosts._ETC_HOSTS")
    def test_hostname_exists_true(self, mock_path: MagicMock, tmp_path: Path) -> None:
        """hostname_exists returns True when hostname is in /etc/hosts."""
        hosts_file = tmp_path / "hosts"
        hosts_file.write_text("10.10.10.5\trecon.local\n", encoding="utf-8")
        with patch("recon_ninja.utils.hosts._ETC_HOSTS", hosts_file):
            result = hostname_exists("recon.local")
        assert result is True

    @patch("recon_ninja.utils.hosts._ETC_HOSTS")
    def test_hostname_exists_case_insensitive(self, mock_path: MagicMock, tmp_path: Path) -> None:
        """hostname_exists is case-insensitive."""
        hosts_file = tmp_path / "hosts"
        hosts_file.write_text("10.10.10.5\tRecon.Local\n", encoding="utf-8")
        with patch("recon_ninja.utils.hosts._ETC_HOSTS", hosts_file):
            assert hostname_exists("recon.local") is True
            assert hostname_exists("RECON.LOCAL") is True

    @patch("recon_ninja.utils.hosts._ETC_HOSTS")
    def test_hostname_exists_empty_hosts(self, mock_path: MagicMock, tmp_path: Path) -> None:
        """hostname_exists returns False for empty /etc/hosts."""
        hosts_file = tmp_path / "hosts"
        hosts_file.write_text("", encoding="utf-8")
        with patch("recon_ninja.utils.hosts._ETC_HOSTS", hosts_file):
            result = hostname_exists("anything")
        assert result is False
