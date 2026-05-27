"""Tests for the configuration system.

Covers load_config, get_config, reset_config, _deep_merge,
ScanConfig, WordlistsConfig, MergeConfig, and edge cases like
unknown YAML keys, empty YAML files, and the three-layer merge
pipeline (defaults < file < CLI).
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from recon_ninja.core.config import (
    MergeConfig,
    ScanConfig,
    WordlistsConfig,
    _deep_merge,
    get_config,
    load_config,
    reset_config,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_singleton():
    """Reset the config singleton before and after every test."""
    reset_config()
    yield
    reset_config()


# ===================================================================
# _deep_merge tests
# ===================================================================

class TestDeepMerge:
    """Tests for the _deep_merge helper."""

    def test_deep_merge_simple(self) -> None:
        """_deep_merge({'a': 1}, {'a': 2}) → {'a': 2}."""
        result = _deep_merge({"a": 1}, {"a": 2})
        assert result == {"a": 2}

    def test_deep_merge_nested(self) -> None:
        """_deep_merge({'a': {'b': 1}}, {'a': {'c': 2}}) → {'a': {'b': 1, 'c': 2}}."""
        result = _deep_merge({"a": {"b": 1}}, {"a": {"c": 2}})
        assert result == {"a": {"b": 1, "c": 2}}

    def test_deep_merge_none_override(self) -> None:
        """_deep_merge({'a': 1}, {'a': None}) → {'a': None}."""
        result = _deep_merge({"a": 1}, {"a": None})
        assert result == {"a": None}

    def test_deep_merge_adds_new_key(self) -> None:
        """Override dict adds keys not present in base."""
        result = _deep_merge({"a": 1}, {"b": 2})
        assert result == {"a": 1, "b": 2}

    def test_deep_merge_deep_nested(self) -> None:
        """Three levels of nesting merge correctly."""
        base = {"a": {"b": {"c": 1, "d": 2}}}
        override = {"a": {"b": {"c": 99, "e": 3}}}
        result = _deep_merge(base, override)
        assert result == {"a": {"b": {"c": 99, "d": 2, "e": 3}}}

    def test_deep_merge_base_unchanged(self) -> None:
        """_deep_merge should not mutate the base dict."""
        base = {"a": {"b": 1}}
        override = {"a": {"c": 2}}
        result = _deep_merge(base, override)
        assert base == {"a": {"b": 1}}  # base unchanged
        assert result == {"a": {"b": 1, "c": 2}}

    def test_deep_merge_empty_override(self) -> None:
        """Empty override returns a copy of base."""
        base = {"a": 1}
        result = _deep_merge(base, {})
        assert result == {"a": 1}

    def test_deep_merge_empty_base(self) -> None:
        """Empty base with override returns copy of override."""
        result = _deep_merge({}, {"a": 1})
        assert result == {"a": 1}

    def test_deep_merge_replaces_non_dict_with_dict(self) -> None:
        """If base value is a scalar but override is a dict, override wins."""
        result = _deep_merge({"a": 1}, {"a": {"b": 2}})
        assert result == {"a": {"b": 2}}

    def test_deep_merge_replaces_dict_with_scalar(self) -> None:
        """If base value is a dict but override is a scalar, override wins."""
        result = _deep_merge({"a": {"b": 2}}, {"a": 1})
        assert result == {"a": 1}


# ===================================================================
# load_config tests
# ===================================================================

class TestLoadConfig:
    """Tests for the load_config function."""

    def test_load_config_defaults(self, tmp_path: Path) -> None:
        """load_config with no file returns MergeConfig with all defaults."""
        config_path = tmp_path / "nonexistent" / "config.yaml"
        config = load_config(config_path=config_path)
        assert isinstance(config, MergeConfig)
        assert isinstance(config.scan, ScanConfig)
        assert config.scan.default_threads == 10
        assert config.scan.default_timeout == 300
        assert config.scan.nmap_min_rate == 5000
        assert config.scan.stealth_mode is False

    def test_load_config_from_file(self, tmp_path: Path) -> None:
        """load_config with YAML file overrides defaults."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            yaml.dump({
                "scan": {
                    "default_threads": 25,
                    "stealth_mode": True,
                },
                "wordlists": {
                    "seclists_base": "/opt/seclists",
                },
            }),
            encoding="utf-8",
        )
        config = load_config(config_path=config_path)
        assert config.scan.default_threads == 25
        assert config.scan.stealth_mode is True
        # Non-overridden defaults remain
        assert config.scan.default_timeout == 300
        assert config.wordlists.seclists_base == "/opt/seclists"

    def test_load_config_cli_overrides(self, tmp_path: Path) -> None:
        """CLI overrides take precedence over file values."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            yaml.dump({"scan": {"default_threads": 20}}),
            encoding="utf-8",
        )
        config = load_config(
            config_path=config_path,
            cli_overrides={"scan": {"default_threads": 50}},
        )
        assert config.scan.default_threads == 50

    def test_unknown_keys_ignored(self, tmp_path: Path) -> None:
        """YAML with extra keys doesn't crash — unknown keys silently ignored."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            yaml.dump({
                "scan": {
                    "default_threads": 5,
                    "nonexistent_key": "should_be_ignored",
                },
                "unknown_section": {"foo": "bar"},
            }),
            encoding="utf-8",
        )
        config = load_config(config_path=config_path)
        assert config.scan.default_threads == 5
        # Should not raise — unknown keys are silently dropped

    def test_empty_yaml(self, tmp_path: Path) -> None:
        """Empty YAML file → all defaults used."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text("", encoding="utf-8")
        config = load_config(config_path=config_path)
        assert config.scan.default_threads == 10
        assert config.scan.default_timeout == 300

    def test_config_creates_file(self, tmp_path: Path) -> None:
        """load_config creates config file if it doesn't exist."""
        config_path = tmp_path / "new_dir" / "config.yaml"
        assert not config_path.is_file()
        load_config(config_path=config_path)
        assert config_path.is_file()

    def test_cli_overrides_file_overrides_defaults(self, tmp_path: Path) -> None:
        """3-layer merge: default=10, file=20, cli=30 → 30."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            yaml.dump({"scan": {"default_timeout": 20}}),
            encoding="utf-8",
        )
        config = load_config(
            config_path=config_path,
            cli_overrides={"scan": {"default_timeout": 30}},
        )
        assert config.scan.default_timeout == 30


# ===================================================================
# ScanConfig defaults
# ===================================================================

class TestScanConfig:
    """Tests for ScanConfig dataclass defaults."""

    def test_scan_config_defaults(self) -> None:
        """ScanConfig() has expected default values."""
        sc = ScanConfig()
        assert sc.default_threads == 10
        assert sc.default_timeout == 300
        assert sc.nmap_min_rate == 5000
        assert sc.rustscan_ulimit == 5000
        assert sc.udp_enabled is False
        assert sc.stealth_mode is False


# ===================================================================
# WordlistsConfig path properties
# ===================================================================

class TestWordlistsConfig:
    """Tests for WordlistsConfig path property construction."""

    def test_wordlists_paths(self) -> None:
        """WordlistsConfig path properties construct correct paths."""
        wc = WordlistsConfig()
        assert wc.dir_medium_path == Path("/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")
        assert wc.dir_small_path == Path("/usr/share/seclists/Discovery/Web-Content/common.txt")
        assert wc.vhosts_path == Path("/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt")
        assert wc.usernames_path == Path("/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt")
        assert wc.snmp_path == Path("/usr/share/seclists/Discovery/SNMP/snmp.txt")

    def test_wordlists_paths_custom_base(self) -> None:
        """Custom seclists_base changes all derived paths."""
        wc = WordlistsConfig(seclists_base="/opt/seclists")
        assert wc.dir_medium_path == Path("/opt/seclists/Discovery/Web-Content/raft-medium-directories.txt")
        assert wc.vhosts_path == Path("/opt/seclists/Discovery/DNS/subdomains-top1million-5000.txt")


# ===================================================================
# get_config singleton
# ===================================================================

class TestGetConfig:
    """Tests for get_config singleton behavior."""

    def test_get_config_singleton(self, tmp_path: Path) -> None:
        """get_config returns same object on repeated calls."""
        config1 = get_config(config_path=tmp_path / "config.yaml")
        config2 = get_config()
        assert config1 is config2

    def test_reset_config(self, tmp_path: Path) -> None:
        """reset_config + get_config reloads configuration."""
        config1 = get_config(config_path=tmp_path / "config.yaml")
        reset_config()
        config2 = get_config(config_path=tmp_path / "config.yaml")
        # After reset, a new instance is created
        assert config1 is not config2
        # But values should be the same (defaults)
        assert config1.scan.default_threads == config2.scan.default_threads

    def test_get_config_ignores_args_on_second_call(self, tmp_path: Path) -> None:
        """Subsequent get_config calls ignore config_path and cli_overrides."""
        config1 = get_config(config_path=tmp_path / "config.yaml")
        # This second call has different args but should be ignored
        config2 = get_config(
            config_path=tmp_path / "other.yaml",
            cli_overrides={"scan": {"default_threads": 999}},
        )
        assert config1 is config2
        assert config2.scan.default_threads != 999  # Should still be default


# ===================================================================
# MergeConfig structure
# ===================================================================

class TestMergeConfig:
    """Tests for MergeConfig structure and section types."""

    def test_merge_config_all_sections(self) -> None:
        """MergeConfig has all expected sections with correct types."""
        mc = MergeConfig()
        assert isinstance(mc.scan, ScanConfig)
        assert isinstance(mc.wordlists, WordlistsConfig)

    def test_merge_config_from_load(self, tmp_path: Path) -> None:
        """Full config loaded from file populates all sections."""
        config_path = tmp_path / "config.yaml"
        config_path.write_text(
            yaml.dump({
                "scan": {"default_threads": 50, "stealth_mode": True},
                "output": {"always_html": True},
                "htb": {"vpn_interface": "tun1"},
            }),
            encoding="utf-8",
        )
        config = load_config(config_path=config_path)
        assert config.scan.default_threads == 50
        assert config.scan.stealth_mode is True
        assert config.output.always_html is True
        assert config.htb.vpn_interface == "tun1"
        # Unchanged defaults
        assert config.scan.default_timeout == 300
        assert config.output.always_json is True
