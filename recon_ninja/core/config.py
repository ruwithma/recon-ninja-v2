"""Configuration loader for Recon Ninja v2.

Handles loading, merging, and persisting user configuration from
``~/.config/recon-ninja/config.yaml``.  The merge order is:

    built-in defaults  <  YAML file  <  CLI overrides

A singleton accessor :func:`get_config` is provided so every module can
reach the resolved configuration without passing it around explicitly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default configuration values (mirrors the YAML structure in the spec)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG: dict[str, Any] = {
    "scan": {
        "default_threads": 10,
        "default_timeout": 300,
        "nmap_min_rate": 5000,
        "rustscan_ulimit": 5000,
        "udp_enabled": False,
        "stealth_mode": False,
    },
    "wordlists": {
        "seclists_base": "/usr/share/seclists",
        "dir_medium": "Discovery/Web-Content/raft-medium-directories.txt",
        "dir_small": "Discovery/Web-Content/common.txt",
        "vhosts": "Discovery/DNS/subdomains-top1million-5000.txt",
        "usernames": "Usernames/xato-net-10-million-usernames-dup.txt",
        "snmp": "Discovery/SNMP/snmp.txt",
        "custom_dir": None,
    },
    "tools": {
        "preferred_dir_fuzzer": "feroxbuster",
        "preferred_smb_enum": "enum4linux-ng",
    },
    "output": {
        "always_html": False,
        "always_json": True,
        "timestamp_dirs": True,
    },
    "htb": {
        "vpn_interface": "tun0",
        "auto_add_hosts": False,
        "machine_name": None,
    },
    "api_keys": {
        "shodan": None,
        "nvd": None,
    },
}


# ---------------------------------------------------------------------------
# Dataclass sections
# ---------------------------------------------------------------------------


@dataclass
class ScanConfig:
    """Scan performance and behaviour knobs."""

    default_threads: int = 10
    default_timeout: int = 300
    nmap_min_rate: int = 5000
    rustscan_ulimit: int = 5000
    udp_enabled: bool = False
    stealth_mode: bool = False


@dataclass
class WordlistsConfig:
    """Paths to wordlist files used by various modules."""

    seclists_base: str = "/usr/share/seclists"
    dir_medium: str = "Discovery/Web-Content/raft-medium-directories.txt"
    dir_small: str = "Discovery/Web-Content/common.txt"
    vhosts: str = "Discovery/DNS/subdomains-top1million-5000.txt"
    usernames: str = "Usernames/xato-net-10-million-usernames-dup.txt"
    snmp: str = "Discovery/SNMP/snmp.txt"
    custom_dir: str | None = None

    @property
    def dir_medium_path(self) -> Path:
        """Fully-qualified path for the medium directory wordlist."""
        base = Path(self.seclists_base)
        return base / self.dir_medium

    @property
    def dir_small_path(self) -> Path:
        """Fully-qualified path for the small directory wordlist."""
        base = Path(self.seclists_base)
        return base / self.dir_small

    @property
    def vhosts_path(self) -> Path:
        """Fully-qualified path for the vhosts wordlist."""
        base = Path(self.seclists_base)
        return base / self.vhosts

    @property
    def usernames_path(self) -> Path:
        """Fully-qualified path for the usernames wordlist."""
        base = Path(self.seclists_base)
        return base / self.usernames

    @property
    def snmp_path(self) -> Path:
        """Fully-qualified path for the SNMP wordlist."""
        base = Path(self.seclists_base)
        return base / self.snmp


@dataclass
class ToolsConfig:
    """Preferred tool choices when multiple alternatives exist."""

    preferred_dir_fuzzer: str = "feroxbuster"
    preferred_smb_enum: str = "enum4linux-ng"


@dataclass
class OutputConfig:
    """Output format and directory naming preferences."""

    always_html: bool = False
    always_json: bool = True
    timestamp_dirs: bool = True


@dataclass
class HTBConfig:
    """HackTheBox-specific settings."""

    vpn_interface: str = "tun0"
    auto_add_hosts: bool = False
    machine_name: str | None = None


@dataclass
class APIKeysConfig:
    """Optional API keys for enriched data sources."""

    shodan: str | None = None
    nvd: str | None = None


@dataclass
class MergeConfig:
    """Top-level configuration container assembled from three layers.

    Resolution order (later wins):

    1. **defaults** — hard-coded in :data:`_DEFAULT_CONFIG`.
    2. **file**     — ``~/.config/recon-ninja/config.yaml``.
    3. **cli**      — flags passed on the command-line.
    """

    scan: ScanConfig = field(default_factory=ScanConfig)
    wordlists: WordlistsConfig = field(default_factory=WordlistsConfig)
    tools: ToolsConfig = field(default_factory=ToolsConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    htb: HTBConfig = field(default_factory=HTBConfig)
    api_keys: APIKeysConfig = field(default_factory=APIKeysConfig)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Mapping from the top-level keys in the YAML/dict to the dataclass type
_SECTION_MAP: dict[str, type] = {
    "scan": ScanConfig,
    "wordlists": WordlistsConfig,
    "tools": ToolsConfig,
    "output": OutputConfig,
    "htb": HTBConfig,
    "api_keys": APIKeysConfig,
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into *base*, returning a new dict.

    Only dicts are merged recursively — all other types are simply replaced
    by the override value.  ``None`` values in *override* are treated as
    intentional (they override), preserving the ability to explicitly
    null-out a setting.
    """
    merged: dict[str, Any] = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _dict_to_section(section_cls: type, data: dict[str, Any]) -> Any:
    """Instantiate a dataclass section, silently ignoring unknown keys.

    This prevents the loader from crashing if the user has extra or
    deprecated keys in their config file.
    """
    valid_field_names: set[str] = {f.name for f in fields(section_cls)}
    filtered: dict[str, Any] = {k: v for k, v in data.items() if k in valid_field_names}
    return section_cls(**filtered)


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file, returning an empty dict on any failure."""
    if not path.is_file():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
        data: Any = yaml.safe_load(text)
        if data is None:
            return {}
        if not isinstance(data, dict):
            logger.warning("Config file %s does not contain a YAML mapping — ignoring.", path)
            return {}
        return data
    except yaml.YAMLError as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return {}
    except OSError as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return {}


def _write_defaults(path: Path) -> None:
    """Write the default configuration to *path*, creating parent dirs.

    Errors are logged but never raised — this is a best-effort convenience.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            yaml.dump(_DEFAULT_CONFIG, default_flow_style=False, sort_keys=False),
            encoding="utf-8",
        )
        logger.debug("Wrote default config to %s", path)
    except OSError as exc:
        logger.warning("Could not write default config to %s: %s", path, exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_PATH = Path.home() / ".config" / "recon-ninja" / "config.yaml"

# Module-level singleton holder (simple, import-safe)
_instance: MergeConfig | None = None


def load_config(
    config_path: Path | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> MergeConfig:
    """Build a :class:`MergeConfig` from the three-layer merge pipeline.

    Parameters
    ----------
    config_path:
        Path to the YAML config file.  Defaults to
        ``~/.config/recon-ninja/config.yaml``.  If the file does not exist
        it is created from defaults silently.
    cli_overrides:
        Flat or nested dictionary of CLI flag overrides.  Nested dicts
        follow the same structure as the YAML (e.g.
        ``{"scan": {"stealth_mode": True}}``).  ``None`` means no CLI
        overrides.

    Returns
    -------
    MergeConfig
        The fully-resolved configuration object.
    """
    path: Path = config_path or _DEFAULT_CONFIG_PATH

    # 1. Start with built-in defaults
    merged: dict[str, Any] = _deep_merge({}, _DEFAULT_CONFIG)

    # 2. Create the file from defaults if it does not exist
    if not path.is_file():
        _write_defaults(path)

    # 3. Load file values and merge on top of defaults
    file_data: dict[str, Any] = _load_yaml(path)
    if file_data:
        merged = _deep_merge(merged, file_data)

    # 4. Merge CLI overrides (highest precedence)
    if cli_overrides:
        merged = _deep_merge(merged, cli_overrides)

    # 5. Convert the merged dict into typed dataclass sections
    config = MergeConfig()
    for section_name, section_cls in _SECTION_MAP.items():
        section_data: dict[str, Any] = merged.get(section_name, {})
        if isinstance(section_data, dict):
            setattr(config, section_name, _dict_to_section(section_cls, section_data))
        else:
            logger.warning(
                "Config section '%s' is not a mapping — using defaults.", section_name
            )

    return config


def get_config(
    config_path: Path | None = None,
    cli_overrides: dict[str, Any] | None = None,
) -> MergeConfig:
    """Return the global :class:`MergeConfig` singleton.

    On the first call the configuration is loaded via :func:`load_config`.
    Subsequent calls return the cached instance, **ignoring** *config_path*
    and *cli_overrides* unless ``force_reload=True`` is set via
    :func:`reset_config` first.

    Parameters
    ----------
    config_path:
        Passed to :func:`load_config` on the first call only.
    cli_overrides:
        Passed to :func:`load_config` on the first call only.

    Returns
    -------
    MergeConfig
        The globally-resolved configuration object.
    """
    global _instance
    if _instance is None:
        _instance = load_config(config_path=config_path, cli_overrides=cli_overrides)
    return _instance


def reset_config() -> None:
    """Clear the singleton so the next :func:`get_config` call re-loads.

    Primarily useful for tests or for handling a config reload at runtime.
    """
    global _instance
    _instance = None
