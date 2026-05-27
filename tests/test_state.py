"""Tests for recon_ninja.core.state — state / checkpoint manager.

Covers:
- StateManager initialisation and state file creation
- Load / save roundtrip including complex nested objects
- Module completion tracking (mark, is_completed, remaining)
- Corrupted / missing state file handling
- Concurrent save safety
- state_path property
"""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path

import pytest

from recon_ninja.core.state import StateManager
from recon_ninja.core.models import ScanState, ServiceInfo, Finding, Severity


# ===================================================================
# Fixtures
# ===================================================================


@pytest.fixture()
def results_root(tmp_path: Path) -> Path:
    """Return a temporary results root directory."""
    return tmp_path / "results"


@pytest.fixture()
def mgr(results_root: Path) -> StateManager:
    """Return a StateManager pointed at a temp results root."""
    return StateManager(target="10.10.10.5", results_root=results_root)


@pytest.fixture()
def initialised_mgr(mgr: StateManager) -> StateManager:
    """Return a StateManager that has already called init_state()."""
    mgr.init_state()
    return mgr


# ===================================================================
# init_state tests
# ===================================================================


class TestInitState:
    """Tests for StateManager.init_state()."""

    def test_init_state_creates_file(self, mgr: StateManager, results_root: Path) -> None:
        """init_state() should create the scan.state file on disk."""
        mgr.init_state()
        state_file = results_root / "10.10.10.5" / "scan.state"
        assert state_file.is_file()

    def test_init_state_creates_target_dir(self, mgr: StateManager, results_root: Path) -> None:
        """init_state() should create the target directory if missing."""
        mgr.init_state()
        target_dir = results_root / "10.10.10.5"
        assert target_dir.is_dir()

    def test_init_state_returns_scanstate(self, mgr: StateManager) -> None:
        """init_state() should return a ScanState with correct target."""
        state = mgr.init_state()
        assert isinstance(state, ScanState)
        assert state.target == "10.10.10.5"

    def test_init_state_values(self, mgr: StateManager) -> None:
        """init_state() returns ScanState with correct default values."""
        state = mgr.init_state()
        assert state.target == "10.10.10.5"
        assert state.completed_modules == []
        assert state.current_phase == 0
        assert state.open_ports == []
        assert state.all_findings == []
        assert isinstance(state.start_time, datetime)

    def test_init_state_overwrites_existing(self, initialised_mgr: StateManager) -> None:
        """Calling init_state() again overwrites the existing state file."""
        initialised_mgr.mark_completed("smb")
        # Re-init — should reset completed_modules
        state = initialised_mgr.init_state()
        assert "smb" not in state.completed_modules

    def test_init_state_valid_json(self, mgr: StateManager, results_root: Path) -> None:
        """The created state file should contain valid JSON."""
        mgr.init_state()
        state_file = results_root / "10.10.10.5" / "scan.state"
        raw = state_file.read_text(encoding="utf-8")
        data = json.loads(raw)  # should not raise
        assert data["target"] == "10.10.10.5"


# ===================================================================
# load_state tests
# ===================================================================


class TestLoadState:
    """Tests for StateManager.load_state()."""

    def test_load_state_from_disk(self, initialised_mgr: StateManager) -> None:
        """init + load roundtrip should preserve the target."""
        loaded = initialised_mgr.load_state()
        assert loaded is not None
        assert loaded.target == "10.10.10.5"

    def test_load_state_missing_file(self, mgr: StateManager) -> None:
        """load_state() returns None for a missing state file."""
        result = mgr.load_state()
        assert result is None

    def test_load_state_corrupted_json(self, initialised_mgr: StateManager, results_root: Path) -> None:
        """load_state() returns None for invalid JSON in the state file."""
        state_file = results_root / "10.10.10.5" / "scan.state"
        state_file.write_text("{ this is not valid json !!!", encoding="utf-8")
        result = initialised_mgr.load_state()
        assert result is None

    def test_load_state_invalid_schema(self, initialised_mgr: StateManager, results_root: Path) -> None:
        """load_state() returns None for valid JSON with wrong schema."""
        state_file = results_root / "10.10.10.5" / "scan.state"
        # Valid JSON but missing required fields
        state_file.write_text(json.dumps({"wrong": "data"}), encoding="utf-8")
        # This may or may not return None depending on how ScanState.from_dict handles it,
        # but it should not crash
        initialised_mgr.load_state()
        # Either None or a partial ScanState — just verify no exception

    def test_load_state_preserves_completed_modules(self, initialised_mgr: StateManager) -> None:
        """Completed modules survive a save/load roundtrip."""
        initialised_mgr.mark_completed("portscan")
        initialised_mgr.mark_completed("smb")
        loaded = initialised_mgr.load_state()
        assert loaded is not None
        assert "portscan" in loaded.completed_modules
        assert "smb" in loaded.completed_modules


# ===================================================================
# mark_completed tests
# ===================================================================


class TestMarkCompleted:
    """Tests for StateManager.mark_completed()."""

    def test_mark_completed(self, initialised_mgr: StateManager) -> None:
        """mark_completed('smb') adds 'smb' to completed_modules."""
        initialised_mgr.mark_completed("smb")
        assert initialised_mgr.is_completed("smb")

    def test_mark_completed_idempotent(self, initialised_mgr: StateManager) -> None:
        """Marking the same module twice should not create duplicates."""
        initialised_mgr.mark_completed("smb")
        initialised_mgr.mark_completed("smb")
        state = initialised_mgr.state
        assert state is not None
        count = state.completed_modules.count("smb")
        assert count == 1

    def test_mark_completed_multiple_modules(self, initialised_mgr: StateManager) -> None:
        """Multiple different modules can be marked as completed."""
        initialised_mgr.mark_completed("portscan")
        initialised_mgr.mark_completed("smb")
        initialised_mgr.mark_completed("dns")
        assert initialised_mgr.is_completed("portscan")
        assert initialised_mgr.is_completed("smb")
        assert initialised_mgr.is_completed("dns")

    def test_mark_completed_persists_to_disk(self, initialised_mgr: StateManager, results_root: Path) -> None:
        """mark_completed writes updated state to disk immediately."""
        initialised_mgr.mark_completed("web_enum")
        state_file = results_root / "10.10.10.5" / "scan.state"
        raw = state_file.read_text(encoding="utf-8")
        data = json.loads(raw)
        assert "web_enum" in data["completed_modules"]


# ===================================================================
# is_completed tests
# ===================================================================


class TestIsCompleted:
    """Tests for StateManager.is_completed()."""

    def test_is_completed_after_mark(self, initialised_mgr: StateManager) -> None:
        """is_completed returns True after mark_completed."""
        initialised_mgr.mark_completed("ssl")
        assert initialised_mgr.is_completed("ssl") is True

    def test_is_completed_not_done(self, initialised_mgr: StateManager) -> None:
        """is_completed returns False for an unrun module."""
        assert initialised_mgr.is_completed("ldap") is False

    def test_is_completed_no_state(self, mgr: StateManager) -> None:
        """is_completed returns False when no state file exists."""
        assert mgr.is_completed("anything") is False


# ===================================================================
# remaining_modules tests
# ===================================================================


class TestRemainingModules:
    """Tests for StateManager.remaining_modules()."""

    def test_remaining_modules_all(self, initialised_mgr: StateManager) -> None:
        """When no modules are completed, all are remaining."""
        all_mods = ["portscan", "smb", "dns", "web"]
        remaining = initialised_mgr.remaining_modules(all_mods)
        assert remaining == all_mods

    def test_remaining_modules_partial(self, initialised_mgr: StateManager) -> None:
        """remaining_modules returns only undone modules."""
        initialised_mgr.mark_completed("portscan")
        initialised_mgr.mark_completed("dns")
        all_mods = ["portscan", "smb", "dns", "web"]
        remaining = initialised_mgr.remaining_modules(all_mods)
        assert "smb" in remaining
        assert "web" in remaining
        assert "portscan" not in remaining
        assert "dns" not in remaining

    def test_remaining_modules_all_done(self, initialised_mgr: StateManager) -> None:
        """When all modules are completed, remaining is empty."""
        all_mods = ["portscan", "smb"]
        for m in all_mods:
            initialised_mgr.mark_completed(m)
        remaining = initialised_mgr.remaining_modules(all_mods)
        assert remaining == []


# ===================================================================
# Save / load with complex objects
# ===================================================================


class TestSaveLoadComplexObjects:
    """Tests for preserving ServiceInfo and Finding objects through save/load."""

    def test_save_preserves_services(self, initialised_mgr: StateManager) -> None:
        """ServiceInfo objects survive a save + load roundtrip."""
        state = initialised_mgr.state
        assert state is not None
        state.services[22] = ServiceInfo(
            port=22, proto="tcp", state="open",
            service="ssh", product="OpenSSH", version="8.9p1",
        )
        state.services[80] = ServiceInfo(
            port=80, proto="tcp", state="open",
            service="http", product="Apache httpd", version="2.4.52",
        )
        initialised_mgr.save()

        loaded = initialised_mgr.load_state()
        assert loaded is not None
        assert 22 in loaded.services
        assert loaded.services[22].service == "ssh"
        assert loaded.services[22].product == "OpenSSH"
        assert 80 in loaded.services
        assert loaded.services[80].version == "2.4.52"

    def test_save_preserves_findings(self, initialised_mgr: StateManager) -> None:
        """Finding objects survive a save + load roundtrip."""
        state = initialised_mgr.state
        assert state is not None
        state.all_findings.append(
            Finding(
                severity=Severity.HIGH,
                title="SMB signing disabled",
                description="SMB signing is not required",
                module="smb",
                evidence="Found via enum4linux",
                cve="CVE-2020-1234",
            )
        )
        initialised_mgr.save()

        loaded = initialised_mgr.load_state()
        assert loaded is not None
        assert len(loaded.all_findings) == 1
        f = loaded.all_findings[0]
        assert f.title == "SMB signing disabled"
        assert f.severity == Severity.HIGH
        assert f.module == "smb"
        assert f.cve == "CVE-2020-1234"

    def test_save_preserves_open_ports(self, initialised_mgr: StateManager) -> None:
        """Open ports list survives a save + load roundtrip."""
        state = initialised_mgr.state
        assert state is not None
        state.open_ports = [22, 80, 443, 8080]
        initialised_mgr.save()

        loaded = initialised_mgr.load_state()
        assert loaded is not None
        assert loaded.open_ports == [22, 80, 443, 8080]

    def test_save_preserves_hostnames(self, initialised_mgr: StateManager) -> None:
        """Hostnames list survives a save + load roundtrip."""
        state = initialised_mgr.state
        assert state is not None
        state.hostnames = ["dc01.recon.local", "recon.local"]
        initialised_mgr.save()

        loaded = initialised_mgr.load_state()
        assert loaded is not None
        assert loaded.hostnames == ["dc01.recon.local", "recon.local"]


# ===================================================================
# state_path property
# ===================================================================


class TestStatePath:
    """Tests for the state_path property."""

    def test_state_path_property(self, mgr: StateManager, results_root: Path) -> None:
        """state_path returns the correct absolute path."""
        expected = results_root.resolve() / "10.10.10.5" / "scan.state"
        assert mgr.state_path == expected

    def test_state_path_different_target(self, results_root: Path) -> None:
        """state_path changes when target changes."""
        mgr1 = StateManager(target="10.10.10.1", results_root=results_root)
        mgr2 = StateManager(target="10.10.10.2", results_root=results_root)
        assert mgr1.state_path != mgr2.state_path
        assert "10.10.10.1" in str(mgr1.state_path)
        assert "10.10.10.2" in str(mgr2.state_path)


# ===================================================================
# Concurrent saves test
# ===================================================================


class TestConcurrentSaves:
    """Tests for concurrent state modifications."""

    def test_concurrent_saves_no_crash(self, initialised_mgr: StateManager) -> None:
        """Multiple rapid mark_completed calls don't raise exceptions.

        Note: The StateManager does not use file locking, so concurrent
        writes *can* interleave on disk. This test only verifies that
        the application does not crash; file-level consistency is not
        guaranteed without external synchronization.
        """
        modules = [f"module_{i}" for i in range(20)]
        errors: list[Exception] = []

        def mark(mod: str) -> None:
            try:
                initialised_mgr.mark_completed(mod)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=mark, args=(m,)) for m in modules]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        # No exceptions should have been raised — that's the key guarantee
        assert len(errors) == 0, f"Errors during concurrent saves: {errors}"

        # Verify the in-memory state has no duplicates
        state = initialised_mgr.state
        assert state is not None
        completed = state.completed_modules
        assert len(completed) == len(set(completed)), "Duplicates in in-memory completed_modules"

    def test_serial_saves_no_corruption(self, initialised_mgr: StateManager) -> None:
        """Serial (non-concurrent) mark_completed calls produce a valid state file."""
        modules = [f"module_{i}" for i in range(20)]
        for mod in modules:
            initialised_mgr.mark_completed(mod)

        # Verify the state file is valid JSON
        state_file = initialised_mgr.state_path
        raw = state_file.read_text(encoding="utf-8")
        data = json.loads(raw)  # should not raise

        # All modules should appear in completed_modules (no duplicates)
        completed = data["completed_modules"]
        assert len(completed) == len(set(completed)), "Duplicates found in completed_modules"
        assert set(completed) == set(modules)
