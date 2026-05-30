"""State / checkpoint manager for ReconNinja v2.

Serialises the :class:`~recon_ninja.core.models.ScanState` to disk after
every completed phase so that a scan can be resumed with ``--resume``.

State file location::

    results/<target>/scan.state

The state file is plain JSON so it is human-readable and diff-friendly.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from recon_ninja.core.models import ScanState

logger = logging.getLogger(__name__)

# Default top-level results directory (relative to CWD)
_DEFAULT_RESULTS_ROOT = Path("results")

# Name of the state file inside a target directory
_STATE_FILENAME = "scan.state"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _target_dir(target: str, results_root: Path | None = None) -> Path:
    """Return the per-target output directory.

    Parameters
    ----------
    target:
        The target hostname or IP address.
    results_root:
        Top-level results directory.  Defaults to ``results/`` under CWD.

    Returns
    -------
    Path
        Absolute path to ``results/<target>/``.
    """
    root = (results_root or _DEFAULT_RESULTS_ROOT).resolve()
    return root / target


def _state_path(target: str, results_root: Path | None = None) -> Path:
    """Return the path to the ``scan.state`` file for *target*.

    Parameters
    ----------
    target:
        The target hostname or IP address.
    results_root:
        Top-level results directory.  Defaults to ``results/`` under CWD.

    Returns
    -------
    Path
        Absolute path to ``results/<target>/scan.state``.
    """
    return _target_dir(target, results_root) / _STATE_FILENAME


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class StateManager:
    """Manages checkpointing and resumption of a reconnaissance scan.

    Typical lifecycle::

        mgr = StateManager(target="10.10.11.42")

        # Fresh scan — creates the initial state file.
        state = mgr.init_state()

        # After each module finishes:
        mgr.mark_completed("portscan")
        mgr.mark_completed("web_enum")

        # Later, to resume:
        state = mgr.load_state()
        if mgr.is_completed("portscan"):
            ...  # skip

    The :class:`ScanState` object is always written to disk after every
    call to :meth:`mark_completed`, guaranteeing crash-safe resumption.
    """

    def __init__(
        self,
        target: str,
        results_root: Path | None = None,
    ) -> None:
        """Initialise the state manager for a given *target*.

        Parameters
        ----------
        target:
            Target hostname or IP address.
        results_root:
            Top-level results directory.  Defaults to ``results/`` under
            the current working directory.
        """
        self.target: str = target
        self.results_root: Path = results_root or _DEFAULT_RESULTS_ROOT
        self._state_path: Path = _state_path(target, self.results_root)
        self._target_dir: Path = _target_dir(target, self.results_root)
        # In-memory cache — avoids repeated disk reads during a live scan.
        self._state: ScanState | None = None

    # ------------------------------------------------------------------
    # State initialisation
    # ------------------------------------------------------------------

    def init_state(self) -> ScanState:
        """Create a fresh :class:`ScanState` and persist it to disk.

        This should be called at the beginning of a **new** scan (not a
        resume).  If a state file already exists it will be **overwritten**.

        Returns
        -------
        ScanState
            The newly-created state object.
        """
        from datetime import datetime

        state = ScanState(
            target=self.target,
            start_time=datetime.now(),
            output_dir=self._target_dir,
        )
        self._state = state
        self._save(state)
        logger.info(
            "Initialised scan state for %s at %s",
            self.target,
            self._state_path,
        )
        return state

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _save(self, state: ScanState) -> None:
        """Serialise *state* to the ``scan.state`` file.

        Creates the target directory if it does not already exist.
        Errors are logged but **not** raised — losing a checkpoint should
        not crash the scan.
        """
        try:
            self._target_dir.mkdir(parents=True, exist_ok=True)
            payload: dict[str, Any] = state.to_dict()
            self._state_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except (OSError, TypeError) as exc:
            logger.error(
                "Failed to save scan state to %s: %s",
                self._state_path,
                exc,
            )

    def save(self) -> None:
        """Persist the current in-memory state to disk.

        Convenience wrapper that calls :meth:`_save` with the cached state.
        No-op if no state has been loaded or initialised yet.
        """
        if self._state is not None:
            self._save(self._state)
        else:
            logger.warning("save() called but no state is loaded — skipping.")

    # ------------------------------------------------------------------
    # Loading / resume
    # ------------------------------------------------------------------

    def load_state(self) -> ScanState | None:
        """Load the scan state from disk for ``--resume`` support.

        Returns
        -------
        ScanState | None
            The deserialised state, or ``None`` if the file is missing
            or corrupted.
        """
        if not self._state_path.is_file():
            logger.info("No scan.state found at %s — cannot resume.", self._state_path)
            return None

        try:
            raw: str = self._state_path.read_text(encoding="utf-8")
            data: dict[str, Any] = json.loads(raw)
            state: ScanState = ScanState.from_dict(data)
            self._state = state
            logger.info(
                "Resumed scan state for %s (phase %d, %d modules done).",
                self.target,
                state.current_phase,
                len(state.completed_modules),
            )
            return state
        except json.JSONDecodeError as exc:
            logger.error(
                "Corrupted state file %s (invalid JSON): %s",
                self._state_path,
                exc,
            )
            return None
        except (KeyError, TypeError, ValueError) as exc:
            logger.error(
                "Corrupted state file %s (schema mismatch): %s",
                self._state_path,
                exc,
            )
            return None
        except OSError as exc:
            logger.error("Could not read state file %s: %s", self._state_path, exc)
            return None

    # ------------------------------------------------------------------
    # Module completion tracking
    # ------------------------------------------------------------------

    def mark_completed(self, module_name: str) -> None:
        """Mark a module as completed and persist the updated state.

        The module name is appended to
        :attr:`ScanState.completed_modules` and the full state is
        written to disk immediately.

        Parameters
        ----------
        module_name:
            Identifier of the module that just finished (e.g.
            ``"portscan"``, ``"smb_enum"``).
        """
        if self._state is None:
            logger.warning(
                "mark_completed('%s') called but no state loaded — loading from disk.",
                module_name,
            )
            self._state = self.load_state()
            if self._state is None:
                logger.error("Cannot mark module — no state available.")
                return

        if module_name not in self._state.completed_modules:
            self._state.completed_modules.append(module_name)
            logger.debug("Module '%s' marked as completed.", module_name)
        else:
            logger.debug("Module '%s' already in completed_modules — skipping add.", module_name)

        self._save(self._state)

    def is_completed(self, module_name: str) -> bool:
        """Check whether a module was already completed in a prior run.

        This is the primary decision point for ``--resume``: modules
        that return ``True`` should be skipped.

        Parameters
        ----------
        module_name:
            Identifier of the module to check.

        Returns
        -------
        bool
            ``True`` if the module appears in
            :attr:`ScanState.completed_modules`.
        """
        if self._state is None:
            self._state = self.load_state()
        if self._state is None:
            return False
        return module_name in self._state.completed_modules

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    @property
    def state(self) -> ScanState | None:
        """Return the in-memory :class:`ScanState`, loading from disk if needed."""
        if self._state is None:
            self._state = self.load_state()
        return self._state

    @property
    def state_path(self) -> Path:
        """Absolute path to the ``scan.state`` file."""
        return self._state_path

    def completed_modules(self) -> list[str]:
        """Return a copy of the completed-modules list.

        Returns
        -------
        list[str]
            Module names that have been marked as completed.
        """
        if self._state is None:
            self._state = self.load_state()
        if self._state is None:
            return []
        return list(self._state.completed_modules)

    def remaining_modules(self, all_modules: list[str]) -> list[str]:
        """Return the subset of *all_modules* that have not yet completed.

        Parameters
        ----------
        all_modules:
            The full ordered list of modules in the scan pipeline.

        Returns
        -------
        list[str]
            Modules from *all_modules* not present in
            :attr:`ScanState.completed_modules`.
        """
        done: set[str] = set(self.completed_modules())
        return [m for m in all_modules if m not in done]
