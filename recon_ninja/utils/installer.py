"""Auto-installer for ReconNinja v2 external tools.

Detects the host OS and package manager, then installs all (or a subset of)
required security tools using the appropriate method:

  - ``apt`` / ``dnf`` / ``pacman`` for system packages
  - ``go install`` for Go-based tools
  - ``pip install`` for Python-based tools
  - ``cargo install`` for Rust-based tools
  - ``gem install`` for Ruby-based tools
  - ``git clone`` for tools distributed via Git repos

The installer is designed to be **idempotent** — running it multiple times
will skip tools that are already installed.  It also degrades gracefully
when running without root privileges (warns instead of crashing).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console
from rich.panel import Panel


from recon_ninja.utils.checker import (
    ToolInfo,
    TOOL_REGISTRY,
    check_tool,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Install result tracking
# ---------------------------------------------------------------------------


@dataclass
class InstallResult:
    """Result of a single tool installation attempt."""

    tool_name: str
    status: str  # "installed" | "skipped" | "already_installed" | "failed"
    message: str = ""
    duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# OS / package manager detection
# ---------------------------------------------------------------------------


def detect_package_manager() -> str | None:
    """Detect the system package manager.

    Returns:
        ``"apt"``, ``"dnf"``, ``"pacman"``, or ``None``.
    """
    for mgr in ("apt", "dnf", "pacman"):
        if shutil.which(mgr):
            return mgr
    return None


def detect_go() -> bool:
    """Check if Go is available."""
    return shutil.which("go") is not None


def detect_cargo() -> bool:
    """Check if Cargo/Rust is available."""
    return shutil.which("cargo") is not None


def detect_pip() -> bool:
    """Check if pip is available."""
    return shutil.which("pip") is not None or shutil.which("pip3") is not None


def detect_gem() -> bool:
    """Check if gem (Ruby) is available."""
    return shutil.which("gem") is not None


def detect_git() -> bool:
    """Check if git is available."""
    return shutil.which("git") is not None


def is_root() -> bool:
    """Check if running as root (or with sudo)."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


# ---------------------------------------------------------------------------
# Subprocess helper
# ---------------------------------------------------------------------------


def _run_sync(cmd: list[str], timeout: int = 300) -> tuple[int, str, str]:
    """Run a synchronous subprocess and return (rc, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ},
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "TIMEOUT"
    except (FileNotFoundError, PermissionError, OSError) as exc:
        return -2, "", str(exc)


# ---------------------------------------------------------------------------
# Package manager wrappers
# ---------------------------------------------------------------------------


def _pkg_update(pkg_mgr: str) -> bool:
    """Update package lists."""
    console = Console()
    console.print(f"[dim]Updating package lists ({pkg_mgr})...[/]")

    if pkg_mgr == "apt":
        rc, _, _ = _run_sync(["sudo", "apt", "update", "-y"], timeout=120)
    elif pkg_mgr == "dnf":
        rc, _, _ = _run_sync(["sudo", "dnf", "check-update", "-y"], timeout=120)
    elif pkg_mgr == "pacman":
        rc, _, _ = _run_sync(["sudo", "pacman", "-Sy", "--noconfirm"], timeout=120)
    else:
        return False

    return rc in (0, 100)


def _pkg_install(pkg_mgr: str, package: str) -> tuple[bool, str]:
    """Install a single package using the system package manager.

    Returns:
        ``(success, message)`` tuple.
    """
    if pkg_mgr == "apt":
        rc, stdout, stderr = _run_sync(
            ["sudo", "apt", "install", "-y", package], timeout=600
        )
    elif pkg_mgr == "dnf":
        rc, stdout, stderr = _run_sync(
            ["sudo", "dnf", "install", "-y", package], timeout=600
        )
    elif pkg_mgr == "pacman":
        rc, stdout, stderr = _run_sync(
            ["sudo", "pacman", "-S", "--noconfirm", "--needed", package], timeout=600
        )
    else:
        return False, f"Unsupported package manager: {pkg_mgr}"

    if rc == 0:
        return True, f"Installed {package} via {pkg_mgr}"
    return False, f"Failed to install {package} via {pkg_mgr}: {stderr[:200]}"


# ---------------------------------------------------------------------------
# Individual install methods
# ---------------------------------------------------------------------------


def _install_apt_tool(pkg_mgr: str, tool: ToolInfo) -> InstallResult:
    """Install a tool via the system package manager."""
    pkg = tool.install_package
    if not pkg:
        return InstallResult(tool.name, "skipped", "No apt package specified")

    success, msg = _pkg_install(pkg_mgr, pkg)
    if success:
        return InstallResult(tool.name, "installed", msg)
    return InstallResult(tool.name, "failed", msg)


def _install_go_tool(tool: ToolInfo) -> InstallResult:
    """Install a Go tool via ``go install``."""
    if not detect_go():
        return InstallResult(tool.name, "skipped", "Go not installed — install Go first")

    module = tool.install_package
    if not module:
        return InstallResult(tool.name, "skipped", "No Go module specified")

    # Ensure ~/go/bin exists
    go_bin = Path.home() / "go" / "bin"
    go_bin.mkdir(parents=True, exist_ok=True)

    rc, stdout, stderr = _run_sync(
        ["go", "install", module],
        timeout=600,
    )

    if rc == 0:
        # Verify binary was installed
        binary_name = tool.name
        check_paths = [go_bin / binary_name]
        for alt in (tool.alt_names or []):
            check_paths.append(go_bin / alt)

        found = any(p.is_file() for p in check_paths)

        msg = f"Installed {tool.name} via go install"
        if not found:
            msg += " (binary not found in ~/go/bin — may need to add to PATH)"

        return InstallResult(tool.name, "installed" if found else "failed", msg)
    return InstallResult(
        tool.name, "failed",
        f"go install failed: {stderr[:300]}"
    )


def _install_pip_tool(tool: ToolInfo) -> InstallResult:
    """Install a Python tool via ``pip install``."""
    pip_cmd = "pip3" if shutil.which("pip3") else "pip"
    if not shutil.which(pip_cmd):
        return InstallResult(tool.name, "skipped", "pip not found")

    pkg = tool.install_package
    if not pkg:
        return InstallResult(tool.name, "skipped", "No pip package specified")

    # Try with --break-system-packages first (PEP 668)
    rc, stdout, stderr = _run_sync(
        [pip_cmd, "install", pkg, "--break-system-packages"],
        timeout=600,
    )

    if rc == 0:
        return InstallResult(tool.name, "installed", f"Installed {pkg} via pip")

    # Try without --break-system-packages (older pip / venv)
    rc2, stdout2, stderr2 = _run_sync(
        [pip_cmd, "install", pkg],
        timeout=600,
    )
    if rc2 == 0:
        return InstallResult(tool.name, "installed", f"Installed {pkg} via pip")

    return InstallResult(
        tool.name, "failed",
        f"pip install {pkg} failed: {stderr[:300]}"
    )


def _install_cargo_tool(tool: ToolInfo) -> InstallResult:
    """Install a Rust tool via ``cargo install``."""
    if not detect_cargo():
        return InstallResult(tool.name, "skipped", "Cargo/Rust not installed")

    crate = tool.install_package
    if not crate:
        return InstallResult(tool.name, "skipped", "No crate specified")

    rc, stdout, stderr = _run_sync(
        ["cargo", "install", crate],
        timeout=1200,
    )

    if rc == 0:
        return InstallResult(tool.name, "installed", f"Installed {crate} via cargo")
    return InstallResult(
        tool.name, "failed",
        f"cargo install {crate} failed: {stderr[:300]}"
    )


def _install_gem_tool(tool: ToolInfo) -> InstallResult:
    """Install a Ruby gem."""
    if not detect_gem():
        return InstallResult(tool.name, "skipped", "Ruby/gem not found")

    gem_name = tool.install_package
    if not gem_name:
        return InstallResult(tool.name, "skipped", "No gem name specified")

    rc, stdout, stderr = _run_sync(
        ["gem", "install", gem_name],
        timeout=600,
    )

    if rc == 0:
        return InstallResult(tool.name, "installed", f"Installed {gem_name} via gem")
    return InstallResult(
        tool.name, "failed",
        f"gem install {gem_name} failed: {stderr[:300]}"
    )


def _install_git_tool(tool: ToolInfo) -> InstallResult:
    """Clone a tool from Git into /opt/recon-tools/."""
    if not detect_git():
        return InstallResult(tool.name, "skipped", "git not found")

    url = tool.install_package
    if not url:
        return InstallResult(tool.name, "skipped", "No Git URL specified")

    repo_name = url.rstrip("/").split("/")[-1].replace(".git", "")
    target_dir = Path("/opt/recon-tools") / repo_name

    if target_dir.exists():
        return InstallResult(tool.name, "already_installed", f"Already cloned to {target_dir}")

    target_dir.parent.mkdir(parents=True, exist_ok=True)

    rc, stdout, stderr = _run_sync(
        ["sudo", "git", "clone", "--depth", "1", url, str(target_dir)],
        timeout=300,
    )

    if rc == 0:
        # Make scripts executable
        for script in target_dir.glob("*.sh"):
            try:
                script.chmod(0o755)
            except OSError:
                pass
        for script in target_dir.glob("*.pl"):
            try:
                script.chmod(0o755)
            except OSError:
                pass

        return InstallResult(tool.name, "installed", f"Cloned to {target_dir}")
    return InstallResult(
        tool.name, "failed",
        f"git clone failed: {stderr[:300]}"
    )


# ---------------------------------------------------------------------------
# SecLists installer
# ---------------------------------------------------------------------------


def _install_seclists() -> InstallResult:
    """Ensure SecLists wordlists are available."""
    seclists_dir = Path("/usr/share/seclists")

    if seclists_dir.is_dir():
        return InstallResult("seclists", "already_installed", f"Found at {seclists_dir}")

    pkg_mgr = detect_package_manager()
    if pkg_mgr == "apt":
        success, msg = _pkg_install(pkg_mgr, "seclists")
        if success:
            return InstallResult("seclists", "installed", msg)

    if detect_git():
        rc, stdout, stderr = _run_sync(
            ["sudo", "git", "clone", "--depth", "1",
             "https://github.com/danielmiessler/SecLists.git",
             str(seclists_dir)],
            timeout=600,
        )
        if rc == 0:
            return InstallResult("seclists", "installed", f"Cloned to {seclists_dir}")

    return InstallResult("seclists", "failed", "Could not install SecLists")


# ---------------------------------------------------------------------------
# Go / Rust installation helpers
# ---------------------------------------------------------------------------


def _install_go_if_needed() -> InstallResult:
    """Install Go if not already present."""
    if detect_go():
        return InstallResult("go", "already_installed", f"Go found: {shutil.which('go')}")

    console = Console()
    console.print("[dim]Go not found — attempting to install...[/]")

    pkg_mgr = detect_package_manager()
    if pkg_mgr:
        success, msg = _pkg_install(pkg_mgr, "golang")
        if success:
            return InstallResult("go", "installed", msg)

    # Fallback: download Go binary
    go_version = "1.22.0"
    tarball = f"go{go_version}.linux-amd64.tar.gz"
    url = f"https://go.dev/dl/{tarball}"

    rc, stdout, stderr = _run_sync(
        ["sudo", "wget", "-q", url, "-O", f"/tmp/{tarball}"],
        timeout=300,
    )
    if rc != 0:
        return InstallResult("go", "failed", f"Failed to download Go: {stderr[:200]}")

    rc, stdout, stderr = _run_sync(
        ["sudo", "tar", "-C", "/usr/local", "-xzf", f"/tmp/{tarball}"],
        timeout=120,
    )

    _run_sync(["rm", "-f", f"/tmp/{tarball}"])

    if rc == 0:
        go_bin = "/usr/local/go/bin"
        current_path = os.environ.get("PATH", "")
        if go_bin not in current_path:
            os.environ["PATH"] = f"{go_bin}:{current_path}"

        return InstallResult(
            "go", "installed",
            f"Go {go_version} installed to /usr/local/go — "
            f"add 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' to your shell config"
        )

    return InstallResult("go", "failed", f"Go installation failed: {stderr[:200]}")


def _install_rust_if_needed() -> InstallResult:
    """Install Rust/Cargo if not already present."""
    if detect_cargo():
        return InstallResult("rust", "already_installed", f"Cargo found: {shutil.which('cargo')}")

    console = Console()
    console.print("[dim]Rust/Cargo not found — attempting to install via rustup...[/]")

    rc, stdout, stderr = _run_sync(
        ["sh", "-c", "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"],
        timeout=300,
    )

    if rc == 0:
        cargo_env = Path.home() / ".cargo" / "env"
        if cargo_env.is_file():
            try:
                with open(cargo_env) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("export ") and "=" in line:
                            key, _, val = line[len("export "):].partition("=")
                            val = val.strip('"').strip("'")
                            os.environ[key] = val
            except OSError:
                pass

        return InstallResult(
            "rust", "installed",
            "Rust/Cargo installed — run 'source ~/.cargo/env' or restart your shell"
        )

    return InstallResult("rust", "failed", f"rustup install failed: {stderr[:200]}")


# ---------------------------------------------------------------------------
# Main installer class
# ---------------------------------------------------------------------------


class ToolInstaller:
    """High-level tool installer with Rich progress display.

    Usage::

        installer = ToolInstaller()
        results = installer.install_all()
        installer.print_summary(results)
    """

    def __init__(self, *, verbose: bool = False) -> None:
        self.console = Console()
        self.verbose = verbose
        self.pkg_mgr = detect_package_manager()
        self._results: list[InstallResult] = []

    def _print_header(self, title: str) -> None:
        """Print a styled section header."""
        self.console.print()
        self.console.rule(f"[bold bright_cyan]{title}", style="bright_cyan")
        self.console.print()

    def _install_single_tool(self, tool: ToolInfo) -> InstallResult:
        """Route a single tool to the appropriate install method."""
        t0 = time.monotonic()

        # Check if already installed
        check_tool(tool)
        if tool.found:
            result = InstallResult(
                tool.name, "already_installed",
                f"Already installed: {tool.path} ({tool.version or 'version unknown'})"
            )
            result.duration_seconds = time.monotonic() - t0
            return result

        # Route to install method
        method = tool.install_method
        if method == "apt":
            if not self.pkg_mgr:
                result = InstallResult(tool.name, "skipped", "No system package manager detected")
            else:
                result = _install_apt_tool(self.pkg_mgr, tool)
        elif method == "go":
            result = _install_go_tool(tool)
        elif method == "pip":
            result = _install_pip_tool(tool)
        elif method == "cargo":
            result = _install_cargo_tool(tool)
        elif method == "gem":
            result = _install_gem_tool(tool)
        elif method == "git":
            result = _install_git_tool(tool)
        elif method == "manual":
            result = InstallResult(tool.name, "skipped", "Manual installation required")
        else:
            result = InstallResult(tool.name, "skipped", f"Unknown install method: {method}")

        result.duration_seconds = time.monotonic() - t0
        return result

    def _install_prerequisites(self) -> list[InstallResult]:
        """Install prerequisites like Go, Rust, etc."""
        results: list[InstallResult] = []

        self._print_header("Installing Prerequisites")

        # Go — needed for go tools
        go_result = _install_go_if_needed()
        results.append(go_result)
        self._print_install_result(go_result)

        # Rust/Cargo — needed for cargo tools
        cargo_result = _install_rust_if_needed()
        results.append(cargo_result)
        self._print_install_result(cargo_result)

        return results

    def _print_install_result(self, result: InstallResult) -> None:
        """Print a single install result with color coding."""
        if result.status == "installed":
            self.console.print(f"  [green]✔[/] [bold]{result.tool_name}[/] — {result.message}")
        elif result.status == "already_installed":
            self.console.print(f"  [dim]✔[/] [dim]{result.tool_name}[/] — {result.message}")
        elif result.status == "skipped":
            self.console.print(f"  [yellow]⊘[/] [dim]{result.tool_name}[/] — [yellow]{result.message}[/]")
        elif result.status == "failed":
            self.console.print(f"  [red]✘[/] [bold]{result.tool_name}[/] — [red]{result.message}[/]")

    def install_all(self, *, include_optional: bool = True) -> list[InstallResult]:
        """Install all tools (required + optional).

        Parameters
        ----------
        include_optional:
            If ``True`` (default), install optional tools too.
            If ``False``, only install required tools.
        """
        self._results = []

        # ── Banner ──────────────────────────────────────────────────────
        self.console.print()
        self.console.print(Panel(
            "[bold]🥷 ReconNinja v2 — Tool Installer[/]\n\n"
            f"  Package manager: [cyan]{self.pkg_mgr or 'not detected'}[/]\n"
            f"  Running as root: [cyan]{'yes' if is_root() else 'no'}[/]\n"
            f"  Include optional: [cyan]{'yes' if include_optional else 'no'}[/]",
            border_style="cyan",
        ))

        if not is_root():
            self.console.print(
                "[yellow]⚠ Not running as root — some installs may fail. "
                "Consider running with sudo.[/]"
            )

        # ── Prerequisites ───────────────────────────────────────────────
        prereq_results = self._install_prerequisites()
        self._results.extend(prereq_results)

        # ── System packages ─────────────────────────────────────────────
        if self.pkg_mgr:
            self._print_header("Updating Package Lists")
            _pkg_update(self.pkg_mgr)

        # ── Required tools ──────────────────────────────────────────────
        required_tools = [t for t in TOOL_REGISTRY if t.category == "required"]
        self._print_header(f"Installing Required Tools ({len(required_tools)})")
        for tool in required_tools:
            result = self._install_single_tool(tool)
            self._results.append(result)
            self._print_install_result(result)

        # ── Optional tools ──────────────────────────────────────────────
        if include_optional:
            optional_tools = [t for t in TOOL_REGISTRY if t.category == "optional"]
            self._print_header(f"Installing Optional Tools ({len(optional_tools)})")
            for tool in optional_tools:
                result = self._install_single_tool(tool)
                self._results.append(result)
                self._print_install_result(result)

        # ── SecLists ────────────────────────────────────────────────────
        self._print_header("Installing SecLists Wordlists")
        seclists_result = _install_seclists()
        self._results.append(seclists_result)
        self._print_install_result(seclists_result)

        # ── PATH configuration ──────────────────────────────────────────
        self._configure_path()

        return self._results

    def install_required_only(self) -> list[InstallResult]:
        """Install only required tools."""
        return self.install_all(include_optional=False)

    def _configure_path(self) -> None:
        """Ensure ~/go/bin and ~/.local/bin are in PATH and shell config."""
        self._print_header("Configuring PATH")

        go_bin = str(Path.home() / "go" / "bin")
        local_bin = str(Path.home() / ".local" / "bin")
        path_additions = [go_bin, local_bin]

        for rc_file in [Path.home() / ".bashrc", Path.home() / ".zshrc"]:
            if not rc_file.is_file():
                continue

            try:
                content = rc_file.read_text(encoding="utf-8")
            except OSError:
                continue

            modified = False
            for add_dir in path_additions:
                if add_dir not in content:
                    with open(rc_file, "a", encoding="utf-8") as f:
                        f.write(f'\n# Added by ReconNinja installer\nexport PATH="{add_dir}:$PATH"\n')
                    modified = True

            if modified:
                self.console.print(f"  [green]✔[/] Updated {rc_file}")
            else:
                self.console.print(f"  [dim]✔[/] {rc_file} already configured")

        # Also add cargo env
        cargo_env = Path.home() / ".cargo" / "env"
        if cargo_env.is_file():
            for rc_file in [Path.home() / ".bashrc", Path.home() / ".zshrc"]:
                if not rc_file.is_file():
                    continue
                try:
                    content = rc_file.read_text(encoding="utf-8")
                except OSError:
                    continue
                if ".cargo/env" not in content:
                    with open(rc_file, "a", encoding="utf-8") as f:
                        f.write('\n# Added by ReconNinja installer\nsource "$HOME/.cargo/env"\n')
                    self.console.print(f"  [green]✔[/] Added cargo env to {rc_file}")

    def print_summary(self, results: list[InstallResult] | None = None) -> None:
        """Print the final installation summary."""
        results = results or self._results

        installed = [r for r in results if r.status == "installed"]
        already = [r for r in results if r.status == "already_installed"]
        skipped = [r for r in results if r.status == "skipped"]
        failed = [r for r in results if r.status == "failed"]

        self.console.print()
        summary_lines = [
            f"  [green bold]Installed:[/]    [green]{len(installed)}[/] new tools",
            f"  [dim]Pre-existing:[/]  [dim]{len(already)}[/] already installed",
            f"  [yellow]Skipped:[/]      [yellow]{len(skipped)}[/] tools",
            f"  [red]Failed:[/]       [red]{len(failed)}[/] tools",
        ]

        if failed:
            summary_lines.append("")
            summary_lines.append("  [bold red]Failed tools:[/]")
            for r in failed:
                summary_lines.append(f"    [red]✘[/] {r.tool_name}: {r.message[:100]}")

        self.console.print(Panel(
            "\n".join(summary_lines),
            title="[bold]📊 Installation Summary[/]",
            border_style="green" if not failed else "yellow",
        ))

        if not failed:
            self.console.print()
            self.console.print(
                "[bold green]✔ All tools installed successfully![/]"
            )
            self.console.print(
                "[dim]Run 'source ~/.bashrc' (or ~/.zshrc) to update your PATH, "
                "then: reconninja check-tools[/]"
            )


__all__: list[str] = [
    "ToolInstaller",
    "InstallResult",
    "detect_package_manager",
    "is_root",
]
