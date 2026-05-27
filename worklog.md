---
Task ID: 1
Agent: main
Task: Add auto-installer and enhanced tool detection to ReconNinja v2

Work Log:
- Reviewed existing checker.py (shutil.which only, no version/path detection)
- Reviewed existing main.py (single Typer command, no subcommands)
- Reviewed engine.py (truncated _parse_nmap_grep_ports - confirmed it's complete)
- Enhanced checker.py with ToolInfo dataclass, version detection, alternative names, extra search paths
- Created utils/installer.py with ToolInstaller class supporting apt/go/pip/cargo/gem/git install methods
- Updated main.py to use custom ReconNinjaGroup (auto-routes bare args to scan command)
- Added three CLI commands: scan, check-tools, install
- Added --version/-V flag on main app callback
- Added click>=8.0 to pyproject.toml dependencies
- Updated install.sh header to reference built-in Python installer
- Updated utils/__init__.py with proper exports
- All 310 tests pass
- All 21 module imports verified
- CLI commands tested: reconninja --version, reconninja check-tools, reconninja install --required, reconninja scan --help

Stage Summary:
- Enhanced tool detection: 30 tools tracked with version, path, install method, alt names
- Tool registry now includes install_method (apt/go/pip/cargo/gem/git) for each tool
- Version detection works (runs --version and parses output)
- Alternative binary names (e.g. enum4linux vs enum4linux-ng)
- Extra search paths (~/go/bin, ~/.local/bin, /usr/local/bin, /opt)
- New CLI: `reconninja check-tools` shows detailed table with versions and paths
- New CLI: `reconninja install [--required|--optional]` auto-installs all tools
- New CLI: `reconninja <target>` still works (auto-routes to scan command)
- Installer handles: apt, dnf, pacman, go install, pip install, cargo install, gem install, git clone
- Installer includes: Go/Rust prerequisite installation, SecLists installation, PATH configuration
