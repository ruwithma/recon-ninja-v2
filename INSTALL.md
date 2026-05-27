# Installation Guide — Recon Ninja v2

Complete guide to installing Recon Ninja v2 and its 30 external security tools.
Covers four installation methods, the built-in installer, tool inventory, and troubleshooting.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation Methods](#2-installation-methods)
   - [Quick Install (pip)](#21-quick-install--pip)
   - [Shell Script](#22-shell-script)
   - [Built-in Installer](#23-built-in-installer)
   - [Manual Installation](#24-manual-installation)
3. [External Tools Reference](#3-external-tools-reference)
   - [Required Tools (8)](#31-required-tools-8)
   - [Optional Tools (22)](#32-optional-tools-22)
   - [Tool Install Methods Summary](#33-tool-install-methods-summary)
4. [Checking Tool Status](#4-checking-tool-status)
5. [Supported Operating Systems](#5-supported-operating-systems)
6. [PATH Configuration](#6-path-configuration)
7. [SecLists Wordlists](#7-seclists-wordlists)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. Prerequisites

| Requirement | Minimum Version | Notes |
|---|---|---|
| **Python** | 3.10+ | Required to run Recon Ninja itself |
| **pip** | Latest | Python package installer |
| **git** | Any | For cloning Git-based tools |
| **sudo / root** | — | Needed for system package installs and `/opt` writes |

Optional runtimes (auto-installed by the built-in installer if missing):

- **Go** — needed for `ffuf`, `nuclei`, `subfinder`, `httpx`, `kerbrute`, `gowitness`, `amass`, `windapsearch`
- **Rust/Cargo** — needed for `rustscan`
- **Ruby/gem** — needed for `wpscan`

---

## 2. Installation Methods

### 2.1 Quick Install — pip

The fastest way to get Recon Ninja itself installed and the `recon-ninja` command on your PATH:

```bash
# Clone the repository
git clone https://github.com/your-org/recon-ninja.git
cd recon-ninja

# Install in editable mode (recommended for development)
pip install -e .

# Or install without editable mode
pip install .
```

This installs the Python package and its dependencies (`rich`, `typer`, `click`, `requests`, `pyyaml`, `jinja2`, `aiofiles`), and creates the `recon-ninja` CLI entry point.

> **Note:** This only installs the Python package — it does **not** install the 30 external security tools. After this step, run `recon-ninja install` to get the tools, or use one of the other methods below.

Verify the installation:

```bash
recon-ninja --version
# recon-ninja v2.0.0
```

On systems with PEP 668 enforcement (Ubuntu 23.04+, Debian 12+), use `--break-system-packages` or a virtual environment:

```bash
# Option A: --break-system-packages
pip install -e . --break-system-packages

# Option B: Virtual environment (preferred)
python3 -m venv ~/recon-env
source ~/recon-env/bin/activate
pip install -e .
```

---

### 2.2 Shell Script

The `install.sh` script is a self-contained Bash installer that handles everything in one shot: Python package, system packages, Go tools, Rust/Cargo, Python pip tools, Ruby gems, Git clones, SecLists, and PATH configuration.

```bash
chmod +x install.sh
sudo ./install.sh
```

**What it does (in order):**

1. **Detects your package manager** — `apt`, `dnf`, or `pacman`
2. **Updates package lists** — `apt update`, `dnf check-update`, or `pacman -Sy`
3. **Installs system packages** — nmap, smbclient, nikto, whatweb, sslscan, dnsrecon, ldap-utils, gobuster, feroxbuster, onesixtyone, snmp, seclists, plus optional crackmapexec and ssh-audit
4. **Installs Rust via rustup** — then installs `rustscan` via `cargo install`
5. **Installs Go** — via package manager, snap, or binary download (v1.22.0 fallback)
6. **Installs Go-based tools** — ffuf, nuclei, subfinder, httpx, kerbrute, gowitness, amass, windapsearch-go
7. **Installs Python tools** — theHarvester, crackmapexec, ssh-audit, enum4linux-ng, smbmap, droopescan
8. **Installs Recon Ninja** — `pip install -e .`
9. **Installs WPScan** — via `gem install wpscan`
10. **Installs SecLists** — via package manager or `git clone` to `/usr/share/seclists`
11. **Clones Git-based tools** — testssl.sh and joomscan to `/opt/recon-tools/`
12. **Configures PATH** — adds `~/go/bin`, `~/.cargo/env` to `~/.bashrc` and `~/.zshrc`

The script is **idempotent** — already-installed tools are detected and skipped. It prints a full summary at the end showing what succeeded, what was optional/missing, and what failed.

---

### 2.3 Built-in Installer

Recon Ninja includes a Python-based installer accessible via the CLI. This is the recommended method after the initial `pip install -e .`.

```bash
# Install ALL tools (required + optional)
sudo recon-ninja install

# Install only the 8 required tools
sudo recon-ninja install --required
```

**Supported install methods (6):**

| Method | Command Used | Tools |
|---|---|---|
| **apt/dnf/pacman** | System package manager | nmap, smbclient, nikto, whatweb, sslscan, dnsrecon, searchsploit, ldapsearch, feroxbuster, gobuster, onesixtyone, snmpwalk |
| **go install** | `go install <module>@latest` | ffuf, nuclei, subfinder, httpx, kerbrute, gowitness, amass, windapsearch |
| **pip install** | `pip install <package>` | theHarvester, crackmapexec, ssh-audit, enum4linux-ng, smbmap, droopescan |
| **cargo install** | `cargo install <crate>` | rustscan |
| **gem install** | `gem install <gem>` | wpscan |
| **git clone** | `git clone --depth 1 <url> /opt/recon-tools/` | testssl.sh, joomscan |

**Auto-detection and prerequisite handling:**

- **Package manager detection** — Automatically detects `apt`, `dnf`, or `pacman` and uses the correct commands
- **Go installation** — If Go is not found, installs it via the system package manager (`golang` package) or downloads the binary (v1.22.0) to `/usr/local/go`
- **Rust/Cargo installation** — If Cargo is not found, installs Rust via `rustup` (`curl | sh -s -- -y`) and sources `~/.cargo/env`
- **SecLists installation** — Checks for `/usr/share/seclists`; installs via `apt install seclists` or falls back to `git clone` from GitHub
- **PATH configuration** — Automatically appends `~/go/bin`, `~/.local/bin`, and `source ~/.cargo/env` to `~/.bashrc` and `~/.zshrc` if not already present

**Idempotent behavior:**

The installer checks each tool before attempting installation. If a tool is already present on the system (detected via `shutil.which()` plus extra search paths like `~/go/bin`, `~/.local/bin`, `/usr/local/bin`, `/opt/recon-tools/`), it is marked as `already_installed` and skipped.

**Root privileges:**

Running with `sudo` is strongly recommended. Without root:
- System package installs (`apt install`, `dnf install`, `pacman -S`) will fail
- Git clones to `/opt/recon-tools/` will fail
- Go/pip/cargo/gem installs to user directories will still work

If you run without `sudo`, the installer warns you and continues with what it can.

---

### 2.4 Manual Installation

If you prefer full control, install each component manually.

#### Step 1: Install Recon Ninja

```bash
pip install -e .
```

#### Step 2: Install system packages

**Debian/Ubuntu/Kali (apt):**
```bash
sudo apt update
sudo apt install -y nmap samba-client nikto whatweb sslscan dnsrecon exploitdb ldap-utils feroxbuster gobuster onesixtyone snmp
```

**Fedora/RHEL (dnf):**
```bash
sudo dnf install -y nmap samba-client nikto whatweb sslscan dnsrecon exploitdb openldap-clients feroxbuster gobuster onesixtyone net-snmp-utils
```

**Arch Linux (pacman):**
```bash
sudo pacman -Sy --noconfirm --needed nmap smbclient nikto whatweb sslscan dnsrecon exploitdb ldap-utils feroxbuster gobuster onesixtyone net-snmp
```

#### Step 3: Install Go + Go tools

```bash
# Install Go (if not already installed)
sudo apt install -y golang   # or: sudo dnf install golang / sudo pacman -S go

# Ensure ~/go/bin exists and is on PATH
mkdir -p ~/go/bin
export PATH="$PATH:/usr/local/go/bin:$HOME/go/bin"

# Install each Go tool
go install github.com/ffuf/ffuf/v2@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/ropnop/kerbrute@latest
go install github.com/sensepost/gowitness@latest
go install github.com/owasp-amass/amass/v4/overrides/cmd/amass@latest
go install github.com/ropnop/windapsearch-go@latest
```

#### Step 4: Install Rust + RustScan

```bash
# Install Rust via rustup (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Install RustScan
cargo install rustscan
```

#### Step 5: Install Python tools

```bash
pip install theHarvester crackmapexec ssh-audit enum4linux-ng smbmap droopescan
```

On PEP 668 systems:
```bash
pip install --break-system-packages theHarvester crackmapexec ssh-audit enum4linux-ng smbmap droopescan
```

#### Step 6: Install WPScan (Ruby)

```bash
gem install wpscan
```

> Requires Ruby development headers. On Debian/Ubuntu: `sudo apt install -y ruby-dev`

#### Step 7: Clone Git-based tools

```bash
sudo mkdir -p /opt/recon-tools

# testssl.sh
sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/recon-tools/testssl.sh
sudo chmod +x /opt/recon-tools/testssl.sh/testssl.sh

# joomscan
sudo git clone --depth 1 https://github.com/OWASP/joomscan.git /opt/recon-tools/joomscan
sudo chmod +x /opt/recon-tools/joomscan/joomscan.pl
```

#### Step 8: Install SecLists

```bash
# Option A: Via apt (Kali/Debian)
sudo apt install -y seclists

# Option B: Via git clone
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

#### Step 9: Configure PATH

Add the following to `~/.bashrc` or `~/.zshrc`:

```bash
# Go tools
export PATH="$HOME/go/bin:$PATH"

# User-local Python tools
export PATH="$HOME/.local/bin:$PATH"

# Rust/Cargo
source "$HOME/.cargo/env" 2>/dev/null || true
```

Then reload your shell:

```bash
source ~/.bashrc   # or: source ~/.zshrc
```

---

## 3. External Tools Reference

Recon Ninja integrates **30 external security tools**. Each is detected at runtime — missing required tools produce a warning; missing optional tools cause the corresponding module to be gracefully skipped.

### 3.1 Required Tools (8)

These tools are essential for Recon Ninja's core functionality. If any are missing, you will be warned before a scan starts.

| Tool | Package Name | Install Method | Version Flag | Description |
|---|---|---|---|---|
| **nmap** | `nmap` | apt | `--version` | Network port scanner and service enumerator |
| **smbclient** | `samba-client` | apt | `--version` | SMB/CIFS client for share enumeration |
| **nikto** | `nikto` | apt | `-Version` | Web server vulnerability scanner |
| **whatweb** | `whatweb` | apt | `--version` | Web technology fingerprinter |
| **sslscan** | `sslscan` | apt | `--version` | SSL/TLS cipher and certificate scanner |
| **dnsrecon** | `dnsrecon` | apt | `--version` | DNS enumeration and reconnaissance tool |
| **searchsploit** | `exploitdb` | apt | `-V` | Offline exploit database search tool |
| **ldapsearch** | `ldap-utils` | apt | `-VV` | LDAP directory query client |

> **Package name note:** The `smbclient` binary is provided by the `samba-client` package on some distributions. The `searchsploit` binary is provided by the `exploitdb` package. The installer handles these mappings automatically.

### 3.2 Optional Tools (22)

Optional tools extend Recon Ninja's capabilities. If missing, the corresponding module is skipped with a notice.

#### Go-based Tools (8)

| Tool | Go Module | Version Flag | Description |
|---|---|---|---|
| **ffuf** | `github.com/ffuf/ffuf/v2@latest` | `-V` | Fast web fuzzer |
| **nuclei** | `github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | `--version` | Vulnerability scanner using templates |
| **subfinder** | `github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | `--version` | Passive subdomain discovery tool |
| **httpx** | `github.com/projectdiscovery/httpx/cmd/httpx@latest` | `--version` | Fast HTTP prober and toolkit |
| **kerbrute** | `github.com/ropnop/kerbrute@latest` | `--version` | Kerberos pre-auth brute forcer |
| **gowitness** | `github.com/sensepost/gowitness@latest` | `--version` | Web screenshot tool using Chrome headless |
| **amass** | `github.com/owasp-amass/amass/v4/overrides/cmd/amass@latest` | `--version` | In-depth attack surface and asset mapping |
| **windapsearch** | `github.com/ropnop/windapsearch-go@latest` | `--version` | Active Directory LDAP enumeration tool |

> Go binaries install to `~/go/bin/`. Ensure this directory is on your PATH.

#### Python-based Tools (6)

| Tool | pip Package | Version Flag | Description |
|---|---|---|---|
| **theHarvester** | `theHarvester` | `--version` | OSINT email, domain, and IP harvester |
| **crackmapexec** | `crackmapexec` | `--version` | Network swiss-army knife for AD pentesting |
| **ssh-audit** | `ssh-audit` | `--version` | SSH server configuration and policy auditor |
| **enum4linux-ng** | `enum4linux-ng` | `--version` | SMB/NetBIOS enumeration tool (next-gen) |
| **smbmap** | `smbmap` | `--version` | SMB share permission enumeration tool |
| **droopescan** | `droopescan` | `--version` | CMS vulnerability scanner (Drupal, SilverStripe, etc.) |

#### Rust-based Tool (1)

| Tool | Crate | Version Flag | Description |
|---|---|---|---|
| **rustscan** | `rustscan` | `--version` | Fast port scanner (Rust-based nmap wrapper) |

> Requires Rust/Cargo. Install via `rustup`: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y`

#### Ruby-based Tool (1)

| Tool | Gem Name | Version Flag | Description |
|---|---|---|---|
| **wpscan** | `wpscan` | `--version` | WordPress security scanner |

> Requires Ruby and development headers (`ruby-dev` on Debian/Ubuntu).

#### System Package Tools (2)

| Tool | Package Name | Version Flag | Description |
|---|---|---|---|
| **onesixtyone** | `onesixtyone` | `--help` | Fast SNMP community string brute forcer |
| **snmpwalk** | `snmp` | `-v 2c` | SNMP MIB tree walker |

> The `snmpwalk` binary is provided by the `snmp` package on apt-based systems, and `net-snmp-utils` on dnf-based systems.

#### Git-based Tools (2)

| Tool | Repository URL | Version Flag | Description | Install Location |
|---|---|---|---|---|
| **testssl.sh** | `https://github.com/drwetter/testssl.sh.git` | `--help` | Comprehensive SSL/TLS testing tool | `/opt/recon-tools/testssl.sh/` |
| **joomscan** | `https://github.com/OWASP/joomscan.git` | `--version` | Joomla CMS vulnerability scanner | `/opt/recon-tools/joomscan/` |

> Git-based tools are cloned with `--depth 1` (shallow clone). Shell scripts (`.sh`) and Perl scripts (`.pl`) are automatically made executable.

### 3.3 Tool Install Methods Summary

| Method | Count | Tools |
|---|---|---|
| **apt/dnf/pacman** | 12 | nmap, smbclient (samba-client), nikto, whatweb, sslscan, dnsrecon, searchsploit (exploitdb), ldapsearch (ldap-utils), feroxbuster, gobuster, onesixtyone, snmpwalk (snmp) |
| **go install** | 8 | ffuf, nuclei, subfinder, httpx, kerbrute, gowitness, amass, windapsearch |
| **pip install** | 6 | theHarvester, crackmapexec, ssh-audit, enum4linux-ng, smbmap, droopescan |
| **cargo install** | 1 | rustscan |
| **gem install** | 1 | wpscan |
| **git clone** | 2 | testssl.sh, joomscan |
| **Total** | **30** | |

---

## 4. Checking Tool Status

Use the `check-tools` command to see which tools are installed, their versions, paths, and install hints for missing tools:

```bash
recon-ninja check-tools
```

**Output includes:**

- **Summary header** — counts of required/optional/total tools found
- **Required tools table** — name, status (found/missing), version, path, install command
- **Optional tools table** — same columns
- **Missing tools panel** — lists missing required and optional tools with install suggestions

**Example output:**

```
┌──────────────────────────────────────────────────────────────────┐
│  🥷 Recon Ninja — Tool Inventory                                 │
│  Required: 8/8 found  Optional: 18/22 found  Total: 26/30       │
└──────────────────────────────────────────────────────────────────┘

  ── Required Tools ──────────────────────────────────────────────────
  Tool            Status   Version              Path                Install
  nmap            ✔        Nmap 7.94            /usr/bin/nmap       apt install nmap
  smbclient       ✔        Version 4.19.5       /usr/bin/smbclient  apt install samba-client
  nikto           ✔        Nikto 2.5.0          /usr/bin/nikto      apt install nikto
  ...

  ── Optional Tools ──────────────────────────────────────────────────
  rustscan        ✔        2.1.1                ~/.cargo/bin/rustscan  cargo install rustscan
  ffuf            ✔        2.1.0                ~/go/bin/ffuf       go install github.com/ffuf/ffuf/v2@latest
  wpscan          ✘                                                  gem install wpscan
  ...
```

**Detection strategy (per tool):**

1. Standard `which` lookup on `$PATH`
2. Alternative binary names (e.g., `enum4linux` for `enum4linux-ng`, `cme` for `crackmapexec`)
3. Extra search paths: `~/go/bin/`, `~/.local/bin/`, `/usr/local/bin/`, `/usr/local/sbin/`, `/opt/recon-tools/`, `/opt/`
4. Version detection via running `<tool> <version_flag>` and parsing the output
5. Functional validation — ensures the binary is actually executable

---

## 5. Supported Operating Systems

| OS | Package Manager | Status | Notes |
|---|---|---|---|
| **Kali Linux** | `apt` | Fully supported | Best experience — most tools available as system packages |
| **Ubuntu/Debian** | `apt` | Fully supported | Some security tools may need additional repositories |
| **Fedora/RHEL** | `dnf` | Supported | Package names may differ (e.g., `samba-client` vs `smbclient`) |
| **Arch Linux** | `pacman` | Supported | Tools available in AUR or official repos |

The installer auto-detects the package manager and adapts install commands accordingly. On unsupported distributions, the built-in installer will skip system package installs but will still attempt Go, pip, cargo, gem, and git-based installations.

---

## 6. PATH Configuration

Several tools install to directories that may not be on your default PATH. The installer automatically configures these in `~/.bashrc` and `~/.zshrc`:

| Directory | Purpose | Tools |
|---|---|---|
| `~/go/bin` | Go tool binaries | ffuf, nuclei, subfinder, httpx, kerbrute, gowitness, amass, windapsearch |
| `~/.local/bin` | User-local Python binaries | theHarvester, crackmapexec, ssh-audit, enum4linux-ng, smbmap, droopescan |
| `~/.cargo/bin` | Rust/Cargo binaries | rustscan |
| `/usr/local/go/bin` | Go itself (if installed manually) | `go` command |
| `/opt/recon-tools/` | Git-cloned tools | testssl.sh, joomscan |

**After installation, reload your shell:**

```bash
source ~/.bashrc     # bash users
source ~/.zshrc      # zsh users
```

Or start a new terminal session.

**Manual PATH setup** — if the installer cannot modify your shell config, add these lines manually:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/go/bin:$PATH"
export PATH="$HOME/.local/bin:$PATH"
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
```

---

## 7. SecLists Wordlists

Recon Ninja uses the [SecLists](https://github.com/danielmiessler/SecLists) collection for directory fuzzing, DNS enumeration, and other wordlist-based attacks.

**Installation locations (checked in order):**

1. `/usr/share/seclists/` — standard system install (via `apt install seclists` on Kali/Debian)
2. Git clone fallback — `/usr/share/seclists/` (if apt install fails)

**The installer handles SecLists automatically:**

- If `/usr/share/seclists/` already exists → marked as found
- On `apt` systems → tries `apt install seclists`
- Otherwise → `git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists`

**Manual install:**

```bash
# Kali/Debian
sudo apt install seclists

# Other distributions
sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

Recon Ninja's wordlist resolver (`recon_ninja.utils.wordlists`) automatically locates the SecLists directory and resolves paths for common wordlists (directory brute-forcing, DNS, vhosts, etc.).

---

## 8. Troubleshooting

### `pip install -e .` fails with PEP 668 error

**Symptom:** `error: externally-managed-environment`

**Fix:** Use one of:

```bash
pip install -e . --break-system-packages
# or use a venv:
python3 -m venv ~/recon-env && source ~/recon-env/bin/activate && pip install -e .
```

### Go tools not found after `go install`

**Symptom:** `ffuf: command not found` even though `go install` succeeded.

**Fix:** Add `~/go/bin` to your PATH:

```bash
export PATH="$HOME/go/bin:$PATH"
```

And persist it in `~/.bashrc` or `~/.zshrc`. The built-in installer does this automatically.

### `cargo install rustscan` fails

**Symptom:** Compilation errors during `cargo install rustscan`.

**Fix:** Ensure you have build essentials installed:

```bash
sudo apt install -y build-essential pkg-config libssl-dev   # Debian/Ubuntu
sudo dnf install -y gcc openssl-devel                        # Fedora
sudo pacman -S --noconfirm base-devel openssl                # Arch
```

Then retry `cargo install rustscan`.

### `gem install wpscan` fails

**Symptom:** `ERROR: Failed to build gem native extension.`

**Fix:** Install Ruby development headers:

```bash
sudo apt install -y ruby-dev   # Debian/Ubuntu
sudo dnf install -y ruby-devel # Fedora
sudo pacman -S --noconfirm ruby # Arch
```

### Tools installed but `recon-ninja check-tools` doesn't detect them

**Symptom:** A tool is installed but shows as missing in the check-tools output.

**Fix:**

1. Verify the tool is on your PATH: `which <tool>`
2. If it's in `~/go/bin/` or `~/.local/bin/`, ensure those directories are in your PATH
3. Reload your shell: `source ~/.bashrc`
4. Run `recon-ninja check-tools` again

### `recon-ninja install` skips system packages

**Symptom:** Tools like `nmap` show as skipped with "No system package manager detected."

**Fix:** Ensure one of `apt`, `dnf`, or `pacman` is installed and on your PATH. This error typically occurs on unsupported distributions. Install system packages manually (see [Section 2.4](#24-manual-installation)).

### Git clone fails for testssl.sh or joomscan

**Symptom:** `git clone failed` when installing Git-based tools.

**Fix:**

1. Ensure you have internet access and `git` is installed
2. The clone target `/opt/recon-tools/` requires root — run with `sudo`
3. Clone manually:
   ```bash
   sudo mkdir -p /opt/recon-tools
   sudo git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/recon-tools/testssl.sh
   sudo git clone --depth 1 https://github.com/OWASP/joomscan.git /opt/recon-tools/joomscan
   ```

### SecLists not found

**Symptom:** Wordlist paths resolve to `None` during scans.

**Fix:**

```bash
# Check if SecLists exists
ls /usr/share/seclists/

# Install if missing
sudo apt install seclists
# or: sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

---

*For more information, see the [README.md](README.md) or run `recon-ninja --help`.*
