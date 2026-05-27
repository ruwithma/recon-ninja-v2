<p align="center">
<img src="https://img.shields.io/badge/version-2.0.0-cyan?style=for-the-badge&labelColor=1a1a2e" alt="version">
<img src="https://img.shields.io/badge/python-3.10%2B-blue?style=for-the-badge&labelColor=1a1a2e" alt="python">
<img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge&labelColor=1a1a2e" alt="license">
<img src="https://img.shields.io/badge/status-beta-orange?style=for-the-badge&labelColor=1a1a2e" alt="status">
</p>

```
  ╭──────────────────────────────────────────╮
  │           R E C O N N I N J A            │
  │               v2.0.0                     │
  │   Automated recon for CTFs & pentesting  │
  ╰──────────────────────────────────────────╯
```

---

ReconNinja v2 is a fully automated reconnaissance pipeline for CTF competitions
(HackTheBox, TryHackMe, OSCP) and authorized pentesting engagements. It runs
the right tools in the right order, branches on what it finds, surfaces
findings with suggested next steps, and generates polished reports --- all from
a single command.

**Key highlights:**

- 7-phase async pipeline with checkpoint/resume
- 18 service modules (16 protocol-specific + OSINT + Vuln Correlation)
- 30+ external tools tracked with version detection and auto-install
- Rich terminal UI with live progress bars, panels, and severity tables
- Auto box-classification (WINDOWS_AD, LINUX_WEB, etc.)
- Regex-based loot extraction (creds, flags, hashes, keys)
- 3-layer config merge: defaults < YAML < CLI flags
- Multi-format reporting: Markdown + HTML + JSON

---

## Table of Contents

- [Quick Start](#quick-start)
- [Installation](#installation)
- [CLI Commands](#cli-commands)
- [Scan Flags](#scan-flags)
- [Execution Pipeline](#execution-pipeline)
- [Service Modules](#service-modules)
- [Box Profile Classification](#box-profile-classification)
- [Configuration](#configuration)
- [Output Structure](#output-structure)
- [Project Structure](#project-structure)
- [External Tools](#external-tools)
- [Dependencies](#dependencies)
- [Usage Examples](#usage-examples)
- [Legal Disclaimer](#legal-disclaimer)

---

## Quick Start

```bash
# Install the package (editable mode)
pip install -e .

# Or use the one-shot installer (includes all external tools)
chmod +x install.sh && sudo ./install.sh

# Run your first scan
reconninja 10.10.11.58

# HackTheBox machine with auto /etc/hosts
reconninja 10.10.11.58 --htb --add-hosts

# Fast scan (port scan + basic service enum only)
reconninja 10.10.11.58 --fast

# Full scan with all optional modules enabled
reconninja 10.10.11.58 --full

# Resume an interrupted scan
reconninja 10.10.11.58 --resume

# Check which tools are installed
reconninja check-tools

# Install missing tools automatically
sudo reconninja install
```

---

## Installation

### Option 1: pip (Python package only)

```bash
pip install -e .
```

This installs the `reconninja` CLI and Python dependencies. External security
tools (nmap, nikto, etc.) must be installed separately.

### Option 2: One-shot shell script

```bash
chmod +x install.sh && sudo ./install.sh
```

The shell script installs everything end-to-end:

1. System package update (apt/dnf/pacman)
2. Required and optional apt packages (nmap, smbclient, nikto, seclists, etc.)
3. Rust/Cargo + RustScan
4. Go + 8 Go-based tools (ffuf, nuclei, subfinder, httpx, kerbrute, gowitness, amass, windapsearch)
5. Python tools (theHarvester, crackmapexec, ssh-audit, enum4linux-ng, smbmap, droopescan)
6. Ruby gems (wpscan)
7. SecLists wordlists
8. Git-cloned tools (testssl.sh, joomscan)
9. PATH configuration for `~/go/bin` and `~/.cargo/env`

### Option 3: Built-in Python installer

```bash
# Install all tools (required + optional)
sudo reconninja install

# Install only required tools
sudo reconninja install --required
```

The built-in installer supports 6 install methods:
`apt`, `go install`, `pip install`, `cargo install`, `gem install`, and `git clone`.
Already-installed tools are detected and skipped automatically.

### Verify your setup

```bash
reconninja check-tools          # Summary view
reconninja check-tools -v       # Detailed view with paths and versions
reconninja --version            # Print version
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `reconninja <target>` | Run a scan against a target (shorthand) |
| `reconninja scan <target> [OPTIONS]` | Run a scan (explicit subcommand) |
| `reconninja check-tools` | Check which external tools are installed with versions |
| `reconninja install` | Auto-install all tools |
| `reconninja install --required` | Install only required tools |
| `reconninja --version` / `-V` | Show version |

The shorthand `reconninja <target>` is equivalent to
`reconninja scan <target>`. If the first positional argument does not match a
known subcommand, it is automatically routed to the `scan` command.

---

## Scan Flags

```
reconninja <TARGET> [OPTIONS]
```

### Scan Control

| Flag | Default | Description |
|------|---------|-------------|
| `--fast` | off | Port scan + basic service enum only (top-1000 ports) |
| `--full` | off | All modules including nuclei, amass, theHarvester, testssl |
| `--udp` | off | Enable UDP scanning (requires root) |
| `--stealth` | off | Low-rate scanning (T2 timing, 200ms scan-delay) |
| `--aggressive` | off | Include potentially disruptive checks |
| `--ports PORTS` | all | Override port list (e.g. `80,443,8080`) |
| `--rate N` | 5000 | Nmap `--min-rate` override |
| `--timeout N` | 300 | Global per-tool timeout in seconds |
| `-t, --threads N` | 10 | Max concurrent modules (semaphore gate) |

### Module Toggles

| Flag | Description |
|------|-------------|
| `--no-web` | Skip web enumeration modules |
| `--no-smb` | Skip SMB enumeration modules |
| `--no-vuln` | Skip vulnerability correlation phase |
| `--no-osint` | Skip OSINT phase |
| `--only-web` | Only run web enumeration (disables all other modules) |
| `--only-ports` | Phase 1 + 2 only (port scan + service enum) |

### Input / Output

| Flag | Default | Description |
|------|---------|-------------|
| `-o, --output DIR` | `./results/<target>/` | Output directory |
| `--config FILE` | `~/.config/reconninja/config.yaml` | Config file path |
| `--wordlist FILE` | SecLists raft-medium-directories | Custom wordlist for directory fuzzing |
| `--html` | off | Generate styled HTML report |
| `--json` / `--no-json` | on | Generate machine-readable JSON findings file |
| `--resume` | off | Resume from last checkpoint |
| `--no-vpn-check` | off | Skip VPN interface check |

### Authentication

| Flag | Description |
|------|-------------|
| `--creds USER:PASS` | Pass credentials to modules that support authentication |
| `--domain DOMAIN` | Active Directory domain name |

### CTF Helpers

| Flag | Description |
|------|-------------|
| `--htb` | HackTheBox mode: VPN check on `tun0`, auto `/etc/hosts` |
| `--add-hosts` | Auto-add discovered hostnames to `/etc/hosts` |
| `--platform` | Platform hint: `htb`, `thm`, `oscp`, `bugbounty` |

### Verbosity

| Flag | Description |
|------|-------------|
| `-v, --verbose` | Print raw tool output and debug logging |
| `-q, --quiet` | Final summary only (suppress all live output) |
| `--proxy URL` | Route HTTP tools through a proxy (e.g. `http://127.0.0.1:8080`) |

---

## Execution Pipeline

ReconNinja executes a 7-phase pipeline. Each phase is checkpointed so
interrupted scans can be resumed with `--resume`.

| Phase | Name | What Happens | Key Tools |
|-------|------|-------------|-----------|
| **0** | Pre-flight | Target validation, VPN check, tool inventory, SecLists detection, output directory setup | Internal |
| **1** | Port Discovery | Fast SYN scan for open ports; RustScan with nmap fallback; optional UDP scan | RustScan, nmap |
| **2** | Deep Service Enumeration | `nmap -sC -sV -O` on discovered ports; XML parsing; hostname detection; box classification | nmap |
| **3** | Service-Specific Modules | Concurrent module execution gated by semaphore; 16 protocol modules dispatched by detected services | Per-module (see below) |
| **4** | OSINT | DNS enumeration, subdomain discovery, email/host harvesting | dnsrecon, subfinder, theHarvester |
| **5** | Vulnerability Correlation | Exploit search for every product+version pair; template-based vulnerability scanning | searchsploit, nuclei, NVD API |
| **6** | Loot Extraction | Regex scan of all output files for credentials, flags, hashes, and private keys | Internal (regex engine) |
| **7** | Report Generation | Markdown + HTML (opt-in) + JSON reports; state checkpoint saved | Jinja2, internal |

Phase 3 modules run concurrently under an `asyncio.Semaphore` controlled by
`--threads`. Each module catches its own errors so a single failure never
blocks the rest of the pipeline.

---

## Service Modules

18 modules are dispatched in Phase 3 based on the services discovered in
Phases 1-2. Modules whose required tools are missing are gracefully skipped.

### Web (4 sub-modules)

| Sub-module | Purpose | Tools |
|-----------|---------|-------|
| `web_core` | Technology fingerprint, headers, robots.txt, screenshots | whatweb, gowitness |
| `web_dirfuzz` | Directory and vhost fuzzing | feroxbuster, gobuster, ffuf |
| `web_cms` | CMS detection and scanning | wpscan, droopescan, joomscan |
| `web_vuln` | Web vulnerability scanning | nikto, nuclei |

### Protocol Modules

| Module | Trigger Ports | Description |
|--------|--------------|-------------|
| SMB | 139, 445 | Share enumeration, null sessions, vulnerability checks |
| SSH | 22 | Configuration audit, banner analysis |
| FTP | 21 | Anonymous login, banner grabbing, directory listing |
| SMTP | 25, 465, 587 | Open relay check, user enumeration |
| SNMP | UDP 161 | Community string brute-force, MIB walking |
| DNS | 53 | Zone transfer, record enumeration |
| LDAP | 389, 636 | Directory queries, attribute extraction |
| Kerberos | 88 | User enumeration, pre-auth brute-force |
| RPC | 111, 135 | Endpoint mapping, program enumeration |
| NFS | 2049 | Share discovery, mount/export checks |
| RDP | 3389 | Security layer detection, encryption checks |
| VNC | 5900-5910 | Authentication brute-force, banner check |
| WinRM | 5985, 5986 | Remote management capability check |
| Database | 3306, 1433, 5432, 6379, 27017, 1521 | MySQL, MSSQL, PostgreSQL, Redis, MongoDB, Oracle detection |
| SSL | HTTPS services | Certificate analysis, cipher suite checks |

### Additional Modules

| Module | Phase | Description |
|--------|-------|-------------|
| OSINT | 4 | dnsrecon, subfinder, theHarvester for domain targets |
| Vulnerability Correlation | 5 | searchsploit per product+version, nuclei templates, NVD API lookup |

---

## Box Profile Classification

After Phase 2, ReconNinja automatically classifies the target into a box
profile based on detected services. This classification is stored in the scan
state and displayed in the final summary.

| Profile | Detection Criteria | Typical Scenario |
|---------|-------------------|-----------------|
| `WINDOWS_AD` | Kerberos (88) + LDAP (389/636) + SMB (445) + WinRM (5985) or NetBIOS (139) | Active Directory domain controller |
| `WINDOWS_WEB` | IIS detected in service product, no Kerberos | Windows web server |
| `LINUX_WEB` | SSH (22) + HTTP, no SMB | Linux web application server |
| `LINUX_AD` | Samba (445) + LDAP (389/636), no Kerberos | Samba domain member |
| `LINUX_SERVER` | SSH (22) only, no HTTP | Hardened Linux server |
| `UNKNOWN` | Default | Insufficient data for classification |

---

## Configuration

ReconNinja uses a 3-layer config merge with increasing priority:

```
Built-in defaults  <  YAML config file  <  CLI flags
```

### Default config location

```
~/.config/reconninja/config.yaml
```

### Example configuration

```yaml
scan:
  default_threads: 10
  default_timeout: 300
  nmap_min_rate: 5000
  rustscan_ulimit: 5000
  udp_enabled: false
  stealth_mode: false

wordlists:
  seclists_base: /usr/share/seclists
  dir_medium: Discovery/Web-Content/raft-medium-directories.txt
  dir_small: Discovery/Web-Content/common.txt
  vhosts: Discovery/DNS/subdomains-top1million-5000.txt
  usernames: Usernames/xato-net-10-million-usernames-dup.txt
  snmp: Discovery/SNMP/snmp.txt
  custom_dir: null

tools:
  preferred_dir_fuzzer: feroxbuster
  preferred_smb_enum: enum4linux-ng

output:
  always_html: false
  always_json: true
  timestamp_dirs: true

htb:
  vpn_interface: tun0
  auto_add_hosts: false
  machine_name: null

api_keys:
  shodan: null
  nvd: null
```

### SecLists support

ReconNinja automatically detects SecLists at `/usr/share/seclists` and uses
the following wordlists by default:

- **Directory fuzzing:** `raft-medium-directories.txt` (or `common.txt` for `--fast`)
- **Vhost fuzzing:** `subdomains-top1million-5000.txt`
- **SNMP community strings:** `snmp.txt`
- **Username enumeration:** `xato-net-10-million-usernames-dup.txt`

Override any wordlist with `--wordlist` or the `wordlists` config section.

---

## Output Structure

Each scan creates an output directory under `./results/`. With timestamp
directories enabled (the default), the structure looks like this:

```
results/10.10.11.58_20250527_1430/
├── 00_SUMMARY.md              # Full markdown report
├── 00_SUMMARY.html            # Styled HTML report (with --html)
├── 00_findings.json           # Machine-readable JSON findings
├── reconninja.log            # Debug log
├── scan.state                 # Checkpoint file for --resume
├── state.json                 # Raw state dump
├── ports.txt                  # Comma-separated open port list
├── rustscan.txt               # RustScan raw output (if used)
├── nmap_fast.txt              # Nmap fast scan output
├── nmap_deep.xml              # Nmap deep scan XML
├── nmap_deep.txt              # Nmap deep scan human-readable
├── nmap_udp.txt               # UDP scan output (with --udp)
├── web/                       # Web module output
│   ├── whatweb.txt
│   ├── nikto.txt
│   ├── feroxbuster.txt
│   └── ...
├── smb/                       # SMB module output
├── dns/                       # DNS module output
├── loot/                      # Extracted credentials and artifacts
│   ├── credentials.txt
│   ├── flags.txt
│   ├── hashes.txt
│   └── keys.txt
├── searchsploit_22.txt        # Per-port exploit search results
├── searchsploit_80.txt
├── nuclei.txt                 # Nuclei scan results
├── dnsrecon.txt
├── dnsrecon.json
├── subfinder.txt
└── ...
```

### Checkpoint / Resume

Scan state is saved after every phase. If a scan is interrupted (Ctrl+C,
timeout, crash), resume it:

```bash
reconninja 10.10.11.58 --resume
```

Completed phases are skipped, and the scan continues from the last
checkpointed phase.

---

## Project Structure

```
recon_ninja/
├── __init__.py                  # Version and metadata
├── main.py                      # CLI entry point (typer + rich)
├── core/
│   ├── engine.py                # Async orchestrator — runs phases in order
│   ├── runner.py                # asyncio.create_subprocess_exec wrapper
│   ├── models.py                # ModuleResult, Finding, ServiceInfo, ScanState, ReconConfig
│   ├── config.py                # Config loader (3-layer merge: defaults < YAML < CLI)
│   ├── state.py                 # Session state / checkpoint save + restore
│   ├── display.py               # Rich live display, panels, tables, progress bars
│   ├── report.py                # Markdown + HTML + JSON report writer
│   └── loot.py                  # Regex-based loot extractor
├── modules/
│   ├── web/
│   │   ├── __init__.py          # Web module orchestrator
│   │   ├── web_core.py          # whatweb, headers, robots.txt, screenshots
│   │   ├── web_dirfuzz.py       # feroxbuster / gobuster / ffuf dir + vhost
│   │   ├── web_vuln.py          # nikto, nuclei, wafw00f
│   │   └── web_cms.py           # CMS detect → wpscan / droopescan / joomscan + API
│   ├── smb.py                   # SMB enumeration and share access
│   ├── ssh.py                   # SSH audit and banner analysis
│   ├── ftp.py                   # FTP anonymous login and enumeration
│   ├── smtp.py                  # SMTP relay and user enumeration
│   ├── snmp.py                  # SNMP community brute-force and MIB walk
│   ├── dns.py                   # DNS zone transfer and record enum
│   ├── ldap.py                  # LDAP directory queries
│   ├── kerberos.py              # Kerberos user enum and pre-auth brute-force
│   ├── rpc.py                   # RPC endpoint mapping
│   ├── nfs.py                   # NFS share discovery
│   ├── rdp.py                   # RDP security layer detection
│   ├── vnc.py                   # VNC authentication check
│   ├── winrm.py                 # WinRM capability check
│   ├── database.py              # Database service detection
│   ├── ssl.py                   # SSL/TLS certificate and cipher analysis
│   ├── osint.py                 # OSINT aggregation module
│   └── vuln_correlate.py        # searchsploit + nuclei against all versions
└── utils/
    ├── checker.py               # Enhanced tool availability checker with version detection
    ├── installer.py             # Auto-installer (6 methods: apt/go/pip/cargo/gem/git)
    ├── wordlists.py             # SecLists path resolver
    ├── nmap_parser.py           # Pure xml.etree nmap XML parser
    ├── network.py               # IP/CIDR validation, VPN interface check
    └── hosts.py                 # /etc/hosts read/write helper
```

---

## External Tools

ReconNinja integrates with 30 external security tools. Required tools must
be present for a full scan; optional tools are gracefully skipped when missing.

### Required (8)

| Tool | Install | Purpose |
|------|---------|---------|
| nmap | `apt install nmap` | Network port scanner and service enumerator |
| smbclient | `apt install samba-client` | SMB/CIFS client for share enumeration |
| nikto | `apt install nikto` | Web server vulnerability scanner |
| whatweb | `apt install whatweb` | Web technology fingerprinter |
| sslscan | `apt install sslscan` | SSL/TLS cipher and certificate scanner |
| dnsrecon | `apt install dnsrecon` | DNS enumeration and reconnaissance |
| searchsploit | `apt install exploitdb` | Offline exploit database search |
| ldapsearch | `apt install ldap-utils` | LDAP directory query client |

### Optional (22)

| Tool | Install Method | Purpose |
|------|---------------|---------|
| rustscan | `cargo install rustscan` | Fast port scanner (Rust-based nmap wrapper) |
| feroxbuster | `apt install feroxbuster` | Recursive directory fuzzer (Rust) |
| gobuster | `apt install gobuster` | Directory/DNS/VHost fuzzer (Go) |
| ffuf | `go install github.com/ffuf/ffuf/v2@latest` | Fast web fuzzer (Go) |
| nuclei | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | Template-based vulnerability scanner |
| subfinder | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` | Passive subdomain discovery |
| httpx | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` | Fast HTTP prober and toolkit |
| kerbrute | `go install github.com/ropnop/kerbrute@latest` | Kerberos pre-auth brute forcer |
| gowitness | `go install github.com/sensepost/gowitness@latest` | Web screenshot tool (Chrome headless) |
| amass | `go install github.com/owasp-amass/amass/v4/overrides/cmd/amass@latest` | Attack surface and asset mapping |
| windapsearch | `go install github.com/ropnop/windapsearch-go@latest` | Active Directory LDAP enumeration |
| theHarvester | `pip install theHarvester` | OSINT email, domain, and IP harvester |
| crackmapexec | `pip install crackmapexec` | Network swiss-army knife for AD pentesting |
| ssh-audit | `pip install ssh-audit` | SSH server configuration auditor |
| enum4linux-ng | `pip install enum4linux-ng` | SMB/NetBIOS enumeration (next-gen) |
| smbmap | `pip install smbmap` | SMB share permission enumeration |
| droopescan | `pip install droopescan` | CMS vulnerability scanner (Drupal, etc.) |
| onesixtyone | `apt install onesixtyone` | Fast SNMP community string brute forcer |
| snmpwalk | `apt install snmp` | SNMP MIB tree walker |
| wpscan | `gem install wpscan` | WordPress security scanner |
| testssl.sh | `git clone https://github.com/drwetter/testssl.sh.git` | Comprehensive SSL/TLS testing |
| joomscan | `git clone https://github.com/OWASP/joomscan.git` | Joomla CMS vulnerability scanner |

### Tool detection

The checker uses a multi-strategy detection approach:

1. **Standard PATH lookup** via `shutil.which()`
2. **Alternative binary names** (e.g. `enum4linux` vs `enum4linux-ng`, `cme` vs `crackmapexec`)
3. **Extra search paths** (`~/go/bin/`, `~/.local/bin/`, `/usr/local/bin/`, `/opt/recon-tools/`, `/opt/`)
4. **Version detection** by running `<tool> --version` (or `-V`, `-VV`, `--help` as appropriate)
5. **Functional validation** ensuring the binary is actually executable

---

## Dependencies

### Python dependencies (auto-installed with `pip install -e .`)

| Package | Version | Purpose |
|---------|---------|---------|
| rich | >= 13.0 | Terminal UI: panels, tables, progress bars, spinners |
| typer | >= 0.9 | CLI framework with rich markup support |
| click | >= 8.0 | Underlying CLI library (typer dependency) |
| requests | >= 2.31 | HTTP client for NVD API and web checks |
| pyyaml | >= 6.0 | YAML config file parsing |
| jinja2 | >= 3.1 | HTML report template rendering |
| aiofiles | >= 23.0 | Async file I/O for output writing |

### Dev dependencies

```bash
pip install -e ".[dev]"
# Installs: pytest>=7.0, pytest-asyncio>=0.21
```

---

## Usage Examples

### Basic scans

```bash
# Standard scan against an IP
reconninja 10.10.10.1

# Scan a domain target
reconninja example.com

# Scan with custom output directory
reconninja 10.10.10.1 -o /tmp/scan-results

# Scan with verbose output (raw tool output + debug log)
reconninja 10.10.10.1 -v
```

### Speed profiles

```bash
# Fast scan: top-1000 ports, basic service enum only
reconninja 10.10.10.1 --fast

# Full scan: all modules including nuclei, amass, theHarvester, testssl
reconninja 10.10.10.1 --full

# Stealth: low-rate scanning to avoid IDS detection
reconninja 10.10.10.1 --stealth

# Aggressive: include potentially disruptive checks
reconninja 10.10.10.1 --aggressive
```

### Targeted scans

```bash
# Web-only enumeration
reconninja dog.htb --only-web

# Port scan + service enum only (no modules, no vuln, no OSINT)
reconninja 10.10.10.1 --only-ports

# Skip specific modules
reconninja 10.10.10.1 --no-web --no-smb

# Scan specific ports
reconninja 10.10.10.1 --ports 22,80,443,8080

# Skip vulnerability scanning
reconninja 10.10.10.1 --no-vuln
```

### CTF workflows

```bash
# HackTheBox machine (VPN check + auto /etc/hosts)
reconninja 10.10.11.58 --htb --add-hosts

# HTB with domain name
reconninja 10.10.11.58 --htb --domain corp.local --add-hosts

# TryHackMe machine
reconninja 10.10.10.1 --platform thm

# OSCP exam target
reconninja 10.10.10.1 --platform oscp --full

# Scan with credentials
reconninja 10.10.10.1 --creds admin:password123 --domain corp.local
```

### Network options

```bash
# Enable UDP scanning (requires root)
sudo reconninja 10.10.10.1 --udp

# Custom nmap rate and timeout
reconninja 10.10.10.1 --rate 10000 --timeout 600

# Limit concurrent modules
reconninja 10.10.10.1 -t 5

# Route through a proxy (Burp Suite, etc.)
reconninja 10.10.10.1 --proxy http://127.0.0.1:8080
```

### Resume and recovery

```bash
# Resume an interrupted scan
reconninja 10.10.10.1 --resume

# Skip VPN check on resume
reconninja 10.10.10.1 --resume --no-vpn-check
```

### Output and reporting

```bash
# Generate HTML report
reconninja 10.10.10.1 --html

# Disable JSON output
reconninja 10.10.10.1 --no-json

# Custom wordlist for directory fuzzing
reconninja 10.10.10.1 --wordlist /path/to/custom-wordlist.txt

# Custom config file
reconninja 10.10.10.1 --config /path/to/my-config.yaml

# Quiet mode (summary only)
reconninja 10.10.10.1 -q
```

---

## Legal Disclaimer

**ReconNinja is designed exclusively for authorized security testing.**

Use only on machines and networks you own or have explicit written permission
to test. Unauthorized scanning is illegal under the Computer Fraud and Abuse
Act (CFAA), the Computer Misuse Act, and equivalent laws worldwide.

HackTheBox, TryHackMe, OSCP exam labs, and your own home lab are the intended
environments.

---

*Built for CTF warriors. Sharpened for pentesters.*
