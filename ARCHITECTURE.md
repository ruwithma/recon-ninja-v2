# ReconNinja v2 — Architecture Reference

> Internal codebase architecture document for ReconNinja v2.0.0.
> Describes the project structure, data flow, pipeline phases, key design
> patterns, configuration system, tool detection, and auto-installer.

---

## Table of Contents

1. [Project Structure](#project-structure)
2. [Data Flow](#data-flow)
3. [The 7-Phase Pipeline](#the-7-phase-pipeline)
4. [Core Modules](#core-modules)
5. [Reconnaissance Modules](#reconnaissance-modules)
6. [Utility Modules](#utility-modules)
7. [Key Design Patterns](#key-design-patterns)
8. [Configuration System](#configuration-system)
9. [Tool Detection](#tool-detection)
10. [Auto-Installer](#auto-installer)
11. [State & Checkpoint/Resume](#state--checkpointresume)
12. [Report Generation](#report-generation)
13. [Testing](#testing)

---

## Project Structure

```
recon_ninja/
├── __init__.py              # Package metadata (__version__ = "2.0.0")
├── main.py                  # CLI entry point (Typer app, 3 commands)
├── core/
│   ├── __init__.py
│   ├── config.py            # 3-layer config merge (defaults < YAML < CLI)
│   ├── engine.py            # Async orchestrator, 7-phase pipeline
│   ├── models.py            # Dataclasses: Severity, Finding, ServiceInfo,
│   │                        #   ModuleResult, ScanState, ReconConfig
│   ├── runner.py            # Async subprocess execution
│   │                        #   (run_tool, run_tool_streaming, run_multiple)
│   ├── state.py             # Checkpoint/resume state manager (StateManager)
│   ├── display.py           # Rich terminal UI (banners, progress, tables,
│   │                        #   panels, live displays)
│   ├── report.py            # Report generation (Markdown + HTML + JSON)
│   └── loot.py              # Regex-based loot extractor
├── modules/
│   ├── __init__.py
│   ├── web/                 # Web module (4 sub-modules)
│   │   ├── __init__.py      # Top-level orchestrator: web_core → web_dirfuzz
│   │   │                    #   → web_vuln → web_cms
│   │   ├── web_core.py      # HTTP fingerprinting (whatweb, curl, httpx)
│   │   ├── web_dirfuzz.py   # Directory/file fuzzing (feroxbuster/gobuster/ffuf)
│   │   ├── web_cms.py       # CMS detection (wpscan, droopescan, joomscan)
│   │   └── web_vuln.py      # Web vulnerability scanning (nikto, nuclei)
│   ├── smb.py               # SMB enumeration (enum4linux-ng, smbclient, smbmap,
│   │                        #   crackmapexec, nmap SMB vuln scripts)
│   ├── ssh.py               # SSH enumeration (ssh-audit, nmap scripts)
│   ├── ftp.py               # FTP enumeration (anonymous login, nmap scripts)
│   ├── smtp.py              # SMTP enumeration (smtp-enum, nmap scripts)
│   ├── snmp.py              # SNMP enumeration (snmpwalk, onesixtyone)
│   ├── dns.py               # DNS enumeration (dnsrecon, dig)
│   ├── ldap.py              # LDAP enumeration (ldapsearch, windapsearch)
│   ├── kerberos.py          # Kerberos enumeration (kerbrute, nmap scripts)
│   ├── rpc.py               # RPC enumeration (rpcclient, nmap scripts)
│   ├── nfs.py               # NFS enumeration (showmount, nmap scripts)
│   ├── rdp.py               # RDP enumeration (nmap scripts, xfreerdp)
│   ├── vnc.py               # VNC enumeration (nmap scripts)
│   ├── winrm.py             # WinRM enumeration (crackmapexec, nmap scripts)
│   ├── database.py          # Database enumeration (nmap scripts, manual probes)
│   ├── ssl.py               # SSL/TLS analysis (sslscan, testssl.sh)
│   ├── osint.py             # OSINT gathering (dnsrecon, subfinder, theHarvester)
│   └── vuln_correlate.py    # Vulnerability correlation (searchsploit, nuclei,
│                            #   NVD API enrichment)
├── utils/
│   ├── __init__.py
│   ├── checker.py           # Enhanced tool detection (30 tools, version,
│   │                        #   paths, install metadata, ToolInfo dataclass)
│   ├── installer.py         # Auto-installer (6 methods, ToolInstaller class)
│   ├── network.py           # IP/CIDR validation, VPN check, root check,
│   │                        #   private IP classification, CIDR expansion
│   ├── hosts.py             # /etc/hosts helper (read, search, append via sudo)
│   ├── wordlists.py         # SecLists resolver (auto-discovery, category helpers)
│   └── nmap_parser.py       # Nmap XML/grepable parser, RustScan text parser
config/
└── default_config.yaml      # Default scan/wordlist/tools/output/htb/api_keys settings
tests/                       # 310 pytest tests
    ├── test_engine.py
    ├── test_runner.py
    ├── test_models.py
    ├── test_report.py
    ├── test_state.py
    ├── test_utils.py
    ├── test_loot.py
    ├── test_config.py
    ├── test_modules.py
    └── test_parser.py
install.sh                   # Shell-based installer script
```

---

## Data Flow

The entire scan lifecycle follows a single deterministic path from CLI
invocation to final report generation:

```
CLI flags
  │
  ▼
_build_cli_overrides()          # Translate Typer options → nested dict
  │
  ▼
load_config()                   # 3-layer merge:
  │   1. _DEFAULT_CONFIG (hard-coded dict)
  │   2. YAML file (config/default_config.yaml + ~/.config/reconninja/config.yaml)
  │   3. cli_overrides (highest precedence)
  │
  ▼
MergeConfig                     # Typed dataclass container:
  ├── ScanConfig                #   threads, timeout, nmap_min_rate, udp, stealth
  ├── WordlistsConfig           #   seclists_base, dir_medium, vhosts, usernames, snmp
  ├── ToolsConfig               #   preferred_dir_fuzzer, preferred_smb_enum
  ├── OutputConfig              #   always_html, always_json, timestamp_dirs
  ├── HTBConfig                 #   vpn_interface, auto_add_hosts, machine_name
  └── APIKeysConfig             #   shodan, nvd
  │
  ▼
_build_recon_config()           # MergeConfig + remaining CLI flags → ReconConfig
  │
  ▼
ReconConfig                     # Runtime scan configuration:
  ├── fast_mode, udp_scan, osint_enabled
  ├── max_concurrent, default_timeout
  ├── module_toggles            # dict[str, bool] — per-module enable/disable
  ├── extra_nmap_flags          # list[str] — appended to every nmap call
  ├── skip_vuln_correlate, skip_loot
  ├── web_wordlist, dns_wordlist
  ├── nuclei_templates
  └── is_domain
  │
  ▼
StateManager.init_state()       # Create ScanState, persist to results/<target>/scan.state
  │
  ▼
ScanState                       # Mutable scan state (JSON-serializable):
  ├── target, start_time, output_dir
  ├── open_ports, udp_ports
  ├── services: dict[int, ServiceInfo]
  ├── hostnames, box_profile
  ├── completed_modules
  ├── all_findings: list[Finding]
  ├── module_results: list[ModuleResult]
  ├── available_tools: dict[str, bool]
  ├── current_phase             # 0–7, incremented after each phase
  └── end_time
  │
  ▼
ReconEngine.run()               # Execute phases 1–7 sequentially
  │   (skips already-completed phases on resume)
  │   Saves ScanState after every phase
  │
  ▼
final ScanState                 # Complete state with all findings, services, loot
  │
  ▼
Reports                         # 00_SUMMARY.md, 00_SUMMARY.html (opt-in),
                                # 00_findings.json, state.json
```

---

## The 7-Phase Pipeline

The `ReconEngine` class in `core/engine.py` orchestrates all reconnaissance
through a sequential 7-phase pipeline. Each phase is an async method.
After each phase completes, `ScanState.current_phase` is incremented and the
full state is serialized to disk (`scan.state`), enabling crash-safe resume.

### Phase 0: Pre-flight (executed in `main.py`)

Not part of the engine loop — handled by the CLI layer before the engine is
created:

| Step | Action | Module |
|------|--------|--------|
| 0a | Load & merge configuration | `core/config.py` → `load_config()` |
| 0b | Validate target (IP/hostname/CIDR → resolved IP) | `utils/network.py` → `validate_target()` |
| 0c | VPN interface check (if `--htb`) | `utils/network.py` → `check_vpn_interface()` |
| 0d | Root privilege check | `utils/network.py` → `is_root()` |
| 0e | Tool inventory | `utils/checker.py` → `check_tools()` |
| 0f | SecLists wordlist discovery | `utils/wordlists.py` → `find_seclists()` |
| 0g | Create output directory (with optional timestamp) | `main.py` → `_create_output_dir()` |
| 0h | Display pre-flight checklist | `main.py` → `_display_preflight()` |
| 0i | Build `ReconConfig` from merged config + CLI flags | `main.py` → `_build_recon_config()` |
| 0j | Initialize or resume `ScanState` | `core/state.py` → `StateManager.init_state()` / `load_state()` |

### Phase 1: Port Discovery

**Method:** `ReconEngine.phase1_port_discovery()`

Discovers open TCP ports on the target. The strategy is adaptive:

1. **RustScan** (preferred): Fast SYN scan using `rustscan --top-ports`.
   - Top 1000 ports in `--fast` mode, top 10,000 otherwise.
   - Parses `Open <ip>:<port>` lines from stdout.
   - On failure, falls back to nmap.

2. **Nmap fast scan** (fallback): `nmap -Pn -sS --top-ports -T4`.
   - Same port range logic as RustScan.
   - Parses `N/tcp open <service>` lines.

3. **UDP scan** (optional, requires root): `nmap -Pn -sU --top-ports 20 -T4`.
   - Only runs when `--udp` flag is set and running as root.

Output: `state.open_ports` (sorted list of ints), `state.udp_ports`,
`results/<target>/ports.txt`.

### Phase 2: Deep Service Enumeration

**Method:** `ReconEngine.phase2_deep_scan()`

Runs a comprehensive nmap scan against discovered ports:

```
nmap -Pn -sC -sV -O -p <ports> -oX nmap_deep.xml <target>
```

- `-sC`: Default NSE script suite
- `-sV`: Version detection
- `-O`: OS detection
- XML output parsed by `parse_nmap_xml()` (standalone, no `python-nmap` dependency)

Extracted data:

| Field | Source | Storage |
|-------|--------|---------|
| Service name, product, version | `<service>` element | `ServiceInfo.service/product/version` |
| NSE script output | `<script>` elements | `ServiceInfo.scripts: dict[str, str]` |
| Hostnames | `<hostname>` elements + `http-title` script | `ScanState.hostnames` |
| Box profile | Port/service heuristic | `ScanState.box_profile` |

**Box classification logic** (`_classify_box`):

| Profile | Detection Criteria |
|---------|-------------------|
| `WINDOWS_AD` | Port 88 (Kerberos) + 389/636 (LDAP) + 139/445 (SMB) + (5985/5986 or 139) |
| `WINDOWS_WEB` | IIS in product string, no Kerberos |
| `LINUX_WEB` | Port 22 (SSH) + HTTP, no SMB |
| `LINUX_AD` | SMB + LDAP, no Kerberos |
| `LINUX_SERVER` | Port 22, no HTTP |
| `UNKNOWN` | Default fallback |

### Phase 3: Service-Specific Modules

**Method:** `ReconEngine.phase3_modules()`

Launches service-specific enumeration modules concurrently. The process:

1. **Module discovery** (`_determine_modules`): Lazily imports all 16 module
   entry points (`from recon_ninja.modules.<name> import run_<name>_module`)
   inside `try/except ImportError` blocks so missing sub-packages don't crash
   the engine.

2. **Module filtering** (`_filter_relevant_modules`): Only keeps modules whose
   target service/port is present:

   | Module | Trigger Condition |
   |--------|------------------|
   | `web` | Any service containing `"http"` |
   | `smb` | Port 139 or 445 open |
   | `ssh` | Port 22 or service `"ssh"` |
   | `ftp` | Port 21 open |
   | `smtp` | Port 25, 465, or 587 open |
   | `snmp` | UDP port 161 open |
   | `dns` | Port 53 open |
   | `ldap` | Port 389 or 636 open |
   | `kerberos` | Port 88 open |
   | `rpc` | Port 111 or 135 open |
   | `nfs` | Port 2049 open |
   | `rdp` | Port 3389 open |
   | `vnc` | Port 5900–5910 open |
   | `winrm` | Port 5985 or 5986 open |
   | `database` | Port 3306/1433/5432/6379/27017/1521 open |
   | `ssl` | Service contains `"ssl"` or `"https"` |

3. **Module toggles**: `config.is_module_enabled(name)` checks `module_toggles`
   dict — defaults to `True` if not explicitly set. `--only-web`, `--no-smb`,
   `--no-vuln`, etc. all modify this dict.

4. **Resume filter**: Modules already in `state.completed_modules` are skipped.

5. **Concurrent execution**: All enabled modules run under an
   `asyncio.Semaphore(config.max_concurrent)`. Each module is wrapped in
   `_run_module()` which catches all exceptions and produces a
   `ModuleResult(status="error"|"timeout")` rather than crashing the pipeline.

6. **Result aggregation**: Each `ModuleResult.findings` is merged into
   `ScanState.all_findings` via `state.add_finding()` (deduplicates by
   `title+module`). Completed module names are appended to
   `state.completed_modules`.

**Module contract** — every module function has this signature:

```python
async def run_<name>_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult: ...
```

If a required external tool is missing, the module returns
`ModuleResult(status="skipped")` — this is the **graceful degradation** pattern.

### Phase 4: OSINT

**Method:** `ReconEngine.phase4_osint()`

Runs OSINT modules only when:
- `config.osint_enabled` is `True` (default), AND
- The target is a domain OR hostnames were discovered in Phase 2.

Tools executed (in sequence, not parallel):

| Tool | Command | Output File |
|------|---------|-------------|
| `dnsrecon` | `dnsrecon -d <domain> -t std -o dnsrecon.json` | `dnsrecon.txt` |
| `subfinder` | `subfinder -d <domain> -o subfinder.txt -silent` | `subfinder.txt` |
| `theHarvester` | `theHarvester -d <domain> -b all -f harvester` | `harvester.*` |

Each tool is only executed if found on PATH (`shutil.which()` check).
Missing tools are silently skipped.

### Phase 5: Vulnerability Correlation

**Method:** `ReconEngine.phase5_vuln_correlate()`

Also available as a standalone module (`modules/vuln_correlate.py`) for
reuse outside the engine. The workflow:

1. **searchsploit**: For each `ServiceInfo` with both `product` and `version`,
   runs `searchsploit --json "<product> <version>"`. If no results, retries
   with just `<product>` (broader search).

2. **nuclei**: For each HTTP/HTTPS service, runs nuclei with CVE, exposure,
   and misconfiguration templates at `critical,high,medium` severity.

3. **Deduplication**: Findings with the same CVE ID are merged, keeping the
   one with higher severity.

4. **NVD enrichment**: CVE findings are enriched with CVSS severity from the
   NVD API (`https://services.nvd.nist.gov/rest/json/cves/2.0`). If NVD
   reports a higher severity, it overrides the initial estimate.

Skipped entirely when `config.skip_vuln_correlate` is `True` (`--no-vuln`).

### Phase 6: Loot Extraction

**Method:** `ReconEngine.phase6_loot()`

Scans **all** `.txt` files in the output directory for common CTF/pentest
loot patterns using regex matching:

| Category | Patterns |
|----------|----------|
| `credentials` | `password`, `passwd`, `pwd`, `login`, `credential`, `secret`, `apikey`, `api_key`, `token` |
| `flags` | `flag{`, `HTB{`, `THM{`, `CTF{`, `picoCTF{` |
| `hashes` | `$id$` hash prefixes, 32/40/64-char hex strings |
| `keys` | `BEGIN (RSA\|DSA\|EC\|OPENSSH )?PRIVATE KEY`, `ssh-rsa`, `ssh-ed25519` |

Matches are written to `results/<target>/loot/<category>.txt` and promoted
to `Finding` objects (severity `INFO`) in the scan state.

The `core/loot.py` module provides a more structured standalone extractor
with additional categories (`usernames`, `emails`, `ips`, `paths`), capture
group extraction, and false-positive filtering.

Skipped when `config.skip_loot` is `True` (`--only-ports`).

### Phase 7: Report Generation

**Method:** `ReconEngine.phase7_report()`

Delegates to `core/report.py` → `generate_reports()`. Produces:

| Format | File | Always? | Trigger |
|--------|------|---------|---------|
| Markdown | `00_SUMMARY.md` | Yes | Always |
| HTML | `00_SUMMARY.html` | No | `--html` flag or `output.always_html` |
| JSON | `00_findings.json` | Yes (default) | `--json` flag (default on) |
| State | `state.json` | Yes | Always (for checkpoint/resume) |

Markdown report sections:
1. Target Information (IP, hostname, box profile, duration, open port count)
2. Open Ports & Services (table: port, proto, service, product, version)
3. Box Profile
4. Key Findings (sorted by severity with badges)
5. Per-Service Details (grouped by type with NSE script output)
6. Loot (category → count table)
7. Suggested Attack Paths (deduplicated commands from findings, top 10)
8. Raw Output File Index

HTML report: Self-contained dark-themed HTML document using an inline
Jinja2 template with CSS variables for theming. Includes finding cards
with severity color-coding, loot grid, and collapsible NSE script details.

---

## Core Modules

### `core/models.py` — Data Model

All core data structures are `@dataclass` classes with `to_dict()` /
`from_dict()` serialization for JSON checkpoint persistence.

**`Severity`** (str, Enum):
- `CRITICAL` → 🔴 rank 0
- `HIGH` → 🟠 rank 1
- `MEDIUM` → 🟡 rank 2
- `LOW` → 🔵 rank 3
- `INFO` → ⚪ rank 4

Properties: `rank` (int), `icon` (emoji), `rich_style` (Rich color string).

**`Finding`**: A single security finding from any module.

| Field | Type | Description |
|-------|------|-------------|
| `severity` | `Severity` | Impact level |
| `title` | `str` | Short description |
| `description` | `str` | Detailed explanation |
| `module` | `str` | Source module name (e.g. `"smb"`, `"vuln_correlate"`) |
| `evidence` | `str` | Raw evidence text |
| `cve` | `str \| None` | CVE identifier if applicable |
| `suggested_commands` | `list[str]` | Attack/exploitation commands |
| `timestamp` | `datetime` | Auto-set to `datetime.now()` |

**`ServiceInfo`**: Information about a single port/service.

| Field | Type | Description |
|-------|------|-------------|
| `port` | `int` | Port number |
| `proto` | `str` | `"tcp"` or `"udp"` |
| `state` | `str` | `"open"`, `"filtered"`, `"closed"` |
| `service` | `str` | Service name (e.g. `"http"`, `"ssh"`) |
| `product` | `str` | Product name (e.g. `"Apache httpd"`) |
| `version` | `str` | Version string (e.g. `"2.4.52"`) |
| `extra_info` | `str` | Additional nmap info |
| `scripts` | `dict[str, str]` | NSE script ID → output |
| `hostname` | `str \| None` | Discovered hostname |

Properties: `url` (constructs HTTP/HTTPS URL), `display_product` (product + version).

**`ModuleResult`**: Result from a single module execution.

| Field | Type | Description |
|-------|------|-------------|
| `module_name` | `str` | Module identifier |
| `status` | `str` | `"done"`, `"skipped"`, `"error"`, `"timeout"` |
| `findings` | `list[Finding]` | Security findings from this module |
| `raw_output` | `str` | Combined tool stdout (truncated to 10,000 chars) |
| `output_file` | `Path \| None` | Path to output directory/file |
| `duration_seconds` | `float` | Wall-clock time |
| `error_message` | `str` | Error details if status is `"error"` |

**`ScanState`**: Complete mutable scan state. Serialized as JSON after every
phase. Key properties:

- `add_finding(finding)`: Adds a finding, deduplicating by `title+module`.
- `findings_by_severity()`: Groups findings into `dict[Severity, list[Finding]]`.
- `duration`: Computed property `(end_time - start_time).total_seconds()`.
- `web_ports`: Ports with HTTP/HTTPS services.
- `primary_hostname`: First discovered hostname.
- `save()`: Writes `state.json` to `output_dir`.

**`ReconConfig`**: Runtime scan configuration, distinct from `MergeConfig`
(which represents the file-layer config). `ReconConfig` is what the engine
and modules receive.

### `core/runner.py` — Async Subprocess Execution

The fundamental building block for **all** tool execution. Never uses
`subprocess.run` — everything goes through `asyncio.create_subprocess_exec`.

**`run_tool(cmd, output_file, timeout, cwd, env)`**:
- Returns `(returncode, stdout, stderr)`.
- On timeout: kills the process, returns `(-1, "", "TIMEOUT after {timeout}s")`.
- On `FileNotFoundError`/`PermissionError`: returns `(-2, "", error_message)`.
- If `output_file` is provided, stdout is written to it.
- Environment variables are merged with `os.environ` (not replaced).

**`run_tool_streaming(cmd, ...)`**:
- Async generator yielding stdout lines as they arrive.
- Collects all lines and writes to `output_file` on completion.
- Same timeout/kill semantics as `run_tool`.

**`run_multiple(commands, max_concurrent, timeout)`**:
- Takes a list of `(name, cmd, output_file)` tuples.
- Runs them concurrently under an `asyncio.Semaphore(max_concurrent)`.
- Returns `dict[name, (rc, stdout, stderr)]`.
- Used by Phase 5 for parallel searchsploit/nuclei queries.

**`format_cmd(cmd)`**: Shell-quotes a command list for logging.

### `core/config.py` — Configuration System

See [Configuration System](#configuration-system) below.

### `core/state.py` — State Manager

See [State & Checkpoint/Resume](#state--checkpointresume) below.

### `core/display.py` — Rich Terminal UI

All visual output uses the `rich` library. The module maintains a
module-level `Console` instance that can be swapped via `set_console()`
(for testing or file redirection).

Key functions:

| Function | Description |
|----------|-------------|
| `display_banner()` | Startup banner with target, interface, root status |
| `display_preflight_checklist()` | Tool availability table with icons |
| `display_phase_header()` | Phase number + name with rule line |
| `display_port_table()` | Color-coded service table |
| `display_box_profile()` | Classification badge |
| `display_findings_panel()` | Findings sorted by severity |
| `display_next_steps()` | Suggested commands panel (top 8) |
| `display_loot_summary()` | Loot category grid with icons |
| `display_scan_summary()` | Complete post-scan summary |
| `create_progress_tracker()` | Multi-task Rich `Progress` bar |
| `create_phase_progress()` | Single indeterminate progress spinner |
| `live_scan_display()` | `Live` context wrapping progress tracker |

Service types are color-coded (HTTP=green, SSH=cyan, SMB=yellow,
Kerberos=red, etc.) via the `_SERVICE_STYLES` mapping.

### `core/loot.py` — Loot Extractor

Standalone regex-based extractor that walks all output files and extracts
structured loot. More granular than the engine's Phase 6:

| Category | Patterns | False-Positive Filters |
|----------|----------|----------------------|
| `usernames` | `Username:\s+(\S+)`, `uid=\d+\((\w+)\)`, `user:\s*(\S+)` | CVE IDs |
| `hashes` | 32-char hex, `$id$` prefixes, NTLM format | All-zero/all-f hex |
| `emails` | Standard email regex | `@example.com/org/net` |
| `passwords` | `Password:\s+(\S+)`, `Pass:\s+(\S+)`, `pwd:\s+(\S+)` | `****` masked values |
| `ips` | RFC 1918 private ranges (10.x, 172.16-31.x, 192.168.x) | — |
| `paths` | Unix paths (2+ segments) | — |

Functions:
- `extract_loot(output_dir)`: Walks directory tree, returns `dict[str, list[str]]`.
- `save_loot(output_dir, loot)`: Writes `loot/<category>.txt` files.
- `loot_to_findings(loot)`: Converts significant loot to `Finding` objects
  (passwords → CRITICAL, hashes → HIGH, others → INFO).

---

## Reconnaissance Modules

All modules live in `recon_ninja/modules/` and follow the same contract:
an async function `run_<name>_module(target, state, config, output_dir) -> ModuleResult`.

### Web Module (`modules/web/`)

The web module is a composite of four sub-modules orchestrated by
`modules/web/__init__.py`. For each HTTP port discovered:

1. **`web_core.py`**: HTTP fingerprinting using `whatweb`, `curl`, and `httpx`.
2. **`web_dirfuzz.py`**: Directory/file fuzzing. Chooses the preferred fuzzer
   from `config.module_toggles` or `ToolsConfig.preferred_dir_fuzzer`
   (feroxbuster → gobuster → ffuf fallback chain).
3. **`web_vuln.py`**: Web vulnerability scanning with `nikto` and `nuclei`.
4. **`web_cms.py`**: CMS detection using `wpscan` (WordPress),
   `droopescan` (Drupal/SilverStripe), and `joomscan` (Joomla).

Results from all sub-modules and ports are aggregated into a single
`ModuleResult(module_name="web")`.

### SMB Module (`modules/smb.py`)

Runs a 5-step SMB enumeration pipeline:

1. `enum4linux-ng` / `enum4linux` — full enumeration (anonymous/guest access,
   OS/domain info).
2. `smbclient -L` — null session share listing.
3. `smbmap` — share permission enumeration (read/write detection, guest retry).
4. `nmap --script smb-vuln-ms17-010,smb-vuln-cve-2020-0796` — EternalBlue/SMBGhost detection.
5. `crackmapexec smb` — signing status, null session confirmation.

Produces findings for anonymous access (HIGH), guest access (HIGH),
writable shares (HIGH), signing not required (MEDIUM), EternalBlue (CRITICAL),
SMBGhost (CRITICAL).

### Vulnerability Correlation (`modules/vuln_correlate.py`)

Detailed in [Phase 5](#phase-5-vulnerability-correlation) above. Key
implementation details:

- **searchsploit parsing**: Handles `RESULTS_SEARCH`, `RESULTS_EXPLOIT`, and
  `results` JSON keys (different across searchsploit versions). Extracts
  CVE IDs from messy/comma-separated strings.
- **nuclei parsing**: Processes JSONL output, maps nuclei severity strings
  to the `Severity` enum, extracts CVEs from template IDs and references.
- **Deduplication**: By CVE ID (keeps higher severity) or by title (for
  non-CVE findings).
- **NVD enrichment**: Queries the NVD 2.0 API, prefers CVSS v3 over v2,
  can upgrade (but never downgrade) severity based on NVD data.

### Other Modules

All follow the same pattern: check if required tools exist, run them via
`run_tool()`, parse output with regex, produce `Finding` objects.

| Module | Primary Tools | Key Findings |
|--------|--------------|-------------|
| `ssh.py` | `ssh-audit`, nmap scripts | Weak ciphers, key algorithms |
| `ftp.py` | `ftp`, nmap scripts | Anonymous login |
| `smtp.py` | `smtp-enum`, nmap scripts | Open relay, user enumeration |
| `snmp.py` | `snmpwalk`, `onesixtyone` | Community strings, system info |
| `dns.py` | `dnsrecon`, `dig` | Zone transfer, records |
| `ldap.py` | `ldapsearch`, `windapsearch` | AD structure, users, groups |
| `kerberos.py` | `kerbrute`, nmap scripts | Pre-auth users, AS-REP roastable |
| `rpc.py` | `rpcclient`, nmap scripts | RPC endpoints, user list |
| `nfs.py` | `showmount`, nmap scripts | Exported shares |
| `rdp.py` | nmap scripts, `xfreerdp` | Security layer, CredSSP |
| `vnc.py` | nmap scripts | VNC auth type |
| `winrm.py` | `crackmapexec`, nmap scripts | WinRM version, auth methods |
| `database.py` | nmap scripts | Database type, version |
| `ssl.py` | `sslscan`, `testssl.sh` | Weak ciphers, cert issues, heartbleed |
| `osint.py` | `dnsrecon`, `subfinder`, `theHarvester` | Subdomains, emails, DNS records |

---

## Utility Modules

### `utils/checker.py` — Tool Detection

Comprehensive tool detection with rich metadata. The `TOOL_REGISTRY` list
contains `ToolInfo` entries for 30+ tools:

- **8 required tools**: nmap, smbclient, nikto, whatweb, sslscan, dnsrecon,
  searchsploit, ldapsearch
- **22 optional tools**: RustScan, feroxbuster, gobuster, ffuf, nuclei,
  subfinder, httpx, kerbrute, gowitness, amass, windapsearch, theHarvester,
  crackmapexec, ssh-audit, enum4linux-ng, smbmap, droopescan, onesixtyone,
  snmpwalk, wpscan, testssl.sh, joomscan

**Detection strategy** (per `check_tool()`):

1. `shutil.which(name)` — standard PATH lookup
2. Try each `alt_name` via `shutil.which()` (e.g. `enum4linux` for `enum4linux-ng`)
3. Check extra search paths: `~/go/bin/`, `~/.local/bin/`,
   `/usr/local/bin/`, `/usr/local/sbin/`, `/opt/recon-tools/`, `/opt/`
4. If found, detect version by running `<binary> <version_flag>` and parsing
   the first meaningful line of output

**`ToolInfo` dataclass** fields:
`name`, `category` ("required"/"optional"), `install_method` ("apt"/"go"/"pip"/"cargo"/"gem"/"git"/"manual"),
`install_package`, `alt_names`, `version_flag`, `description`,
`found`, `path`, `version`, `which_name`.

### `utils/installer.py` — Auto-Installer

The `ToolInstaller` class installs all tools from `TOOL_REGISTRY` using
the appropriate method for each.

**6 install methods:**

| Method | Command | Example |
|--------|---------|---------|
| `apt` | `sudo apt install -y <package>` | `nmap` |
| `go` | `go install <module>@latest` | `github.com/ffuf/ffuf/v2@latest` |
| `pip` | `pip install <package>` (with `--break-system-packages` fallback) | `theHarvester` |
| `cargo` | `cargo install <crate>` | `rustscan` |
| `gem` | `gem install <gem>` | `wpscan` |
| `git` | `sudo git clone --depth 1 <url> /opt/recon-tools/<repo>` | `testssl.sh` |

**Prerequisites**: The installer automatically detects and installs Go and
Rust/Cargo if needed (Go via apt or binary tarball, Rust via rustup).

**SecLists**: Installed via apt or git clone to `/usr/share/seclists`.

**PATH configuration**: Appends `~/go/bin` and `~/.local/bin` to `.bashrc`
and `.zshrc`, sources `~/.cargo/env`.

**Idempotent**: Already-installed tools are detected via `check_tool()` and
skipped.

### `utils/network.py` — Network Utilities

- `validate_target(target)`: Validates IPv4, IPv6, CIDR, or hostname.
  Resolves hostnames via DNS. Returns `(bool, str)`.
- `check_vpn_interface(interface="tun0")`: Parses `ip addr show <if>`.
  Returns `(bool, ip_or_error)`.
- `is_root()`: Checks `os.geteuid() == 0`.
- `get_local_ip(interface)`: Returns IP of interface or `None`.
- `is_private_ip(ip)`: Checks RFC 1918 ranges.
- `expand_cidr(cidr)`: Expands CIDR to individual host addresses.

### `utils/hosts.py` — /etc/hosts Helper

- `read_etc_hosts()`: Parses `/etc/hosts` into `list[(ip, hostname)]`.
- `hostname_exists(hostname)`: Case-insensitive search.
- `add_to_hosts(ip, hostname)`: Appends via `sudo tee -a /etc/hosts`.
  Idempotent (skips if hostname already exists).

### `utils/wordlists.py` — SecLists Resolver

- `find_seclists()`: Searches `/usr/share/seclists`, `/opt/seclists`,
  `~/SecLists`, `/usr/local/share/seclists`. Returns base path or `None`.
- `resolve_wordlist(name, seclists_base, custom_dir)`: Tries custom_dir
  first, then seclists_base. Direct path lookup, then recursive glob by
  filename.
- Category helpers: `get_dir_wordlist()`, `get_vhost_wordlist()`,
  `get_username_wordlist()`, `get_snmp_wordlist()`. Each tries multiple
  candidate paths in priority order.

### `utils/nmap_parser.py` — Nmap Output Parser

Pure `xml.etree.ElementTree` parser (no `python-nmap` dependency).

- `parse_nmap_xml(xml_path)`: Returns `(dict[int, ServiceInfo], list[str])`
  (services + hostnames). Extracts port, service, product, version,
  NSE script output, and hostnames from `<hostname>` elements and
  `http-title` scripts.
- `parse_rustscan_output(output)`: Extracts port numbers from RustScan text.
  Handles both `Open <port>` and `<port>/tcp` formats.
- `parse_nmap_grepable(output)`: Parses nmap `-oG` output for open ports.

---

## Key Design Patterns

### Async-First Architecture

All tool execution uses `asyncio.create_subprocess_exec` (never
`subprocess.run`). This allows many tools to run concurrently without
blocking the event loop. The `core/runner.py` module is the single
source of truth for subprocess management.

### Checkpoint/Resume

`ScanState` is serialized to JSON (`scan.state`) after every completed
phase. On `--resume`, the engine skips phases where
`state.current_phase > phase_num`. Individual modules are also skipped
if they appear in `state.completed_modules`. This enables crash-safe
resumption of long-running scans.

### Module Auto-Discovery

The engine lazily imports module entry points inside `try/except ImportError`
blocks. This means:
- Missing sub-packages don't crash the engine at import time.
- Only modules relevant to detected services are loaded.
- Module filtering is a two-stage process: import, then port/service check.

### Graceful Degradation

Every module checks for its required tools before running. If a tool is
missing, the module returns `ModuleResult(status="skipped")` instead of
raising an error. The pipeline always continues to the next phase/module.
Phase-level exceptions are caught, recorded as HIGH findings, and the
engine proceeds.

### Semaphore-Gated Concurrency

`asyncio.Semaphore(config.max_concurrent)` controls the maximum number
of concurrent module executions in Phase 3. Default is 10, configurable
via `--threads` / `config.scan.default_threads`.

### Box Classification

Auto-detects the target type based on port/service patterns. This
classification drives module selection and report presentation. Six
profiles are supported: `WINDOWS_AD`, `WINDOWS_WEB`, `LINUX_WEB`,
`LINUX_AD`, `LINUX_SERVER`, `UNKNOWN`.

### Custom CLI Group

`ReconNinjaGroup` extends `TyperGroup` to route unknown first arguments
to the `scan` command. This enables `reconninja 10.10.10.1` as a
shorthand for `reconninja scan 10.10.10.1`.

---

## Configuration System

Three configuration layers are deep-merged in order of increasing
precedence:

```
Built-in defaults (_DEFAULT_CONFIG dict)
        ↓  deep merge
YAML file (config/default_config.yaml, then ~/.config/reconninja/config.yaml)
        ↓  deep merge
CLI overrides (_build_cli_overrides dict)
```

### Deep Merge

The `_deep_merge(base, override)` function recursively merges nested
dicts. Non-dict values in `override` replace `base` values entirely.
`None` values in `override` are treated as intentional (they override).

### Section Dataclasses

The merged dict is converted into typed dataclass sections:

| Section | Dataclass | Fields |
|---------|-----------|--------|
| `scan` | `ScanConfig` | `default_threads`, `default_timeout`, `nmap_min_rate`, `rustscan_ulimit`, `udp_enabled`, `stealth_mode` |
| `wordlists` | `WordlistsConfig` | `seclists_base`, `dir_medium`, `dir_small`, `vhosts`, `usernames`, `snmp`, `custom_dir` + path properties |
| `tools` | `ToolsConfig` | `preferred_dir_fuzzer`, `preferred_smb_enum` |
| `output` | `OutputConfig` | `always_html`, `always_json`, `timestamp_dirs` |
| `htb` | `HTBConfig` | `vpn_interface`, `auto_add_hosts`, `machine_name` |
| `api_keys` | `APIKeysConfig` | `shodan`, `nvd` |

Unknown keys in the YAML file are silently ignored (via
`_dict_to_section()` which filters to valid dataclass fields).

### Singleton Access

`get_config()` provides a module-level singleton for code that needs
config without explicit injection. `reset_config()` clears the singleton
for testing.

### Default YAML

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

---

## Tool Detection

The `utils/checker.py` module provides enhanced tool detection beyond
simple `shutil.which()`:

### Detection Strategy

For each `ToolInfo` in `TOOL_REGISTRY`:

1. **PATH lookup**: `shutil.which(tool_info.name)`
2. **Alternative names**: Try each `tool_info.alt_names` via `shutil.which()`
   (e.g., `enum4linux-ng` also checks for `enum4linux`)
3. **Extra search paths**: Check `~/go/bin/`, `~/.local/bin/`,
   `/usr/local/bin/`, `/usr/local/sbin/`, `/opt/recon-tools/`, `/opt/`
4. **Version detection**: Run `<binary> <version_flag>` (default `--version`,
   but some tools use `-V`, `-VV`, `--help`). Parse the first non-empty,
   non-usage line. Timeout: 10 seconds.

### Tool Categories

- **Required** (8): Must be present for a full scan. Missing required tools
  trigger a warning and may cause modules to return `status="skipped"`.
- **Optional** (22): Enhance the scan but are not mandatory. Missing optional
  tools cause individual checks to be silently skipped.

### API Surface

| Function | Returns | Description |
|----------|---------|-------------|
| `check_tools()` | `dict[str, bool]` | Quick availability check for all tools |
| `check_tools_detailed()` | `list[ToolInfo]` | Full detection with version, path, install metadata |
| `check_tool(tool_info)` | `ToolInfo` | Check a single tool (mutates in-place) |
| `get_missing_required(available)` | `list[str]` | Names of missing required tools |
| `get_missing_optional(available)` | `list[str]` | Names of missing optional tools |
| `format_detailed_status(tools)` | `None` | Rich console display with versions/paths |

---

## Auto-Installer

The `utils/installer.py` module provides the `ToolInstaller` class for
automated tool installation.

### Install Flow

```
ToolInstaller.install_all()
  │
  ├── 1. Install prerequisites (Go, Rust/Cargo)
  │     ├── _install_go_if_needed()     # apt install golang OR binary tarball
  │     └── _install_rust_if_needed()   # rustup
  │
  ├── 2. Update package lists
  │     └── _pkg_update(pkg_mgr)        # apt update / dnf check-update / pacman -Sy
  │
  ├── 3. Install required tools
  │     └── For each ToolInfo with category="required":
  │         _install_single_tool(tool)  # Routes to apt/go/pip/cargo/gem/git
  │
  ├── 4. Install optional tools
  │     └── For each ToolInfo with category="optional":
  │         _install_single_tool(tool)
  │
  ├── 5. Install SecLists wordlists
  │     └── _install_seclists()          # apt or git clone
  │
  └── 6. Configure PATH
        └── _configure_path()            # Append ~/go/bin, ~/.local/bin to .bashrc/.zshrc
```

### Install Methods

Each `_install_*_tool()` function follows the same pattern:
1. Check prerequisites (Go, pip, gem, etc.) — skip if unavailable.
2. Run the install command synchronously (`subprocess.run` with timeout).
3. Verify installation (check binary exists in expected path).
4. Return `InstallResult` with status `"installed"`, `"skipped"`,
   `"already_installed"`, or `"failed"`.

### CLI Integration

The `reconninja install` command provides:
- `--required`: Install only required tools.
- `--optional`: Install only optional tools.
- `-v / --verbose`: Show detailed output.

---

## State & Checkpoint/Resume

The `core/state.py` module manages scan state persistence.

### State File Location

```
results/<target>/scan.state
```

The state file is plain JSON (human-readable, diff-friendly).

### StateManager API

| Method | Description |
|--------|-------------|
| `init_state()` | Create fresh `ScanState`, persist to disk |
| `load_state()` | Deserialize from `scan.state`, return `None` if missing/corrupt |
| `save()` | Persist in-memory state to disk |
| `mark_completed(module_name)` | Append to `completed_modules` and persist |
| `is_completed(module_name)` | Check if module was done in a prior run |
| `completed_modules()` | Return copy of completed module list |
| `remaining_modules(all)` | Return subset not yet completed |

### Resume Flow

1. User runs `reconninja <target> --resume`.
2. `StateManager.load_state()` deserializes `scan.state`.
3. `ReconEngine.run()` iterates phases 1–7, skipping any where
   `state.current_phase > phase_num`.
4. Phase 3 additionally skips modules in `state.completed_modules`.
5. On `KeyboardInterrupt` or exception, `state.save()` is called to
   preserve progress.

### Error Handling

- Missing state file: Returns `None`, engine starts fresh.
- Corrupted JSON: Logs error, returns `None`.
- Schema mismatch: Logs error, returns `None`.
- Write failures: Logged but never raised — losing a checkpoint should
  not crash the scan.

---

## Report Generation

The `core/report.py` module generates multi-format reports from a
completed `ScanState`.

### Markdown Report (`00_SUMMARY.md`)

Built programmatically using `_build_markdown(state)`. Sections:

1. Header with target, timestamp
2. Target Information table (IP, hostname, box profile, duration, ports)
3. Open Ports & Services table
4. Box Profile
5. Key Findings (sorted by severity with shields.io badges)
6. Per-Service Details (grouped by type: Web, SMB, SSH, etc.)
7. Loot table (category → count)
8. Suggested Attack Paths (deduplicated commands, top 10)
9. Raw Output File Index

### HTML Report (`00_SUMMARY.html`)

Rendered via Jinja2 from an inline template (no external template files).
Features:

- Dark theme with CSS variables (`--bg-primary: #1a1a2e`, etc.)
- Severity color-coded finding cards with left border accent
- Loot grid with counts
- Collapsible NSE script details (`<details>/<summary>`)
- Self-contained (no external CSS/JS dependencies)

### JSON Report (`00_findings.json`)

Machine-readable export containing:
- Target, scan time, box profile
- Open ports (port, proto, state, service, product, version)
- Services (full `ServiceInfo` dicts keyed by port string)
- Findings (severity, title, description, CVE, module, suggested commands)
- Loot (category → item list)

### Async File I/O

All report files are written using `aiofiles` (async file I/O) to avoid
blocking the event loop during large report generation.

---

## Testing

The project includes 310 pytest tests covering all modules:

| Test File | Coverage Area |
|-----------|---------------|
| `test_engine.py` | Phase execution, module filtering, box classification, RustScan/nmap parsing |
| `test_runner.py` | `run_tool()`, `run_tool_streaming()`, `run_multiple()`, timeout handling |
| `test_models.py` | Serialization/deserialization, finding deduplication, severity ranking |
| `test_report.py` | Markdown/HTML/JSON generation, loot extraction, command deduplication |
| `test_state.py` | State persistence, resume, module completion tracking |
| `test_utils.py` | Tool detection, network validation, VPN check, hosts helper |
| `test_loot.py` | Regex patterns, false-positive filtering, loot-to-findings conversion |
| `test_config.py` | Config merge, deep merge, YAML loading, section dataclass conversion |
| `test_modules.py` | Module contracts, skip conditions, finding generation |
| `test_parser.py` | Nmap XML, grepable, and RustScan output parsing |
