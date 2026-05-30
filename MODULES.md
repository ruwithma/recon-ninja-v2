# ReconNinja v2 — Service Module Reference

This document covers all 18 service modules, their external tool dependencies,
trigger conditions, findings, and the shared async interface they implement.

---

## Table of Contents

- [Module Interface](#module-interface)
- [Engine Dispatch Logic](#engine-dispatch-logic)
- [Web Module](#web-module) (4 sub-modules)
- [SMB Module](#smb-module)
- [SSH Module](#ssh-module)
- [FTP Module](#ftp-module)
- [SMTP Module](#smtp-module)
- [SNMP Module](#snmp-module)
- [DNS Module](#dns-module)
- [LDAP Module](#ldap-module)
- [Kerberos Module](#kerberos-module)
- [RPC Module](#rpc-module)
- [NFS Module](#nfs-module)
- [RDP Module](#rdp-module)
- [VNC Module](#vnc-module)
- [WinRM Module](#winrm-module)
- [Database Module](#database-module)
- [SSL Module](#ssl-module)
- [OSINT Module](#osint-module)
- [Vulnerability Correlation Module](#vulnerability-correlation-module)
- [Tool Dependency Summary](#tool-dependency-summary)

---

## Module Interface

Every module exposes the same async entry point:

```python
async def run_X_module(
    target: str,
    state: ScanState,
    config: ReconConfig,
    output_dir: Path,
) -> ModuleResult
```

| Parameter | Type | Description |
|---|---|---|
| `target` | `str` | Raw target IP or hostname from the CLI |
| `state` | `ScanState` | Shared scan state with discovered ports, services, hostnames, and accumulated findings |
| `config` | `ReconConfig` | Scan configuration — timeouts, toggles, wordlist paths, API keys |
| `output_dir` | `Path` | Per-target output directory for raw tool output files |

### ModuleResult

```python
@dataclass
class ModuleResult:
    module_name: str          # e.g. "smb", "web", "ssl"
    status: str               # "done" | "skipped" | "error" | "timeout"
    findings: list[Finding]   # Security findings discovered by this module
    raw_output: str           # Concatenated tool stdout (truncated)
    output_file: Path | None  # Primary output directory or file
    duration_seconds: float   # Wall-clock execution time
    error_message: str        # Non-empty when status is "error" or "skipped"
```

### Finding

```python
@dataclass
class Finding:
    severity: Severity                # CRITICAL | HIGH | MEDIUM | LOW | INFO
    title: str                        # Short, human-readable summary
    description: str                  # Detailed explanation
    module: str                       # Module name that produced this finding
    evidence: str                     # Raw evidence from tool output
    cve: str | None                   # CVE identifier if applicable
    suggested_commands: list[str]     # Follow-up commands for the operator
    timestamp: datetime
```

### Graceful Degradation

Every tool invocation is guarded by `shutil.which()`. If a required external
tool is not installed, the module logs a debug message and skips that step
rather than crashing. The module still returns a `ModuleResult` — typically
with `status="done"` but fewer findings, or `status="skipped"` if no relevant
tools are available at all.

---

## Engine Dispatch Logic

The `ReconEngine` (in `recon_ninja/core/engine.py`) runs modules during
**Phase 3 — Service-Specific Modules**. It calls `_determine_modules()` which
imports every module lazily and then filters them by the services discovered
in Phase 2:

| Module | Trigger Condition |
|---|---|
| `web` | Any service containing `"http"` in its name |
| `smb` | Port 139 or 445 open |
| `ssh` | Port 22 open, or service name contains `"ssh"` |
| `ftp` | Port 21 open |
| `smtp` | Port 25, 465, or 587 open |
| `snmp` | UDP port 161 detected |
| `dns` | Port 53 open (TCP or UDP) |
| `ldap` | Port 389 or 636 open |
| `kerberos` | Port 88 open |
| `rpc` | Port 111 or 135 open |
| `nfs` | Port 2049 open |
| `rdp` | Port 3389 open |
| `vnc` | Any port in 5900–5910 open |
| `winrm` | Port 5985 or 5986 open |
| `database` | Port 3306, 1433, 5432, 6379, 27017, or 1521 open |
| `ssl` | Service name contains `"ssl"` or `"https"`, or port is 443/8443 |

Modules can also be individually disabled via `config.module_toggles` or
skipped automatically if they already appear in `state.completed_modules`
(for resume support). The engine runs all applicable modules concurrently,
bounded by `config.max_concurrent` (default: 10).

---

## Web Module

**Source:** `recon_ninja/modules/web/`
**Entry point:** `run_web_module()` in `web/__init__.py`
**Trigger:** Any HTTP/HTTPS service detected

The Web module is a composite module — its top-level `run_web_module()`
iterates over every HTTP port discovered in the scan state and runs four
sub-modules in sequence for each port:

```
web_core → web_dirfuzz → web_vuln → web_cms
```

All sub-module findings are aggregated into a single `ModuleResult` with
`module_name="web"`.

### web_core

**Source:** `recon_ninja/modules/web/web_core.py`
**External tools:** `curl`, `whatweb`, `wafw00f`, `gowitness`

| Step | Tool | Purpose | Output File |
|---|---|---|---|
| 1 | `curl -sI -L --max-redirs 5` | Fetch response headers, follow redirects, extract server banner, cookies, hostnames from `Location` / `Set-Cookie` headers | `curl_headers.txt` |
| 2 | `whatweb -a 3` | Technology stack fingerprinting — CMS, frameworks, languages | `whatweb.txt` |
| 3 | `wafw00f` | Web Application Firewall detection | `wafw00f.txt` |
| 4 | `curl -sL` | Fetch `/robots.txt` and `/sitemap.xml` | `robots_txt`, `sitemap_xml` |
| 5 | `gowitness single` | Screenshot capture of the web page | `screenshots/` directory |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| Server banner disclosed | INFO | `Server:` header reveals software/version |
| Missing security header | INFO | Each absent header from {CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy} is flagged |
| WAF detected | INFO | wafw00f reports a firewall product |
| CMS detected (WordPress/Drupal/Joomla/etc.) | INFO | whatweb identifies a CMS and version |
| Framework detected (PHP/Express/Django/etc.) | INFO | whatweb identifies a backend framework |
| Discovered `/robots.txt` or `/sitemap.xml` | INFO | File is accessible and non-empty |

**Internal helpers:**
- `_parse_curl_headers()` — Parses curl `-sI -L` output into a lowercase header dict, keeping only the final response after redirects.
- `_extract_hostnames_from_headers()` — Extracts hostnames from `Location` and `Set-Cookie domain=` directives, adding them to `state.hostnames`.
- `_parse_whatweb()` — Extracts `Name[Detail]` pairs from whatweb output into a tech-name → detail mapping.
- `_check_security_headers()` — Compares response headers against the `REQUIRED_SECURITY_HEADERS` constant and returns one finding per missing header.

### web_dirfuzz

**Source:** `recon_ninja/modules/web/web_dirfuzz.py`
**External tools:** `feroxbuster` (primary), `gobuster` (fallback), `ffuf` (vhost fallback), `curl`

| Step | Tool | Purpose | Output File |
|---|---|---|---|
| 1 | `feroxbuster` or `gobuster dir` | Directory and file brute forcing with context-aware extensions | `feroxbuster.txt` or `gobuster_dir.txt` |
| 2 | `gobuster vhost` or `ffuf` | Virtual host enumeration (only when a hostname is known) | `gobuster_vhost.txt` or `ffuf_vhost.txt` |
| 3 | `curl -sI` (async HEAD) | Probe 15+ common sensitive paths | In-memory only |

**Extension selection logic** — The `_determine_extensions()` function inspects
`state.all_findings` from `web_core` and the service product name to choose
the right file extensions for the fuzzer:

| Tech Stack | Extensions |
|---|---|
| IIS / ASP.NET | `asp,aspx,txt,html,config` |
| Tomcat / Java | `jsp,do,action,java` |
| Apache / Nginx / PHP | `php,txt,html,sh,bak` |
| Generic (fallback) | `php,html,txt,js,json` |

**Sensitive path probes** — 15 common paths are checked concurrently via
async `curl -sI` HEAD requests, each with a default severity:

| Path | Default Severity |
|---|---|
| `/.git/`, `/.git/HEAD` | HIGH |
| `/.env` | CRITICAL |
| `/.htpasswd` | HIGH |
| `/config.php.bak` | HIGH |
| `/swagger.json`, `/graphql` | MEDIUM |
| `/phpinfo.php`, `/backup/`, `/web.config` | MEDIUM |
| `/admin`, `/admin/`, `/.htaccess`, `/server-status` | LOW |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| Fuzz: `<path>` (HTTP 200, `<size>`B) | LOW–HIGH | Discovered path via directory brute force; severity escalates for sensitive paths |
| Vhost found | INFO | Virtual host discovered on the server |
| Path found: `/.env` (HTTP 200) | CRITICAL | Environment file is publicly accessible |
| Path found: `/.git/HEAD` (HTTP 200) | HIGH | Git repository is exposed |

### web_cms

**Source:** `recon_ninja/modules/web/web_cms.py`
**External tools:** `wpscan`, `droopescan`, `joomscan`, `curl`

| Step | Tool | Purpose | Condition |
|---|---|---|---|
| 1 | `wpscan --enumerate u,p,t` | WordPress user, plugin, and theme enumeration | CMS = WordPress (detected by `web_core`) |
| 2 | `droopescan scan drupal` | Drupal scanning and version detection | CMS = Drupal |
| 3 | `joomscan -u` | Joomla scanning and vulnerability detection | CMS = Joomla |
| 4 | `curl -sI` | Application server detection: Tomcat (`/manager/html`), Jenkins (`/script`), Spring Boot (`/actuator`, `/actuator/env`) | Always |
| 5 | `curl -s` | API endpoint discovery: `/api/`, `/swagger.json`, `/openapi.json`, `/graphql`, `/graphiql`, etc. | Always |
| 6 | `curl -s -X POST` | GraphQL introspection query against discovered GraphQL endpoint | If `/graphql` responds |
| 7 | `curl -s` | Sensitive file exposure check: `/.git/HEAD`, `/.env`, `/config.php.bak`, `/web.config` | Always |

CMS detection is performed by `_detect_cms()` which reads findings from
`web_core` and looks for WordPress, Drupal, or Joomla in the title text.

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| WordPress users found | MEDIUM | wpscan enumerated usernames (suggests password spraying) |
| WordPress vulnerability | HIGH | wpscan reported a known vulnerability |
| Drupal/Joomla findings | INFO–MEDIUM | Scanner output parsed for vulnerabilities |
| App server detected: Tomcat Manager | HIGH | `/manager/html` responds (suggests default creds) |
| App server detected: Jenkins Script Console | CRITICAL | `/script` responds (unauthenticated RCE possible) |
| App server detected: Spring Boot Actuator | MEDIUM–HIGH | `/actuator` or `/actuator/env` responds |
| GraphQL introspection enabled | HIGH | Full schema is publicly queryable |
| Sensitive file exposed | HIGH–CRITICAL | `.git`, `.env`, or config backups accessible |

### web_vuln

**Source:** `recon_ninja/modules/web/web_vuln.py`
**External tools:** `nikto`, `nuclei`

| Step | Tool | Purpose | Timeout |
|---|---|---|---|
| 1 | `nikto -h` | Comprehensive web-server vulnerability scanner | 180 s |
| 2 | `nuclei -u -tags cve,exposure,misconfig` | Template-based vulnerability scanning | 300 s |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| Nikto findings with CVE/OSVDB references | MEDIUM | Lines starting with `+` containing CVE or OSVDB IDs |
| Nikto findings with high-risk keywords | MEDIUM | Password, injection, XSS, RCE, config file, `.env`, `.git` |
| Other Nikto findings | INFO | General information disclosures |
| Nuclei template matches | Per template | Severity mapped from nuclei output: critical/high/medium/low/info |

**Parsing:**
- `_parse_nikto_findings()` — Extracts lines starting with `+`, detects CVE/OSVDB references, and applies keyword-based severity escalation.
- `_parse_nuclei_findings()` — Matches the `[template-id] [type] [severity] url` line format and maps nuclei severity strings to the `Severity` enum.

---

## SMB Module

**Source:** `recon_ninja/modules/smb.py`
**Entry point:** `run_smb_module()`
**Trigger:** Port 139 or 445 open
**External tools:** `enum4linux-ng` / `enum4linux`, `smbclient`, `smbmap`, `nmap`, `crackmapexec`

| Step | Tool | Command | Purpose |
|---|---|---|---|
| 1 | `enum4linux-ng -A` (or `enum4linux -a`) | Full SMB enumeration | Anonymous/guest access, OS/domain info, share listing |
| 2 | `smbclient -L //<target>/ -N` | Null session share listing | List accessible shares without authentication |
| 3 | `smbmap -H` (null session, then guest) | Share permission mapping | Identify readable and writable shares |
| 4 | `nmap --script smb-vuln-ms17-010,smb-vuln-cve-2020-0796` | Vulnerability scanning | EternalBlue and SMBGhost detection |
| 5 | `crackmapexec smb` | Signing and null session status | SMB signing requirement check, null session confirmation |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| SMB Anonymous Access Enabled | HIGH | Null session access confirmed |
| SMB Guest Access Enabled | HIGH | Guest access without authentication |
| SMB OS/Domain Information | INFO | OS and domain details from enum4linux |
| SMB Shares Discovered (Null Session) | INFO | Share names enumerated via unauthenticated smbclient |
| Writable SMB Shares Found | HIGH | Shares writable without auth — file drop / lateral movement risk |
| Readable SMB Shares Found | HIGH | Shares readable without auth — data exfiltration risk |
| MS17-010 EternalBlue Vulnerable | CRITICAL | Unauthenticated RCE via CVE-2017-0144 |
| CVE-2020-0796 SMBGhost Vulnerable | CRITICAL | SMBv3 compression RCE |
| SMB Signing Not Required | MEDIUM | Susceptible to NTLM relay attacks |

**Output directory:** `<output_dir>/smb/`

---

## SSH Module

**Source:** `recon_ninja/modules/ssh.py`
**Entry point:** `run_ssh_module()`
**Trigger:** Port 22 open, or service name contains `"ssh"`
**External tools:** `nmap` (NSE scripts), `ssh-audit`

| Step | Tool | NSE Scripts | Purpose |
|---|---|---|---|
| 1 | `nmap` | `ssh-auth-methods, ssh2-enum-algos, ssh-hostkey` | Auth methods, algorithm enumeration, host key |
| 2 | `ssh-audit` | — | Detailed algorithm and configuration audit |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| SSH Banner / Version | INFO | Server banner string |
| SSH Password Authentication Enabled | HIGH | Password-based auth is susceptible to brute force |
| SSH Key-Only Authentication | INFO | Only public-key auth is accepted (good) |
| Weak SSH Algorithms Detected | MEDIUM | Deprecated algorithms found (e.g., `diffie-hellman-group1-sha1`, `aes128-cbc`, `hmac-md5`, `ssh-dss`) |
| SSH Host Key | INFO | Key fingerprint information |
| SSH Audit: Failed Check | HIGH | ssh-audit reported a `(fail)` result |
| SSH Audit: Warning | MEDIUM | ssh-audit reported a `(warn)` result |

The weak algorithm check in `_identify_weak_algos()` compares detected
algorithms against a hardcoded set of insecure key exchange methods, ciphers,
MACs, and host key types.

**Output directory:** `<output_dir>/ssh/`

---

## FTP Module

**Source:** `recon_ninja/modules/ftp.py`
**Entry point:** `run_ftp_module()`
**Trigger:** Port 21 open
**External tools:** `nmap` (NSE scripts)

| Step | Tool | NSE Scripts | Purpose |
|---|---|---|---|
| 1 | `nmap` | `ftp-anon, ftp-syst, ftp-bounce` | Anonymous login, system type, bounce attack |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| FTP Banner | INFO | Server version string |
| Known Vulnerable FTP Server | CRITICAL | Banner matches known backdoor versions (`vsftpd 2.3.4`, `proftpd 1.3.5`, `proftpd 1.3.3c`) |
| FTP Anonymous Login Allowed | HIGH | Unauthenticated file access |
| FTP System Type | INFO | SYST command reveals OS information |
| FTP Bounce Attack Possible | MEDIUM | PORT command can be abused for port scanning |

**Output directory:** `<output_dir>/ftp/`

---

## SMTP Module

**Source:** `recon_ninja/modules/smtp.py`
**Entry point:** `run_smtp_module()`
**Trigger:** Port 25, 465, or 587 open
**External tools:** `nmap` (NSE scripts), `smtp-user-enum`

| Step | Tool | Command | Purpose |
|---|---|---|---|
| 1 | `nmap` | `smtp-commands, smtp-open-relay, smtp-ntlm-info` | Command enumeration, open relay check, NTLM domain info |
| 2 | `smtp-user-enum -M VRFY` | User enumeration via VRFY | Valid username discovery |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| SMTP Banner | INFO | Server version string |
| SMTP VRFY Command Enabled | MEDIUM | Enables user account enumeration |
| SMTP EXPN Command Enabled | MEDIUM | Enables mailing list expansion |
| SMTP Open Relay Detected | CRITICAL | Unauthenticated email relay — spam and phishing vector |
| SMTP NTLM Information | INFO | Domain and NetBIOS name from NTLM auth |
| SMTP User Enumeration | HIGH | Valid usernames discovered via VRFY |

**Wordlist:** Tries `/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt`,
falls back to `/usr/share/seclists/Usernames/names.txt`, then `/usr/share/wordlists/dirb/big.txt`.

**Output directory:** `<output_dir>/smtp/`

---

## SNMP Module

**Source:** `recon_ninja/modules/snmp.py`
**Entry point:** `run_snmp_module()`
**Trigger:** UDP port 161 detected
**External tools:** `onesixtyone`, `snmpwalk`

| Step | Tool | Command | Purpose |
|---|---|---|---|
| 1 | `onesixtyone -c <wordlist>` | Community string brute force | Find valid community strings |
| 2 | `snmpwalk -v2c -c <community>` | Full MIB walk (per valid community) | Extract usernames, processes, network info, software |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| SNMP Community String(s) Found | HIGH | Unauthenticated information disclosure |
| SNMP Usernames Discovered | MEDIUM | Users extracted from OID `1.3.6.1.4.1.77.1.2.25` (Windows) and `1.3.6.1.2.1.25.4.2.1` (Linux) |
| Interesting Process | MEDIUM | Process matching keywords: apache, nginx, mysql, ssh, docker, etc. |
| SNMP Running Processes | INFO | Full process list from `hrSWRunName` OID |
| SNMP Network Information | INFO | Interface and routing data from `ipAddrTable`, `ifTable` |
| SNMP Installed Software | INFO | Software from `hrSWInstalledName` OID |

If `onesixtyone` is not available, the module defaults to trying community
string `"public"` for the snmpwalk step.

**Output directory:** `<output_dir>/snmp/`

---

## DNS Module

**Source:** `recon_ninja/modules/dns.py`
**Entry point:** `run_dns_module()`
**Trigger:** Port 53 open (TCP or UDP)
**External tools:** `dig`, `dnsrecon`, `dnsenum`

| Step | Tool | Command | Purpose |
|---|---|---|---|
| 1 | `dig axfr` | Zone transfer attempt | AXFR against the target DNS server |
| 2 | `dnsrecon -d <domain> -t axfr,srv` (+ brute) | Zone transfer, SRV records, subdomain brute force | Comprehensive DNS enumeration |
| 3 | `dnsenum <domain>` | Additional subdomain and MX record discovery | Cross-verification and supplementary data |
| 4 | `dig ANY` | Basic query fallback | Used when no domain name is resolved (IP-only target) |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| DNS Zone Transfer Successful | CRITICAL | AXFR allowed — exposes entire internal network topology |
| DNS Zone Transfer Denied | INFO | Server correctly restricts AXFR |
| DNS Subdomains Discovered | MEDIUM | New subdomains found via dnsrecon brute force |
| DNS SRV Records | INFO | Internal service records discovered |
| DNS Additional Subdomains (dnsenum) | MEDIUM | Subdomains found only by dnsenum |
| DNS MX Records | INFO | Mail exchange records |
| DNS — No Domain Resolved | INFO | Port 53 open but no domain available for queries |

The module first resolves a domain from `state.hostnames` or the target string
itself (if it looks like a domain, not an IP). If no domain can be resolved,
most DNS tools are skipped since they require a domain name.

**Output directory:** `<output_dir>/dns/`

---

## LDAP Module

**Source:** `recon_ninja/modules/ldap.py`
**Entry point:** `run_ldap_module()`
**Trigger:** Port 389 or 636 open
**External tools:** `nmap` (NSE scripts), `ldapsearch`, `windapsearch` (optional)

| Step | Tool | Command | Purpose |
|---|---|---|---|
| 1 | `nmap` | `ldap-rootdse, ldap-search` | Root DSE information, directory search |
| 2 | `ldapsearch -x -H ldap://<target> -b "" -s base namingContexts` | Anonymous bind test | Check if anonymous bind is allowed |
| 3 | `ldapsearch -x -b <base_dn> "(objectClass=*)"` | Full object enumeration | Enumerate users and groups via anonymous access |
| 4 | `windapsearch -m users --dc <target> --full` | Active Directory deep enumeration | Enumerate AD user accounts (optional) |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| LDAP Root DSE Information | INFO | Server metadata from Root DSE |
| LDAP Search Results Exposed | MEDIUM | Directory data retrieved via nmap |
| LDAP Anonymous Bind Access | HIGH | Unauthenticated directory queries are possible |
| LDAP Base DN Discovered | INFO | Naming context extracted for further queries |
| LDAP User Objects Enumerated | HIGH | User entries discovered via anonymous query |
| LDAP Group Objects Enumerated | MEDIUM | Group entries discovered via anonymous query |
| AD Users Enumerated via windapsearch | HIGH | Active Directory user accounts enumerated |

**Output directory:** `<output_dir>/ldap/`

---

## Kerberos Module

**Source:** `recon_ninja/modules/kerberos.py`
**Entry point:** `run_kerberos_module()`
**Trigger:** Port 88 open
**External tools:** `kerbrute`, `nmap` (NSE scripts)

| Step | Tool | Command | Purpose |
|---|---|---|---|
| 1 | `kerbrute userenum` | Username enumeration | Brute-force valid Kerberos usernames |
| 2 | `nmap --script krb5-enum-users` | NSE-based user enumeration | Alternative username discovery |
| 3 | — | Informational finding | Kerberos detected — suggests AD environment |
| 4 | — | Suggested Impacket commands | `GetNPUsers.py`, `GetUserSPNs.py`, `GetTGT.py`, `GetADUsers.py` |

The domain is derived from `state.hostnames` by `_derive_domain()` — it
extracts the domain portion from FQDN hostnames (e.g., `dc01.corp.local`
yields `CORP.LOCAL`). If the target itself is a domain and `config.is_domain`
is set, the target is used directly.

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| Valid Kerberos Usernames Discovered | HIGH | kerbrute confirmed valid accounts |
| Kerberos Users via NSE Script | HIGH | nmap krb5-enum-users found additional usernames |
| Kerberos Service Detected | INFO | Port 88 indicates Active Directory |
| Suggested Kerberos Attack Commands | INFO | Impacket commands for AS-REP roasting, Kerberoasting, etc. |

**Wordlist:** `/usr/share/seclists/Usernames/xato-net-10-million-usernames-dup.txt`

**Output directory:** `<output_dir>/kerberos/`

---

## RPC Module

**Source:** `recon_ninja/modules/rpc.py`
**Entry point:** `run_rpc_module()`
**Trigger:** Port 111 or 135 open
**External tools:** `rpcclient`, `rpcinfo`, `nmap` (NSE scripts), `impacket-rpcdump` (optional)

| Step | Tool | Command | Purpose |
|---|---|---|---|
| 1 | `rpcclient -U "" -N -c "enumdomusers;enumdomgroups;querydominfo"` | Null-session enumeration | Users, groups, domain info via unauthenticated RPC |
| 2 | `rpcinfo -p` | Registered RPC services | List all registered RPC programs (port 111) |
| 3 | `nmap --script msrpc-enum` | MSRPC endpoint enumeration | Discover RPC endpoints on port 135 |
| 4 | `impacket-rpcdump` | RPC endpoint dump | Alternative endpoint enumeration (optional) |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| RPC Null Session Access | HIGH | Unauthenticated rpcclient connection succeeded |
| Domain Users Enumerated via Null Session | HIGH | Usernames extracted from `enumdomusers` |
| Domain Groups Enumerated via Null Session | MEDIUM | Group names extracted from `enumdomgroups` |
| Domain Information via querydominfo | INFO | Domain details from rpcclient |
| RPC Null Session Denied | INFO | Access was properly restricted |
| RPC Services Registered | INFO | rpcinfo listed registered services |
| MSRPC Endpoints Enumerated | MEDIUM | nmap discovered RPC endpoints |

**Output directory:** `<output_dir>/rpc/`

---

## NFS Module

**Source:** `recon_ninja/modules/nfs.py`
**Entry point:** `run_nfs_module()`
**Trigger:** Port 2049 open
**External tools:** `showmount`, `nmap` (NSE scripts)

| Step | Tool | Command | Purpose |
|---|---|---|---|
| 1 | `showmount -e` | List exported shares | Discover NFS exports accessible to the attacker |
| 2 | `nmap --script nfs-ls,nfs-showmount,nfs-statfs` | NSE-based NFS enumeration | Directory listings, share discovery, filesystem stats |
| 3 | — | Suggested mount commands | `sudo mount -t nfs` commands for each discovered share |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| NFS Exported Shares Accessible | MEDIUM | Unauthenticated access to exported directories |
| NFS Service Detected — No Exported Shares | INFO | NFS running but no shares listed |
| NFS Directory Listing via nmap | MEDIUM | nfs-ls script listed files in a share |
| Additional NFS Shares via nmap nfs-showmount | MEDIUM | Shares discovered by nmap but not by showmount |
| NFS Filesystem Statistics | INFO | Disk usage and filesystem type from nfs-statfs |
| NFS Mount Commands | INFO | Ready-to-use mount commands for each share |

**Output directory:** `<output_dir>/nfs/`

---

## RDP Module

**Source:** `recon_ninja/modules/rdp.py`
**Entry point:** `run_rdp_module()`
**Trigger:** Port 3389 open
**External tools:** `nmap` (NSE scripts)

| Step | Tool | NSE Scripts | Purpose |
|---|---|---|---|
| 1 | `nmap` | `rdp-enum-encryption, rdp-vuln-ms12-020` | Encryption level, NLA status, MS12-020 check |
| 2 | `nmap` | `rdp-vuln-ms19-0708` | BlueKeep vulnerability check |
| 3 | — | Suggested tools | `xfreerdp`, `rdesktop` connection commands |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| RDP NLA Enabled | INFO | CredSSP/NLA is required (good configuration) |
| RDP NLA Disabled | HIGH | No pre-auth required — vulnerable to credential stuffing |
| RDP Encryption Level | INFO | Encryption level reported by rdp-enum-encryption |
| RDP Vulnerable to MS12-020 | HIGH | CVE-2012-0152 — RCE vulnerability |
| RDP Vulnerable to BlueKeep (CVE-2019-0708) | CRITICAL | Wormable unauthenticated RCE |
| RDP Not Vulnerable to BlueKeep | INFO | Server appears patched |
| RDP Connection Tools | INFO | Suggested xfreerdp/rdesktop commands |

**Output directory:** `<output_dir>/rdp/`

---

## VNC Module

**Source:** `recon_ninja/modules/vnc.py`
**Entry point:** `run_vnc_module()`
**Trigger:** Any port in 5900–5910 open
**External tools:** `nmap` (NSE scripts)

| Step | Tool | NSE Script | Purpose |
|---|---|---|---|
| 1 | `nmap` | `vnc-info` | Protocol version, authentication type |

The module iterates over all VNC ports found and runs `nmap --script vnc-info`
against each. The authentication type is classified into three categories:

| Auth Category | Matching Types | Finding Severity |
|---|---|---|
| No authentication | `none`, `no auth`, `no authentication` | CRITICAL |
| Weak authentication | `vnc authentication`, `ultravnc`, `realvnc` | HIGH |
| Standard / unknown | All other types | INFO |

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| VNC No Authentication on Port N | CRITICAL | Full desktop control without any credentials |
| VNC Weak Authentication on Port N | HIGH | Short VNC passwords — brute-force feasible |
| VNC Service Detected on Port N | INFO | Standard VNC with auth |
| VNC Version on Port N | INFO | Protocol version (e.g., RFB 003.008) |

**Output directory:** `<output_dir>/vnc/`

---

## WinRM Module

**Source:** `recon_ninja/modules/winrm.py`
**Entry point:** `run_winrm_module()`
**Trigger:** Port 5985 (HTTP) or 5986 (HTTPS) open
**External tools:** `nmap` (NSE scripts), `evil-winrm` (suggested), `crackmapexec` (suggested)

| Step | Tool | NSE Script | Purpose |
|---|---|---|---|
| 1 | `nmap` | `http-auth-finder` | Determine authentication type |
| 2 | — | Suggested tools | `evil-winrm` and `crackmapexec` commands |

Even if nmap is not available, the module still produces findings based on
the portscan data alone — flagging the open WinRM ports with attack commands.

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| WinRM Open (HTTP) on Port 5985 | HIGH | Remote shell access possible with credentials |
| WinRM Open (HTTPS) on Port 5986 | HIGH | Encrypted transport, but still a remote shell vector |
| WinRM over Unencrypted HTTP (Port 5985) | MEDIUM | Credentials transmitted in cleartext |
| WinRM over HTTPS (Port 5986) | INFO | Transport encrypted; self-signed certs may cause issues |
| WinRM Suggested Attack Tools | INFO | `evil-winrm`, `crackmapexec` commands |

**Output directory:** `<output_dir>/winrm/`

---

## Database Module

**Source:** `recon_ninja/modules/database.py`
**Entry point:** `run_database_module()`
**Trigger:** Port 3306, 1433, 5432, 6379, 27017, or 1521 open
**External tools:** `nmap` (NSE scripts), `redis-cli`

The database module dispatches to per-database sub-enumerators based on the
detected port:

| Port | Database | Sub-enumerator | NSE Scripts / Tools |
|---|---|---|---|
| 3306 | MySQL | `_enum_mysql()` | `mysql-info`, `mysql-empty-password`, `mysql-enum` |
| 1433 | MSSQL | `_enum_mssql()` | `ms-sql-info`, `ms-sql-empty-password`, `ms-sql-config` |
| 5432 | PostgreSQL | `_enum_postgresql()` | `pgsql-brute` |
| 6379 | Redis | `_enum_redis()` | `redis-cli ping/info`, `redis-info` (nmap) |
| 27017 | MongoDB | `_enum_mongodb()` | `mongodb-info`, `mongodb-databases` |
| 1521 | Oracle | `_enum_oracle()` | `oracle-tns-version`, `tnscmd10g` (optional) |

### MySQL Findings

| Finding | Severity |
|---|---|
| MySQL Server Info | INFO |
| MySQL Empty Root Password | CRITICAL |
| MySQL User Enumeration | MEDIUM |
| MySQL Suggested Commands | INFO |

### MSSQL Findings

| Finding | Severity |
|---|---|
| MSSQL Server Info | INFO |
| MSSQL Empty SA Password | CRITICAL |
| MSSQL Configuration | INFO |
| MSSQL Suggested Commands | INFO |

### PostgreSQL Findings

| Finding | Severity |
|---|---|
| PostgreSQL Valid Credentials | HIGH |
| PostgreSQL Brute-Force No Hits | INFO |
| PostgreSQL Suggested Commands | INFO |

### Redis Findings

| Finding | Severity |
|---|---|
| Redis Unauthenticated Access | CRITICAL |
| Redis Server Info | INFO |
| Redis Requires Authentication | INFO |

The Redis check first tries `redis-cli -h <target> -p <port> ping`. If the
response is `PONG`, unauthenticated access is confirmed. It then retrieves
server info via `redis-cli info server`.

### MongoDB Findings

| Finding | Severity |
|---|---|
| MongoDB Server Info | INFO |
| MongoDB No Authentication | CRITICAL |
| MongoDB Databases Listed | HIGH |

### Oracle Findings

| Finding | Severity |
|---|---|
| Oracle TNS Version | INFO |
| Oracle Suggested Commands | INFO |

Suggested Oracle commands include `tnscmd10g`, `nmap oracle-sid-brute`,
`nmap oracle-brute`, and `odat all`.

**Output directory:** `<output_dir>/database/`

---

## SSL Module

**Source:** `recon_ninja/modules/ssl.py`
**Entry point:** `run_ssl_module()`
**Trigger:** Service name contains `"ssl"` or `"https"`, or port is 443/8443
**External tools:** `sslscan`, `nmap` (NSE scripts), `testssl.sh` (optional)

The module identifies all SSL/TLS ports from the scan state and runs three
tools against each port:

| Step | Tool | Purpose | Output File |
|---|---|---|---|
| 1 | `sslscan --no-colour` | Cipher suites, certificate details, protocol support | `sslscan_<port>.txt` |
| 2 | `nmap --script ssl-heartbleed,ssl-ccs-injection,ssl-dh-params` | Vulnerability detection | `nmap_ssl_<port>.txt` |
| 3 | `testssl.sh --quiet` | Comprehensive TLS audit (2x timeout) | `testssl_<port>.txt` |

**Certificate hostname extraction:** The module parses `sslscan` output for
`Subject: CN=` and `Subject Alternative Name: DNS:` entries, adding all
discovered hostnames to `state.hostnames`.

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| SSLv2 protocol enabled | MEDIUM | Insecure and deprecated |
| SSLv3 protocol enabled (POODLE) | MEDIUM | CVE-2014-3566 |
| TLS 1.0 protocol enabled | MEDIUM | Deprecated (RFC 8996), vulnerable to BEAST (CVE-2011-3389) |
| TLS 1.1 protocol enabled | MEDIUM | Deprecated (RFC 8996) |
| Weak cipher suites detected | MEDIUM | 40/56-bit key ciphers found |
| OpenSSL Heartbleed vulnerability | CRITICAL | CVE-2014-0160 — memory disclosure |
| OpenSSL CCS Injection vulnerability | HIGH | CVE-2014-0224 — MITM interception |
| Weak DH parameters | MEDIUM | DH parameter size below 2048 bits |
| Missing HSTS header | INFO | No HTTP Strict Transport Security |
| testssl findings | Per testssl | Severity parsed from CRITICAL/HIGH/MEDIUM/LOW/WARN labels |

All findings are prefixed with `[Port N]` to disambiguate when multiple
SSL ports are present. Findings are deduplicated by `(title, module)` tuple.

**Output directory:** `<output_dir>/ssl/`

---

## OSINT Module

**Source:** `recon_ninja/modules/osint.py`
**Entry point:** `run_osint_module()`
**Trigger:** Runs during **Phase 4** (not Phase 3), only for domain targets
**External tools:** `whois`, `theHarvester`, `subfinder`, `amass`, `shodan` (all optional except `whois`)

> **Note:** The OSINT module is invoked directly by the engine's
> `phase4_osint()` method, not through the `_determine_modules()` dispatch.
> It runs when `config.osint_enabled` is `True` and the target is a domain
> (or a hostname has been discovered).

| Step | Tool / Source | Purpose |
|---|---|---|
| 1 | `whois <domain>` | Registrar, organisation, creation/expiry dates, ASN |
| 2 | crt.sh API (`requests.get`) | Certificate Transparency log subdomain enumeration |
| 3 | `theHarvester -d <domain> -b google,bing,crtsh,dnsdumpster` | Multi-source OSINT aggregation (2x timeout) |
| 4 | `subfinder -d <domain>` | Passive subdomain discovery |
| 5 | `amass enum -passive -d <domain>` | Passive subdomain enumeration (2x timeout) |
| 6 | `shodan host <target>` | Host intelligence — ports, technologies, CVEs (requires API key) |

**Subdomain aggregation:** All discovered subdomains from crt.sh, theHarvester,
subfinder, and amass are normalized (lowercased, wildcard-stripped,
deduplicated) and added to `state.hostnames`.

**Shodan API key resolution:** Checked from `config.api_keys.shodan` first,
then from the `SHODAN_API_KEY` environment variable.

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| WHOIS registrar / organisation / dates / ASN | INFO | Domain registration details |
| OSINT: N unique subdomains discovered | INFO | Aggregated subdomain count with sources |
| Shodan open ports | INFO | Ports reported by Shodan |
| Shodan technologies | INFO | Products detected by Shodan |
| Shodan: CVE-XXXX-XXXX | HIGH | Vulnerability reported by Shodan |

**Output directory:** `<output_dir>/osint/`

---

## Vulnerability Correlation Module

**Source:** `recon_ninja/modules/vuln_correlate.py`
**Entry point:** `run_vuln_correlate_module()`
**Trigger:** Runs during **Phase 5** (not Phase 3), always if not disabled
**External tools:** `searchsploit`, `nuclei`, NVD API

> **Note:** This module is invoked by the engine's `phase5_vuln_correlate()`
> method. It runs after all service-specific modules have completed, unless
> `config.skip_vuln_correlate` is `True`.

The module performs three correlation activities:

### 1. searchsploit Queries

For each `ServiceInfo` that has both `product` and `version` populated:

1. **Specific query:** `searchsploit --json "Product Version"` (e.g., `"Apache httpd 2.4.52"`)
2. **Broad query** (fallback): `searchsploit --json "Product"` — only if the specific query returns no results

Each searchsploit result is parsed via `_parse_searchsploit_json()` and
mapped to a `Finding` with severity based on exploit type:

| Exploit Type | Severity |
|---|---|
| `remote`, `webapps` | HIGH |
| `local`, `dos` | MEDIUM |
| Other | LOW |

### 2. nuclei Template Scanning

For each web target URL in the scan state, nuclei is run with:

```
nuclei -u <url> -t cves/ -t exposures/ -t misconfiguration/ \
  -severity critical,high,medium -json -silent
```

Custom templates can be added via `config.nuclei_templates`. Output is
parsed as JSONL (one JSON object per line) via `_parse_nuclei_output()`.

### 3. NVD API Enrichment

For all findings that contain a CVE identifier, the module queries the
NVD API (`https://services.nvd.nist.gov/rest/json/cves/2.0`) to retrieve
the CVSS v3 (or v2) base score. If the NVD-reported severity is higher
than the initial assessment, the finding's severity is upgraded.

An optional NVD API key (from `config.api_keys.nvd`) can be provided for
higher rate limits.

### Deduplication

`_deduplicate_findings()` merges findings that share the same CVE ID,
keeping the one with the higher severity. Non-CVE findings are deduplicated
by title.

**Key findings:**

| Finding | Severity | Description |
|---|---|---|
| `[Port N] Product Version: Exploit Title` | HIGH–LOW | searchsploit found a matching exploit |
| `[nuclei] Template Name` | Per template | nuclei template matched on a web target |

**Output directory:** `<output_dir>/vuln_correlate/`
**Additional output:** `vuln_findings.json` — all findings serialized as JSON

---

## Tool Dependency Summary

The table below lists every external tool referenced across all modules,
which modules use it, and whether it is required or optional.

| Tool | Module(s) | Required? | Install Command |
|---|---|---|---|
| `nmap` | smb, ssh, ftp, smtp, ldap, kerberos, rpc, nfs, rdp, vnc, winrm, database, ssl, web_vuln | **Yes** (core) | `sudo apt install nmap` |
| `curl` | web_core, web_dirfuzz, web_cms | **Yes** (web) | `sudo apt install curl` |
| `whatweb` | web_core | No | `sudo apt install whatweb` |
| `wafw00f` | web_core | No | `pip install wafw00f` |
| `gowitness` | web_core | No | `go install github.com/sensepost/gowitness@latest` |
| `feroxbuster` | web_dirfuzz | No (primary fuzzer) | `sudo apt install feroxbuster` |
| `gobuster` | web_dirfuzz | No (fallback fuzzer / vhost) | `sudo apt install gobuster` |
| `ffuf` | web_dirfuzz | No (vhost fallback) | `go install github.com/ffuf/ffuf/v2@latest` |
| `nikto` | web_vuln | No | `sudo apt install nikto` |
| `nuclei` | web_vuln, vuln_correlate | No | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `wpscan` | web_cms | No | `sudo apt install wpscan` |
| `droopescan` | web_cms | No | `pip install droopescan` |
| `joomscan` | web_cms | No | `sudo apt install joomscan` |
| `enum4linux-ng` | smb | No (preferred) | `pip install enum4linux-ng` |
| `enum4linux` | smb | No (fallback) | `sudo apt install enum4linux` |
| `smbclient` | smb | No | `sudo apt install smbclient` |
| `smbmap` | smb | No | `pip install smbmap` |
| `crackmapexec` | smb, winrm | No | `pipx install crackmapexec` |
| `ssh-audit` | ssh | No | `pip install ssh-audit` |
| `smtp-user-enum` | smtp | No | `sudo apt install smtp-user-enum` |
| `onesixtyone` | snmp | No | `sudo apt install onesixtyone` |
| `snmpwalk` | snmp | No | `sudo apt install snmp` |
| `dig` | dns | No (bundled with bind9) | `sudo apt install dnsutils` |
| `dnsrecon` | dns, osint (engine Phase 4) | No | `pip install dnsrecon` |
| `dnsenum` | dns | No | `sudo apt install dnsenum` |
| `ldapsearch` | ldap | No | `sudo apt install ldap-utils` |
| `windapsearch` | ldap | No | `pip install windapsearch` |
| `kerbrute` | kerberos | No | `go install github.com/ropnop/kerbrute@latest` |
| `rpcclient` | rpc | No | `sudo apt install samba-common-bin` |
| `rpcinfo` | rpc | No | `sudo apt install rpcbind` |
| `impacket-rpcdump` | rpc | No | `pip install impacket` |
| `showmount` | nfs | No | `sudo apt install nfs-common` |
| `redis-cli` | database | No | `sudo apt install redis-tools` |
| `tnscmd10g` | database | No | `pipx install tnscmd10g` |
| `sslscan` | ssl | No | `sudo apt install sslscan` |
| `testssl.sh` | ssl | No | `git clone https://github.com/drwetter/testssl.sh.git` |
| `whois` | osint | No | `sudo apt install whois` |
| `theHarvester` | osint | No | `pip install theHarvester` |
| `subfinder` | osint | No | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `amass` | osint | No | `go install github.com/owasp-amass/amass/v4/...@master` |
| `shodan` | osint | No (+ API key) | `pip install shodan` |
| `searchsploit` | vuln_correlate | No | `sudo apt install exploitdb` |

### Minimum Viable Toolset

ReconNinja can run with just `nmap` and `curl` installed — every other tool
is checked at runtime and skipped gracefully if absent. However, for
comprehensive results on a typical engagement, the recommended minimum is:

```
nmap, curl, feroxbuster (or gobuster), nikto, enum4linux-ng,
smbclient, sslscan, searchsploit
```
