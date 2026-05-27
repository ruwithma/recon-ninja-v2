"""Report generator for ReconNinja v2.

Produces Markdown, HTML, and JSON reports from the completed
:class:`~recon_ninja.core.models.ScanState`.

Output files:

* ``00_SUMMARY.md``   — Human-readable Markdown report.
* ``00_SUMMARY.html`` — Styled HTML report with dark theme (opt-in).
* ``00_findings.json`` — Machine-readable JSON export.

Typical usage::

    from recon_ninja.core.report import generate_reports

    paths = await generate_reports(
        state=scan_state,
        output_dir=Path("results/10.10.11.58"),
        html=True,
        json_output=True,
    )
    # paths == {"markdown": Path(...), "html": Path(...), "json": Path(...)}
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

import aiofiles
from jinja2 import BaseLoader, Environment

from recon_ninja.core.models import Finding, ScanState, ServiceInfo, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Output file names
# ---------------------------------------------------------------------------

_MD_FILENAME = "00_SUMMARY.md"
_HTML_FILENAME = "00_SUMMARY.html"
_JSON_FILENAME = "00_findings.json"

# ---------------------------------------------------------------------------
# Jinja2 environment — inline templates, no file-system loader
# ---------------------------------------------------------------------------

_jinja_env = Environment(
    loader=BaseLoader(),
    autoescape=True,  # safety first for HTML
    trim_blocks=True,
    lstrip_blocks=True,
)

# ---------------------------------------------------------------------------
# HTML template (inline — keeps the tool self-contained)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconNinja — {{ target }}</title>
<style>
  :root {
    --bg-primary: #1a1a2e;
    --bg-secondary: #16213e;
    --bg-card: #0f3460;
    --bg-table-row: #16213e;
    --bg-table-row-alt: #1a1a2e;
    --text-primary: #e0e0e0;
    --text-secondary: #a0a0b0;
    --accent: #e94560;
    --accent-green: #00d672;
    --accent-cyan: #00c8ff;
    --accent-yellow: #ffc107;
    --border-color: #2a2a4a;
    --sev-critical: #ff1744;
    --sev-high: #ff9100;
    --sev-medium: #ffc107;
    --sev-low: #00b0ff;
    --sev-info: #9e9e9e;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: var(--bg-primary);
    color: var(--text-primary);
    font-family: 'Segoe UI', 'Inter', -apple-system, sans-serif;
    line-height: 1.6;
    padding: 2rem;
  }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 {
    color: var(--accent);
    font-size: 1.8rem;
    border-bottom: 2px solid var(--accent);
    padding-bottom: 0.5rem;
    margin-bottom: 1.5rem;
  }
  h2 {
    color: var(--accent-cyan);
    font-size: 1.3rem;
    margin-top: 2rem;
    margin-bottom: 0.75rem;
    border-bottom: 1px solid var(--border-color);
    padding-bottom: 0.3rem;
  }
  h3 {
    color: var(--accent-green);
    font-size: 1.1rem;
    margin-top: 1.5rem;
    margin-bottom: 0.5rem;
  }
  .meta-table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 1rem;
  }
  .meta-table td {
    padding: 0.4rem 1rem;
    border-bottom: 1px solid var(--border-color);
  }
  .meta-table td:first-child {
    color: var(--text-secondary);
    font-weight: 600;
    width: 180px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 1rem;
  }
  th {
    background: var(--bg-card);
    color: var(--accent-cyan);
    text-align: left;
    padding: 0.6rem 0.8rem;
    font-size: 0.85rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }
  td {
    padding: 0.5rem 0.8rem;
    font-size: 0.9rem;
  }
  tr:nth-child(even) { background: var(--bg-table-row); }
  tr:nth-child(odd)  { background: var(--bg-table-row-alt); }
  .finding-card {
    background: var(--bg-card);
    border-left: 4px solid var(--sev-medium);
    border-radius: 4px;
    padding: 0.8rem 1rem;
    margin-bottom: 0.6rem;
  }
  .finding-card.critical { border-left-color: var(--sev-critical); }
  .finding-card.high     { border-left-color: var(--sev-high); }
  .finding-card.medium   { border-left-color: var(--sev-medium); }
  .finding-card.low      { border-left-color: var(--sev-low); }
  .finding-card.info     { border-left-color: var(--sev-info); }
  .sev-badge {
    display: inline-block;
    padding: 0.15rem 0.5rem;
    border-radius: 3px;
    font-size: 0.75rem;
    font-weight: 700;
    color: #fff;
    margin-right: 0.5rem;
  }
  .sev-badge.critical { background: var(--sev-critical); }
  .sev-badge.high     { background: var(--sev-high); }
  .sev-badge.medium   { background: var(--sev-medium); color: #1a1a2e; }
  .sev-badge.low      { background: var(--sev-low); }
  .sev-badge.info     { background: var(--sev-info); }
  .finding-title {
    font-weight: 600;
    color: var(--text-primary);
  }
  .finding-desc {
    color: var(--text-secondary);
    margin-top: 0.3rem;
  }
  .finding-cve {
    color: var(--accent-yellow);
    font-size: 0.8rem;
  }
  .command-block {
    background: var(--bg-secondary);
    border: 1px solid var(--border-color);
    border-radius: 4px;
    padding: 0.6rem 1rem;
    margin-bottom: 0.4rem;
    font-family: 'Fira Code', 'Cascadia Code', monospace;
    font-size: 0.85rem;
    color: var(--accent-green);
    white-space: pre-wrap;
    word-break: break-all;
  }
  .loot-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(160px, 1fr));
    gap: 0.8rem;
    margin-top: 0.5rem;
  }
  .loot-item {
    background: var(--bg-card);
    border-radius: 4px;
    padding: 0.8rem;
    text-align: center;
  }
  .loot-item .count {
    font-size: 1.6rem;
    font-weight: 700;
    color: var(--accent-green);
  }
  .loot-item .label {
    color: var(--text-secondary);
    font-size: 0.8rem;
  }
  .file-index {
    list-style: none;
    padding-left: 0;
  }
  .file-index li {
    padding: 0.3rem 0;
    border-bottom: 1px solid var(--border-color);
    font-family: monospace;
    font-size: 0.85rem;
  }
  .profile-badge {
    display: inline-block;
    background: var(--bg-card);
    border: 1px solid var(--accent-cyan);
    color: var(--accent-cyan);
    padding: 0.3rem 0.8rem;
    border-radius: 4px;
    font-weight: 700;
    letter-spacing: 0.05em;
  }
  footer {
    margin-top: 2rem;
    padding-top: 1rem;
    border-top: 1px solid var(--border-color);
    color: var(--text-secondary);
    font-size: 0.8rem;
    text-align: center;
  }
</style>
</head>
<body>
<div class="container">

<h1>ReconNinja Report — {{ target }}</h1>

<!-- Target Information -->
<h2>Target Information</h2>
<table class="meta-table">
  <tr><td>Target</td><td>{{ target }}</td></tr>
  <tr><td>Hostname</td><td>{{ hostname or "—" }}</td></tr>
  <tr><td>Box Profile</td><td><span class="profile-badge">{{ box_profile }}</span></td></tr>
  <tr><td>Scan Duration</td><td>{{ duration }}</td></tr>
  <tr><td>Scan Time</td><td>{{ scan_time }}</td></tr>
  <tr><td>Open Ports</td><td>{{ open_ports | length }}</td></tr>
</table>

<!-- Open Ports & Services -->
<h2>Open Ports &amp; Services</h2>
{% if services %}
<table>
  <tr>
    <th>Port</th><th>Proto</th><th>Service</th><th>Product</th><th>Version</th>
  </tr>
  {% for svc in services %}
  <tr>
    <td>{{ svc.port }}</td>
    <td>{{ svc.proto }}</td>
    <td>{{ svc.service }}</td>
    <td>{{ svc.product or "—" }}</td>
    <td>{{ svc.version or "—" }}</td>
  </tr>
  {% endfor %}
</table>
{% else %}
<p style="color:var(--text-secondary)">No open ports discovered.</p>
{% endif %}

<!-- Box Profile -->
<h2>Box Profile</h2>
<p><span class="profile-badge">{{ box_profile }}</span></p>

<!-- Detected Technologies -->
<h2>Detected Technologies</h2>
{% if detected_techs %}
{% for port_data in tech_by_port %}
<h3>Port {{ port_data.port }}</h3>
<table>
  <tr>
    <th>Technology</th><th>Version</th><th>Category</th><th>Confidence</th><th>Source</th><th>Vulnerable</th><th>CVEs</th>
  </tr>
  {% for tech in port_data.techs %}
  <tr>
    <td>{{ tech.name }}</td>
    <td>{{ tech.version or "—" }}</td>
    <td>{{ tech.category or "—" }}</td>
    <td>{{ tech.confidence }}</td>
    <td>{{ tech.source }}</td>
    <td>{% if tech.is_vulnerable %}<span class="sev-badge critical">YES</span>{% else %}—{% endif %}</td>
    <td>{% if tech.cves %}<span class="finding-cve">{{ tech.cves | join(', ') }}</span>{% else %}—{% endif %}</td>
  </tr>
  {% endfor %}
</table>
{% endfor %}
{% if vulnerable_techs %}
<div class="finding-card critical" style="margin-top:1rem">
  <span class="finding-title">Vulnerable Technologies Detected</span>
  <div class="finding-desc" style="margin-top:0.5rem">
  {% for vt in vulnerable_techs %}
    <div style="margin-bottom:0.4rem">
      <span class="sev-badge critical">{{ vt.cves | join(', ') }}</span>
      <strong>{{ vt.name }} {{ vt.version }}</strong> (port {{ vt.port }}) via {{ vt.source }}
    </div>
  {% endfor %}
  </div>
</div>
{% endif %}
{% else %}
<p style="color:var(--text-secondary)">No technologies detected.</p>
{% endif %}

<!-- Key Findings -->
<h2>Key Findings</h2>
{% if findings %}
{% for finding in findings %}
<div class="finding-card {{ finding.severity | lower }}">
  <span class="sev-badge {{ finding.severity | lower }}">{{ finding.severity }}</span>
  <span class="finding-title">{{ finding.title }}</span>
  {% if finding.cve %}
  <span class="finding-cve">({{ finding.cve }})</span>
  {% endif %}
  <div class="finding-desc">{{ finding.description }}</div>
  {% if finding.evidence %}
  <div class="finding-desc" style="margin-top:0.3rem;font-family:monospace;font-size:0.8rem">{{ finding.evidence[:500] }}</div>
  {% endif %}
</div>
{% endfor %}
{% else %}
<p style="color:var(--text-secondary)">No findings recorded.</p>
{% endif %}

<!-- Per-Service Details -->
<h2>Per-Service Details</h2>
{% for svc_detail in service_details %}
<h3>{% if svc_detail.icon %}{{ svc_detail.icon }} {% endif %}{{ svc_detail.label }} (port {{ svc_detail.port }})</h3>
{% if svc_detail.product %}
<p style="color:var(--text-secondary)">Product: {{ svc_detail.product }}</p>
{% endif %}
{% if svc_detail.tech_stack %}
<p style="color:var(--text-secondary)">Tech stack: {{ svc_detail.tech_stack | join(', ') }}</p>
{% endif %}
{% if svc_detail.dirs %}
<p style="color:var(--accent-green);font-family:monospace;font-size:0.85rem">Directories: {{ svc_detail.dirs | join(', ') }}</p>
{% endif %}
{% if svc_detail.shares %}
<p style="color:var(--accent-yellow)">Shares: {{ svc_detail.shares | join(', ') }}</p>
{% endif %}
{% if svc_detail.vulns %}
<ul>
  {% for v in svc_detail.vulns %}
  <li style="color:var(--sev-high)">{{ v }}</li>
  {% endfor %}
</ul>
{% endif %}
{% if svc_detail.scripts %}
{% for name, output in svc_detail.scripts.items() %}
<details>
  <summary style="cursor:pointer;color:var(--accent-cyan);font-size:0.9rem">{{ name }}</summary>
  <div class="command-block">{{ output }}</div>
</details>
{% endfor %}
{% endif %}
{% endfor %}

<!-- Loot -->
<h2>Loot</h2>
{% if loot %}
<div class="loot-grid">
  {% for category, items in loot.items() %}
  <div class="loot-item">
    <div class="count">{{ items | length }}</div>
    <div class="label">{{ category }}</div>
  </div>
  {% endfor %}
</div>
{% else %}
<p style="color:var(--text-secondary)">No loot extracted.</p>
{% endif %}

<!-- Suggested Attack Paths -->
<h2>Suggested Attack Paths</h2>
{% if attack_commands %}
{% for cmd in attack_commands %}
<div class="command-block">{{ loop.index }}. {{ cmd }}</div>
{% endfor %}
{% else %}
<p style="color:var(--text-secondary)">No suggested attack paths.</p>
{% endif %}

<!-- Raw Output File Index -->
<h2>Raw Output File Index</h2>
{% if output_files %}
<ul class="file-index">
  {% for f in output_files %}
  <li>{{ f }}</li>
  {% endfor %}
</ul>
{% else %}
<p style="color:var(--text-secondary)">No output files recorded.</p>
{% endif %}

<footer>
  Generated by <strong>ReconNinja v2</strong> &mdash; {{ scan_time }}
</footer>

</div>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Markdown generation
# ---------------------------------------------------------------------------


def _format_duration(seconds: float) -> str:
    """Format *seconds* into a human-friendly duration string."""
    mins, secs = divmod(int(seconds), 60)
    if mins >= 60:
        hrs, mins = divmod(mins, 60)
        return f"{hrs}h {mins}m {secs}s"
    return f"{mins}m {secs}s"


def _severity_md_badge(severity: Severity) -> str:
    """Return a Markdown badge string for *severity*."""
    colours = {
        Severity.CRITICAL: "red",
        Severity.HIGH: "orange",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "lightgrey",
    }
    colour = colours.get(severity, "lightgrey")
    return f"![{severity.value}](https://img.shields.io/badge/{severity.value}-{colour})"


def _build_markdown(state: ScanState) -> str:
    """Build the full Markdown report string from *state*.

    Parameters
    ----------
    state:
        The completed :class:`ScanState`.

    Returns
    -------
    str
        The Markdown document content.
    """
    lines: list[str] = []

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    duration = _format_duration(state.duration)

    # 1. Header
    lines.append(f"# ReconNinja Report — {state.target} — {now}\n")

    # 2. Target Information
    lines.append("## Target Information\n")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| **Target** | `{state.target}` |")
    lines.append(f"| **Hostname** | {state.primary_hostname or '—'} |")
    lines.append(f"| **Box Profile** | {state.box_profile} |")
    lines.append(f"| **Scan Duration** | {duration} |")
    lines.append(f"| **Open Ports** | {len(state.open_ports)} |")
    tech_count = len(state.detected_techs)
    vuln_count = len(state.vulnerable_techs())
    lines.append(f"| **Technologies** | {tech_count} detected ({vuln_count} vulnerable) |")
    lines.append("")

    # 3. Open Ports & Services
    lines.append("## Open Ports & Services\n")
    if state.services:
        lines.append("| Port | Proto | Service | Product | Version |")
        lines.append("|------|-------|---------|---------|---------|")
        for port in sorted(state.services):
            svc = state.services[port]
            product = svc.product or "—"
            version = svc.version or "—"
            lines.append(
                f"| {port} | {svc.proto} | {svc.service} | {product} | {version} |"
            )
    else:
        lines.append("*No open ports discovered.*")
    lines.append("")

    # 4. Box Profile
    lines.append("## Box Profile\n")
    lines.append(f"**{state.box_profile}**\n")

    # 4.5 Tech Stack
    lines.append("## Detected Technologies\n")
    if state.detected_techs:
        # Group by port
        ports_with_techs = sorted({t.port for t in state.detected_techs})
        for port in ports_with_techs:
            port_techs = [t for t in state.detected_techs if t.port == port]
            lines.append(f"### Port {port}\n")
            lines.append("| Technology | Version | Category | Confidence | Source | Vulnerable | CVEs |")
            lines.append("|------------|---------|----------|------------|--------|------------|------|")
            for tech in port_techs:
                vuln_badge = "Yes" if tech.is_vulnerable else "—"
                cves = ", ".join(tech.cves) if tech.cves else "—"
                lines.append(
                    f"| {tech.name} | {tech.version or '—'} | {tech.category or '—'} | "
                    f"{tech.confidence} | {tech.source} | {vuln_badge} | {cves} |"
                )
            lines.append("")

        # Vulnerable techs summary
        vulnerable = state.vulnerable_techs()
        if vulnerable:
            lines.append("### Vulnerable Technologies\n")
            for vtech in vulnerable:
                cve_list = ", ".join(vtech.cves)
                lines.append(
                    f"- **{vtech.name} {vtech.version}** (port {vtech.port}) — "
                    f"[{cve_list}] detected via {vtech.source}"
                )
                lines.append(
                    f"  - `searchsploit {vtech.name} {vtech.version}`"
                )
            lines.append("")
    else:
        lines.append("*No technologies detected.*")
    lines.append("")

    # 5. Key Findings
    lines.append("## Key Findings\n")
    sorted_findings = sorted(state.all_findings, key=lambda f: f.severity.rank)
    if sorted_findings:
        for finding in sorted_findings:
            badge = _severity_md_badge(finding.severity)
            cve_tag = f" `{finding.cve}`" if finding.cve else ""
            lines.append(
                f"- {badge} **{finding.title}**{cve_tag} — {finding.description}"
            )
            if finding.evidence:
                evidence_preview = finding.evidence[:300].replace("\n", " ")
                lines.append(f"  - Evidence: `{evidence_preview}`")
    else:
        lines.append("*No findings recorded.*")
    lines.append("")

    # 6. Per-Service Details
    lines.append("## Per-Service Details\n")
    _write_service_details_md(lines, state)

    # 7. Loot
    lines.append("## Loot\n")
    loot = _extract_loot(state)
    if loot:
        lines.append("| Category | Count |")
        lines.append("|----------|-------|")
        for cat, items in sorted(loot.items()):
            lines.append(f"| {cat} | {len(items)} |")
    else:
        lines.append("*No loot extracted.*")
    lines.append("")

    # 8. Suggested Attack Paths
    lines.append("## Suggested Attack Paths\n")
    # Combine finding-level commands with context-aware attack paths
    finding_cmds = _deduplicated_commands(state.all_findings, limit=10)
    context_cmds = _generate_attack_paths(state)
    all_cmds = finding_cmds + [c for c in context_cmds if c not in set(finding_cmds)]
    if all_cmds:
        for i, cmd in enumerate(all_cmds[:20], 1):
            lines.append(f"{i}. `{cmd}`")
    else:
        lines.append("*No suggested attack paths.*")
    lines.append("")

    # 9. Raw Output File Index
    lines.append("## Raw Output File Index\n")
    output_files = _collect_output_files(state)
    if output_files:
        for fpath in sorted(output_files):
            lines.append(f"- `{fpath}`")
    else:
        lines.append("*No output files recorded.*")
    lines.append("")

    return "\n".join(lines)


def _write_service_details_md(lines: list[str], state: ScanState) -> None:
    """Append per-service detail subsections to *lines*.

    Services are grouped by type (Web, SMB, SSH, etc.) with relevant
    sub-information for each.
    """
    # Group services by type
    service_groups: dict[str, list[ServiceInfo]] = {}
    for port in sorted(state.services):
        svc = state.services[port]
        group = _service_group(svc.service, svc.port)
        service_groups.setdefault(group, []).append(svc)

    icons: dict[str, str] = {
        "Web": "",
        "SMB": "",
        "SSH": "",
        "FTP": "",
        "DNS": "",
        "SMTP": "",
        "LDAP": "",
        "Kerberos": "",
        "RDP": "",
        "VNC": "",
        "NFS": "",
        "SNMP": "",
        "Database": "",
        "SSL": "",
        "Other": "",
    }

    for group_name, svcs in sorted(service_groups.items()):
        icon = icons.get(group_name, "")
        icon_str = f"{icon} " if icon else ""
        for svc in svcs:
            lines.append(f"### {icon_str}{group_name} (port {svc.port})\n")
            if svc.product:
                lines.append(f"- **Product**: {svc.display_product}")
            if svc.hostname:
                lines.append(f"- **Hostname**: `{svc.hostname}`")
            if svc.extra_info:
                lines.append(f"- **Extra**: {svc.extra_info}")
            # NSE script output
            if svc.scripts:
                for script_name, output in svc.scripts.items():
                    lines.append(f"- **{script_name}**:")
                    lines.append("  ```")
                    for out_line in output.splitlines()[:20]:
                        lines.append(f"  {out_line}")
                    lines.append("  ```")
            lines.append("")


def _service_group(service: str, port: int = 0) -> str:
    """Classify a service string into a display group name."""
    svc = service.lower()
    if "http" in svc or "ssl/http" in svc:
        return "Web"
    # Common web ports that nmap misidentifies (e.g. port 3000 → "ppp")
    _KNOWN_WEB_PORTS = {
        3000, 3001, 4000, 5000, 8000, 8001, 8081, 8082, 8088,
        8888, 9000, 9090,
    }
    if port in _KNOWN_WEB_PORTS:
        return "Web"
    if "smb" in svc or "microsoft-ds" in svc or "netbios" in svc:
        return "SMB"
    if "ssh" in svc:
        return "SSH"
    if "ftp" in svc:
        return "FTP"
    if "dns" in svc or "domain" in svc:
        return "DNS"
    if "smtp" in svc or "pop3" in svc or "imap" in svc:
        return "SMTP"
    if "ldap" in svc:
        return "LDAP"
    if "kerberos" in svc or "kpasswd" in svc:
        return "Kerberos"
    if "ms-wbt" in svc or "rdp" in svc:
        return "RDP"
    if "vnc" in svc:
        return "VNC"
    if "nfs" in svc:
        return "NFS"
    if "snmp" in svc:
        return "SNMP"
    if "mysql" in svc or "msql" in svc or "postgres" in svc or "mssql" in svc:
        return "Database"
    if "ssl" in svc:
        return "SSL"
    return "Other"


# ---------------------------------------------------------------------------
# HTML generation
# ---------------------------------------------------------------------------


def _build_html(state: ScanState) -> str:
    """Render the HTML report from *state* using the inline Jinja2 template.

    Parameters
    ----------
    state:
        The completed :class:`ScanState`.

    Returns
    -------
    str
        The full HTML document.
    """
    template = _jinja_env.from_string(_HTML_TEMPLATE)

    # Prepare service details for the template
    service_details = []
    for port in sorted(state.services):
        svc = state.services[port]
        group = _service_group(svc.service, svc.port)
        icon_map = {
            "Web": "", "SMB": "", "SSH": "", "FTP": "",
            "DNS": "", "SMTP": "", "LDAP": "", "Kerberos": "",
            "RDP": "", "VNC": "", "NFS": "", "SNMP": "",
            "Database": "", "SSL": "", "Other": "",
        }
        detail: dict[str, Any] = {
            "port": svc.port,
            "label": f"{group} ({svc.service})",
            "icon": icon_map.get(group, ""),
            "product": svc.display_product if svc.product else None,
            "tech_stack": [],
            "dirs": [],
            "shares": [],
            "vulns": [],
            "scripts": svc.scripts,
        }
        # Heuristic: extract tech stack / dirs from NSE scripts
        for script_name, output in svc.scripts.items():
            if "http-headers" in script_name or "http-server-header" in script_name:
                detail["tech_stack"].append(output.strip().split("\n")[0])
            if "http-enum" in script_name:
                for line in output.splitlines():
                    if "/" in line:
                        detail["dirs"].append(line.strip())
            if "smb-enum-shares" in script_name:
                for line in output.splitlines():
                    if "Type:" in line or "Share" in line:
                        detail["shares"].append(line.strip())
            if "vuln" in script_name:
                for line in output.splitlines():
                    if line.strip():
                        detail["vulns"].append(line.strip())
        service_details.append(detail)

    # Loot
    loot = _extract_loot(state)

    # Tech stack data
    tech_by_port = []
    ports_with_techs = sorted({t.port for t in state.detected_techs})
    for port in ports_with_techs:
        port_techs = [t for t in state.detected_techs if t.port == port]
        tech_by_port.append({"port": port, "techs": [t.to_dict() for t in port_techs]})

    vulnerable_techs = [t.to_dict() for t in state.vulnerable_techs()]
    detected_techs = len(state.detected_techs) > 0

    # Attack commands
    finding_cmds = _deduplicated_commands(state.all_findings, limit=10)
    context_cmds = _generate_attack_paths(state)
    attack_commands = finding_cmds + [c for c in context_cmds if c not in set(finding_cmds)]

    # Output files
    output_files = _collect_output_files(state)

    # Findings for template (sorted)
    findings_data = []
    for f in sorted(state.all_findings, key=lambda x: x.severity.rank):
        findings_data.append({
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "cve": f.cve,
            "evidence": f.evidence,
        })

    # Services for table
    services_data = []
    for port in sorted(state.services):
        svc = state.services[port]
        services_data.append({
            "port": svc.port,
            "proto": svc.proto,
            "service": svc.service,
            "product": svc.product,
            "version": svc.version,
        })

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return template.render(
        target=state.target,
        hostname=state.primary_hostname,
        box_profile=state.box_profile,
        duration=_format_duration(state.duration),
        scan_time=now,
        open_ports=state.open_ports,
        services=services_data,
        findings=findings_data,
        service_details=service_details,
        loot=loot,
        detected_techs=detected_techs,
        tech_by_port=tech_by_port,
        vulnerable_techs=vulnerable_techs,
        attack_commands=attack_commands,
        output_files=output_files,
    )


# ---------------------------------------------------------------------------
# JSON generation
# ---------------------------------------------------------------------------


def _build_json(state: ScanState) -> str:
    """Build the JSON report string from *state*.

    Parameters
    ----------
    state:
        The completed :class:`ScanState`.

    Returns
    -------
    str
        Pretty-printed JSON string.
    """
    now = datetime.now().isoformat()

    # Services dict with integer keys serialised
    services_data: dict[str, Any] = {}
    for port, svc in state.services.items():
        services_data[str(port)] = svc.to_dict()

    # Open ports list
    open_ports_data: list[dict[str, Any]] = []
    for port in sorted(state.services):
        svc = state.services[port]
        open_ports_data.append({
            "port": svc.port,
            "proto": svc.proto,
            "state": svc.state,
            "service": svc.service,
            "product": svc.product,
            "version": svc.version,
        })

    # Findings
    findings_data = [
        {
            "severity": f.severity.value,
            "title": f.title,
            "description": f.description,
            "cve": f.cve,
            "module": f.module,
            "suggested_commands": f.suggested_commands,
        }
        for f in sorted(state.all_findings, key=lambda x: x.severity.rank)
    ]

    # Loot
    loot = _extract_loot(state)

    # Detected techs
    techs_data = [t.to_dict() for t in state.detected_techs]

    report: dict[str, Any] = {
        "target": state.target,
        "scan_time": now,
        "box_profile": state.box_profile,
        "open_ports": open_ports_data,
        "services": services_data,
        "detected_techs": techs_data,
        "findings": findings_data,
        "loot": loot,
    }

    return json.dumps(report, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _extract_loot(state: ScanState) -> dict[str, list[str]]:
    """Extract loot categories from module results.

    This is a best-effort heuristic that scans raw output for patterns.
    In the future modules should push structured loot data into the state.

    Returns
    -------
    dict[str, list[str]]
        Mapping of category name → list of found items.
    """
    loot: dict[str, list[str]] = {
        "usernames": [],
        "hashes": [],
        "emails": [],
        "shares": [],
    }

    for result in state.module_results:
        raw = result.raw_output
        if not raw:
            continue

        for line in raw.splitlines():
            line_stripped = line.strip()
            if not line_stripped:
                continue

            lower = line_stripped.lower()

            # Username patterns
            if any(marker in lower for marker in ("user:", "username:", "account:", "cn=")):
                if line_stripped not in loot["usernames"]:
                    loot["usernames"].append(line_stripped)

            # Hash patterns
            if any(marker in lower for marker in ("::", "$1$", "$2a$", "$6$", "ntlm", "hash:")):
                if line_stripped not in loot["hashes"]:
                    loot["hashes"].append(line_stripped)

            # Email patterns
            if "@" in line_stripped and "." in line_stripped:
                if line_stripped not in loot["emails"]:
                    loot["emails"].append(line_stripped)

            # Share patterns
            if "share" in lower and ("type:" in lower or "disk" in lower or "print" in lower):
                if line_stripped not in loot["shares"]:
                    loot["shares"].append(line_stripped)

    # Prune empty categories
    return {k: v for k, v in loot.items() if v}


def _deduplicated_commands(findings: list[Finding], limit: int = 10) -> list[str]:
    """Return deduplicated suggested commands from *findings*, up to *limit*.

    Parameters
    ----------
    findings:
        Findings to extract commands from.
    limit:
        Maximum number of commands to return.

    Returns
    -------
    list[str]
        Ordered, deduplicated command strings.
    """
    seen: set[str] = set()
    commands: list[str] = []
    for finding in sorted(findings, key=lambda f: f.severity.rank):
        for cmd in finding.suggested_commands:
            if cmd not in seen:
                seen.add(cmd)
                commands.append(cmd)
            if len(commands) >= limit:
                return commands
    return commands


def _generate_attack_paths(state: ScanState) -> list[str]:
    """Generate context-aware attack path suggestions based on the scan state.

    This uses the detected services, tech stack, and box profile to suggest
    concrete attack commands that a pentester/CTF player can copy-paste.

    Parameters
    ----------
    state:
        The completed :class:`ScanState`.

    Returns
    -------
    list[str]
        Ordered list of attack command suggestions.
    """
    commands: list[str] = []
    target = state.target
    port_set = set(state.open_ports)
    services = state.services
    techs = state.detected_techs

    # Build tech lookup for attack path generation

    # --- Vulnerable techs (highest priority) ---
    vulnerable = state.vulnerable_techs()
    for vtech in vulnerable:
        cves = ", ".join(vtech.cves)
        commands.append(
            f"# [!] {vtech.name} {vtech.version} is VULNERABLE ({cves}) — "
            f"searchsploit {vtech.name} {vtech.version}"
        )

    # --- SSH ---
    if 22 in port_set or any("ssh" in s.service.lower() for s in services.values()):
        commands.append(f"ssh {target}  # Try default creds: root:root, admin:admin")
        commands.append(f"hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://{target}")

    # --- Web ---
    _KNOWN_WEB_PORTS = {
        80, 443, 8080, 8443,
        3000, 3001, 4000, 5000, 8000, 8001, 8081, 8082, 8088,
        8888, 9000, 9090, 4443,
    }
    web_ports = []
    for p in state.open_ports:
        if p in _KNOWN_WEB_PORTS:
            web_ports.append(p)
        elif p in services and "http" in services[p].service.lower():
            web_ports.append(p)
    for wp in web_ports:
        scheme = "https" if wp in (443, 8443, 4443) else "http"
        url = f"{scheme}://{target}:{wp}"
        commands.append(f"nmap -p{wp} --script http-enum,http-headers,http-methods,http-vuln* {target}")
        commands.append(f"nikto -h {url}")
        commands.append(f"feroxbuster -u {url} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")
        commands.append(f"gobuster dir -u {url} -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")
        # Only suggest one curl per web port
        commands.append(f"curl -sI {url}  # Check headers for tech stack")
        break  # One set of web commands is enough; adjust port manually

    # --- SMB ---
    if port_set.intersection({139, 445}):
        commands.append(f"smbclient -L //{target}/ -N")
        commands.append(f"smbmap -H {target}")
        commands.append(f"enum4linux -a {target}")
        commands.append(f"crackmapexec smb {target}")

    # --- FTP ---
    if 21 in port_set:
        commands.append(f"ftp {target}  # Try anonymous:anonymous")
        commands.append(f"hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://{target}")

    # --- DNS ---
    if 53 in port_set:
        commands.append(f"dnsrecon -d {target} -t std")
        commands.append(f"dig axfr {target} @{target}")

    # --- SNMP ---
    if 161 in set(state.udp_ports):
        commands.append(f"snmpwalk -v2c -c public {target}")
        commands.append(f"onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt {target}")

    # --- LDAP ---
    if port_set.intersection({389, 636}):
        commands.append(f"ldapsearch -x -H ldap://{target} -b '' -s base namingContexts")
        commands.append(f"enum4linux -a {target}")

    # --- Kerberos ---
    if 88 in port_set:
        commands.append(f"kerbrute userenum --domain corp.local --dc {target} /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt")

    # --- NFS ---
    if 2049 in port_set:
        commands.append(f"showmount -e {target}")
        commands.append(f"mount -t nfs {target}:/ /mnt/nfs")

    # --- RDP ---
    if 3389 in port_set:
        commands.append(f"xfreerdp /v:{target} /cert:ignore /u:admin")

    # --- Database ---
    db_ports = {3306: "mysql", 5432: "psql", 1433: "mssql", 6379: "redis-cli", 27017: "mongosh"}
    for dp, tool in db_ports.items():
        if dp in port_set:
            if tool == "mysql":
                commands.append(f"mysql -h {target} -u root -p")
            elif tool == "psql":
                commands.append(f"psql -h {target} -U postgres")
            elif tool == "mssql":
                commands.append(f"impacket-mssqlclient admin@{target}")
            elif tool == "redis-cli":
                commands.append(f"redis-cli -h {target} INFO")
            elif tool == "mongosh":
                commands.append(f"mongosh mongodb://{target}")

    # --- Tech-specific attack paths ---
    _KNOWN_WEB_PORTS = {
        80, 443, 8080, 8443,
        3000, 3001, 4000, 5000, 8000, 8001, 8081, 8082, 8088,
        8888, 9000, 9090, 4443,
    }
    for wp in web_ports:
        scheme = "https" if wp in (443, 8443, 4443) else "http"
        url = f"{scheme}://{target}:{wp}"

        port_techs = [t for t in techs if t.port == wp]

        # WordPress
        if any(t.name.lower() == "wordpress" for t in port_techs):
            commands.append(f"wpscan --url {url} --enumerate u,p,t --passwords /usr/share/wordlists/rockyou.txt")

        # Drupal
        if any(t.name.lower() == "drupal" for t in port_techs):
            commands.append(f"droopescan scan drupal -u {url}")
            commands.append(f"python3 drupa7-CVE-2018-7600.py {url}  # Drupalgeddon2")

        # Joomla
        if any(t.name.lower() == "joomla" for t in port_techs):
            commands.append(f"joomscan -u {url}")

        # Next.js
        if any(t.name.lower() == "next.js" for t in port_techs):
            commands.append(f"curl {url}/_next/data/  # Next.js data endpoint")
            commands.append(f"curl {url}/api/  # Next.js API routes")

        # ASP.NET
        if any("asp.net" in t.name.lower() for t in port_techs):
            commands.append(f"dotnet {url}  # Check for ViewState deserialization")

        # PHP
        if any(t.name.lower() == "php" for t in port_techs):
            commands.append(f"feroxbuster -u {url} -x php,txt,bak -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt")

        # Tomcat
        if any("tomcat" in t.name.lower() for t in port_techs):
            commands.append(f"hydra -L users.txt -P pass.txt {url} http-get /manager/html")

        # Spring Boot
        if any("spring" in t.name.lower() for t in port_techs):
            commands.append(f"curl {url}/actuator/env  # Spring Boot actuator")

        break  # One set of tech-specific commands per web port group

    # --- Nuclei ---
    commands.append(f"nuclei -u {target} -t /usr/share/nuclei-templates/")

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for cmd in commands:
        if cmd not in seen:
            seen.add(cmd)
            unique.append(cmd)

    return unique[:25]  # cap at 25 suggestions


def _collect_output_files(state: ScanState) -> list[str]:
    """Collect all output file paths from module results.

    Returns
    -------
    list[str]
        Stringified paths to output files produced by each module.
    """
    files: list[str] = []
    for result in state.module_results:
        if result.output_file:
            files.append(str(result.output_file))
    return sorted(files)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def generate_reports(
    state: ScanState,
    output_dir: Path,
    html: bool = False,
    json_output: bool = True,
) -> dict[str, Path]:
    """Generate all report formats from a completed scan.

    Creates the following files inside *output_dir*:

    * ``00_SUMMARY.md``   — always generated.
    * ``00_SUMMARY.html`` — generated when *html* is ``True``.
    * ``00_findings.json`` — generated when *json_output* is ``True``.

    Parameters
    ----------
    state:
        The completed :class:`ScanState` with all findings and results.
    output_dir:
        Directory where report files will be written.  Created if needed.
    html:
        Whether to also produce an HTML report.
    json_output:
        Whether to produce the JSON findings export.  Defaults to ``True``.

    Returns
    -------
    dict[str, Path]
        Mapping of format name (``"markdown"``, ``"html"``, ``"json"``)
        to the :class:`Path` of the generated file.

    Raises
    ------
    OSError
        If the output directory cannot be created or a file cannot be written.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    generated: dict[str, Path] = {}

    # --- Markdown ---
    try:
        md_path = output_dir / _MD_FILENAME
        md_content = _build_markdown(state)
        async with aiofiles.open(md_path, mode="w", encoding="utf-8") as f:
            await f.write(md_content)
        generated["markdown"] = md_path
        logger.info("Markdown report written to %s", md_path)
    except OSError:
        logger.exception("Failed to write Markdown report")
        raise

    # --- HTML ---
    if html:
        try:
            html_path = output_dir / _HTML_FILENAME
            html_content = _build_html(state)
            async with aiofiles.open(html_path, mode="w", encoding="utf-8") as f:
                await f.write(html_content)
            generated["html"] = html_path
            logger.info("HTML report written to %s", html_path)
        except OSError:
            logger.exception("Failed to write HTML report")
            raise

    # --- JSON ---
    if json_output:
        try:
            json_path = output_dir / _JSON_FILENAME
            json_content = _build_json(state)
            async with aiofiles.open(json_path, mode="w", encoding="utf-8") as f:
                await f.write(json_content)
            generated["json"] = json_path
            logger.info("JSON report written to %s", json_path)
        except OSError:
            logger.exception("Failed to write JSON report")
            raise

    return generated
