"""Pure ``xml.etree`` Nmap XML parser for ReconNinja v2.

Parses Nmap XML output **without** depending on the ``python-nmap``
library.  Also provides helpers for RustScan text output and Nmap
grepable (``-oG``) output.

The parser extracts:
- Open port services (port, proto, state, service name, product,
  version, extrainfo)
- Per-port script output (``<script>`` elements)
- Hostnames from ``<hostname>`` elements and ``http-title`` script
  output
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from recon_ninja.core.models import ServiceInfo


# ---------------------------------------------------------------------------
# Nmap XML parser
# ---------------------------------------------------------------------------

def parse_nmap_xml(
    xml_path: Path,
) -> tuple[dict[int, ServiceInfo], list[str]]:
    """Parse an Nmap XML scan file.

    Parameters
    ----------
    xml_path : Path
        Path to the ``.xml`` file produced by ``nmap -oX``.

    Returns
    -------
    tuple[dict[int, ServiceInfo], list[str]]
        A 2-tuple of:
        - ``services``: dict keyed by port number → :class:`ServiceInfo`
        - ``hostnames``: list of deduplicated hostname strings discovered
          from ``<hostname>`` elements and ``http-title`` scripts.

    Notes
    -----
    Malformed XML is handled gracefully — an empty result set is
    returned and the error is silently swallowed so the scan pipeline
    can continue.
    """
    services: dict[int, ServiceInfo] = {}
    hostnames: list[str] = []

    try:
        tree = ET.parse(str(xml_path))
    except (ET.ParseError, FileNotFoundError, PermissionError, OSError):
        return services, hostnames

    root = tree.getroot()

    # -- Extract hostnames from <hostname> elements --------------------------
    for hostname_elem in root.iter("hostname"):
        name = hostname_elem.get("name", "").strip()
        if name and name not in hostnames:
            hostnames.append(name)

    # -- Parse each <port> element ------------------------------------------
    for port_elem in root.iter("port"):
        try:
            port_id = int(port_elem.get("portid", "0"))
        except (ValueError, TypeError):
            continue

        proto = port_elem.get("protocol", "tcp")
        state_elem = port_elem.find("state")
        state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"

        # Only care about open / open|filtered ports
        if state not in ("open", "open|filtered"):
            continue

        svc_elem = port_elem.find("service")
        service_name = svc_elem.get("name", "unknown") if svc_elem is not None else "unknown"
        product = svc_elem.get("product", "") if svc_elem is not None else ""
        version = svc_elem.get("version", "") if svc_elem is not None else ""
        extra_info = svc_elem.get("extrainfo", "") if svc_elem is not None else ""

        # -- Parse <script> children ----------------------------------------
        scripts: dict[str, str] = {}
        for script_elem in port_elem.findall("script"):
            script_id = script_elem.get("id", "")
            script_output = script_elem.get("output", "")
            if script_id:
                scripts[script_id] = script_output

            # Extract hostname from http-title script
            if script_id == "http-title" and script_output:
                title = script_output.strip()
                if title and title not in hostnames:
                    hostnames.append(title)

        info = ServiceInfo(
            port=port_id,
            proto=proto,
            state=state,
            service=service_name,
            product=product,
            version=version,
            extra_info=extra_info,
            scripts=scripts,
        )
        services[port_id] = info

    return services, hostnames


# ---------------------------------------------------------------------------
# RustScan output parser
# ---------------------------------------------------------------------------

_RUSTSCAN_PORT_RE = re.compile(r"\b(\d{1,5})/tcp\b")
_RUSTSCAN_OPEN_RE = re.compile(r"Open\s+(\d{1,5})")


def parse_rustscan_output(output: str) -> list[int]:
    """Extract open port numbers from RustScan text output.

    RustScan prints lines like::

        Open 22
        Open 80
        Open 443

    It also commonly includes an nmap-style summary like ``22/tcp``.
    Both formats are handled.

    Parameters
    ----------
    output : str
        Raw stdout from a RustScan run.

    Returns
    -------
    list[int]
        Sorted list of unique open port numbers.
    """
    ports: set[int] = set()

    for match in _RUSTSCAN_OPEN_RE.finditer(output):
        try:
            ports.add(int(match.group(1)))
        except (ValueError, TypeError):
            continue

    for match in _RUSTSCAN_PORT_RE.finditer(output):
        try:
            ports.add(int(match.group(1)))
        except (ValueError, TypeError):
            continue

    return sorted(ports)


# ---------------------------------------------------------------------------
# Nmap grepable output parser
# ---------------------------------------------------------------------------

_NMAP_GREPABLE_RE = re.compile(
    r"Ports:\s+(.+?)(?:\s+Ignored State:|$)"
)


def parse_nmap_grepable(output: str) -> list[int]:
    """Extract open port numbers from Nmap grepable (``-oG``) output.

    The ``Ports:`` field in grepable output looks like::

        Ports: 22/open/tcp//ssh//OpenSSH 8.9p1/, 80/open/tcp//http//Apache httpd 2.4.52/

    Each entry is ``port/state/proto//service//product/version/``.

    Parameters
    ----------
    output : str
        Raw content of an ``-oG`` file or string.

    Returns
    -------
    list[int]
        Sorted list of unique open port numbers.
    """
    ports: set[int] = set()

    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("Host:") and "Ports:" not in line:
            continue

        match = _NMAP_GREPABLE_RE.search(line)
        if not match:
            continue

        port_section = match.group(1)
        # Split on comma+space, each entry like "22/open/tcp//ssh//OpenSSH 8.9p1/"
        for entry in port_section.split(","):
            entry = entry.strip()
            parts = entry.split("/")
            if len(parts) >= 2:
                try:
                    port_num = int(parts[0])
                    port_state = parts[1]
                    if port_state == "open":
                        ports.add(port_num)
                except (ValueError, TypeError):
                    continue

    return sorted(ports)


__all__: list[str] = [
    "parse_nmap_xml",
    "parse_rustscan_output",
    "parse_nmap_grepable",
]
