"""Regex-based loot extractor for Recon Ninja v2.

After all modules complete, scan ALL raw output files in the results
directory and extract structured loot (usernames, hashes, emails,
passwords, private IPs, paths) using pattern-matching regexes.

Extracted loot is saved per-category under ``results/loot/`` and
significant items are promoted to :class:`Finding` objects so they
appear in the final report.
"""

from __future__ import annotations

import re
from pathlib import Path

from recon_ninja.core.models import Finding, Severity

# ---------------------------------------------------------------------------
# Loot patterns — each category maps to a list of regex strings
# ---------------------------------------------------------------------------

LOOT_PATTERNS: dict[str, list[str]] = {
    "usernames": [
        r"Username:\s+(\S+)",
        r"uid=\d+\((\w+)\)",
        r"user:\s*(\S+)",
    ],
    "hashes": [
        r"[a-f0-9]{32}",
        r"\$[0-9a-z]+\$\S+",
        r"[A-Z0-9]{32}:[a-f0-9]{32}",
    ],
    "emails": [
        r"[\w.+-]+@[\w-]+\.[\w.-]+",
    ],
    "passwords": [
        r"[Pp]assword[:\s]+(\S+)",
        r"[Pp]ass[:\s]+(\S+)",
        r"pwd[:\s]+(\S+)",
    ],
    "ips": [
        r"\b(?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    ],
    "paths": [
        r"(?:/[\w.-]+){2,}",
    ],
}

# False-positive filters applied *after* extraction
_FALSE_POSITIVE_PATTERNS: dict[str, list[str]] = {
    "usernames": [r"CVE-\d{4}-\d+"],  # CVE IDs falsely matched by user: pattern
    "hashes": [r"0{32}", r"f{32}"],    # All-zero / all-f hex strings
    "emails": [r"@example\.(com|org|net)$"],  # Placeholder emails
    "passwords": [r"^[*]+$"],           # Masked passwords like ****
    "ips": [],
    "paths": [],
}

# File extensions to SKIP when scanning output files
_SKIP_EXTENSIONS: set[str] = {".state", ".json", ".md", ".html", ".log"}

# Category → Severity mapping for loot_to_findings
_LOOT_SEVERITY: dict[str, Severity] = {
    "usernames": Severity.INFO,
    "hashes": Severity.HIGH,
    "emails": Severity.INFO,
    "passwords": Severity.CRITICAL,
    "ips": Severity.INFO,
    "paths": Severity.INFO,
}


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------

async def extract_loot(output_dir: Path) -> dict[str, list[str]]:
    """Walk all files in *output_dir* and extract loot using LOOT_PATTERNS.

    Files with extensions in :data:`_SKIP_EXTENSIONS` are ignored.  For
    each category, all regex patterns are applied to every line of every
    eligible file.  Results are deduplicated (order-preserving) and
    returned as a dict of ``category → [values]``.

    Parameters
    ----------
    output_dir:
        The scan output directory (e.g. ``results/10.10.11.42/``).

    Returns
    -------
    dict[str, list[str]]
        Per-category extracted loot, deduplicated.
    """
    loot: dict[str, list[str]] = {cat: [] for cat in LOOT_PATTERNS}
    seen: dict[str, set[str]] = {cat: set() for cat in LOOT_PATTERNS}

    if not output_dir.is_dir():
        return loot

    # Walk the entire directory tree
    for filepath in output_dir.rglob("*"):
        if not filepath.is_file():
            continue
        if filepath.suffix.lower() in _SKIP_EXTENSIONS:
            continue

        try:
            text = filepath.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            continue

        for category, patterns in LOOT_PATTERNS.items():
            compiled_patterns = [re.compile(p) for p in patterns]
            for pattern in compiled_patterns:
                for match in pattern.finditer(text):
                    # Use group(1) if the pattern has a capture group,
                    # otherwise use group(0) (the full match).
                    value = match.group(1) if match.lastindex else match.group(0)
                    value = value.strip()

                    if not value:
                        continue

                    # Apply false-positive filter
                    if _is_false_positive(category, value):
                        continue

                    if value not in seen[category]:
                        seen[category].add(value)
                        loot[category].append(value)

    return loot


def _is_false_positive(category: str, value: str) -> bool:
    """Return ``True`` if *value* matches any false-positive pattern for *category*."""
    for fp_pattern in _FALSE_POSITIVE_PATTERNS.get(category, []):
        if re.search(fp_pattern, value):
            return True
    return False


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_loot(output_dir: Path, loot: dict[str, list[str]]) -> None:
    """Save each loot category to ``results/loot/{category}.txt``.

    Each file contains one extracted value per line.  The ``loot/``
    subdirectory is created inside *output_dir* if it does not exist.

    Parameters
    ----------
    output_dir:
        The scan output directory.
    loot:
        Per-category extracted loot (as returned by :func:`extract_loot`).
    """
    loot_dir = output_dir / "loot"
    loot_dir.mkdir(parents=True, exist_ok=True)

    for category, values in loot.items():
        if not values:
            continue
        loot_file = loot_dir / f"{category}.txt"
        loot_file.write_text(
            "\n".join(values) + "\n",
            encoding="utf-8",
        )


# ---------------------------------------------------------------------------
# Convert loot to Finding objects
# ---------------------------------------------------------------------------

def loot_to_findings(loot: dict[str, list[str]]) -> list[Finding]:
    """Convert significant loot items into :class:`Finding` objects.

    Severity mapping:

    * **usernames** → ``INFO``
    * **hashes** → ``HIGH``
    * **emails** → ``INFO``
    * **passwords** → ``CRITICAL``
    * **ips** (private) → ``INFO``
    * **paths** → ``INFO`` (not promoted to findings by default)

    Categories with no values are skipped.  For categories with many
    values, only the first 50 are included in the finding evidence to
    keep reports readable.

    Parameters
    ----------
    loot:
        Per-category extracted loot (as returned by :func:`extract_loot`).

    Returns
    -------
    list[Finding]
        Findings for non-empty loot categories.
    """
    findings: list[Finding] = []

    # Paths are typically too noisy to promote to findings
    categories_to_report = ["usernames", "hashes", "emails", "passwords", "ips"]

    for category in categories_to_report:
        values = loot.get(category, [])
        if not values:
            continue

        severity = _LOOT_SEVERITY.get(category, Severity.INFO)

        # Cap evidence to first 50 items for readability
        displayed = values[:50]
        evidence_lines = "\n".join(f"  - {v}" for v in displayed)
        extra_count = len(values) - len(displayed)
        if extra_count > 0:
            evidence_lines += f"\n  ... and {extra_count} more"

        finding = Finding(
            severity=severity,
            title=f"Loot: {category.capitalize()} extracted",
            description=(
                f"Extracted {len(values)} {category} from scan output."
            ),
            module="loot",
            evidence=evidence_lines,
        )
        findings.append(finding)

    return findings
