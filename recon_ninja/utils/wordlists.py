"""SecLists wordlist path resolver for ReconNinja v2.

Resolves wordlist files by searching a user-supplied custom directory
first, then falling back to the standard SecLists installation path.
Also provides helpers to auto-discover the SecLists base directory.
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Common SecLists install locations (searched in order)
# ---------------------------------------------------------------------------

_SECLISTS_SEARCH_PATHS: list[str] = [
    "/usr/share/seclists",
    "/opt/seclists",
    str(Path.home() / "SecLists"),
    "/usr/local/share/seclists",
]

# ---------------------------------------------------------------------------
# Wordlist relative paths inside SecLists
# ---------------------------------------------------------------------------

_DIR_WORDLIST_CANDIDATES: list[str] = [
    "Discovery/Web-Content/raft-medium-directories-lowercase.txt",
    "Discovery/Web-Content/raft-medium-directories.txt",
    "Discovery/Web-Content/common.txt",
    "Discovery/Web-Content/directory-list-2.3-medium.txt",
]

_VHOST_WORDLIST_CANDIDATES: list[str] = [
    "Discovery/DNS/subdomains-top1million-5000.txt",
    "Discovery/DNS/subdomains-top1million-110000.txt",
    "Discovery/DNS/namelist.txt",
]

_USERNAME_WORDLIST_CANDIDATES: list[str] = [
    "Usernames/_names/names.txt",
    "Usernames/xato-net-10-million-usernames.txt",
    "Usernames/top-usernames-shortlist.txt",
]

_SNMP_WORDLIST_CANDIDATES: list[str] = [
    "Misc/wordlists-common/snmp.txt",
    "Discovery/SNMP/common-snmp-community-strings.txt",
]


# ---------------------------------------------------------------------------
# Core resolver
# ---------------------------------------------------------------------------

def resolve_wordlist(
    name: str,
    seclists_base: str,
    custom_dir: str | None = None,
) -> Path | None:
    """Resolve a wordlist file by name.

    Search order:
      1. *custom_dir* (if provided) – the file is looked up directly
         and also inside any subdirectory matching *name*.
      2. *seclists_base* – the file is looked up directly and also
         inside any subdirectory matching *name*.

    The *name* parameter is treated as a **relative path fragment**
    inside the search directories (e.g. ``"Discovery/Web-Content/common.txt"``).
    It can also be a simple filename — the function will try both the
    plain name and a recursive search via :meth:`Path.rglob`.

    Parameters
    ----------
    name : str
        Relative path or filename of the desired wordlist.
    seclists_base : str
        Root directory of the SecLists collection.
    custom_dir : str | None
        Optional user-supplied directory that takes priority.

    Returns
    -------
    Path | None
        The first matching path, or ``None`` if nothing is found.
    """
    search_dirs: list[Path] = []
    if custom_dir is not None:
        search_dirs.append(Path(custom_dir))
    search_dirs.append(Path(seclists_base))

    for base in search_dirs:
        if not base.is_dir():
            continue

        # Try the relative path directly
        direct = base / name
        if direct.is_file():
            return direct

        # Try a recursive glob for just the filename
        filename = Path(name).name
        try:
            for match in base.rglob(filename):
                if match.is_file():
                    return match
        except PermissionError:
            continue

    return None


# ---------------------------------------------------------------------------
# SecLists auto-discovery
# ---------------------------------------------------------------------------

def find_seclists() -> str | None:
    """Attempt to locate a SecLists installation on the system.

    Searches the standard paths defined in :data:`_SECLISTS_SEARCH_PATHS`.

    Returns
    -------
    str | None
        The base directory path as a string, or ``None`` if not found.
    """
    for candidate in _SECLISTS_SEARCH_PATHS:
        p = Path(candidate)
        if p.is_dir():
            # Quick sanity check – SecLists should have at least one
            # known subdirectory.
            if (p / "Discovery").is_dir() or (p / "Usernames").is_dir():
                return candidate
            # If the dir exists but lacks the expected layout, still
            # return it – the user may have a custom structure.
            return candidate
    return None


# ---------------------------------------------------------------------------
# Category helpers
# ---------------------------------------------------------------------------

def _resolve_first(
    candidates: list[str],
    seclists_base: str,
    custom_dir: str | None = None,
) -> Path | None:
    """Try each candidate path in order, return the first found."""
    for rel_path in candidates:
        result = resolve_wordlist(rel_path, seclists_base, custom_dir)
        if result is not None:
            return result
    return None


def get_dir_wordlist(seclists_base: str, custom_dir: str | None = None) -> Path | None:
    """Return a directory brute-force wordlist from SecLists.

    Priority order:
      1. ``raft-medium-directories-lowercase``
      2. ``raft-medium-directories``
      3. ``common``
      4. ``directory-list-2.3-medium``

    Parameters
    ----------
    seclists_base : str
        Root directory of the SecLists collection.
    custom_dir : str | None
        Optional custom directory.

    Returns
    -------
    Path | None
        Path to the first available directory wordlist, or ``None``.
    """
    return _resolve_first(_DIR_WORDLIST_CANDIDATES, seclists_base, custom_dir)


def get_dir_small_wordlist(
    seclists_base: str, custom_dir: str | None = None,
) -> Path | None:
    """Return a small directory brute-force wordlist from SecLists.

    Priority order:
      1. ``raft-small-directories-lowercase.txt`` (~32 entries)
      2. ``raft-small-directories.txt`` (~32 entries)
      3. ``common.txt`` (~4614 entries)
      4. ``raft-medium-directories-lowercase.txt`` (~26K entries)

    Parameters
    ----------
    seclists_base : str
        Root directory of the SecLists collection.
    custom_dir : str | None
        Optional custom directory.

    Returns
    -------
    Path | None
        Path to the first available directory wordlist, or ``None``.
    """
    candidates = [
        "Discovery/Web-Content/raft-small-directories-lowercase.txt",
        "Discovery/Web-Content/raft-small-directories.txt",
        "Discovery/Web-Content/common.txt",
        "Discovery/Web-Content/raft-medium-directories-lowercase.txt",
        "Discovery/Web-Content/raft-medium-directories.txt",
    ]
    return _resolve_first(candidates, seclists_base, custom_dir)


def get_vhost_wordlist(seclists_base: str, custom_dir: str | None = None) -> Path | None:
    """Return a virtual-host / subdomain wordlist from SecLists.

    Parameters
    ----------
    seclists_base : str
        Root directory of the SecLists collection.
    custom_dir : str | None
        Optional custom directory.

    Returns
    -------
    Path | None
        Path to the first available vhost wordlist, or ``None``.
    """
    return _resolve_first(_VHOST_WORDLIST_CANDIDATES, seclists_base, custom_dir)


def get_username_wordlist(seclists_base: str, custom_dir: str | None = None) -> Path | None:
    """Return a username wordlist from SecLists.

    Parameters
    ----------
    seclists_base : str
        Root directory of the SecLists collection.
    custom_dir : str | None
        Optional custom directory.

    Returns
    -------
    Path | None
        Path to the first available username wordlist, or ``None``.
    """
    return _resolve_first(_USERNAME_WORDLIST_CANDIDATES, seclists_base, custom_dir)


def get_snmp_wordlist(seclists_base: str, custom_dir: str | None = None) -> Path | None:
    """Return an SNMP community-string wordlist from SecLists.

    Parameters
    ----------
    seclists_base : str
        Root directory of the SecLists collection.
    custom_dir : str | None
        Optional custom directory.

    Returns
    -------
    Path | None
        Path to the first available SNMP wordlist, or ``None``.
    """
    return _resolve_first(_SNMP_WORDLIST_CANDIDATES, seclists_base, custom_dir)


__all__: list[str] = [
    "resolve_wordlist",
    "find_seclists",
    "get_dir_wordlist",
    "get_dir_small_wordlist",
    "get_vhost_wordlist",
    "get_username_wordlist",
    "get_snmp_wordlist",
]
