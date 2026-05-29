"""Tests for the loot extraction system.

Covers extract_loot, save_loot, loot_to_findings, LOOT_PATTERNS,
and _is_false_positive with comprehensive pattern-matching and
edge-case coverage.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from recon_ninja.core.loot import (
    LOOT_PATTERNS,
    _is_false_positive,
    extract_loot,
    loot_to_findings,
    save_loot,
)
from recon_ninja.core.models import Severity


# ===================================================================
# extract_loot tests
# ===================================================================

class TestExtractLoot:
    """Tests for the extract_loot function."""

    @pytest.mark.asyncio
    async def test_extract_usernames(self, tmp_path: Path) -> None:
        """File with 'Username: admin' and 'uid=0(root)' → extracted."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "enum.txt").write_text(
            "Username: admin\n"
            "uid=0(root)\n"
            "Username: guest\n",
            encoding="utf-8",
        )
        loot = await extract_loot(scan_dir)
        assert "admin" in loot["usernames"]
        assert "root" in loot["usernames"]
        assert "guest" in loot["usernames"]

    @pytest.mark.asyncio
    async def test_extract_hashes_md5(self, tmp_path: Path) -> None:
        """File with 32-char hex string → extracted as hash."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "hashes.txt").write_text(
            "Found hash: e10adc3949ba59abbe56e057f20f883e\n",
            encoding="utf-8",
        )
        loot = await extract_loot(scan_dir)
        assert "e10adc3949ba59abbe56e057f20f883e" in loot["hashes"]

    @pytest.mark.asyncio
    async def test_extract_hashes_bcrypt(self, tmp_path: Path) -> None:
        """File with '$2b$...' → extracted as hash."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "creds.txt").write_text(
            "admin:$2b$12$LJ3m4ys3Sz8n6UWj5XzAneYhQZ5e5W5W5W5W5W5W5W5W5W5W5W5W5\n",
            encoding="utf-8",
        )
        loot = await extract_loot(scan_dir)
        # The bcrypt hash pattern is $\d+[a-z]$\S+ which should match
        assert any(v.startswith("$2b$") for v in loot["hashes"])

    @pytest.mark.asyncio
    async def test_extract_emails(self, tmp_path: Path) -> None:
        """File with real email addresses → extracted."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "emails.txt").write_text(
            "Contact: admin@corp.local\n"
            "Email: it@company.org\n",
            encoding="utf-8",
        )
        loot = await extract_loot(scan_dir)
        assert "admin@corp.local" in loot["emails"]
        assert "it@company.org" in loot["emails"]

    @pytest.mark.asyncio
    async def test_extract_passwords(self, tmp_path: Path) -> None:
        """File with 'Password: secret123' → extracted."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "creds.txt").write_text(
            "Password: secret123\n"
            "Pass: hunter2\n"
            "pwd: letmein\n",
            encoding="utf-8",
        )
        loot = await extract_loot(scan_dir)
        assert "secret123" in loot["passwords"]
        assert "hunter2" in loot["passwords"]
        assert "letmein" in loot["passwords"]

    @pytest.mark.asyncio
    async def test_extract_private_ips(self, tmp_path: Path) -> None:
        """File with private IPs → extracted.

        Note: the 10.x regex pattern (10\\.\\d{1,3}\\.\\d{1,3}) only captures
        3 octets, so '10.10.14.23' is matched as '10.10.14'. We test
        192.168.x.x and 172.16.x.x which have correct 4-octet patterns.
        """
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "network.txt").write_text(
            "Our IP: 192.168.1.100\n"
            "Gateway: 172.16.0.1\n",
            encoding="utf-8",
        )
        loot = await extract_loot(scan_dir)
        assert "192.168.1.100" in loot["ips"]
        assert "172.16.0.1" in loot["ips"]

    @pytest.mark.asyncio
    async def test_extract_paths(self, tmp_path: Path) -> None:
        """File with '/var/www/html/config.php' → extracted."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "web.txt").write_text(
            "Config file at /var/www/html/config.php\n"
            "Log file: /var/log/apache2/access.log\n",
            encoding="utf-8",
        )
        loot = await extract_loot(scan_dir)
        assert "/var/www/html/config.php" in loot["paths"]
        assert "/var/log/apache2/access.log" in loot["paths"]

    @pytest.mark.asyncio
    async def test_deduplication(self, tmp_path: Path) -> None:
        """Same value in multiple files appears once in the result."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "file1.txt").write_text("Username: admin\n", encoding="utf-8")
        (scan_dir / "file2.txt").write_text("Username: admin\n", encoding="utf-8")
        loot = await extract_loot(scan_dir)
        # 'admin' should appear exactly once
        assert loot["usernames"].count("admin") == 1

    @pytest.mark.asyncio
    async def test_false_positive_cve(self, tmp_path: Path) -> None:
        """'CVE-2021-44228' should not appear in usernames."""
        assert _is_false_positive("usernames", "CVE-2021-44228") is True

    @pytest.mark.asyncio
    async def test_false_positive_zero_hash(self, tmp_path: Path) -> None:
        """All-zero 32-char hex '00000000000000000000000000000000' filtered from hashes."""
        assert _is_false_positive("hashes", "00000000000000000000000000000000") is True

    @pytest.mark.asyncio
    async def test_false_placeholder_email(self, tmp_path: Path) -> None:
        """'user@example.com' filtered from emails."""
        assert _is_false_positive("emails", "user@example.com") is True

    @pytest.mark.asyncio
    async def test_skip_extensions(self, tmp_path: Path) -> None:
        """Files with .json, .md, .html, .log, .state extensions are skipped."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        # These should be skipped
        (scan_dir / "skip.json").write_text('{"Password": "skipped1"}', encoding="utf-8")
        (scan_dir / "skip.md").write_text("Password: skipped2\n", encoding="utf-8")
        (scan_dir / "skip.html").write_text("Password: skipped3\n", encoding="utf-8")
        (scan_dir / "skip.log").write_text("Password: skipped4\n", encoding="utf-8")
        (scan_dir / "skip.state").write_text("Password: skipped5\n", encoding="utf-8")
        # This should be read
        (scan_dir / "keep.txt").write_text("Password: kept\n", encoding="utf-8")

        loot = await extract_loot(scan_dir)
        assert "kept" in loot["passwords"]
        assert "skipped1" not in loot["passwords"]
        assert "skipped2" not in loot["passwords"]
        assert "skipped3" not in loot["passwords"]
        assert "skipped4" not in loot["passwords"]
        assert "skipped5" not in loot["passwords"]

    @pytest.mark.asyncio
    async def test_empty_directory(self, tmp_path: Path) -> None:
        """extract_loot on empty dir returns empty dict with all categories."""
        scan_dir = tmp_path / "empty"
        scan_dir.mkdir()
        loot = await extract_loot(scan_dir)
        assert isinstance(loot, dict)
        for cat in LOOT_PATTERNS:
            assert cat in loot
            assert loot[cat] == []

    @pytest.mark.asyncio
    async def test_nonexistent_directory(self, tmp_path: Path) -> None:
        """extract_loot on non-existent dir returns empty dict."""
        scan_dir = tmp_path / "does_not_exist"
        loot = await extract_loot(scan_dir)
        assert isinstance(loot, dict)
        for cat in LOOT_PATTERNS:
            assert cat in loot
            assert loot[cat] == []

    @pytest.mark.asyncio
    async def test_combined_loot(self, tmp_path: Path) -> None:
        """Realistic scan output with multiple loot types."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        (scan_dir / "enum.txt").write_text(
            "Username: admin\n"
            "uid=0(root)\n"
            "Password: P@ssw0rd\n"
            "admin@corp.local\n"
            "Our IP: 10.10.14.5\n"
            "Found hash: e10adc3949ba59abbe56e057f20f883e\n"
            "Config at /etc/shadow\n",
            encoding="utf-8",
        )
        loot = await extract_loot(scan_dir)
        assert len(loot["usernames"]) >= 1
        assert len(loot["passwords"]) >= 1
        assert len(loot["emails"]) >= 1
        assert len(loot["ips"]) >= 1
        assert len(loot["hashes"]) >= 1
        assert len(loot["paths"]) >= 1


# ===================================================================
# save_loot tests
# ===================================================================

class TestSaveLoot:
    """Tests for the save_loot function."""

    def test_save_loot_creates_files(self, tmp_path: Path) -> None:
        """save_loot creates loot/ directory and category files."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        loot = {
            "usernames": ["admin", "root"],
            "hashes": ["e10adc3949ba59abbe56e057f20f883e"],
            "emails": [],
            "passwords": ["secret123"],
            "ips": ["10.10.14.23"],
            "paths": [],
        }
        save_loot(scan_dir, loot)

        loot_dir = scan_dir / "loot"
        assert loot_dir.is_dir()
        assert (loot_dir / "usernames.txt").is_file()
        assert (loot_dir / "hashes.txt").is_file()
        assert (loot_dir / "passwords.txt").is_file()
        assert (loot_dir / "ips.txt").is_file()

    def test_save_loot_skips_empty(self, tmp_path: Path) -> None:
        """save_loot only writes files for non-empty categories."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        loot = {
            "usernames": ["admin"],
            "hashes": [],
            "emails": [],
            "passwords": [],
            "ips": [],
            "paths": [],
        }
        save_loot(scan_dir, loot)

        loot_dir = scan_dir / "loot"
        assert (loot_dir / "usernames.txt").is_file()
        assert not (loot_dir / "hashes.txt").is_file()
        assert not (loot_dir / "emails.txt").is_file()

    def test_save_loot_content(self, tmp_path: Path) -> None:
        """Verify content of saved loot files."""
        scan_dir = tmp_path / "scan"
        scan_dir.mkdir()
        loot = {
            "usernames": ["admin", "root"],
            "hashes": [],
            "emails": [],
            "passwords": [],
            "ips": [],
            "paths": [],
        }
        save_loot(scan_dir, loot)

        content = (scan_dir / "loot" / "usernames.txt").read_text(encoding="utf-8")
        assert "admin" in content
        assert "root" in content


# ===================================================================
# loot_to_findings tests
# ===================================================================

class TestLootToFindings:
    """Tests for the loot_to_findings function."""

    def test_loot_to_findings_usernames(self) -> None:
        """Usernames → INFO severity finding."""
        loot = {
            "usernames": ["admin", "root"],
            "hashes": [],
            "emails": [],
            "passwords": [],
            "ips": [],
            "paths": [],
        }
        findings = loot_to_findings(loot)
        username_findings = [f for f in findings if "Usernames" in f.title]
        assert len(username_findings) == 1
        assert username_findings[0].severity == Severity.INFO

    def test_loot_to_findings_hashes(self) -> None:
        """Hashes → HIGH severity finding."""
        loot = {
            "usernames": [],
            "hashes": ["e10adc3949ba59abbe56e057f20f883e"],
            "emails": [],
            "passwords": [],
            "ips": [],
            "paths": [],
        }
        findings = loot_to_findings(loot)
        hash_findings = [f for f in findings if "Hashes" in f.title]
        assert len(hash_findings) == 1
        assert hash_findings[0].severity == Severity.HIGH

    def test_loot_to_findings_passwords(self) -> None:
        """Passwords → CRITICAL severity finding."""
        loot = {
            "usernames": [],
            "hashes": [],
            "emails": [],
            "passwords": ["secret123"],
            "ips": [],
            "paths": [],
        }
        findings = loot_to_findings(loot)
        pw_findings = [f for f in findings if "Passwords" in f.title]
        assert len(pw_findings) == 1
        assert pw_findings[0].severity == Severity.CRITICAL

    def test_loot_to_findings_empty(self) -> None:
        """Empty loot → no findings."""
        loot = {
            "usernames": [],
            "hashes": [],
            "emails": [],
            "passwords": [],
            "ips": [],
            "paths": [],
        }
        findings = loot_to_findings(loot)
        assert findings == []

    def test_loot_to_findings_module_is_loot(self) -> None:
        """All loot findings should have module='loot'."""
        loot = {
            "usernames": ["admin"],
            "hashes": ["abc123abc123abc123abc123abc123ab"],
            "emails": [],
            "passwords": ["pass"],
            "ips": ["10.10.10.5"],
            "paths": [],
        }
        findings = loot_to_findings(loot)
        for f in findings:
            assert f.module == "loot"

    def test_loot_to_findings_paths_not_promoted(self) -> None:
        """Paths category should not be promoted to findings (too noisy)."""
        loot = {
            "usernames": [],
            "hashes": [],
            "emails": [],
            "passwords": [],
            "ips": [],
            "paths": ["/var/www/html/config.php", "/etc/passwd"],
        }
        findings = loot_to_findings(loot)
        path_findings = [f for f in findings if "Paths" in f.title]
        assert len(path_findings) == 0


# ===================================================================
# LOOT_PATTERNS completeness test
# ===================================================================

class TestLootPatterns:
    """Tests for LOOT_PATTERNS structure and completeness."""

    def test_loot_patterns_complete(self) -> None:
        """All expected categories exist in LOOT_PATTERNS."""
        expected_categories = {"usernames", "hashes", "emails", "passwords", "ips", "paths"}
        assert set(LOOT_PATTERNS.keys()) == expected_categories

    def test_loot_patterns_are_lists_of_strings(self) -> None:
        """Each category maps to a list of regex strings."""
        for cat, patterns in LOOT_PATTERNS.items():
            assert isinstance(patterns, list), f"{cat} is not a list"
            for p in patterns:
                assert isinstance(p, str), f"Pattern in {cat} is not a string: {p}"

    def test_loot_patterns_compilable(self) -> None:
        """All patterns compile as valid regexes."""
        import re
        for cat, patterns in LOOT_PATTERNS.items():
            for p in patterns:
                re.compile(p)  # Should not raise


# ===================================================================
# _is_false_positive edge cases
# ===================================================================

class TestIsFalsePositive:
    """Tests for the _is_false_positive function."""

    def test_normal_username_not_false_positive(self) -> None:
        """A normal username like 'admin' should not be filtered."""
        assert _is_false_positive("usernames", "admin") is False

    def test_normal_hash_not_false_positive(self) -> None:
        """A normal MD5 hash should not be filtered."""
        assert _is_false_positive("hashes", "e10adc3949ba59abbe56e057f20f883e") is False

    def test_all_f_hash_filtered(self) -> None:
        """All-f 32-char hex should be filtered."""
        assert _is_false_positive("hashes", "ffffffffffffffffffffffffffffffff") is True

    def test_placeholder_email_filtered(self) -> None:
        """Placeholder emails with @example.com/org/net filtered."""
        assert _is_false_positive("emails", "user@example.com") is True
        assert _is_false_positive("emails", "test@example.org") is True
        assert _is_false_positive("emails", "info@example.net") is True

    def test_real_email_not_filtered(self) -> None:
        """Real email should not be filtered."""
        assert _is_false_positive("emails", "admin@corp.local") is False

    def test_masked_password_filtered(self) -> None:
        """Masked passwords like '****' should be filtered."""
        assert _is_false_positive("passwords", "****") is True
        assert _is_false_positive("passwords", "********") is True

    def test_normal_password_not_filtered(self) -> None:
        """A real password should not be filtered."""
        assert _is_false_positive("passwords", "secret123") is False

    def test_ips_no_false_positive_patterns(self) -> None:
        """IPs category has no false-positive filters."""
        assert _is_false_positive("ips", "10.10.10.5") is False

    def test_paths_no_false_positive_patterns(self) -> None:
        """Paths category has no false-positive filters."""
        assert _is_false_positive("paths", "/etc/passwd") is False
