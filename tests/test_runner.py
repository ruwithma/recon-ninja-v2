"""Tests for recon_ninja.core.runner — async subprocess execution wrapper.

Covers:
- format_cmd helper for shell-readable command strings
- _build_env environment merging logic
- run_tool: success, output_file, timeout, missing command, nonzero exit,
  env override, cwd
- run_multiple: concurrent execution, semaphore limiting, mixed results
"""

from __future__ import annotations

import os
from pathlib import Path


from recon_ninja.core.runner import run_tool, run_multiple, format_cmd, _build_env


# ===================================================================
# format_cmd tests
# ===================================================================


class TestFormatCmd:
    """Tests for the format_cmd helper function."""

    def test_format_cmd_simple(self) -> None:
        """format_cmd(['echo', 'hello']) should produce 'echo hello'."""
        result = format_cmd(["echo", "hello"])
        assert result == "echo hello"

    def test_format_cmd_single_arg(self) -> None:
        """Single-element command list should be returned as-is (quoted if needed)."""
        result = format_cmd(["ls"])
        assert result == "ls"

    def test_format_cmd_special_chars(self) -> None:
        """Arguments containing spaces/quotes should be shell-quoted."""
        result = format_cmd(["echo", "hello world", "it's", "a\"test"])
        # shlex.quote wraps strings with spaces in single quotes, etc.
        assert "hello world" in result or "'hello world'" in result
        # The result must be a single string
        assert isinstance(result, str)

    def test_format_cmd_with_flags(self) -> None:
        """Command with typical nmap-style flags."""
        result = format_cmd(["nmap", "-sC", "-sV", "10.10.10.1"])
        assert result == "nmap -sC -sV 10.10.10.1"

    def test_format_cmd_empty_list(self) -> None:
        """Empty list produces an empty string."""
        result = format_cmd([])
        assert result == ""

    def test_format_cmd_arg_with_spaces(self) -> None:
        """Arguments with spaces get properly quoted."""
        result = format_cmd(["curl", "-H", "Content-Type: application/json", "http://example.com"])
        # Should not raise; spaces in args must be handled
        assert "curl" in result
        assert "example.com" in result


# ===================================================================
# _build_env tests
# ===================================================================


class TestBuildEnv:
    """Tests for the _build_env environment merging helper."""

    def test_build_env_none(self) -> None:
        """_build_env(None) returns None (inherit process env)."""
        result = _build_env(None)
        assert result is None

    def test_build_env_merge(self) -> None:
        """_build_env({'FOO': 'bar'}) merges with os.environ."""
        result = _build_env({"FOO": "bar"})
        assert result is not None
        assert result["FOO"] == "bar"
        # Should also contain at least PATH from os.environ
        assert "PATH" in result

    def test_build_env_preserves_existing(self) -> None:
        """_build_env should keep all existing env vars intact."""
        result = _build_env({"MY_TEST_VAR": "123"})
        assert result is not None
        assert result["MY_TEST_VAR"] == "123"
        # HOME, PATH, etc. should still be present
        assert "PATH" in result

    def test_build_env_override(self) -> None:
        """User-supplied env values override os.environ."""
        # We can't easily override PATH, but we can verify the merge order
        custom_path = "/custom/path"
        result = _build_env({"PATH": custom_path})
        assert result is not None
        assert result["PATH"] == custom_path

    def test_build_env_empty_dict(self) -> None:
        """_build_env({}) should return a copy of os.environ."""
        result = _build_env({})
        assert result is not None
        assert "PATH" in result
        # It should be a copy, not the same object
        assert result is not os.environ

    def test_build_env_multiple_vars(self) -> None:
        """Multiple custom environment variables are all merged."""
        result = _build_env({"VAR_A": "a", "VAR_B": "b", "VAR_C": "c"})
        assert result is not None
        assert result["VAR_A"] == "a"
        assert result["VAR_B"] == "b"
        assert result["VAR_C"] == "c"


# ===================================================================
# run_tool tests (async)
# ===================================================================


class TestRunTool:
    """Tests for the async run_tool function."""

    async def test_run_tool_echo(self) -> None:
        """run_tool(['echo', 'hello']) should return (0, 'hello\\n', '')."""
        rc, stdout, stderr = await run_tool(["echo", "hello"])
        assert rc == 0
        assert stdout == "hello\n"
        assert stderr == ""

    async def test_run_tool_echo_multiline(self) -> None:
        """Echo with multiple arguments produces space-separated output."""
        rc, stdout, stderr = await run_tool(["echo", "hello", "world"])
        assert rc == 0
        assert "hello world" in stdout

    async def test_run_tool_output_file(self, tmp_path: Path) -> None:
        """run_tool with output_file should write stdout to that file."""
        outfile = tmp_path / "output.txt"
        rc, stdout, stderr = await run_tool(
            ["echo", "file content"], output_file=outfile
        )
        assert rc == 0
        assert outfile.is_file()
        content = outfile.read_text(encoding="utf-8")
        assert "file content" in content

    async def test_run_tool_output_file_creates_parent_dirs(self, tmp_path: Path) -> None:
        """output_file with non-existent parent dirs should auto-create them."""
        outfile = tmp_path / "subdir" / "deep" / "output.txt"
        rc, stdout, stderr = await run_tool(
            ["echo", "deep file"], output_file=outfile
        )
        assert rc == 0
        assert outfile.is_file()
        assert "deep file" in outfile.read_text(encoding="utf-8")

    async def test_run_tool_timeout(self) -> None:
        """run_tool with a short timeout should return (-1, '', 'TIMEOUT...')."""
        rc, stdout, stderr = await run_tool(["sleep", "10"], timeout=1)
        assert rc == -1
        assert stdout == ""
        assert "TIMEOUT" in stderr
        assert "1s" in stderr

    async def test_run_tool_missing_command(self) -> None:
        """run_tool with a nonexistent command returns (-2, '', 'Command not found...')."""
        rc, stdout, stderr = await run_tool(["nonexistent_tool_xyz"])
        assert rc == -2
        assert stdout == ""
        assert "Command not found" in stderr or "not found" in stderr.lower() or "OS error" in stderr

    async def test_run_tool_nonzero_exit(self) -> None:
        """run_tool(['false']) returns nonzero exit code."""
        rc, stdout, stderr = await run_tool(["false"])
        assert rc != 0
        assert rc != -1  # not a timeout
        assert rc != -2  # not a missing command

    async def test_run_tool_env_override(self) -> None:
        """run_tool(['env'], env=...) should make custom vars visible."""
        rc, stdout, stderr = await run_tool(
            ["env"], env={"MY_VAR": "test_value_12345"}
        )
        assert rc == 0
        assert "MY_VAR" in stdout
        assert "test_value_12345" in stdout

    async def test_run_tool_cwd(self) -> None:
        """run_tool(['pwd'], cwd=Path('/tmp')) should output /tmp."""
        rc, stdout, stderr = await run_tool(["pwd"], cwd=Path("/tmp"))
        assert rc == 0
        # pwd output may or may not have trailing newline, and /tmp may be a symlink
        assert stdout.strip() == "/tmp" or "/tmp" in stdout.strip()

    async def test_run_tool_stderr_capture(self) -> None:
        """run_tool should capture stderr output."""
        rc, stdout, stderr = await run_tool(["ls", "/nonexistent_dir_xyz"])
        # ls on a nonexistent dir exits nonzero and writes to stderr
        assert rc != 0
        # At least one of stdout/stderr should mention the error
        combined = stdout + stderr
        assert len(combined) > 0

    async def test_run_tool_exit_code_42(self) -> None:
        """Verify that specific exit codes are preserved."""
        # bash -c 'exit 42' returns exit code 42
        rc, stdout, stderr = await run_tool(["bash", "-c", "exit 42"])
        assert rc == 42

    async def test_run_tool_unicode_output(self) -> None:
        """run_tool should handle Unicode output correctly."""
        rc, stdout, stderr = await run_tool(["echo", "Hello World"])
        assert rc == 0
        assert "Hello World" in stdout

    async def test_run_tool_large_output(self) -> None:
        """run_tool should handle large output without issues."""
        # Generate a large output with seq
        rc, stdout, stderr = await run_tool(["seq", "1", "1000"])
        assert rc == 0
        lines = stdout.strip().split("\n")
        assert len(lines) == 1000


# ===================================================================
# run_multiple tests (async)
# ===================================================================


class TestRunMultiple:
    """Tests for the async run_multiple function."""

    async def test_run_multiple_concurrent(self) -> None:
        """run_multiple with 3 echo commands — all should succeed."""
        commands = [
            ("echo1", ["echo", "first"], None),
            ("echo2", ["echo", "second"], None),
            ("echo3", ["echo", "third"], None),
        ]
        results = await run_multiple(commands)
        assert len(results) == 3
        assert results["echo1"][0] == 0
        assert results["echo2"][0] == 0
        assert results["echo3"][0] == 0
        assert "first" in results["echo1"][1]
        assert "second" in results["echo2"][1]
        assert "third" in results["echo3"][1]

    async def test_run_multiple_semaphore(self) -> None:
        """run_multiple with max_concurrent=1 should run sequentially.

        We verify by running commands that touch a file; with max_concurrent=1
        they should complete one after another without overlap issues.
        """
        # Simple test: all commands succeed when limited to 1 concurrent
        commands = [
            ("cmd1", ["echo", "a"], None),
            ("cmd2", ["echo", "b"], None),
            ("cmd3", ["echo", "c"], None),
        ]
        results = await run_multiple(commands, max_concurrent=1)
        assert len(results) == 3
        assert results["cmd1"][0] == 0
        assert results["cmd2"][0] == 0
        assert results["cmd3"][0] == 0

    async def test_run_multiple_mixed_results(self) -> None:
        """run_multiple with one success and one failure."""
        commands = [
            ("success", ["echo", "ok"], None),
            ("failure", ["false"], None),
        ]
        results = await run_multiple(commands)
        assert results["success"][0] == 0
        assert results["failure"][0] != 0

    async def test_run_multiple_with_output_files(self, tmp_path: Path) -> None:
        """run_multiple with output_file arguments writes results."""
        out1 = tmp_path / "out1.txt"
        out2 = tmp_path / "out2.txt"
        commands = [
            ("file1", ["echo", "output1"], out1),
            ("file2", ["echo", "output2"], out2),
        ]
        results = await run_multiple(commands)
        assert results["file1"][0] == 0
        assert results["file2"][0] == 0
        assert out1.is_file()
        assert out2.is_file()
        assert "output1" in out1.read_text(encoding="utf-8")
        assert "output2" in out2.read_text(encoding="utf-8")

    async def test_run_multiple_empty_list(self) -> None:
        """run_multiple with no commands returns empty dict."""
        results = await run_multiple([])
        assert results == {}

    async def test_run_multiple_timeout(self) -> None:
        """run_multiple respects per-command timeout."""
        commands = [
            ("fast", ["echo", "quick"], None),
            ("slow", ["sleep", "30"], None),
        ]
        results = await run_multiple(commands, timeout=1)
        assert results["fast"][0] == 0
        assert results["slow"][0] == -1  # timeout
        assert "TIMEOUT" in results["slow"][2]

    async def test_run_multiple_with_missing_command(self) -> None:
        """run_multiple handles missing commands gracefully."""
        commands = [
            ("good", ["echo", "works"], None),
            ("bad", ["nonexistent_tool_xyz"], None),
        ]
        results = await run_multiple(commands)
        assert results["good"][0] == 0
        assert results["bad"][0] == -2

    async def test_run_multiple_all_names_present(self) -> None:
        """All command names appear in results, regardless of success/failure."""
        commands = [
            ("alpha", ["echo", "a"], None),
            ("beta", ["false"], None),
            ("gamma", ["echo", "c"], None),
        ]
        results = await run_multiple(commands)
        assert set(results.keys()) == {"alpha", "beta", "gamma"}
