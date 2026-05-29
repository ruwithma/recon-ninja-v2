"""Async subprocess execution wrapper for ReconNinja.

This is the fundamental building block for ALL tool execution.
Provides run_tool, run_tool_streaming, and run_multiple for
asynchronous subprocess management with timeout handling, output
capture, and concurrent execution support.
"""

from __future__ import annotations

import asyncio
import logging
import os
import shlex
from pathlib import Path
from typing import AsyncIterator

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def format_cmd(cmd: list[str]) -> str:
    """Format a command list into a human-readable shell string for logging.

    Args:
        cmd: Command and arguments as a list of strings.

    Returns:
        A single string with each argument shell-quoted for readability.

    Example::

        >>> format_cmd(["nmap", "-sC", "-sV", "10.10.10.1"])
        'nmap -sC -sV 10.10.10.1'
    """
    return " ".join(shlex.quote(part) for part in cmd)


def _build_env(env: dict[str, str] | None) -> dict[str, str] | None:
    """Merge a custom environment dict with ``os.environ``.

    If *env* is ``None`` the caller inherits the current process environment
    (``asyncio.create_subprocess_exec`` default), so we return ``None``.
    Otherwise we copy ``os.environ`` and overlay the caller-supplied values.
    """
    if env is None:
        return None
    merged = dict(os.environ)
    merged.update(env)
    return merged


# ---------------------------------------------------------------------------
# Core runner
# ---------------------------------------------------------------------------


async def run_tool(
    cmd: list[str],
    output_file: Path | None = None,
    timeout: int = 300,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Run a subprocess asynchronously, capture output, optionally write to file.

    This is the primary entry point for executing external tools. It uses
    ``asyncio.create_subprocess_exec`` (never ``subprocess.run``) so that
    many tools can run concurrently without blocking the event loop.

    Args:
        cmd: Command and arguments to execute.
        output_file: If provided, stdout is written to this file.
        timeout: Maximum runtime in seconds before the process is killed.
        cwd: Working directory for the subprocess.
        env: Extra environment variables; merged with ``os.environ``.

    Returns:
        A tuple of ``(returncode, stdout, stderr)``.
        On timeout the return code is ``-1``, stdout is ``""``, and stderr
        is ``"TIMEOUT after {timeout}s"``.
    """
    logger.info("Running: %s", format_cmd(cmd))

    proc_env = _build_env(env)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=proc_env,
        )
    except FileNotFoundError:
        msg = f"Command not found: {cmd[0]}"
        logger.error(msg)
        return (-2, "", msg)
    except PermissionError:
        msg = f"Permission denied: {cmd[0]}"
        logger.error(msg)
        return (-2, "", msg)
    except OSError as exc:
        msg = f"OS error launching {cmd[0]}: {exc}"
        logger.error(msg)
        return (-2, "", msg)

    try:
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(), timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.warning("Timeout (%ds) reached for: %s", timeout, format_cmd(cmd))
        try:
            proc.kill()
            await proc.wait()
        except ProcessLookupError:
            pass  # process already gone
        return (-1, "", f"TIMEOUT after {timeout}s")

    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")

    if output_file is not None:
        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(stdout, encoding="utf-8")
            logger.debug("Output written to %s", output_file)
        except OSError as exc:
            logger.error("Failed to write output file %s: %s", output_file, exc)

    rc = proc.returncode if proc.returncode is not None else -3
    logger.info(
        "Finished: %s  [rc=%d] stdout=%d bytes  stderr=%d bytes",
        format_cmd(cmd),
        rc,
        len(stdout),
        len(stderr),
    )
    return (rc, stdout, stderr)


# ---------------------------------------------------------------------------
# Streaming runner
# ---------------------------------------------------------------------------


async def run_tool_streaming(
    cmd: list[str],
    output_file: Path | None = None,
    timeout: int = 300,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> AsyncIterator[str]:
    """Run a subprocess and yield lines of output as they arrive.

    Useful for long-running tools where we want live progress displayed.
    Still captures full output to *output_file* at the end.

    Args:
        cmd: Command and arguments to execute.
        output_file: If provided, the full stdout is written here on completion.
        timeout: Maximum runtime in seconds before the process is killed.
        cwd: Working directory for the subprocess.
        env: Extra environment variables; merged with ``os.environ``.

    Yields:
        Each line of stdout (without trailing newline) as soon as it is
        produced by the subprocess.

    Returns:
        This is an async generator — the final ``StopAsyncIteration`` does
        not carry a value. Callers that also need the return code should
        capture it via the internal process.
    """
    logger.info("Streaming: %s", format_cmd(cmd))

    proc_env = _build_env(env)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
            env=proc_env,
        )
    except (FileNotFoundError, PermissionError, OSError) as exc:
        logger.error("Failed to launch %s: %s", cmd[0], exc)
        return

    collected_lines: list[str] = []
    timed_out = False

    if proc.stdout is None:
        logger.error("Subprocess stdout stream is None")
        return

    try:
        while True:
            try:
                line_bytes = await asyncio.wait_for(
                    proc.stdout.readline(), timeout=timeout
                )
            except asyncio.TimeoutError:
                logger.warning("Streaming timeout (%ds) for: %s", timeout, format_cmd(cmd))
                timed_out = True
                break

            if not line_bytes:
                # EOF — process has closed stdout
                break

            line = line_bytes.decode("utf-8", errors="replace").rstrip("\n\r")
            collected_lines.append(line)
            yield line

    finally:
        if timed_out:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
            logger.warning("Process killed after timeout: %s", format_cmd(cmd))
        else:
            # Give the process a moment to finish; read remaining stderr.
            try:
                await asyncio.wait_for(proc.wait(), timeout=30)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                    await proc.wait()
                except ProcessLookupError:
                    pass

        # Write captured output to file regardless of how we exited.
        if output_file is not None:
            try:
                output_file.parent.mkdir(parents=True, exist_ok=True)
                output_file.write_text(
                    "\n".join(collected_lines), encoding="utf-8"
                )
                logger.debug("Streaming output written to %s", output_file)
            except OSError as exc:
                logger.error("Failed to write streaming output %s: %s", output_file, exc)

        rc = proc.returncode if proc.returncode is not None else -1
        logger.info(
            "Streaming finished: %s  [rc=%d] lines=%d",
            format_cmd(cmd),
            rc,
            len(collected_lines),
        )


# ---------------------------------------------------------------------------
# Concurrent runner
# ---------------------------------------------------------------------------


async def run_multiple(
    commands: list[tuple[str, list[str], Path | None]],  # (name, cmd, output_file)
    max_concurrent: int = 10,
    timeout: int = 300,
) -> dict[str, tuple[int, str, str]]:
    """Run multiple commands concurrently with a semaphore.

    Each command is identified by a unique *name* so that results can be
    correlated even when they complete out of order.

    Args:
        commands: List of ``(name, cmd, output_file)`` tuples.
        max_concurrent: Maximum number of subprocesses running at once.
        timeout: Per-command timeout in seconds.

    Returns:
        Dictionary mapping each command *name* to its
        ``(returncode, stdout, stderr)`` tuple.
    """
    semaphore = asyncio.Semaphore(max_concurrent)
    results: dict[str, tuple[int, str, str]] = {}

    async def _run_named(name: str, cmd: list[str], outfile: Path | None) -> None:
        """Acquire semaphore, run one command, and store the result."""
        async with semaphore:
            logger.info("[%s] Starting (concurrency slot acquired)", name)
            rc, stdout, stderr = await run_tool(
                cmd, output_file=outfile, timeout=timeout
            )
            results[name] = (rc, stdout, stderr)
            logger.info("[%s] Done  rc=%d", name, rc)

    tasks = [
        asyncio.create_task(_run_named(name, cmd, outfile))
        for name, cmd, outfile in commands
    ]

    await asyncio.gather(*tasks, return_exceptions=True)

    # Handle any tasks that raised unexpected exceptions (shouldn't happen
    # inside run_tool, but guard against programming errors).
    for task in tasks:
        if task.exception() is not None:
            exc = task.exception()
            logger.error("Unexpected exception in run_multiple task: %s", exc)

    return results
