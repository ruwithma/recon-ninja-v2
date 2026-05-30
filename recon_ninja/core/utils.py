from __future__ import annotations

import asyncio
import functools
import logging
import time
from typing import Any, Callable, Coroutine

from recon_ninja.core.models import ModuleResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared utility functions
# ---------------------------------------------------------------------------


def extract_line(text: str, keyword: str, case_insensitive: bool = False) -> str | None:
    """Return the first line from *text* containing *keyword*.

    Parameters
    ----------
    text:
        Multi-line text to search.
    keyword:
        Substring to look for in each line.
    case_insensitive:
        If ``True``, performs a case-insensitive match.

    Returns
    -------
    str | None
        The stripped matching line, or ``None`` if no line contains *keyword*.
    """
    if case_insensitive:
        keyword_lower = keyword.lower()
        for line in text.splitlines():
            if keyword_lower in line.lower():
                return line.strip()
    else:
        for line in text.splitlines():
            if keyword in line:
                return line.strip()
    return None


def module_guard(timeout: float | None = None) -> Callable[[Callable[..., Coroutine[Any, Any, ModuleResult]]], Callable[..., Coroutine[Any, Any, ModuleResult]]]:
    """Decorator for module entrypoints to standardize error handling.

    Usage:
        @module_guard()
        async def run_foo_module(...):
            ...

    The decorator catches exceptions and timeouts and returns a
    `ModuleResult(status='error', error_message=...)`. If the wrapped
    function returns None, it's converted to `ModuleResult(status='skipped')`.
    """

    def _decorator(func: Callable[..., Coroutine[Any, Any, ModuleResult]]):
        @functools.wraps(func)
        async def _wrapper(*args, **kwargs) -> ModuleResult:
            t0 = time.monotonic()
            try:
                if timeout is not None:
                    coro = asyncio.wait_for(func(*args, **kwargs), timeout=timeout)
                else:
                    coro = func(*args, **kwargs)

                result = await coro

                if result is None:
                    logger.debug("[module_guard] %s returned None -> skipped", func.__name__)
                    return ModuleResult(module_name=func.__name__, status="skipped", error_message="Module returned None")

                # Ensure duration_seconds is set when missing
                if getattr(result, 'duration_seconds', None) in (None, 0):
                    try:
                        result.duration_seconds = time.monotonic() - t0
                    except Exception:
                        pass

                return result

            except asyncio.TimeoutError:
                logger.exception("[module_guard] %s timed out", func.__name__)
                return ModuleResult(module_name=func.__name__, status="timeout", error_message="Module timed out", duration_seconds=time.monotonic() - t0)
            except Exception as exc:
                logger.exception("[module_guard] %s raised: %s", func.__name__, exc)
                return ModuleResult(module_name=func.__name__, status="error", error_message=str(exc), duration_seconds=time.monotonic() - t0)

        return _wrapper

    return _decorator
