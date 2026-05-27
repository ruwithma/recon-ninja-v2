Contributing
============

Module contract
---------------

- Every module entrypoint should be an `async def` named `run_...module` (e.g. `run_ssh_module`).
- The function MUST return a `ModuleResult` instance on all code paths. If the module has nothing to do, return a `ModuleResult` with `status="skipped"` and a short `error_message` explaining why.
- Helpers may return `None` (e.g. `Finding | None`) when used as filters; only module entrypoints must return `ModuleResult`.
- Avoid broad `except Exception:` swallowing errors — prefer catching specific exceptions. If an unexpected exception occurs inside a module entrypoint, prefer returning `ModuleResult(status="error", error_message=str(exc))` and log the full traceback.

Testing & CI
----------

- Run tests locally with:

```bash
python -m pip install -e '.[dev]'
pytest -q
```

- CI runs on pushes and PRs via GitHub Actions; it executes the test suite on Python 3.10 and 3.11.

Formatting & linting
-------------------

- We include `ruff`, `mypy`, and `pre-commit` configs. Install dev deps and enable pre-commit hooks:

```bash
python -m pip install -e '.[dev]'
pre-commit install
pre-commit run --all-files
```

Thank you for contributing — please open PRs against `main` and include tests for behavior changes.
