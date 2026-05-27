import inspect
import importlib
import pkgutil

import recon_ninja.modules as modules_pkg
from recon_ninja.core import models


def _module_iter():
    for finder, name, ispkg in pkgutil.iter_modules(modules_pkg.__path__, modules_pkg.__name__ + '.'):
        try:
            mod = importlib.import_module(name)
        except Exception:
            # Import errors may be due to missing optional deps; skip those modules
            continue
        yield name, mod


def test_run_functions_have_moduleresult_return_annotation():
    missing = []
    for name, mod in _module_iter():
        for attr_name, attr in vars(mod).items():
            # Only consider module entrypoints named like `run_...module`
            if (
                inspect.iscoroutinefunction(attr)
                and attr_name.startswith('run_')
                and attr_name.endswith('module')
            ):
                ann = attr.__annotations__.get('return', None)
                ann_str = repr(ann)
                if ann is None or 'ModuleResult' not in ann_str:
                    missing.append(f"{name}.{attr_name} -> {ann_str}")

    assert not missing, (
        "Some module run functions are missing a ModuleResult return annotation: "
        + ", ".join(missing)
    )
