"""Smoke test: every cygor top-level module imports cleanly.

A SyntaxError in `cygor.scan` slipped past the 661-test pytest suite once
because no test imported scan.py. This is the cheap insurance: walk the
cygor/ tree and import every module; if any import fails the suite fails
immediately, before any of the per-feature tests run.

Excluded from the walk:
  - cygor.webapp.alembic.versions: alembic migration scripts have implicit
    dependencies on the Alembic config + a live DB connection and aren't
    meant to be import-stable in isolation.
  - cygor.plugins: third-party plugins may have optional deps that aren't
    installed; not part of the cygor surface.
"""
import importlib
import pathlib
import pkgutil

import pytest

import cygor


def _walk_modules(pkg):
    """Yield (modname, ispkg) for every importable module under `pkg`."""
    for finder, modname, ispkg in pkgutil.walk_packages(
        pkg.__path__, prefix=pkg.__name__ + "."
    ):
        # Skip alembic's env.py + versions/ -- both need a live Alembic
        # context with config attached; bare-import doesn't work outside
        # `alembic upgrade`.
        if ".alembic." in modname:
            continue
        # Skip user plugins (optional third-party deps).
        if modname.startswith("cygor.plugins."):
            continue
        yield modname, ispkg


@pytest.mark.parametrize("modname", [m for m, _ in _walk_modules(cygor)])
def test_module_imports_cleanly(modname):
    """Every module in cygor/ must be importable without side-effect errors.

    Failure here usually means one of:
      - SyntaxError (orphaned try/except, dangling indent)
      - ImportError on a top-level `from X import Y` where Y was moved/renamed
      - NameError at module scope from a typo'd identifier
    Each of those is something the rest of the test suite cannot catch
    unless it happens to exercise the broken module specifically.
    """
    importlib.import_module(modname)
