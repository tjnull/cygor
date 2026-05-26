"""
Tests for Cygor database migration functions.

These tests verify that all expected migration functions are defined
in cygor.webapp.db and are async coroutine functions. No database
connection is required.
"""
import importlib
import inspect

import pytest


# ---------------------------------------------------------------------------
# All expected migration functions
# ---------------------------------------------------------------------------

EXPECTED_MIGRATIONS = [
    "_migrate_port_service_fields",
    "_migrate_host_tracking_fields",
    "_migrate_device_fingerprint_tables",
    "_migrate_host_tag_table",
    "_migrate_scheduler_resilience_fields",
    "_migrate_device_info_certainty_fields",
]


# ---------------------------------------------------------------------------
# Module import
# ---------------------------------------------------------------------------

class TestDbModuleImport:
    """Verify the db module can be imported."""

    def test_db_module_importable(self):
        """cygor.webapp.db should be importable."""
        mod = importlib.import_module("cygor.webapp.db")
        assert mod is not None

    def test_init_engine_exists(self):
        """init_engine should be defined."""
        from cygor.webapp.db import init_engine
        assert callable(init_engine)

    def test_get_database_url_exists(self):
        """get_database_url should be defined."""
        from cygor.webapp.db import get_database_url
        assert callable(get_database_url)

    def test_get_default_database_url_exists(self):
        """get_default_database_url (legacy) should be defined."""
        from cygor.webapp.db import get_default_database_url
        assert callable(get_default_database_url)


# ---------------------------------------------------------------------------
# Migration function existence and type
# ---------------------------------------------------------------------------

class TestMigrationFunctionsExist:
    """Verify all expected migration functions are defined in cygor.webapp.db."""

    @pytest.mark.parametrize("func_name", EXPECTED_MIGRATIONS)
    def test_migration_function_exists(self, func_name):
        """Each migration function should be defined in the db module."""
        import cygor.webapp.db as db_mod
        assert hasattr(db_mod, func_name), (
            f"Migration function '{func_name}' not found in cygor.webapp.db"
        )

    @pytest.mark.parametrize("func_name", EXPECTED_MIGRATIONS)
    def test_migration_function_is_callable(self, func_name):
        """Each migration function should be callable."""
        import cygor.webapp.db as db_mod
        func = getattr(db_mod, func_name)
        assert callable(func), f"'{func_name}' is not callable"

    @pytest.mark.parametrize("func_name", EXPECTED_MIGRATIONS)
    def test_migration_function_is_async(self, func_name):
        """Each migration function should be an async coroutine function."""
        import cygor.webapp.db as db_mod
        func = getattr(db_mod, func_name)
        assert inspect.iscoroutinefunction(func), (
            f"'{func_name}' should be an async function but is not"
        )


# ---------------------------------------------------------------------------
# Migration count
# ---------------------------------------------------------------------------

class TestMigrationCompleteness:
    """Verify we have the expected number of migrations."""

    def test_expected_migration_count(self):
        """There should be at least 6 migration functions."""
        assert len(EXPECTED_MIGRATIONS) >= 6

    def test_all_migrations_unique(self):
        """All migration function names should be unique."""
        assert len(EXPECTED_MIGRATIONS) == len(set(EXPECTED_MIGRATIONS))

    def test_no_missing_migrations_in_db_module(self):
        """Cross-check: all _migrate_* functions in db.py should be in our list."""
        import cygor.webapp.db as db_mod
        actual_migrations = [
            name for name in dir(db_mod)
            if name.startswith("_migrate_") and callable(getattr(db_mod, name))
        ]
        for func_name in actual_migrations:
            assert func_name in EXPECTED_MIGRATIONS, (
                f"Found migration '{func_name}' in db.py that is not in "
                f"EXPECTED_MIGRATIONS list -- add it to the test"
            )
