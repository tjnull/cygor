"""
Tests for the Cygor ingest module.

These tests verify that the ingest module can be imported and that
key functions exist and behave correctly, without requiring a database.
"""
import importlib
import inspect
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Module import
# ---------------------------------------------------------------------------

class TestIngestImport:
    """Verify the ingest module can be imported without error."""

    def test_ingest_module_importable(self):
        """cygor.webapp.ingest should be importable."""
        mod = importlib.import_module("cygor.webapp.ingest")
        assert mod is not None

    def test_fingerprint_collector_importable(self):
        """FingerprintCollector class should be importable."""
        from cygor.webapp.ingest import FingerprintCollector
        assert FingerprintCollector is not None


# ---------------------------------------------------------------------------
# get_default_database_url
# ---------------------------------------------------------------------------

class TestGetDefaultDatabaseUrl:
    """Test the get_default_database_url function."""

    def test_returns_string(self):
        """get_default_database_url should return a string."""
        from cygor.webapp.ingest import get_default_database_url
        result = get_default_database_url()
        assert isinstance(result, str)

    def test_returns_nonempty(self):
        """The returned URL should not be empty."""
        from cygor.webapp.ingest import get_default_database_url
        result = get_default_database_url()
        assert len(result) > 0

    def test_default_contains_sqlite_or_postgresql(self):
        """The returned URL should reference sqlite or postgresql."""
        from cygor.webapp.ingest import get_default_database_url
        result = get_default_database_url()
        assert "sqlite" in result or "postgresql" in result

    def test_fallback_sqlite_parameter(self):
        """Passing a custom fallback_sqlite should be reflected when no env/pg is available."""
        from cygor.webapp.ingest import get_default_database_url
        import os

        # Only test if CYGOR_DB_URL is not set (otherwise it takes priority)
        if not os.getenv("CYGOR_DB_URL"):
            result = get_default_database_url(fallback_sqlite="custom/path.db")
            # Either pg_isready succeeds (postgresql) or we get the fallback
            assert "postgresql" in result or "custom/path.db" in result


# ---------------------------------------------------------------------------
# Key functions exist
# ---------------------------------------------------------------------------

class TestKeyFunctionsExist:
    """Verify that important ingest functions are defined."""

    def test_ingest_directory_exists(self):
        """ingest_directory should be defined and async."""
        from cygor.webapp.ingest import ingest_directory
        assert callable(ingest_directory)
        assert inspect.iscoroutinefunction(ingest_directory)

    def test_ingest_file_exists(self):
        """ingest_file should be defined and async."""
        from cygor.webapp.ingest import ingest_file
        assert callable(ingest_file)
        assert inspect.iscoroutinefunction(ingest_file)

    def test_ingest_generic_json_exists(self):
        """ingest_generic_json should be defined and async."""
        from cygor.webapp.ingest import ingest_generic_json
        assert callable(ingest_generic_json)
        assert inspect.iscoroutinefunction(ingest_generic_json)


# ---------------------------------------------------------------------------
# FingerprintCollector
# ---------------------------------------------------------------------------

class TestFingerprintCollector:
    """Test FingerprintCollector basic behavior."""

    def test_can_instantiate(self):
        """FingerprintCollector should be instantiable."""
        from cygor.webapp.ingest import FingerprintCollector
        fc = FingerprintCollector()
        assert fc is not None

    def test_initial_state(self):
        """A new FingerprintCollector should have empty collections."""
        from cygor.webapp.ingest import FingerprintCollector
        fc = FingerprintCollector()
        assert fc.results == []
        assert len(fc.os_counts) == 0
        assert len(fc.type_counts) == 0
        assert fc.confidence_buckets["high"] == 0
        assert fc.confidence_buckets["low"] == 0
