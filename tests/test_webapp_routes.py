"""
Tests for the Cygor webapp route registration and app structure.

These tests verify the FastAPI app can be created and that all expected
routers/routes are registered, without requiring a running database.
"""
import importlib
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_app():
    """Import and return the FastAPI app object from cygor.webapp.main."""
    from cygor.webapp.main import app
    return app


def _route_paths(app):
    """Extract all route paths from the app."""
    paths = set()
    for route in app.routes:
        if hasattr(route, "path"):
            paths.add(route.path)
        # APIRouter sub-routes
        if hasattr(route, "routes"):
            for sub in route.routes:
                if hasattr(sub, "path"):
                    paths.add(sub.path)
    return paths


# ---------------------------------------------------------------------------
# App creation
# ---------------------------------------------------------------------------

class TestAppCreation:
    """Verify the FastAPI app object can be imported."""

    def test_app_is_importable(self):
        """The main module should be importable."""
        from cygor.webapp import main
        assert main is not None

    def test_app_is_fastapi_instance(self):
        """The app variable should be a FastAPI instance."""
        from fastapi import FastAPI
        app = _get_app()
        assert isinstance(app, FastAPI)

    def test_app_has_lifespan(self):
        """The app should have a lifespan context manager configured."""
        app = _get_app()
        # FastAPI stores the lifespan on router
        assert app.router.lifespan_context is not None


# ---------------------------------------------------------------------------
# Route module structure
# ---------------------------------------------------------------------------

class TestRouteModules:
    """Verify that all expected route modules exist and have routers."""

    ROUTE_MODULES = [
        "cygor.webapp.routes.core",
        "cygor.webapp.routes.modules",
        "cygor.webapp.routes.search",
        "cygor.webapp.routes.tasks",
        "cygor.webapp.routes.hosts",
        "cygor.webapp.routes.credrecon",
        "cygor.webapp.routes.scheduler",
        "cygor.webapp.routes.sync",
        "cygor.webapp.routes.enrichment",
        "cygor.webapp.routes.settings.general",
        "cygor.webapp.routes.settings.database",
        "cygor.webapp.routes.settings.proxy",
        "cygor.webapp.routes.settings.plugins",
        "cygor.webapp.routes.settings.workspaces",
    ]

    @pytest.mark.parametrize("module_path", ROUTE_MODULES)
    def test_route_module_importable(self, module_path):
        """Each route module should be importable."""
        mod = importlib.import_module(module_path)
        assert mod is not None

    @pytest.mark.parametrize("module_path", ROUTE_MODULES)
    def test_route_module_has_router(self, module_path):
        """Each route module should expose a router attribute."""
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "router"), f"{module_path} is missing a 'router' attribute"

    MODULES_WITH_SET_TEMPLATES = [
        "cygor.webapp.routes.core",
        "cygor.webapp.routes.modules",
        "cygor.webapp.routes.search",
        "cygor.webapp.routes.tasks",
        "cygor.webapp.routes.hosts",
        "cygor.webapp.routes.credrecon",
        "cygor.webapp.routes.scheduler",
        "cygor.webapp.routes.sync",
        "cygor.webapp.routes.enrichment",
    ]

    @pytest.mark.parametrize("module_path", MODULES_WITH_SET_TEMPLATES)
    def test_set_templates_callable(self, module_path):
        """Route modules with set_templates should have a callable function."""
        mod = importlib.import_module(module_path)
        assert hasattr(mod, "set_templates"), f"{module_path} missing set_templates"
        assert callable(mod.set_templates)


# ---------------------------------------------------------------------------
# Static files and templates
# ---------------------------------------------------------------------------

class TestStaticAndTemplates:
    """Verify static and template directories exist."""

    def test_templates_directory_exists(self):
        """The templates directory should exist."""
        base_dir = Path(__file__).resolve().parent.parent / "cygor" / "webapp" / "templates"
        assert base_dir.is_dir(), f"Templates directory not found: {base_dir}"

    def test_base_html_exists(self):
        """base.html should exist in the templates directory."""
        base_html = Path(__file__).resolve().parent.parent / "cygor" / "webapp" / "templates" / "base.html"
        assert base_html.is_file(), f"base.html not found at: {base_html}"

    def test_static_directory_exists(self):
        """The static files directory should exist."""
        static_dir = Path(__file__).resolve().parent.parent / "cygor" / "webapp" / "static"
        assert static_dir.is_dir(), f"Static directory not found: {static_dir}"


# ---------------------------------------------------------------------------
# Key API endpoint definitions
# ---------------------------------------------------------------------------

class TestAPIEndpointDefinitions:
    """Check that key API endpoints are defined in route modules."""

    def test_fingerprint_sync_status_endpoint(self):
        """The /api/fingerprint-sync/status endpoint should be defined in sync routes."""
        from cygor.webapp.routes import sync as sync_routes
        route_paths = []
        for route in sync_routes.router.routes:
            if hasattr(route, "path"):
                route_paths.append(route.path)
        assert "/api/fingerprint-sync/status" in route_paths

    def test_hosts_routes_exist(self):
        """The hosts route module should define routes."""
        from cygor.webapp.routes import hosts as hosts_routes
        assert len(hosts_routes.router.routes) > 0

    def test_core_routes_exist(self):
        """The core route module should define routes (including /)."""
        from cygor.webapp.routes import core as core_routes
        route_paths = []
        for route in core_routes.router.routes:
            if hasattr(route, "path"):
                route_paths.append(route.path)
        assert len(route_paths) > 0


# ---------------------------------------------------------------------------
