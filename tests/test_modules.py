"""
Tests for Cygor module base class, schema, and plugin system.

These tests verify the CygorModule base class functionality,
module discovery, and plugin loader without requiring external tools.
"""
import importlib
import inspect
import os
from pathlib import Path
from typing import Dict, Any, List

import pytest


# ---------------------------------------------------------------------------
# CygorModule base class
# ---------------------------------------------------------------------------

class TestCygorModuleBase:
    """Test the CygorModule abstract base class."""

    def test_base_class_importable(self):
        """CygorModule should be importable from cygor.modules.base."""
        from cygor.modules.base import CygorModule
        assert CygorModule is not None

    def test_base_class_is_abstract(self):
        """CygorModule should be abstract (cannot be instantiated directly)."""
        from cygor.modules.base import CygorModule
        with pytest.raises(TypeError):
            CygorModule()

    def test_subclass_can_be_created(self):
        """A concrete subclass of CygorModule should be instantiable."""
        from cygor.modules.base import CygorModule

        class DummyModule(CygorModule):
            name = "Dummy"
            slug = "dummy"

            def run(self, targets, **kwargs):
                pass

        mod = DummyModule(output_dir="/tmp/test-dummy")
        assert mod is not None
        assert mod.name == "Dummy"
        assert mod.slug == "dummy"

    def test_slug_property(self):
        """The slug attribute should be accessible on subclasses."""
        from cygor.modules.base import CygorModule

        class SlugTest(CygorModule):
            name = "Slug Test Module"
            slug = "slug_test"

            def run(self, targets, **kwargs):
                pass

        mod = SlugTest(output_dir="/tmp/test-slug")
        assert mod.slug == "slug_test"

    def test_default_version(self):
        """Default version should be 1.0.0."""
        from cygor.modules.base import CygorModule

        class VersionTest(CygorModule):
            name = "V"
            slug = "v"

            def run(self, targets, **kwargs):
                pass

        mod = VersionTest(output_dir="/tmp/test-ver")
        assert mod.version == "1.0.0"

    def test_add_result(self):
        """add_result should append to the internal results list."""
        from cygor.modules.base import CygorModule

        class ResultTest(CygorModule):
            name = "R"
            slug = "r"

            def run(self, targets, **kwargs):
                pass

        mod = ResultTest(output_dir="/tmp/test-res")
        assert mod.result_count == 0
        mod.add_result({"host": "10.0.0.1", "finding": "open"})
        assert mod.result_count == 1
        assert mod.results[0]["host"] == "10.0.0.1"

    def test_add_results_bulk(self):
        """add_results should extend the results list."""
        from cygor.modules.base import CygorModule

        class BulkTest(CygorModule):
            name = "B"
            slug = "b"

            def run(self, targets, **kwargs):
                pass

        mod = BulkTest(output_dir="/tmp/test-bulk")
        mod.add_results([{"a": 1}, {"a": 2}, {"a": 3}])
        assert mod.result_count == 3

    def test_output_dir_override(self):
        """output_dir should use the provided path."""
        from cygor.modules.base import CygorModule

        class DirTest(CygorModule):
            name = "D"
            slug = "d"

            def run(self, targets, **kwargs):
                pass

        mod = DirTest(output_dir="/tmp/custom-output")
        assert str(mod._output_dir) == "/tmp/custom-output"


# ---------------------------------------------------------------------------
# Schema building
# ---------------------------------------------------------------------------

class TestSchemaBuilding:
    """Test schema/result building from CygorModule."""

    def _make_module(self):
        from cygor.modules.base import CygorModule

        class SchemaModule(CygorModule):
            name = "Schema Test"
            slug = "schema_test"
            version = "2.0.0"
            category = "enumeration"
            view = "table"
            columns = [
                {"key": "host", "label": "Host", "type": "ip"},
                {"key": "port", "label": "Port", "type": "string"},
            ]

            def run(self, targets, **kwargs):
                pass

        return SchemaModule(output_dir="/tmp/test-schema")

    def test_build_schema_returns_schema_definition(self):
        """_build_schema should return a SchemaDefinition."""
        from cygor.modules.schema import SchemaDefinition
        mod = self._make_module()
        schema = mod._build_schema()
        assert isinstance(schema, SchemaDefinition)

    def test_schema_has_columns(self):
        """Built schema should contain the defined columns."""
        mod = self._make_module()
        schema = mod._build_schema()
        assert len(schema.columns) == 2
        assert schema.columns[0].key == "host"
        assert schema.columns[1].key == "port"

    def test_build_result_returns_cygor_result(self):
        """build_result should return a CygorResult with all fields."""
        from cygor.modules.schema import CygorResult
        mod = self._make_module()
        mod.add_result({"host": "10.0.0.1", "port": 22})
        result = mod.build_result()
        assert isinstance(result, CygorResult)
        assert result.module.name == "Schema Test"
        assert result.module.slug == "schema_test"
        assert len(result.results) == 1

    def test_build_module_info(self):
        """_build_module_info should return a ModuleInfo."""
        from cygor.modules.schema import ModuleInfo
        mod = self._make_module()
        info = mod._build_module_info()
        assert isinstance(info, ModuleInfo)
        assert info.version == "2.0.0"


# ---------------------------------------------------------------------------
# Export methods
# ---------------------------------------------------------------------------

class TestExportMethods:
    """Verify export-related methods exist on CygorModule."""

    def _make_module(self):
        from cygor.modules.base import CygorModule

        class ExportMod(CygorModule):
            name = "Export"
            slug = "export_test"

            def run(self, targets, **kwargs):
                pass

        return ExportMod(output_dir="/tmp/test-export")

    def test_save_method_exists(self):
        """CygorModule should have a save() method."""
        mod = self._make_module()
        assert hasattr(mod, "save")
        assert callable(mod.save)

    def test_exporters_importable(self):
        """The exporters module should export csv, xml, txt functions."""
        from cygor.modules.exporters import export_to_csv, export_to_xml, export_to_txt
        assert callable(export_to_csv)
        assert callable(export_to_xml)
        assert callable(export_to_txt)


# ---------------------------------------------------------------------------
# Module discovery (file existence)
# ---------------------------------------------------------------------------

class TestModuleDiscovery:
    """Verify expected module files exist in cygor/modules/."""

    MODULES_DIR = Path(__file__).resolve().parent.parent / "cygor" / "modules"

    EXPECTED_FILES = [
        "lockon.py",
        "smbexplorer.py",
        "nfsexplorer.py",
        "base.py",
        "schema.py",
        "exporters.py",
        "__init__.py",
    ]

    @pytest.mark.parametrize("filename", EXPECTED_FILES)
    def test_module_file_exists(self, filename):
        """Each expected module file should exist."""
        filepath = self.MODULES_DIR / filename
        assert filepath.is_file(), f"Missing module file: {filepath}"

    def test_modules_directory_exists(self):
        """The modules directory should exist."""
        assert self.MODULES_DIR.is_dir()

    def test_example_template_files_are_excluded(self, tmp_path, monkeypatch):
        """A stray developer-example file (template_module.py) must never be
        discovered as a real module -- guards against stale builds resurrecting
        it in the sidebar."""
        import cygor.module_loader as ml
        tmpl = 'module_info = {{"name": "{n}", "slug": "{s}", "module_type": "enumeration"}}\n'
        (tmp_path / "template_module.py").write_text(tmpl.format(n="Template Module", s="template_module"))
        (tmp_path / "example_module.py").write_text(tmpl.format(n="Example", s="example_module"))
        (tmp_path / "realmod.py").write_text(tmpl.format(n="Real Mod", s="realmod"))
        (tmp_path / "__init__.py").write_text("")
        monkeypatch.setattr(ml, "MODULES_DIR", tmp_path)
        slugs = {m.slug for m in ml.discover_modules()}
        assert "realmod" in slugs                  # a normal module IS discovered
        assert "template_module" not in slugs       # example excluded
        assert "example_module" not in slugs        # example excluded


# ---------------------------------------------------------------------------
# get_module_info helper
# ---------------------------------------------------------------------------

class TestGetModuleInfo:
    """Test the get_module_info compatibility helper."""

    def test_get_module_info_returns_dict(self):
        """get_module_info should return a dict with expected keys."""
        from cygor.modules.base import CygorModule, get_module_info

        class InfoMod(CygorModule):
            name = "Info Test"
            slug = "info_test"
            version = "1.2.3"
            category = "enumeration"
            view = "table"
            columns = [{"key": "host", "label": "Host"}]

            def run(self, targets, **kwargs):
                pass

        info = get_module_info(InfoMod)
        assert isinstance(info, dict)
        assert info["name"] == "Info Test"
        assert info["slug"] == "info_test"
        assert info["version"] == "1.2.3"
        assert "table" in info
        assert "columns" in info["table"]


# ---------------------------------------------------------------------------
# Plugin loader
# ---------------------------------------------------------------------------

class TestPluginLoader:
    """Test the plugin loader directory definitions and validation."""

    def test_plugin_dirs_defined(self):
        """PLUGIN_DIRS should be a list of Path objects."""
        from cygor.plugin_loader import PLUGIN_DIRS
        assert isinstance(PLUGIN_DIRS, list)
        assert len(PLUGIN_DIRS) >= 2  # user + system dirs
        for d in PLUGIN_DIRS:
            assert isinstance(d, Path)

    def test_default_plugin_dirs_paths(self):
        """Default plugin dirs should include ~/.cygor/plugins and /etc/cygor/plugins."""
        from cygor.plugin_loader import PLUGIN_DIRS
        dir_strs = [str(d) for d in PLUGIN_DIRS]
        assert any(".cygor/plugins" in s for s in dir_strs)
        assert any("/etc/cygor/plugins" in s for s in dir_strs)

    def test_validate_plugin_exists(self):
        """validate_plugin function should be importable and callable."""
        from cygor.plugin_loader import validate_plugin
        assert callable(validate_plugin)

    def test_discover_plugins_exists(self):
        """discover_plugins function should be importable and callable."""
        from cygor.plugin_loader import discover_plugins
        assert callable(discover_plugins)
