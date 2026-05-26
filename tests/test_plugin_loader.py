"""
Tests for the cygor plugin loader: discovery, validation, version checks,
fingerprinting, and error tracking.
"""
import os
from pathlib import Path
from textwrap import dedent

import pytest


@pytest.fixture
def isolated_plugin_dir(monkeypatch, tmp_path):
    """Point CYGOR_PLUGIN_DIR at a private dir for the duration of the test."""
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    # plugin_loader reads PLUGIN_DIRS at import time, so we have to rebind it.
    from cygor import plugin_loader
    monkeypatch.setattr(plugin_loader, "PLUGIN_DIRS", [plugin_dir])
    return plugin_dir


def _write_plugin(path: Path, body: str) -> None:
    path.write_text(dedent(body).strip() + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Version parsing / compatibility
# ---------------------------------------------------------------------------

class TestVersionCompat:
    def test_parse_simple(self):
        from cygor.plugin_loader import _parse_version
        assert _parse_version("0.1.0") == (0, 1, 0)
        assert _parse_version("1.10.2") == (1, 10, 2)

    def test_parse_empty(self):
        from cygor.plugin_loader import _parse_version
        assert _parse_version("") == (0,)

    def test_compat_no_requirement(self):
        from cygor.plugin_loader import _check_version_compat
        assert _check_version_compat("", "0.1.0") is None

    def test_compat_satisfied(self):
        from cygor.plugin_loader import _check_version_compat
        assert _check_version_compat("0.1.0", "0.1.0") is None
        assert _check_version_compat("0.0.5", "0.1.0") is None

    def test_compat_too_old(self):
        from cygor.plugin_loader import _check_version_compat
        msg = _check_version_compat("0.2.0", "0.1.0")
        assert msg is not None
        assert "0.2.0" in msg


# ---------------------------------------------------------------------------
# Discovery + ModuleSpec fields
# ---------------------------------------------------------------------------

class TestDiscovery:
    def test_module_info_style_loads(self, isolated_plugin_dir):
        _write_plugin(isolated_plugin_dir / "alpha.py", '''
            module_info = {
                "name": "Alpha",
                "slug": "alpha",
                "version": "1.2.3",
                "description": "alpha plugin",
                "module_type": "enumeration",
                "view": "table",
                "table": {"columns": [{"key": "host", "label": "Host"}]},
            }
        ''')
        from cygor.plugin_loader import discover_plugins
        specs = discover_plugins()
        assert len(specs) == 1
        s = specs[0]
        assert s.slug == "alpha"
        assert s.name == "Alpha"
        assert s.version == "1.2.3"
        assert s.source == "plugin"
        assert s.fingerprint  # sha256 hex

    def test_class_style_loads(self, isolated_plugin_dir):
        _write_plugin(isolated_plugin_dir / "beta.py", '''
            from cygor.modules.base import CygorModule

            class Beta(CygorModule):
                name = "Beta"
                slug = "beta"
                version = "2.0.0"
                description = "beta plugin"
                requires_cygor = "0.0.1"
                columns = [{"key": "host", "label": "Host"}]

                def run(self, targets, **kwargs):
                    pass
        ''')
        from cygor.plugin_loader import discover_plugins
        specs = discover_plugins()
        assert len(specs) == 1
        s = specs[0]
        assert s.slug == "beta"
        assert s.requires_cygor == "0.0.1"
        assert s.source == "plugin"

    def test_hidden_module_type_skipped(self, isolated_plugin_dir):
        _write_plugin(isolated_plugin_dir / "ghost.py", '''
            module_info = {"slug": "ghost", "name": "Ghost", "module_type": "hidden"}
        ''')
        from cygor.plugin_loader import discover_plugins
        assert discover_plugins() == []

    def test_underscore_files_ignored(self, isolated_plugin_dir):
        _write_plugin(isolated_plugin_dir / "_private.py", '''
            module_info = {"slug": "private", "name": "Private"}
        ''')
        from cygor.plugin_loader import discover_plugins
        assert discover_plugins() == []


# ---------------------------------------------------------------------------
# requires_cygor enforcement
# ---------------------------------------------------------------------------

class TestVersionGate:
    def test_plugin_requiring_future_version_rejected(self, isolated_plugin_dir):
        _write_plugin(isolated_plugin_dir / "future.py", '''
            module_info = {
                "slug": "future",
                "name": "Future",
                "module_type": "enumeration",
                "requires_cygor": "999.0.0",
                "table": {"columns": []},
            }
        ''')
        from cygor.plugin_loader import discover_plugins, get_plugin_errors
        specs = discover_plugins()
        assert specs == []
        errs = get_plugin_errors()
        assert len(errs) == 1
        assert errs[0]["kind"] == "version"
        assert "999.0.0" in errs[0]["error"]


# ---------------------------------------------------------------------------
# Error tracking
# ---------------------------------------------------------------------------

class TestErrorTracking:
    def test_syntax_error_recorded(self, isolated_plugin_dir):
        # Deliberately broken Python — discovery should record, not crash.
        (isolated_plugin_dir / "broken.py").write_text("def bad(:\n", encoding="utf-8")
        from cygor.plugin_loader import discover_plugins, get_plugin_errors
        assert discover_plugins() == []
        errs = get_plugin_errors()
        assert len(errs) == 1
        assert errs[0]["kind"] == "import"
        assert "broken.py" in errs[0]["path"]

    def test_missing_schema_recorded(self, isolated_plugin_dir):
        # Imports cleanly but has no module_info or class — should record.
        _write_plugin(isolated_plugin_dir / "blank.py", '''
            x = 1
        ''')
        from cygor.plugin_loader import discover_plugins, get_plugin_errors
        assert discover_plugins() == []
        errs = get_plugin_errors()
        assert len(errs) == 1
        assert errs[0]["kind"] == "schema"

    def test_errors_cleared_on_each_discover(self, isolated_plugin_dir):
        (isolated_plugin_dir / "broken.py").write_text("def bad(:\n", encoding="utf-8")
        from cygor.plugin_loader import discover_plugins, get_plugin_errors
        discover_plugins()
        assert len(get_plugin_errors()) == 1
        # Remove the broken file and rediscover
        (isolated_plugin_dir / "broken.py").unlink()
        discover_plugins()
        assert get_plugin_errors() == []


# ---------------------------------------------------------------------------
# validate_plugin()
# ---------------------------------------------------------------------------

class TestValidatePlugin:
    def test_valid_plugin(self, tmp_path):
        path = tmp_path / "good.py"
        _write_plugin(path, '''
            module_info = {
                "slug": "good",
                "name": "Good",
                "version": "1.0.0",
                "description": "good plugin",
                "module_type": "enumeration",
                "table": {"columns": [{"key": "host", "label": "Host"}]},
            }
        ''')
        from cygor.plugin_loader import validate_plugin
        r = validate_plugin(path)
        assert r["valid"] is True
        assert r["slug"] == "good"
        assert r["fingerprint"]
        assert r["warnings"] == []

    def test_invalid_syntax(self, tmp_path):
        path = tmp_path / "broken.py"
        path.write_text("def bad(:\n")
        from cygor.plugin_loader import validate_plugin
        r = validate_plugin(path)
        assert r["valid"] is False
        assert any("import" in e.lower() for e in r["errors"])

    def test_warnings_for_missing_metadata(self, tmp_path):
        path = tmp_path / "min.py"
        _write_plugin(path, '''
            module_info = {"slug": "min", "name": "Min", "module_type": "enumeration"}
        ''')
        from cygor.plugin_loader import validate_plugin
        r = validate_plugin(path)
        assert r["valid"] is True
        assert r["warnings"]  # description / version / columns warnings

    def test_validate_does_not_pollute_discover_errors(self, isolated_plugin_dir, tmp_path):
        # Seed a discover-time error
        (isolated_plugin_dir / "broken.py").write_text("def bad(:\n", encoding="utf-8")
        from cygor.plugin_loader import discover_plugins, get_plugin_errors, validate_plugin
        discover_plugins()
        before = list(get_plugin_errors())
        # Validate a separate broken file — discover-time errors must persist
        bad = tmp_path / "elsewhere.py"
        bad.write_text("def also_bad(:\n")
        validate_plugin(bad)
        after = list(get_plugin_errors())
        assert before == after


# ---------------------------------------------------------------------------
# Options & dependencies (gaps A and B)
# ---------------------------------------------------------------------------

class TestOptionsAndDependencies:
    def test_options_passed_through(self, tmp_path):
        path = tmp_path / "opt.py"
        _write_plugin(path, '''
            module_info = {
                "slug": "opt", "name": "Opt", "module_type": "enumeration",
                "table": {"columns": [{"key": "host", "label": "Host"}]},
                "options": [
                    {"name": "depth", "label": "Depth", "type": "number", "default": "3"},
                    {"name": "mode", "label": "Mode", "type": "select",
                     "choices": [{"value": "fast", "label": "Fast"}]},
                ],
            }
        ''')
        from cygor.plugin_loader import validate_plugin
        r = validate_plugin(path)
        assert r["valid"] is True
        assert len(r["options"]) == 2
        assert r["options"][0]["name"] == "depth"

    def test_options_schema_warning_for_bad_select(self, tmp_path):
        path = tmp_path / "bad_opts.py"
        _write_plugin(path, '''
            module_info = {
                "slug": "bad_opts", "name": "Bad", "module_type": "enumeration",
                "table": {"columns": [{"key": "x", "label": "X"}]},
                "options": [
                    {"name": "mode", "label": "Mode", "type": "select"},  # missing choices
                ],
            }
        ''')
        from cygor.plugin_loader import validate_plugin
        r = validate_plugin(path)
        assert r["valid"] is True
        assert any("choices" in w for w in r["warnings"])

    def test_missing_dependency_surfaces_in_warnings(self, tmp_path):
        path = tmp_path / "needs_dep.py"
        _write_plugin(path, '''
            module_info = {
                "slug": "needs_dep", "name": "Needs", "module_type": "enumeration",
                "table": {"columns": [{"key": "x", "label": "X"}]},
                "dependencies": ["definitely-not-installed-pkg-xyz"],
            }
        ''')
        from cygor.plugin_loader import validate_plugin
        r = validate_plugin(path)
        assert r["valid"] is True
        assert "definitely-not-installed-pkg-xyz" in r["missing_dependencies"]
        assert any("Missing pip packages" in w for w in r["warnings"])

    def test_requirements_txt_sibling_is_honored(self, tmp_path):
        # Drop a plugin file with a requirements.txt next to it
        (tmp_path / "requirements.txt").write_text("absolutely-not-installed-package\n")
        path = tmp_path / "with_reqs.py"
        _write_plugin(path, '''
            module_info = {
                "slug": "with_reqs", "name": "With", "module_type": "enumeration",
                "table": {"columns": [{"key": "x", "label": "X"}]},
            }
        ''')
        from cygor.plugin_loader import validate_plugin
        r = validate_plugin(path)
        assert r["valid"] is True
        assert "absolutely-not-installed-package" in r["missing_dependencies"]
        assert r["requirements_txt"].endswith("requirements.txt")


# ---------------------------------------------------------------------------
# Allowlist enforcement (gap I)
# ---------------------------------------------------------------------------

class TestAllowlist:
    def test_disabled_allowlist_loads_everything(self, isolated_plugin_dir, monkeypatch, tmp_path):
        # Allowlist file absent -> no enforcement
        from cygor import plugin_loader
        monkeypatch.setattr(plugin_loader, "ALLOWLIST_PATH", tmp_path / "missing.json")
        _write_plugin(isolated_plugin_dir / "free.py", '''
            module_info = {"slug": "free", "name": "Free", "module_type": "enumeration"}
        ''')
        specs = plugin_loader.discover_plugins()
        assert any(s.slug == "free" for s in specs)

    def test_enforce_rejects_unlisted(self, isolated_plugin_dir, monkeypatch, tmp_path):
        from cygor import plugin_loader
        allowlist = tmp_path / "allow.json"
        allowlist.write_text('{"enforce": true, "plugins": {}}', encoding="utf-8")
        monkeypatch.setattr(plugin_loader, "ALLOWLIST_PATH", allowlist)
        _write_plugin(isolated_plugin_dir / "rogue.py", '''
            module_info = {"slug": "rogue", "name": "Rogue", "module_type": "enumeration"}
        ''')
        specs = plugin_loader.discover_plugins()
        assert specs == []
        errs = plugin_loader.get_plugin_errors()
        assert any(e["kind"] == "allowlist" for e in errs)

    def test_enforce_accepts_matching_fingerprint(self, isolated_plugin_dir, monkeypatch, tmp_path):
        from cygor import plugin_loader
        plugin_path = isolated_plugin_dir / "trusted.py"
        _write_plugin(plugin_path, '''
            module_info = {"slug": "trusted", "name": "Trusted", "module_type": "enumeration"}
        ''')
        # Compute the expected fingerprint, then write the allowlist.
        fp = plugin_loader._file_fingerprint(plugin_path)
        allowlist = tmp_path / "allow.json"
        allowlist.write_text(f'{{"enforce": true, "plugins": {{"trusted": "{fp}"}}}}', encoding="utf-8")
        monkeypatch.setattr(plugin_loader, "ALLOWLIST_PATH", allowlist)
        specs = plugin_loader.discover_plugins()
        assert any(s.slug == "trusted" for s in specs)


# ---------------------------------------------------------------------------
# Slug collision (gap H)
# ---------------------------------------------------------------------------

class TestSlugCollision:
    def test_collision_recorded(self, isolated_plugin_dir):
        # Two plugin files claiming the same slug — second should be flagged.
        _write_plugin(isolated_plugin_dir / "a.py", '''
            module_info = {"slug": "dup", "name": "A", "module_type": "enumeration"}
        ''')
        _write_plugin(isolated_plugin_dir / "b.py", '''
            module_info = {"slug": "dup", "name": "B", "module_type": "enumeration"}
        ''')
        from cygor.plugin_loader import discover_plugins, get_plugin_errors
        specs = discover_plugins()
        # Only one wins
        assert len(specs) == 1
        # The other is recorded as a collision error
        errs = get_plugin_errors()
        assert any(e["kind"] == "collision" for e in errs)
