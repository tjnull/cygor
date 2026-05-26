"""Tests for the msfconsole-style `cygor workspace` command surface.

Surface (flat, flag-driven, always-active invariant):

  cygor workspace                       List (* marks active)
  cygor workspace <name>                Switch
  cygor workspace -a <name> [--path]    Add (at default root, or --path)
  cygor workspace -d <name> [--purge]   Delete (files stay unless --purge)
  cygor workspace -r <old> <new>        Rename
  cygor workspace --info <name>         Detail view
  cygor workspace --clean [<name>]      Trim old scan output
  cygor workspace --print-path          Print active path (scripting)

There is always exactly one active workspace; 'default' is auto-created at
the workspaces root when the registry is empty.
"""
import io
import json
import time
from contextlib import redirect_stdout

import pytest

from cygor import workspace as ws


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    """Isolated workspace config + isolated workspaces root + no env interference."""
    cfg_dir = tmp_path / "config" / "cygor"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr(ws, "CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(ws, "CONFIG_FILE", cfg_dir / "config.json")
    # Point the workspaces root at the tmp dir so -a NAME creates under it.
    root = tmp_path / "workspaces"
    monkeypatch.setattr(ws, "DEFAULT_WORKSPACES_ROOT", root)
    monkeypatch.delenv("CYGOR_WORKSPACES_ROOT", raising=False)
    monkeypatch.delenv("CYGOR_WORKSPACE", raising=False)
    monkeypatch.delenv("CYGOR_RESULTS_DIR", raising=False)
    return cfg_dir


def _run(*argv):
    """Drive workspace.main() so dispatch goes through the real parser."""
    return ws.main(list(argv))


def _config(cfg_dir):
    return json.loads((cfg_dir / "config.json").read_text())


def _active(cfg_dir):
    return _config(cfg_dir).get("active_workspace")


# ---------------------------------------------------------------------------
# -a / add  (msf:  workspace -a NAME)
# ---------------------------------------------------------------------------
def test_add_creates_under_default_root(cfg, tmp_path):
    rc = _run("-a", "acme")
    assert rc == 0
    assert _active(cfg) == "acme"
    assert (tmp_path / "workspaces" / "acme").is_dir()
    assert (tmp_path / "workspaces" / "acme" / ".cygor-workspace.json").is_file()


def test_add_with_custom_path(cfg, tmp_path):
    target = tmp_path / "custom" / "acme"
    rc = _run("-a", "acme", "--path", str(target))
    assert rc == 0
    assert _active(cfg) == "acme"
    assert target.is_dir()
    # Standard layout should be laid out at the custom path.
    for sub in ws.SUBDIRS:
        assert (target / sub).is_dir()


def test_add_duplicate_name_errors(cfg):
    _run("-a", "acme")
    assert _run("-a", "acme") == 2


def test_add_makes_workspace_active_immediately(cfg, tmp_path):
    # msf semantics: adding a workspace switches into it.
    _run("-a", "alpha")
    _run("-a", "beta")
    assert _active(cfg) == "beta"


# ---------------------------------------------------------------------------
# bare positional / switch  (msf:  workspace NAME)
# ---------------------------------------------------------------------------
def test_switch_by_name(cfg):
    _run("-a", "alpha")
    _run("-a", "beta")
    assert _active(cfg) == "beta"
    assert _run("alpha") == 0
    assert _active(cfg) == "alpha"


def test_switch_unknown_errors(cfg):
    _run("-a", "alpha")
    assert _run("nonexistent") == 2


def test_switch_to_workspace_with_missing_dir_errors(cfg, tmp_path):
    _run("-a", "alpha")
    # Yank the directory from underneath
    import shutil
    shutil.rmtree(tmp_path / "workspaces" / "alpha")
    assert _run("alpha") == 2


# ---------------------------------------------------------------------------
# -d / delete  (msf:  workspace -d NAME)
# ---------------------------------------------------------------------------
def test_delete_unregisters_but_preserves_files(cfg, tmp_path):
    _run("-a", "alpha")
    _run("-a", "beta")  # 'beta' is now active
    path_alpha = tmp_path / "workspaces" / "alpha"
    assert _run("-d", "alpha") == 0
    assert "alpha" not in _config(cfg)["workspaces"]
    assert path_alpha.exists()                    # files preserved by default
    assert _active(cfg) == "beta"                 # untouched (wasn't active)


def test_delete_active_falls_back_to_remaining(cfg, tmp_path):
    _run("-a", "alpha")
    _run("-a", "beta")  # beta is active
    assert _active(cfg) == "beta"
    assert _run("-d", "beta") == 0
    # Auto-promote to the remaining one rather than leaving the user in
    # "no workspace" state.
    assert _active(cfg) == "alpha"


def test_delete_last_workspace_clears_active(cfg, tmp_path):
    _run("-a", "alpha")
    assert _run("-d", "alpha") == 0
    cfg_now = _config(cfg)
    assert cfg_now["workspaces"] == {}
    assert cfg_now.get("active_workspace") is None
    # Files still on disk.
    assert (tmp_path / "workspaces" / "alpha").exists()


def test_delete_with_purge_wipes_files(cfg, tmp_path, monkeypatch):
    _run("-a", "alpha")
    path_alpha = tmp_path / "workspaces" / "alpha"
    # Bypass the interactive confirm.
    monkeypatch.setattr("builtins.input", lambda *a, **k: "alpha")
    assert _run("-d", "alpha", "--purge") == 0
    assert not path_alpha.exists()


def test_delete_purge_aborts_on_mismatched_confirmation(cfg, tmp_path, monkeypatch):
    _run("-a", "alpha")
    path_alpha = tmp_path / "workspaces" / "alpha"
    monkeypatch.setattr("builtins.input", lambda *a, **k: "wrong-name")
    rc = _run("-d", "alpha", "--purge")
    assert rc == 1
    assert path_alpha.exists()                    # NOT wiped
    assert "alpha" in _config(cfg)["workspaces"]  # NOT unregistered


def test_delete_unknown_errors(cfg):
    assert _run("-d", "nonexistent") == 2


# ---------------------------------------------------------------------------
# -r / rename  (msf:  workspace -r OLD NEW)
# ---------------------------------------------------------------------------
def test_rename_changes_key_and_preserves_active(cfg, tmp_path):
    _run("-a", "alpha")
    assert _run("-r", "alpha", "alpha-2026") == 0
    cfg_now = _config(cfg)
    assert "alpha" not in cfg_now["workspaces"]
    assert "alpha-2026" in cfg_now["workspaces"]
    assert cfg_now["active_workspace"] == "alpha-2026"
    # Directory on disk keeps its original name.
    assert (tmp_path / "workspaces" / "alpha").is_dir()


def test_rename_unknown_old_errors(cfg):
    _run("-a", "alpha")
    assert _run("-r", "nonexistent", "x") == 2


def test_rename_collision_errors(cfg):
    _run("-a", "alpha")
    _run("-a", "beta")
    assert _run("-r", "alpha", "beta") == 2


# ---------------------------------------------------------------------------
# bare workspace  (msf:  workspace)
# ---------------------------------------------------------------------------
def test_bare_workspace_auto_creates_default(cfg, tmp_path):
    """Empty registry + bare command must auto-create 'default' so the user
    is never in a 'no workspace' state. msf invariant."""
    rc = _run()
    assert rc == 0
    cfg_now = _config(cfg)
    assert "default" in cfg_now["workspaces"]
    assert cfg_now["active_workspace"] == "default"
    assert (tmp_path / "workspaces" / "default").is_dir()


def test_bare_workspace_lists_with_asterisk(cfg):
    _run("-a", "alpha")
    _run("-a", "beta")
    buf = io.StringIO()
    with redirect_stdout(buf):
        _run()
    out = buf.getvalue()
    # The active workspace (beta, last added) should have an asterisk.
    assert "*" in out
    assert "alpha" in out and "beta" in out


# ---------------------------------------------------------------------------
# --info
# ---------------------------------------------------------------------------
def test_info_shows_subdir_breakdown(cfg, tmp_path, capsys):
    _run("-a", "alpha")
    base = tmp_path / "workspaces" / "alpha"
    (base / "nmap" / "run-1").mkdir()
    (base / "nmap" / "run-1" / "scan.xml").write_text("data")
    rc = _run("--info", "alpha")
    out = capsys.readouterr().out
    assert rc == 0
    assert "Subdirectories" in out
    assert "nmap" in out


def test_info_unknown_errors(cfg):
    assert _run("--info", "nonexistent") == 2


# ---------------------------------------------------------------------------
# --print-path
# ---------------------------------------------------------------------------
def test_print_path_emits_clean_bytes(cfg, tmp_path, capfd):
    _run("-a", "alpha")
    capfd.readouterr()  # drain
    rc = _run("--print-path")
    out = capfd.readouterr().out
    assert rc == 0
    assert out == f"{tmp_path / 'workspaces' / 'alpha'}\n"
    # No ANSI -- the whole point of using fd 1 directly.
    assert "\x1b" not in out


# ---------------------------------------------------------------------------
# --clean
# ---------------------------------------------------------------------------
def test_clean_keep_last(cfg, tmp_path):
    _run("-a", "alpha")
    nmap = tmp_path / "workspaces" / "alpha" / "nmap"
    for i in range(3):
        r = nmap / f"run-{i}"
        r.mkdir()
        (r / "scan.xml").write_text("x" * 100)
        time.sleep(0.01)
    # No positional name -> operates on active (alpha).
    assert _run("--clean", "--keep-last", "1", "--yes") == 0
    remaining = sorted(p.name for p in nmap.iterdir())
    assert remaining == ["run-2"]


def test_clean_dry_run_keeps_everything(cfg, tmp_path):
    _run("-a", "alpha")
    nmap = tmp_path / "workspaces" / "alpha" / "nmap"
    (nmap / "run-1").mkdir()
    (nmap / "run-1" / "scan.xml").write_text("data")
    assert _run("--clean", "alpha", "--dry-run") == 0
    assert (nmap / "run-1" / "scan.xml").exists()


# ---------------------------------------------------------------------------
# Always-active invariant
# ---------------------------------------------------------------------------
def test_active_workspace_path_auto_creates_default_when_empty(cfg, tmp_path):
    """First call to active_workspace_path() with an empty registry creates
    'default' and returns its path. This is what enables 'cygor scan' etc. to
    always have somewhere to write."""
    p = ws.active_workspace_path()
    assert p == tmp_path / "workspaces" / "default"
    assert p.is_dir()
    assert _active(cfg) == "default"


def test_workspaces_root_env_override(monkeypatch, tmp_path):
    target = tmp_path / "elsewhere"
    monkeypatch.setenv("CYGOR_WORKSPACES_ROOT", str(target))
    assert ws.workspaces_root() == target


# ---------------------------------------------------------------------------
# Env-var resolution (still honored)
# ---------------------------------------------------------------------------
def test_workspace_env_prefers_workspace(monkeypatch, tmp_path):
    monkeypatch.setenv("CYGOR_RESULTS_DIR", str(tmp_path / "legacy"))
    monkeypatch.setenv("CYGOR_WORKSPACE", str(tmp_path / "canonical"))
    assert ws.workspace_env() == str(tmp_path / "canonical")
    monkeypatch.delenv("CYGOR_WORKSPACE")
    assert ws.workspace_env() == str(tmp_path / "legacy")


# ---------------------------------------------------------------------------
# Legacy config migration -- still preserved.
# ---------------------------------------------------------------------------
def test_legacy_default_workspace_config_is_migrated(cfg, tmp_path):
    legacy_path = tmp_path / "legacy"
    legacy_path.mkdir()
    (legacy_path / ".cygor-workspace.json").write_text(json.dumps(
        {"workspace": str(legacy_path), "schema": 3}))
    (cfg / "config.json").write_text(json.dumps({
        "default_workspace": str(legacy_path),
    }))
    assert ws.active_workspace_path() == legacy_path
