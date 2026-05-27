"""Tests for the English-verb `cygor workspace` command surface.

Surface (subcommand-style; no implicit workspace creation):

  cygor workspace                       List (* marks active)
  cygor workspace list                  Same (explicit)
  cygor workspace create <name>         Create + select
  cygor workspace create <name> --path  Create at a custom location
  cygor workspace select <name>         Switch the active workspace
  cygor workspace info <name>           Detail view
  cygor workspace rename <old> <new>    Rename
  cygor workspace delete <name>         Delete (files preserved)
  cygor workspace delete <name> --purge Delete + wipe files
  cygor workspace clean [<name>]        Trim old scan output
  cygor workspace path                  Print active path (scripting)

The user must explicitly create + select a workspace; nothing is created
automatically. Commands that need an active workspace error with guidance
when none is set.
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
    """Read the persisted config; empty dict when nothing's been written.

    `cmd_list` doesn't write a config file in the empty-state path (nothing
    to persist), so test helpers must handle a missing file gracefully."""
    f = cfg_dir / "config.json"
    if not f.exists():
        return {}
    return json.loads(f.read_text())


def _active(cfg_dir):
    return _config(cfg_dir).get("active_workspace")


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------
def test_create_under_default_root(cfg, tmp_path):
    rc = _run("create", "acme")
    assert rc == 0
    assert _active(cfg) == "acme"
    assert (tmp_path / "workspaces" / "acme").is_dir()
    assert (tmp_path / "workspaces" / "acme" / ".cygor-workspace.json").is_file()


def test_create_with_custom_path(cfg, tmp_path):
    target = tmp_path / "custom" / "acme"
    rc = _run("create", "acme", "--path", str(target))
    assert rc == 0
    assert _active(cfg) == "acme"
    assert target.is_dir()
    for sub in ws.SUBDIRS:
        assert (target / sub).is_dir()


def test_create_duplicate_name_errors(cfg):
    _run("create", "acme")
    assert _run("create", "acme") == 2


def test_create_makes_workspace_active_immediately(cfg):
    # Creating always selects the new workspace -- no extra step.
    _run("create", "alpha")
    _run("create", "beta")
    assert _active(cfg) == "beta"


# ---------------------------------------------------------------------------
# select
# ---------------------------------------------------------------------------
def test_select_by_name(cfg):
    _run("create", "alpha")
    _run("create", "beta")
    assert _active(cfg) == "beta"
    assert _run("select", "alpha") == 0
    assert _active(cfg) == "alpha"


def test_select_unknown_errors(cfg):
    _run("create", "alpha")
    assert _run("select", "nonexistent") == 2


def test_select_workspace_with_missing_dir_errors(cfg, tmp_path):
    _run("create", "alpha")
    import shutil
    shutil.rmtree(tmp_path / "workspaces" / "alpha")
    assert _run("select", "alpha") == 2


# ---------------------------------------------------------------------------
# delete
# ---------------------------------------------------------------------------
def test_delete_unregisters_but_preserves_files(cfg, tmp_path):
    _run("create", "alpha")
    _run("create", "beta")  # 'beta' is now active
    path_alpha = tmp_path / "workspaces" / "alpha"
    assert _run("delete", "alpha") == 0
    assert "alpha" not in _config(cfg)["workspaces"]
    assert path_alpha.exists()                    # files preserved by default
    assert _active(cfg) == "beta"                 # untouched (wasn't active)


def test_delete_active_falls_back_to_remaining(cfg):
    _run("create", "alpha")
    _run("create", "beta")  # beta is active
    assert _active(cfg) == "beta"
    assert _run("delete", "beta") == 0
    # Auto-promote to the remaining one -- never strand the user.
    assert _active(cfg) == "alpha"


def test_delete_last_workspace_clears_active(cfg, tmp_path):
    _run("create", "alpha")
    assert _run("delete", "alpha") == 0
    cfg_now = _config(cfg)
    assert cfg_now["workspaces"] == {}
    assert cfg_now.get("active_workspace") is None
    assert (tmp_path / "workspaces" / "alpha").exists()


def test_delete_with_purge_wipes_files(cfg, tmp_path, monkeypatch):
    _run("create", "alpha")
    path_alpha = tmp_path / "workspaces" / "alpha"
    monkeypatch.setattr("builtins.input", lambda *a, **k: "alpha")
    assert _run("delete", "alpha", "--purge") == 0
    assert not path_alpha.exists()


def test_delete_purge_aborts_on_mismatched_confirmation(cfg, tmp_path, monkeypatch):
    _run("create", "alpha")
    path_alpha = tmp_path / "workspaces" / "alpha"
    monkeypatch.setattr("builtins.input", lambda *a, **k: "wrong-name")
    rc = _run("delete", "alpha", "--purge")
    assert rc == 1
    assert path_alpha.exists()
    assert "alpha" in _config(cfg)["workspaces"]


def test_delete_unknown_errors(cfg):
    assert _run("delete", "nonexistent") == 2


# ---------------------------------------------------------------------------
# rename
# ---------------------------------------------------------------------------
def test_rename_changes_key_and_preserves_active(cfg, tmp_path):
    _run("create", "alpha")
    assert _run("rename", "alpha", "alpha-2026") == 0
    cfg_now = _config(cfg)
    assert "alpha" not in cfg_now["workspaces"]
    assert "alpha-2026" in cfg_now["workspaces"]
    assert cfg_now["active_workspace"] == "alpha-2026"
    # Directory on disk keeps its original name.
    assert (tmp_path / "workspaces" / "alpha").is_dir()


def test_rename_unknown_old_errors(cfg):
    _run("create", "alpha")
    assert _run("rename", "nonexistent", "x") == 2


def test_rename_collision_errors(cfg):
    _run("create", "alpha")
    _run("create", "beta")
    assert _run("rename", "alpha", "beta") == 2


# ---------------------------------------------------------------------------
# bare workspace / list
# ---------------------------------------------------------------------------
def test_bare_workspace_empty_state_does_not_create_anything(cfg, tmp_path, capsys):
    """Empty registry + bare command must NOT create anything; it should
    print an empty-state hint and point the user at `create`. The user is
    expected to set up their own workspace explicitly."""
    rc = _run()
    out = capsys.readouterr().out
    assert rc == 0
    cfg_now = _config(cfg)
    assert cfg_now.get("workspaces", {}) == {}
    assert cfg_now.get("active_workspace") is None
    assert not (tmp_path / "workspaces" / "default").exists()
    assert "No workspaces registered" in out
    assert "cygor workspace create" in out


def test_bare_workspace_warns_when_workspaces_exist_but_none_selected(cfg, capsys):
    """If the user has workspaces but somehow none is selected (e.g. just
    deleted the active one and the registry has zero), list still works and
    warns clearly so they know scans won't have a target."""
    _run("create", "alpha")
    _run("delete", "alpha")  # leaves the registry empty
    # Manually plant one workspace via the registry without selecting it,
    # to exercise the "have workspaces, none selected" path.
    _run("create", "beta")
    # Drop the active pointer to simulate the gap.
    import json as _json
    data = _config(cfg)
    data.pop("active_workspace", None)
    (cfg / "config.json").write_text(_json.dumps(data))
    capsys.readouterr()
    rc = _run()
    out = capsys.readouterr().out
    assert rc == 0
    assert "No workspace is currently selected" in out
    assert "cygor workspace select" in out


def test_bare_workspace_lists_with_asterisk(cfg):
    _run("create", "alpha")
    _run("create", "beta")
    buf = io.StringIO()
    with redirect_stdout(buf):
        _run()
    out = buf.getvalue()
    assert "*" in out
    assert "alpha" in out and "beta" in out


def test_list_subcommand_works(cfg):
    """Explicit 'list' verb does the same thing as bare workspace."""
    _run("create", "alpha")
    buf = io.StringIO()
    with redirect_stdout(buf):
        _run("list")
    assert "alpha" in buf.getvalue()


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------
def test_info_shows_subdir_breakdown(cfg, tmp_path, capsys):
    _run("create", "alpha")
    base = tmp_path / "workspaces" / "alpha"
    (base / "nmap" / "run-1").mkdir()
    (base / "nmap" / "run-1" / "scan.xml").write_text("data")
    rc = _run("info", "alpha")
    out = capsys.readouterr().out
    assert rc == 0
    assert "Subdirectories" in out
    assert "nmap" in out


def test_info_unknown_errors(cfg):
    assert _run("info", "nonexistent") == 2


# ---------------------------------------------------------------------------
# path
# ---------------------------------------------------------------------------
def test_path_emits_clean_bytes(cfg, tmp_path, capfd):
    _run("create", "alpha")
    capfd.readouterr()  # drain
    rc = _run("path")
    out = capfd.readouterr().out
    assert rc == 0
    assert out == f"{tmp_path / 'workspaces' / 'alpha'}\n"
    # No ANSI -- the whole point of using fd 1 directly.
    assert "\x1b" not in out


# ---------------------------------------------------------------------------
# clean
# ---------------------------------------------------------------------------
def test_clean_keep_last(cfg, tmp_path):
    _run("create", "alpha")
    nmap = tmp_path / "workspaces" / "alpha" / "nmap"
    for i in range(3):
        r = nmap / f"run-{i}"
        r.mkdir()
        (r / "scan.xml").write_text("x" * 100)
        time.sleep(0.01)
    # No positional name -> operates on active (alpha).
    assert _run("clean", "--keep-last", "1", "--yes") == 0
    remaining = sorted(p.name for p in nmap.iterdir())
    assert remaining == ["run-2"]


def test_clean_dry_run_keeps_everything(cfg, tmp_path):
    _run("create", "alpha")
    nmap = tmp_path / "workspaces" / "alpha" / "nmap"
    (nmap / "run-1").mkdir()
    (nmap / "run-1" / "scan.xml").write_text("data")
    assert _run("clean", "alpha", "--dry-run") == 0
    assert (nmap / "run-1" / "scan.xml").exists()


# ---------------------------------------------------------------------------
# No implicit workspace -- empty registry / no selection means None.
# ---------------------------------------------------------------------------
def test_active_workspace_path_returns_none_when_empty(cfg, tmp_path):
    """No workspaces registered -> None. Nothing gets created on disk."""
    assert ws.active_workspace_path() is None
    assert not (tmp_path / "workspaces").exists()


def test_active_workspace_path_returns_none_when_no_selection(cfg, tmp_path):
    """Workspaces exist but none is selected -> None."""
    _run("create", "alpha")
    # Wipe the active pointer.
    import json as _json
    data = _config(cfg)
    data.pop("active_workspace", None)
    (cfg / "config.json").write_text(_json.dumps(data))
    assert ws.active_workspace_path() is None


def test_workspaces_root_env_override(monkeypatch, tmp_path):
    target = tmp_path / "elsewhere"
    monkeypatch.setenv("CYGOR_WORKSPACES_ROOT", str(target))
    assert ws.workspaces_root() == target


def test_clean_errors_when_no_workspace_selected(cfg, capsys):
    """`clean` with no name AND no active workspace must error out (rather
    than silently doing nothing or auto-creating something)."""
    rc = _run("clean")
    err = capsys.readouterr().err
    assert rc == 2
    assert "No workspace is selected" in err


def test_path_returns_1_when_no_workspace_selected(cfg, capfd):
    """`path` exits 1 with no output -- shell scripts get a clean failure."""
    rc = _run("path")
    captured = capfd.readouterr()
    assert rc == 1
    assert captured.out == ""


# ---------------------------------------------------------------------------
# Env-var resolution (unchanged)
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
