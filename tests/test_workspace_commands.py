"""Tests for the new `cygor workspace` subcommand surface.

The surface was reworked: create / use / info / clean / remove / none / path,
with a no-subcommand dashboard view as the default. The legacy verbs (init,
switch, add, unset, current, list) were removed entirely. These tests cover
the new behaviour end-to-end: directory creation + registration + activation,
auto-activation rules, on-the-fly registration via `use`, removal that
preserves files, and clean's keep-last / dry-run modes.
"""
import io
import json
import time
from contextlib import redirect_stdout

import pytest

from cygor import workspace as ws


@pytest.fixture
def cfg(tmp_path, monkeypatch):
    """Isolated workspace config + no workspace env vars."""
    cfg_dir = tmp_path / "config" / "cygor"
    cfg_dir.mkdir(parents=True)
    monkeypatch.setattr(ws, "CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(ws, "CONFIG_FILE", cfg_dir / "config.json")
    monkeypatch.delenv("CYGOR_WORKSPACE", raising=False)
    monkeypatch.delenv("CYGOR_RESULTS_DIR", raising=False)
    return cfg_dir


def _run(*argv):
    """Drive build_parser() like the user would type the command."""
    args = ws.build_parser().parse_args(list(argv))
    if not getattr(args, "subcmd", None):
        return ws.cmd_dashboard(args)
    return args.func(args)


def _active(cfg_dir):
    return json.loads((cfg_dir / "config.json").read_text()).get("active_workspace")


def _config(cfg_dir):
    return json.loads((cfg_dir / "config.json").read_text())


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------
def test_create_auto_activates_first_workspace(cfg, tmp_path):
    rc = _run("create", str(tmp_path / "alpha"))
    assert rc == 0
    assert _active(cfg) == "alpha"
    # legacy default_workspace key is not written
    assert "default_workspace" not in _config(cfg)


def test_create_does_not_steal_activation(cfg, tmp_path):
    _run("create", str(tmp_path / "alpha"))
    _run("create", str(tmp_path / "beta"))
    assert _active(cfg) == "alpha"  # second create must not steal active


def test_create_no_activate_flag(cfg, tmp_path):
    _run("create", str(tmp_path / "alpha"), "--no-activate")
    assert _active(cfg) is None


def test_create_activate_flag_forces_activation(cfg, tmp_path):
    _run("create", str(tmp_path / "alpha"))
    _run("create", str(tmp_path / "beta"), "--activate")
    assert _active(cfg) == "beta"


def test_create_lays_out_standard_subdirs(cfg, tmp_path):
    target = tmp_path / "alpha"
    _run("create", str(target))
    # The standard layout is what makes a directory a "cygor workspace".
    for sub in ws.SUBDIRS:
        assert (target / sub).is_dir()
    assert (target / ".cygor-workspace.json").is_file()


# ---------------------------------------------------------------------------
# use (replaces switch + add)
# ---------------------------------------------------------------------------
def test_use_switches_by_name(cfg, tmp_path):
    _run("create", str(tmp_path / "alpha"))
    _run("create", str(tmp_path / "beta"), "--no-activate")
    assert _run("use", "beta") == 0
    assert _active(cfg) == "beta"


def test_use_auto_registers_a_raw_path(cfg, tmp_path):
    _run("create", str(tmp_path / "alpha"))
    target = tmp_path / "adhoc"
    target.mkdir()
    rc = _run("use", str(target))
    assert rc == 0
    assert _active(cfg) == "adhoc"
    assert (target / ".cygor-workspace.json").exists()  # initialised on the fly


def test_use_unknown_name_errors(cfg, tmp_path):
    _run("create", str(tmp_path / "alpha"))
    assert _run("use", "does-not-exist") == 2


# ---------------------------------------------------------------------------
# remove
# ---------------------------------------------------------------------------
def test_remove_active_workspace_auto_deactivates(cfg, tmp_path):
    """Removing the active workspace deactivates it and unregisters it -- not
    an error. Files stay on disk; only the registry entry + active pointer go."""
    base_alpha = tmp_path / "alpha"
    base_beta = tmp_path / "beta"
    _run("create", str(base_alpha))                  # activates alpha
    _run("create", str(base_beta), "--no-activate")
    assert _active(cfg) == "alpha"
    assert _run("remove", "alpha") == 0
    cfg_now = _config(cfg)
    assert "alpha" not in cfg_now["workspaces"]
    assert cfg_now.get("active_workspace") is None
    assert "beta" in cfg_now["workspaces"]      # untouched
    assert base_alpha.exists()                  # files preserved


def test_remove_last_workspace_clears_active(cfg, tmp_path):
    base = tmp_path / "alpha"
    _run("create", str(base))
    assert _run("remove", "alpha") == 0
    cfg_now = _config(cfg)
    assert cfg_now.get("workspaces", {}) == {}
    assert cfg_now.get("active_workspace") is None
    assert base.exists()


# ---------------------------------------------------------------------------
# none (replaces unset)
# ---------------------------------------------------------------------------
def test_none_deactivates_without_unregistering(cfg, tmp_path):
    _run("create", str(tmp_path / "alpha"))
    assert _active(cfg) == "alpha"
    assert _run("none") == 0
    cfg_now = _config(cfg)
    assert cfg_now.get("active_workspace") is None
    # Still in the registry -- only the pointer was cleared.
    assert "alpha" in cfg_now["workspaces"]


def test_none_is_idempotent(cfg):
    # No workspaces at all: 'none' must still return 0, not blow up.
    assert _run("none") == 0


# ---------------------------------------------------------------------------
# path (new scriptable accessor)
# ---------------------------------------------------------------------------
def test_path_prints_active(cfg, tmp_path, capfd):
    # 'path' writes raw bytes to fd 1 so shell substitution gets a clean
    # path even when colorama has wrapped sys.stdout -- so we need capfd
    # (file-descriptor capture), not capsys.
    base = tmp_path / "alpha"
    _run("create", str(base))
    capfd.readouterr()  # drain the create output
    rc = _run("path")
    captured = capfd.readouterr()
    assert rc == 0
    assert captured.out == f"{base}\n"
    # And no ANSI contamination -- this is the whole point of going through fd 1.
    assert "\x1b" not in captured.out


def test_path_returns_1_when_no_active(cfg, capfd):
    rc = _run("path")
    captured = capfd.readouterr()
    assert rc == 1
    assert captured.out == ""


# ---------------------------------------------------------------------------
# dashboard (no-subcommand default)
# ---------------------------------------------------------------------------
def test_dashboard_with_no_workspaces(cfg):
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = _run()  # no args at all
    out = buf.getvalue()
    assert rc == 0
    assert "Active workspace" in out
    assert "none set" in out
    # When there are no workspaces, only create + use should appear in hints.
    assert "cygor workspace create" in out
    assert "cygor workspace use" in out


def test_dashboard_with_active_workspace(cfg, tmp_path):
    _run("create", str(tmp_path / "alpha"))
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = _run()
    out = buf.getvalue()
    assert rc == 0
    assert "alpha" in out
    assert "Active workspace" in out
    assert "Commands" in out


def test_dashboard_lists_other_workspaces(cfg, tmp_path):
    _run("create", str(tmp_path / "alpha"))
    _run("create", str(tmp_path / "beta"), "--no-activate")
    buf = io.StringIO()
    with redirect_stdout(buf):
        _run()
    out = buf.getvalue()
    assert "Other workspaces (1)" in out
    assert "beta" in out


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------
def test_info_shows_subdir_breakdown(cfg, tmp_path, capsys):
    base = tmp_path / "alpha"
    _run("create", str(base))
    (base / "nmap" / "run-1").mkdir()
    (base / "nmap" / "run-1" / "scan.xml").write_text("data")
    rc = _run("info", "alpha")
    captured = capsys.readouterr()
    assert rc == 0
    assert "Subdirectories" in captured.out
    assert "nmap" in captured.out


# ---------------------------------------------------------------------------
# clean
# ---------------------------------------------------------------------------
def test_clean_keep_last(cfg, tmp_path):
    base = tmp_path / "alpha"
    _run("create", str(base))
    nmap = base / "nmap"
    for i in range(3):
        r = nmap / f"run-{i}"
        r.mkdir()
        (r / "scan.xml").write_text("x" * 100)
        time.sleep(0.01)  # ensure distinct mtimes
    assert _run("clean", "alpha", "--keep-last", "1", "--yes") == 0
    remaining = sorted(p.name for p in nmap.iterdir())
    assert remaining == ["run-2"]  # newest kept


def test_clean_dry_run_keeps_everything(cfg, tmp_path):
    base = tmp_path / "alpha"
    _run("create", str(base))
    (base / "nmap" / "run-1").mkdir()
    (base / "nmap" / "run-1" / "scan.xml").write_text("data")
    assert _run("clean", "alpha", "--dry-run") == 0
    assert (base / "nmap" / "run-1" / "scan.xml").exists()  # untouched


# ---------------------------------------------------------------------------
# Env-var resolution (unchanged behaviour; lock it in)
# ---------------------------------------------------------------------------
def test_workspace_env_prefers_workspace(monkeypatch, tmp_path):
    monkeypatch.setenv("CYGOR_RESULTS_DIR", str(tmp_path / "legacy"))
    monkeypatch.setenv("CYGOR_WORKSPACE", str(tmp_path / "canonical"))
    assert ws.workspace_env() == str(tmp_path / "canonical")
    monkeypatch.delenv("CYGOR_WORKSPACE")
    assert ws.workspace_env() == str(tmp_path / "legacy")  # back-compat fallback


# ---------------------------------------------------------------------------
# Legacy config migration -- the user's existing on-disk config must still
# work after we dropped 'default_workspace' from runtime reads.
# ---------------------------------------------------------------------------
def test_legacy_default_workspace_config_is_migrated(cfg, tmp_path):
    """A config with only 'default_workspace' (set by an older cygor) must
    still resolve and get promoted to the new active_workspace shape."""
    legacy_path = tmp_path / "legacy"
    legacy_path.mkdir()
    # Plant a valid workspace marker so the migration accepts the path.
    (legacy_path / ".cygor-workspace.json").write_text(json.dumps(
        {"workspace": str(legacy_path), "schema": 3}))
    (cfg / "config.json").write_text(json.dumps({
        "default_workspace": str(legacy_path),
    }))
    # The first lookup triggers migration. active_workspace_path() reads
    # the new shape; if migration didn't write it, we'd get None.
    assert ws.active_workspace_path() == legacy_path
