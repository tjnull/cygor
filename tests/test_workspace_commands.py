"""Tests for the improved `cygor workspace` subcommands.

Covers the behavioural changes: unified active/default, smoother activation
(init auto-activates the first workspace; switch auto-registers a path), the
legacy deprecation aliases, and the new `clean` command.
"""
import json
import time
from pathlib import Path

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
    args = ws.build_parser().parse_args(list(argv))
    return args.func(args)


def _active(cfg_dir):
    data = json.loads((cfg_dir / "config.json").read_text())
    return data.get("active_workspace")


def _config(cfg_dir):
    return json.loads((cfg_dir / "config.json").read_text())


def test_init_auto_activates_first_workspace(cfg, tmp_path):
    rc = _run("init", str(tmp_path / "alpha"))
    assert rc == 0
    assert _active(cfg) == "alpha"
    # legacy default_workspace key is not written
    assert "default_workspace" not in _config(cfg)


def test_init_does_not_steal_activation(cfg, tmp_path):
    _run("init", str(tmp_path / "alpha"))
    _run("init", str(tmp_path / "beta"))
    assert _active(cfg) == "alpha"  # second init must not steal active


def test_init_no_activate_flag(cfg, tmp_path):
    _run("init", str(tmp_path / "alpha"), "--no-activate")
    assert _active(cfg) is None


def test_init_default_flag_forces_activation(cfg, tmp_path):
    _run("init", str(tmp_path / "alpha"))
    _run("init", str(tmp_path / "beta"), "--default")
    assert _active(cfg) == "beta"


def test_switch_auto_registers_path(cfg, tmp_path):
    _run("init", str(tmp_path / "alpha"))
    target = tmp_path / "adhoc"
    target.mkdir()
    rc = _run("switch", str(target))
    assert rc == 0
    assert _active(cfg) == "adhoc"
    assert (target / ".cygor-workspace.json").exists()  # initialized on the fly


def test_switch_unknown_name_errors(cfg, tmp_path):
    _run("init", str(tmp_path / "alpha"))
    assert _run("switch", "does-not-exist") == 2


def test_remove_active_workspace_auto_deactivates(cfg, tmp_path):
    """Removing the active workspace should deactivate it and remove it from
    the registry — not error out. The user's files stay; the registry entry
    and 'active' pointer go away."""
    base_alpha = tmp_path / "alpha"
    base_beta = tmp_path / "beta"
    _run("init", str(base_alpha))                  # activates alpha
    _run("init", str(base_beta), "--no-activate")
    assert _active(cfg) == "alpha"
    # Remove the active workspace by name.
    assert _run("remove", "alpha") == 0
    cfg_now = _config(cfg)
    assert "alpha" not in cfg_now["workspaces"]
    assert cfg_now.get("active_workspace") is None
    # beta is untouched and still in the registry.
    assert "beta" in cfg_now["workspaces"]
    # The directory on disk MUST still exist — removal doesn't delete files.
    assert base_alpha.exists()


def test_remove_last_workspace_clears_active(cfg, tmp_path):
    """If removing the last registered workspace, the active pointer also
    goes away and the user falls back to free mode."""
    base = tmp_path / "alpha"
    _run("init", str(base))
    assert _run("remove", "alpha") == 0
    cfg_now = _config(cfg)
    assert cfg_now.get("workspaces", {}) == {}
    assert cfg_now.get("active_workspace") is None
    assert base.exists()


def test_clean_keep_last(cfg, tmp_path, capsys):
    base = tmp_path / "alpha"
    _run("init", str(base))
    nmap = base / "nmap"
    for i in range(3):
        run = nmap / f"run-{i}"
        run.mkdir()
        (run / "scan.xml").write_text("x" * 100)
        time.sleep(0.01)  # ensure distinct mtimes
    assert _run("clean", "alpha", "--keep-last", "1", "--yes") == 0
    remaining = sorted(p.name for p in nmap.iterdir())
    assert remaining == ["run-2"]  # newest kept


def test_clean_dry_run_keeps_everything(cfg, tmp_path):
    base = tmp_path / "alpha"
    _run("init", str(base))
    (base / "nmap" / "run-1").mkdir()
    (base / "nmap" / "run-1" / "scan.xml").write_text("data")
    assert _run("clean", "alpha", "--dry-run") == 0
    assert (base / "nmap" / "run-1" / "scan.xml").exists()  # untouched


def test_workspace_env_prefers_workspace(monkeypatch, tmp_path):
    monkeypatch.setenv("CYGOR_RESULTS_DIR", str(tmp_path / "legacy"))
    monkeypatch.setenv("CYGOR_WORKSPACE", str(tmp_path / "canonical"))
    assert ws.workspace_env() == str(tmp_path / "canonical")
    monkeypatch.delenv("CYGOR_WORKSPACE")
    assert ws.workspace_env() == str(tmp_path / "legacy")  # back-compat fallback
