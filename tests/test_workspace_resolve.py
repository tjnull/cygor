"""Tests for the central workspace resolver in cygor.workspace.

These cover the behavioural contract introduced when the implicit ./results
default was removed: scan output must come from an explicit path, an
environment variable, or a configured active workspace -- otherwise the
command errors out with guidance.
"""
import json
from pathlib import Path

import pytest

from cygor import workspace as ws


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    """Point the workspace config at a temp dir and clear workspace env vars."""
    cfg_home = tmp_path / "xdg-config"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(cfg_home))
    monkeypatch.delenv("CYGOR_WORKSPACE", raising=False)
    monkeypatch.delenv("CYGOR_RESULTS_DIR", raising=False)
    # workspace.py computes CONFIG_DIR/CONFIG_FILE at import time, so override.
    cfg_dir = cfg_home / "cygor"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(ws, "CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(ws, "CONFIG_FILE", cfg_dir / "config.json")
    return cfg_dir


def _write_config(cfg_dir: Path, data: dict) -> None:
    (cfg_dir / "config.json").write_text(json.dumps(data))


def test_resolve_explicit_wins(isolated_config, tmp_path, monkeypatch):
    monkeypatch.setenv("CYGOR_WORKSPACE", str(tmp_path / "from-env"))
    _write_config(isolated_config, {
        "workspaces": {"a": {"path": str(tmp_path / "from-config")}},
        "active_workspace": "a",
    })
    got = ws.resolve_workspace(str(tmp_path / "explicit"))
    assert got == (tmp_path / "explicit").resolve()


def test_resolve_env_over_config(isolated_config, tmp_path, monkeypatch):
    monkeypatch.setenv("CYGOR_WORKSPACE", str(tmp_path / "from-env"))
    _write_config(isolated_config, {
        "workspaces": {"a": {"path": str(tmp_path / "from-config")}},
        "active_workspace": "a",
    })
    assert ws.resolve_workspace() == (tmp_path / "from-env").resolve()


def test_resolve_results_dir_env_alias(isolated_config, tmp_path, monkeypatch):
    monkeypatch.setenv("CYGOR_RESULTS_DIR", str(tmp_path / "rd"))
    assert ws.resolve_workspace() == (tmp_path / "rd").resolve()


def test_resolve_active_workspace_config(isolated_config, tmp_path):
    _write_config(isolated_config, {
        "workspaces": {"a": {"path": str(tmp_path / "cfg-ws")}},
        "active_workspace": "a",
    })
    assert ws.resolve_workspace() == Path(str(tmp_path / "cfg-ws"))


def test_resolve_none_when_unset(isolated_config):
    assert ws.resolve_workspace() is None


def test_require_workspace_exits_when_unset(isolated_config, capsys):
    with pytest.raises(SystemExit) as exc:
        ws.require_workspace()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "No workspace specified" in err
    assert "results/" in err  # mentions the removed default


def test_require_workspace_creates_layout(isolated_config, tmp_path):
    target = tmp_path / "ws"
    got = ws.require_workspace(str(target))
    assert got == target.resolve()
    for sub in ws.SUBDIRS:
        assert (got / sub).is_dir()
    assert (got / ".cygor-workspace.json").exists()


def test_ensure_workspace_dirs_idempotent(tmp_path):
    target = tmp_path / "ws"
    ws.ensure_workspace_dirs(target)
    # second call must not raise and must preserve existing metadata
    meta = (target / ".cygor-workspace.json").read_text()
    ws.ensure_workspace_dirs(target)
    assert (target / ".cygor-workspace.json").read_text() == meta


def test_app_data_dir_non_root(monkeypatch):
    monkeypatch.setattr(ws.os, "geteuid", lambda: 1000, raising=False)
    assert ws.app_data_dir() == Path.home() / ".cygor"
    assert ws.app_log_dir() == Path.home() / ".cygor" / "logs"
