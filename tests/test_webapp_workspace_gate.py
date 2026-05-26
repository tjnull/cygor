"""Tests for the web-app workspace gating introduced when ./results was removed.

The web server starts even with no workspace configured, but any task that
produces scan output must refuse to launch until a workspace is set.
"""
import pytest

from cygor.webapp.config import _resolve_results_dir
from cygor.webapp.tasks import _resolve_task_workspace, WorkspaceNotConfiguredError


@pytest.fixture
def no_workspace(monkeypatch):
    """No env workspace and an empty config -> nothing resolves."""
    import cygor.workspace as ws
    monkeypatch.delenv("CYGOR_WORKSPACE", raising=False)
    monkeypatch.delenv("CYGOR_RESULTS_DIR", raising=False)
    monkeypatch.setattr(ws, "active_workspace_path", lambda: None)


def test_task_workspace_errors_without_workspace(no_workspace):
    with pytest.raises(WorkspaceNotConfiguredError):
        _resolve_task_workspace(None)


def test_task_workspace_uses_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CYGOR_RESULTS_DIR", str(tmp_path / "ws"))
    assert _resolve_task_workspace(None) == str((tmp_path / "ws").resolve())


def test_task_workspace_respects_explicit_dir(monkeypatch, tmp_path):
    # Even with an env workspace, an explicit non-sentinel output_dir is honored.
    monkeypatch.setenv("CYGOR_RESULTS_DIR", str(tmp_path / "ws"))
    assert _resolve_task_workspace("/explicit/out") == "/explicit/out"


def test_config_results_dir_sentinel_when_unset(no_workspace):
    path, configured = _resolve_results_dir()
    assert configured is False
    assert path.name == "_no_workspace"


def test_config_results_dir_uses_workspace(monkeypatch, tmp_path):
    monkeypatch.setenv("CYGOR_WORKSPACE", str(tmp_path / "ws"))
    path, configured = _resolve_results_dir()
    assert configured is True
    assert path == (tmp_path / "ws").resolve()
