"""
Tests for the TaskManager module-task concurrency guard (gap C).

We construct a fake RUNNING task in TaskManager._tasks and assert that a
second create_module_task() call for the same module_name raises
ModuleAlreadyRunningError before launching anything.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from cygor.webapp.tasks import (
    ModuleAlreadyRunningError,
    Task,
    TaskManager,
    TaskStatus,
)


@pytest.mark.asyncio
async def test_concurrent_module_task_rejected(tmp_path):
    tm = TaskManager()
    # Plant a RUNNING task for module "demo".
    existing = Task(
        task_id="t-existing",
        task_type="module",
        command=["cygor", "enum", "demo"],
        output_dir=tmp_path,
    )
    existing.status = TaskStatus.RUNNING
    existing.module_name = "demo"
    tm.tasks["t-existing"] = existing

    # Patch _run_task so create_module_task doesn't actually try to fork
    # if the lock-check path fails open.
    with patch.object(tm, "_run_task", lambda task: asyncio.sleep(0)):
        with pytest.raises(ModuleAlreadyRunningError) as ei:
            await tm.create_module_task(
                module_name="demo",
                targets_file=str(tmp_path / "targets.txt"),
                output_dir=str(tmp_path),
            )
    assert ei.value.module_name == "demo"
    assert ei.value.existing_task_id == "t-existing"


@pytest.mark.asyncio
async def test_concurrent_different_modules_allowed(tmp_path):
    tm = TaskManager()
    # demo is running, but the user wants to run "other" — that should be fine.
    existing = Task(
        task_id="t-existing",
        task_type="module",
        command=["cygor", "enum", "demo"],
        output_dir=tmp_path,
    )
    existing.status = TaskStatus.RUNNING
    existing.module_name = "demo"
    tm.tasks["t-existing"] = existing

    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("10.10.10.5\n")

    with patch.object(tm, "_run_task", lambda task: asyncio.sleep(0)):
        # Different module name — should not raise.
        new_id = await tm.create_module_task(
            module_name="other",
            targets_file=str(targets_file),
            output_dir=str(tmp_path),
        )
    assert new_id in tm.tasks
    assert tm.tasks[new_id].module_name == "other"


@pytest.mark.asyncio
async def test_workspace_root_attached_to_task(tmp_path):
    tm = TaskManager()
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("10.10.10.5\n")
    with patch.object(tm, "_run_task", lambda task: asyncio.sleep(0)):
        task_id = await tm.create_module_task(
            module_name="demo",
            targets_file=str(targets_file),
            output_dir=str(tmp_path),
        )
    task = tm.tasks[task_id]
    # The workspace_root attribute is what _run_task uses to set
    # CYGOR_RESULTS_DIR in the subprocess env.
    assert task.workspace_root == str(tmp_path)
