"""
Background task management for running scans and enumeration modules from the Web UI.
"""
import asyncio
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from enum import Enum
import json
import uuid

class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

class Task:
    """Represents a background scan or module task."""
    def __init__(self, task_id: str, task_type: str, command: List[str], output_dir: Path):
        self.task_id = task_id
        self.task_type = task_type  # "scan" or "module"
        self.command = command
        self.output_dir = output_dir
        self.status = TaskStatus.PENDING
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.process: Optional[asyncio.subprocess.Process] = None
        self.output_lines: List[str] = []
        self.error_lines: List[str] = []
        self.exit_code: Optional[int] = None

    def to_dict(self) -> Dict:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "command": " ".join(self.command),
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "exit_code": self.exit_code,
            "output_lines": len(self.output_lines),
            "error_lines": len(self.error_lines),
        }

class TaskManager:
    """Manages background tasks for scans and modules."""
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self._lock = asyncio.Lock()

    async def create_scan_task(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        discover: List[str] = None,
        scan_type: str = "top-ports",
        output_dir: str = "results"
    ) -> str:
        """Create a new scan task."""
        task_id = str(uuid.uuid4())

        # Build cygor scan command
        cmd = ["cygor", "scan"]

        if interface:
            cmd.extend(["-i", interface])

        # Add targets
        if len(targets) == 1:
            cmd.extend(["-f", targets[0]]) if os.path.exists(targets[0]) else cmd.extend(["--ips"] + targets)
        else:
            cmd.extend(["--ips"] + targets)

        if discover:
            cmd.extend(["--discover"] + discover)

        cmd.extend(["--scan-type", scan_type])
        cmd.extend(["-o", output_dir])

        task = Task(
            task_id=task_id,
            task_type="scan",
            command=cmd,
            output_dir=Path(output_dir)
        )

        async with self._lock:
            self.tasks[task_id] = task

        # Start the task in the background
        asyncio.create_task(self._run_task(task))

        return task_id

    async def create_module_task(
        self,
        module_name: str,
        targets_file: str,
        output_dir: str = "results"
    ) -> str:
        """Create a new enumeration module task."""
        task_id = str(uuid.uuid4())

        # Build cygor enum command
        module_output = os.path.join(output_dir, "cygor-enumeration-modules", module_name)
        cmd = ["cygor", "enum", module_name, "-f", targets_file, "-o", module_output]

        task = Task(
            task_id=task_id,
            task_type="module",
            command=cmd,
            output_dir=Path(module_output)
        )

        async with self._lock:
            self.tasks[task_id] = task

        # Start the task in the background
        asyncio.create_task(self._run_task(task))

        return task_id

    async def _run_task(self, task: Task):
        """Execute a task in the background."""
        try:
            task.status = TaskStatus.RUNNING
            task.started_at = datetime.utcnow()

            # Create output directory
            task.output_dir.mkdir(parents=True, exist_ok=True)

            # Run the command
            process = await asyncio.create_subprocess_exec(
                *task.command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(task.output_dir.parent)
            )

            task.process = process

            # Stream output
            async def read_stream(stream, lines_list):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode('utf-8', errors='ignore').strip()
                    lines_list.append(decoded)

            # Read stdout and stderr concurrently
            await asyncio.gather(
                read_stream(process.stdout, task.output_lines),
                read_stream(process.stderr, task.error_lines)
            )

            # Wait for process to complete
            task.exit_code = await process.wait()

            if task.exit_code == 0:
                task.status = TaskStatus.COMPLETED
            else:
                task.status = TaskStatus.FAILED

        except asyncio.CancelledError:
            task.status = TaskStatus.CANCELLED
            if task.process:
                task.process.kill()
                await task.process.wait()
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error_lines.append(f"Exception: {str(e)}")
        finally:
            task.completed_at = datetime.utcnow()

    async def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by ID."""
        async with self._lock:
            return self.tasks.get(task_id)

    async def list_tasks(self) -> List[Dict]:
        """List all tasks."""
        async with self._lock:
            return [task.to_dict() for task in self.tasks.values()]

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task."""
        async with self._lock:
            task = self.tasks.get(task_id)
            if not task or task.status != TaskStatus.RUNNING:
                return False

            if task.process:
                task.process.kill()
                task.status = TaskStatus.CANCELLED
                return True
            return False

    async def delete_task(self, task_id: str) -> bool:
        """Delete a task from the manager."""
        async with self._lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                # Don't delete running tasks
                if task.status == TaskStatus.RUNNING:
                    return False
                del self.tasks[task_id]
                return True
            return False

# Global task manager instance
task_manager = TaskManager()
