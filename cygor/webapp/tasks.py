"""
Background task management for running scans and enumeration modules from the Web UI.
"""
import asyncio
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
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
    def __init__(self, task_id: str, task_type: str, command: List[str], output_dir: Path, is_ondemand: bool = False):
        self.task_id = task_id
        self.task_type = task_type  # "scan" or "module"
        self.command = command
        self.output_dir = output_dir
        self.is_ondemand = is_ondemand  # True if created from on-demand scanner
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
            "is_ondemand": self.is_ondemand,
            "output_dir": str(self.output_dir),
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
        ports: Optional[str] = None,
        nmap_options: Optional[str] = None,
        output_dir: str = "results",
        exclusions: Optional[List[str]] = None,
        is_ondemand: bool = False
    ) -> str:
        """Create a new scan task."""
        task_id = str(uuid.uuid4())

        # For on-demand scans, create a timestamped subdirectory
        if is_ondemand:
            timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
            output_dir = os.path.join(output_dir, "ondemand-scans", timestamp)

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

        # Add custom ports if provided
        if ports:
            cmd.extend(["--ports", ports])

        # Add custom Nmap options if provided
        if nmap_options:
            cmd.extend(["--nmap-options", nmap_options])

        # Add exclusions if provided
        if exclusions:
            cmd.extend(["--exclusions"] + exclusions)

        cmd.extend(["-o", output_dir])

        task = Task(
            task_id=task_id,
            task_type="scan",
            command=cmd,
            output_dir=Path(output_dir),
            is_ondemand=is_ondemand
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
        output_dir: str = "results",
        module_options: Dict[str, Any] = None
    ) -> str:
        """Create a new enumeration module task with support for module-specific options."""
        task_id = str(uuid.uuid4())

        # Build cygor enum command
        module_output = os.path.join(output_dir, "cygor-enumeration-modules", module_name)
        cmd = ["cygor", "enum", module_name, "-f", targets_file, "-o", module_output]

        # Add module-specific options to command
        if module_options:
            for key, value in module_options.items():
                if value is not None and value != "" and value != False:
                    # Convert key from camelCase/snake_case to CLI flag format
                    flag = f"--{key.replace('_', '-')}"

                    # Handle boolean flags (just add the flag without value)
                    if isinstance(value, bool) and value is True:
                        cmd.append(flag)
                    # Handle list/array values (add flag multiple times or join with comma)
                    elif isinstance(value, list):
                        # For list values, join with comma (e.g., --status-filter 200,301,302)
                        if value:  # Only add if list is not empty
                            cmd.extend([flag, ",".join(map(str, value))])
                    # Handle regular values
                    else:
                        cmd.extend([flag, str(value)])

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

    async def create_generic_task(
        self,
        task_name: str,
        command: List[str],
        description: str = "",
        output_dir: str = "results"
    ) -> str:
        """Create a generic task for running any command."""
        task_id = str(uuid.uuid4())

        # Use a generic output directory
        task_output = Path(output_dir) / "credrecon"

        task = Task(
            task_id=task_id,
            task_type="generic",
            command=command,
            output_dir=task_output,
            is_ondemand=True
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
            task.output_dir.mkdir(parents=True, exist_ok=True)

            process = await asyncio.create_subprocess_exec(
                *task.command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(task.output_dir.parent)
            )

            task.process = process
            start_time = datetime.utcnow()

            # --- Enhanced stream readers ---
            async def read_stream(stream, lines_list, redirect_to_output=False):
                """Read and filter process output in real time."""
                last_line = ""
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="ignore").strip()

                    # Skip empty lines
                    if not decoded:
                        continue

                    # Skip redundant carriage-return progress lines (nmap/masscan in-place updates)
                    # These lines typically repeat with small changes and clutter the output
                    if decoded == last_line:
                        continue
                    last_line = decoded

                    # Skip rate-only lines (masscan progress)
                    if decoded.startswith("rate:"):
                        continue

                    # Redirect known benign stderr lines (masscan / nmap status)
                    if redirect_to_output:
                        if (
                            decoded.startswith("Starting masscan")
                            or decoded.startswith("Initiating SYN")
                            or decoded.startswith("Scanning ")
                            or decoded.startswith("rate:")
                            or "remaining" in decoded
                            or ("done" in decoded and "rate:" in decoded)
                        ):
                            task.output_lines.append(decoded)
                        else:
                            lines_list.append(decoded)
                    else:
                        lines_list.append(decoded)

            # Read concurrently
            await asyncio.gather(
                read_stream(process.stdout, task.output_lines),
                read_stream(process.stderr, task.error_lines, redirect_to_output=True)
            )

            # Wait for completion
            task.exit_code = await process.wait()
            elapsed = datetime.utcnow() - start_time

            # Append a clean final summary if this was a scan task
            hours, remainder = divmod(int(elapsed.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            summary = (
                f"Total scan process completed in {hours} hours, "
                f"{minutes} minutes, and {seconds} seconds."
            )

            task.output_lines.append(summary)

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

    async def restore_historical_tasks(self, results_dir: str):
        """
        Restore completed tasks from the ondemand-scans directory.
        This is called on startup to populate the task list with historical on-demand scans.
        """
        ondemand_base = Path(results_dir) / "ondemand-scans"
        if not ondemand_base.exists():
            return

        async with self._lock:
            # Iterate through timestamped directories
            for scan_dir in sorted(ondemand_base.iterdir(), reverse=True):
                if not scan_dir.is_dir():
                    continue

                # Generate a task ID based on the directory name for consistency
                task_id = f"historical-{scan_dir.name}"

                # Skip if already loaded
                if task_id in self.tasks:
                    continue

                # Try to determine the scan command and timing from the directory
                nmap_dir = scan_dir / "nmap"
                if not nmap_dir.exists():
                    continue

                # Create a historical task entry
                # We'll mark it as completed and extract timing info from scan files if possible
                task = Task(
                    task_id=task_id,
                    task_type="scan",
                    command=["cygor", "scan", "-o", str(scan_dir)],  # Simplified command
                    output_dir=scan_dir,
                    is_ondemand=True
                )

                # Set status as completed (these are historical scans)
                task.status = TaskStatus.COMPLETED

                # Try to extract timing information from nmap files
                try:
                    # Parse directory name for created_at (format: YYYY-MM-DD_HH-MM-SS)
                    dir_name = scan_dir.name
                    if "_" in dir_name:
                        date_part, time_part = dir_name.split("_", 1)
                        time_part = time_part.replace("-", ":")
                        timestamp_str = f"{date_part} {time_part}"
                        from datetime import datetime
                        task.created_at = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                        task.started_at = task.created_at
                except Exception:
                    # If we can't parse the directory name, use current time as fallback
                    pass

                # Try to find completion time from nmap files
                try:
                    import xml.etree.ElementTree as ET
                    for xml_file in nmap_dir.rglob("*.xml"):
                        try:
                            tree = ET.parse(xml_file)
                            root = tree.getroot()

                            # Get start time
                            if root.get('start'):
                                task.started_at = datetime.fromtimestamp(int(root.get('start')))

                            # Look for runstats to get end time
                            runstats = root.find('.//runstats/finished')
                            if runstats is not None and runstats.get('time'):
                                task.completed_at = datetime.fromtimestamp(int(runstats.get('time')))
                                task.exit_code = 0  # Assume success if we have a complete XML file
                                break
                        except Exception:
                            continue
                except Exception:
                    pass

                # If we didn't find completion time, use the directory's modification time
                if not task.completed_at:
                    try:
                        task.completed_at = datetime.fromtimestamp(scan_dir.stat().st_mtime)
                        task.exit_code = 0
                    except Exception:
                        task.completed_at = task.started_at

                # Read actual nmap output files to populate task output
                try:
                    # Look for .nmap files (nmap normal output format)
                    nmap_files = list(nmap_dir.rglob("*.nmap"))
                    if nmap_files:
                        # Sort by modification time to get the most recent
                        nmap_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

                        for nmap_file in nmap_files:
                            try:
                                content = nmap_file.read_text(errors='ignore')
                                lines = content.splitlines()

                                # Add header for this file
                                task.output_lines.append(f"=== Output from {nmap_file.name} ===")

                                # Add all non-empty lines
                                for line in lines:
                                    stripped = line.strip()
                                    if stripped:
                                        task.output_lines.append(stripped)

                                task.output_lines.append("")  # Blank line separator
                            except Exception as e:
                                task.output_lines.append(f"[!] Could not read {nmap_file.name}: {str(e)}")

                    # Also check for any .gnmap files if no .nmap files found
                    if not nmap_files:
                        gnmap_files = list(nmap_dir.rglob("*.gnmap"))
                        if gnmap_files:
                            gnmap_files.sort(key=lambda f: f.stat().st_mtime, reverse=True)

                            for gnmap_file in gnmap_files:
                                try:
                                    content = gnmap_file.read_text(errors='ignore')
                                    lines = content.splitlines()

                                    task.output_lines.append(f"=== Output from {gnmap_file.name} ===")

                                    for line in lines:
                                        stripped = line.strip()
                                        if stripped:
                                            task.output_lines.append(stripped)

                                    task.output_lines.append("")
                                except Exception as e:
                                    task.output_lines.append(f"[!] Could not read {gnmap_file.name}: {str(e)}")

                    # If still no output found, add a notice
                    if not task.output_lines:
                        task.output_lines.append("[i] No nmap output files found in scan directory")

                except Exception as e:
                    task.output_lines.append(f"[!] Error reading scan output: {str(e)}")

                # Add a summary line at the end
                if task.started_at and task.completed_at:
                    elapsed = (task.completed_at - task.started_at).total_seconds()
                    hours, remainder = divmod(int(elapsed), 3600)
                    minutes, seconds = divmod(remainder, 60)
                    summary = f"Scan completed in {hours} hours, {minutes} minutes, and {seconds} seconds."
                    task.output_lines.append(summary)

                self.tasks[task_id] = task

# Global task manager instance
task_manager = TaskManager()
