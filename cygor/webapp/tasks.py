"""
Background task management for running scans and enumeration modules from the Web UI.
"""
import asyncio
import logging
import os
import signal
import subprocess
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from enum import Enum
import json
import uuid


class ModuleAlreadyRunningError(Exception):
    """Raised when a task is requested for a module slug that already has a running task."""
    def __init__(self, module_name: str, existing_task_id: str):
        self.module_name = module_name
        self.existing_task_id = existing_task_id
        super().__init__(f"Task for module '{module_name}' is already running (task {existing_task_id})")


class WorkspaceNotConfiguredError(Exception):
    """Raised when a scan/module/parse task is launched with no workspace configured."""


def _resolve_task_workspace(output_dir: Optional[str]) -> str:
    """Resolve and validate the workspace for a launching task.

    An explicit, real output_dir is the caller's workspace choice and is honored
    as-is. Otherwise (no output_dir, or the unconfigured-at-startup sentinel) the
    active workspace is freshly resolved -- so a workspace set after the server
    started still enables scans without a restart -- and
    WorkspaceNotConfiguredError is raised when nothing is configured.
    """
    from cygor.workspace import resolve_workspace
    from cygor.webapp.config import settings

    is_sentinel = (
        not settings.WORKSPACE_CONFIGURED and str(output_dir) == str(settings.RESULTS_DIR)
    )
    if output_dir and not is_sentinel:
        return str(output_dir)

    ws = resolve_workspace()
    if ws is None:
        raise WorkspaceNotConfiguredError(
            "No workspace configured. Set one in Settings > Workspaces, or start "
            "the server with --workspace PATH, before running scans."
        )
    return str(ws)

# Max output lines kept in memory per task (ring buffer). Tuned high so
# parallel `nmap -p-` runs across 20+ hosts don't fall off the back of the
# buffer mid-scan. The ``CountingDeque.total_appended`` counter below is the
# real fix for long-running tasks — even if the deque rotates, the UI can
# tell from the counter that new lines have arrived.
MAX_OUTPUT_LINES = 100_000

logger = logging.getLogger(__name__)


class CountingDeque(deque):
    """``deque`` with a monotonic counter that survives rotation.

    Existing call sites use ``task.output_lines.append(line)`` directly, so
    we wire the counter into the deque itself instead of forcing every
    caller through a helper. ``total_appended`` is the absolute number of
    items ever appended — it does NOT shrink when the bounded buffer drops
    old entries. The HTTP output endpoint reports this value so the UI can
    detect new lines via the counter rather than ``len()`` (which caps at
    ``maxlen`` and stops growing).
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.total_appended: int = 0

    def append(self, item):
        super().append(item)
        self.total_appended += 1

    def appendleft(self, item):
        super().appendleft(item)
        self.total_appended += 1

    def extend(self, iterable):
        items = list(iterable)
        super().extend(items)
        self.total_appended += len(items)

    def extendleft(self, iterable):
        items = list(iterable)
        super().extendleft(items)
        self.total_appended += len(items)

class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# Valid state transitions — prevents invalid jumps like COMPLETED -> RUNNING
VALID_TRANSITIONS: Dict[str, set] = {
    TaskStatus.PENDING:   {TaskStatus.RUNNING, TaskStatus.CANCELLED},
    TaskStatus.RUNNING:   {TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED},
    TaskStatus.COMPLETED: set(),  # terminal
    TaskStatus.FAILED:    set(),  # terminal
    TaskStatus.CANCELLED: set(),  # terminal
}


def validate_transition(current: TaskStatus, target: TaskStatus) -> bool:
    """Return True if *current* -> *target* is a legal state transition."""
    return target in VALID_TRANSITIONS.get(current, set())


class Task:
    """Represents a background scan or module task."""
    def __init__(self, task_id: str, task_type: str, command: List[str], output_dir: Path, is_ondemand: bool = False, username: Optional[str] = None, user_id: Optional[int] = None, sudo_password: Optional[str] = None, description: Optional[str] = None):
        self.task_id = task_id
        self.task_type = task_type  # "scan", "module", "enrich", "credrecon", "parse", etc.
        self.command = command
        self.output_dir = output_dir
        self.is_ondemand = is_ondemand  # True if created from on-demand scanner
        self.username = username  # Username who created the task
        self.user_id = user_id  # User ID who created the task
        self.sudo_password = sudo_password  # Sudo password for privileged operations
        self.description = description  # Human-readable description of the task
        self.status = TaskStatus.PENDING
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.process: Optional[asyncio.subprocess.Process] = None
        # Bounded line buffer — drops old lines once ``MAX_OUTPUT_LINES`` is
        # reached. ``CountingDeque`` keeps a monotonic ``total_appended``
        # counter so the API can tell the UI "you've fallen behind, reset"
        # even after the deque rotates. Without this, ``len(output_lines)``
        # caps at ``MAX_OUTPUT_LINES`` forever and the UI thinks output
        # stopped flowing on long-running scans.
        self.output_lines: CountingDeque = CountingDeque(maxlen=MAX_OUTPUT_LINES)
        self.error_lines: CountingDeque = CountingDeque(maxlen=MAX_OUTPUT_LINES)
        # File handles for streaming stdout/stderr to disk during the run.
        # The in-memory ring buffer above caps at MAX_OUTPUT_LINES so the
        # UI can stream without unbounded growth, but the on-disk sidecars
        # MUST capture every line for long scans -- a 200k-line nmap -p-
        # output would otherwise lose its first 100k. These are opened by
        # _run_task() once output_dir is created.
        self._stdout_fh = None
        self._stderr_fh = None
        self.exit_code: Optional[int] = None
        self.last_output_at: Optional[datetime] = None  # Watchdog: last time output was produced
        # True for any task whose ``command`` carries enough args to re-execute
        # the same scan. Set to False when ``restore_historical_tasks`` rebuilds
        # a Task from disk without finding a ``cygor-task.json`` sidecar — in
        # that case the original CLI args are unrecoverable and a "Restart"
        # would only run ``cygor scan -o /path`` (no targets).
        self.restartable: bool = True

    def set_status(self, target: TaskStatus) -> bool:
        """Set status with transition validation. Returns False if transition is invalid."""
        if not validate_transition(self.status, target):
            logger.warning(
                f"Task {self.task_id}: invalid transition {self.status.value} -> {target.value}"
            )
            return False
        self.status = target
        return True

    def to_dict(self) -> Dict:
        return {
            "task_id": self.task_id,
            "task_type": self.task_type,
            "command": " ".join(self.command),
            "description": self.description,
            "status": self.status.value,
            "is_ondemand": self.is_ondemand,
            "output_dir": str(self.output_dir),
            "username": self.username,
            "user_id": self.user_id,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "exit_code": self.exit_code,
            "output_lines": len(self.output_lines),
            "error_lines": len(self.error_lines),
            "restartable": self.restartable,
        }

class TaskManager:
    """Manages background tasks for scans and modules."""
    def __init__(self):
        self.tasks: Dict[str, Task] = {}
        self._lock = asyncio.Lock()
        self._completion_callbacks: Dict[str, List[callable]] = {}  # task_id -> list of callbacks

    def register_completion_callback(self, task_id: str, callback: callable):
        """Register a callback to be called when a task completes."""
        if task_id not in self._completion_callbacks:
            self._completion_callbacks[task_id] = []
        self._completion_callbacks[task_id].append(callback)

    async def _notify_completion(self, task: Task):
        """Notify registered callbacks that a task has completed."""
        if task.task_id in self._completion_callbacks:
            for callback in self._completion_callbacks[task.task_id]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(task)
                    else:
                        callback(task)
                except Exception as e:
                    logger.error(f"Error in completion callback for task {task.task_id}: {e}")
            del self._completion_callbacks[task.task_id]

        # Fire notification events
        try:
            from .notifications import get_dispatcher
            dispatcher = get_dispatcher()
            if dispatcher:
                event_type = "scan_completed" if task.status == TaskStatus.COMPLETED else "scan_failed"
                duration = None
                if task.started_at and task.completed_at:
                    duration = (task.completed_at - task.started_at).total_seconds()
                await dispatcher.dispatch_event(event_type, {
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "status": task.status.value,
                    "exit_code": task.exit_code,
                    "duration": duration,
                    "description": task.description,
                })
        except Exception as e:
            logger.debug(f"Notification dispatch error for task {task.task_id}: {e}")

    async def create_scan_task(
        self,
        targets: List[str],
        interface: Optional[str] = None,
        discover: List[str] = None,
        scan_type: str = "top-ports",
        ports: Optional[str] = None,
        nmap_options: Optional[str] = None,
        output_dir: Optional[str] = None,
        exclusions: Optional[List[str]] = None,
        is_ondemand: bool = False,
        username: Optional[str] = None,
        user_id: Optional[int] = None,
        sudo_password: Optional[str] = None,
        discover_only: bool = False,
        fingerprint: bool = False,
        masscan_ports: Optional[str] = None,
        naabu_ports: Optional[str] = None,
        processes: int = 10,
        nmap_source: str = "merge",
        sync_fp: bool = False,
        task_id: Optional[str] = None
    ) -> str:
        """Create a new scan task."""
        output_dir = _resolve_task_workspace(output_dir)
        if not task_id:
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

        # Add discovery tool-specific ports
        if masscan_ports:
            cmd.extend(["--masscan-ports", masscan_ports])
        if naabu_ports:
            cmd.extend(["--naabu-ports", naabu_ports])

        # If discover-only mode, add the flag and skip scan-type
        if discover_only:
            cmd.append("--discover-only")
        else:
            # Only add scan-type if not in discover-only mode
            cmd.extend(["--scan-type", scan_type])

            # Add custom ports if provided
            if ports:
                cmd.extend(["--ports", ports])

            # Add custom Nmap options if provided
            if nmap_options:
                cmd.extend(["--nmap-options", nmap_options])

            # Add Nmap source if not default
            if nmap_source and nmap_source != "merge":
                cmd.extend(["--nmap-source", nmap_source])

            # Add parallel processes if not the default (matches scan.py default)
            if processes and processes != 10:
                cmd.extend(["--processes", str(processes)])

        # Add exclusions if provided
        if exclusions:
            cmd.extend(["--exclusions"] + exclusions)

        # Add fingerprint flag if enabled
        if fingerprint:
            cmd.append("--fingerprint")

        # Add sync-fp flag if enabled
        if sync_fp:
            cmd.append("--sync-fp")

        cmd.extend(["-o", output_dir])

        task = Task(
            task_id=task_id,
            task_type="scan",
            command=cmd,
            output_dir=Path(output_dir),
            is_ondemand=is_ondemand,
            username=username,
            user_id=user_id,
            sudo_password=sudo_password
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
        output_dir: Optional[str] = None,
        module_options: Dict[str, Any] = None,
        username: Optional[str] = None,
        user_id: Optional[int] = None,
        sudo_password: Optional[str] = None,
        task_id: Optional[str] = None
    ) -> str:
        """Create a new enumeration module task with support for module-specific options."""
        output_dir = _resolve_task_workspace(output_dir)
        if not task_id:
            task_id = str(uuid.uuid4())

        # Work on a copy to avoid mutating the caller's dict
        opts = dict(module_options) if module_options else {}

        # Build cygor enum command
        module_output = os.path.join(output_dir, "cygor-enumeration-modules", module_name)
        cmd = ["cygor", "enum", module_name]

        # Handle positional arguments that must come before flags
        if module_name == "lockon":
            # Lockon requires 'protocol' as a positional arg (not --protocol flag)
            cmd.append(opts.pop("protocol", "web"))

        # smbexplorer and nfsexplorer use -i/--input-file; lockon uses -f/--file
        if module_name in ("smbexplorer", "nfsexplorer"):
            cmd.extend(["-i", targets_file, "-o", module_output])
        else:
            cmd.extend(["-f", targets_file, "-o", module_output])

        # Handle status_filter specially for lockon - it uses nargs="+" (space-separated)
        if module_name == "lockon" and "status_filter" in opts:
            status_val = opts.pop("status_filter")
            if status_val:
                codes = [c.strip() for c in str(status_val).split(",") if c.strip()]
                if codes:
                    cmd.append("--status-filter")
                    cmd.extend(codes)

        # Map module-config option names to their actual CLI flags where they differ
        # from the generic snake_case -> --kebab-case conversion
        OPTION_FLAG_MAP = {
            "smbexplorer": {
                "ntlm_hash": "-H",        # CLI uses -H/--hashes, not --ntlm-hash
                "use_kerberos": "-k",      # CLI uses -k/--kerberos, not --use-kerberos
            },
        }
        flag_overrides = OPTION_FLAG_MAP.get(module_name, {})

        # Also check plugin-defined option_flags from ModuleSpec (for community plugins)
        if not flag_overrides:
            try:
                from ..module_loader import discover_modules
                for spec in discover_modules():
                    if spec.slug == module_name and spec.option_flags:
                        flag_overrides = spec.option_flags
                        break
            except Exception:
                pass

        # Add module-specific options to command
        for key, value in opts.items():
            if value is not None and value != "" and value is not False:
                # Use override flag if one exists, otherwise convert snake_case to --kebab-case
                flag = flag_overrides.get(key, f"--{key.replace('_', '-')}")

                # Handle boolean flags (just add the flag without value)
                if isinstance(value, bool) and value is True:
                    cmd.append(flag)
                # Handle list/array values (add flag multiple times or join with comma)
                elif isinstance(value, list):
                    # For list values, join with comma (e.g., --aux-gids 100,1000)
                    if value:  # Only add if list is not empty
                        cmd.extend([flag, ",".join(map(str, value))])
                # Handle regular values
                else:
                    cmd.extend([flag, str(value)])

        # Scheduled tasks pass task_id with "sched-" prefix; web API tasks don't
        task = Task(
            task_id=task_id,
            task_type="module",
            command=cmd,
            output_dir=Path(module_output),
            is_ondemand=not task_id.startswith("sched-"),
            username=username,
            user_id=user_id,
            sudo_password=sudo_password
        )
        # Stash the slug + workspace root for downstream uses (concurrency
        # check, env propagation). Plain attribute assignment is fine — Task
        # is a dataclass-like holder.
        task.module_name = module_name
        task.workspace_root = output_dir

        async with self._lock:
            # Refuse to start a second task for the same module slug while
            # another is running. Two concurrent runs would race on
            # cygor-result.json in the canonical output directory and the
            # second writer would overwrite the first's output mid-stream.
            for existing_id, existing in self.tasks.items():
                if existing_id == task_id:
                    continue
                if existing.status != TaskStatus.RUNNING:
                    continue
                if getattr(existing, "module_name", None) == module_name:
                    raise ModuleAlreadyRunningError(module_name, existing_id)
            self.tasks[task_id] = task

        # Start the task in the background
        asyncio.create_task(self._run_task(task))

        return task_id

    async def create_generic_task(
        self,
        task_name: str,
        command: List[str],
        description: str = "",
        output_dir: Optional[str] = None,
        username: Optional[str] = None,
        user_id: Optional[int] = None,
        sudo_password: Optional[str] = None
    ) -> str:
        """Create a generic task for running any command.

        Args:
            task_name: The task type identifier (e.g., 'enrich', 'credrecon', 'parse')
            command: The command to execute
            description: Human-readable description of the task
            output_dir: Directory for task output
            username: Username who created the task
            user_id: User ID who created the task
            sudo_password: Sudo password for privileged operations
        """
        output_dir = _resolve_task_workspace(output_dir)
        task_id = str(uuid.uuid4())

        # Use task_name as the subdirectory for task-specific output
        task_output = Path(output_dir)

        task = Task(
            task_id=task_id,
            task_type=task_name,  # Use task_name as the task_type for proper filtering
            command=command,
            output_dir=task_output,
            is_ondemand=True,
            username=username,
            user_id=user_id,
            sudo_password=sudo_password,
            description=description
        )

        async with self._lock:
            self.tasks[task_id] = task

        # Start the task in the background
        asyncio.create_task(self._run_task(task))

        return task_id

    async def _run_task(self, task: Task):
        """Execute a task in the background."""
        logger.info(f"Starting task {task.task_id} ({task.task_type}): {' '.join(task.command)}")
        try:
            task.set_status(TaskStatus.RUNNING)
            task.started_at = datetime.utcnow()
            task.output_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Task {task.task_id} output directory created: {task.output_dir}")

            # Persist enough metadata to re-run this exact task after a server
            # restart. Without this sidecar, ``restore_historical_tasks`` can
            # only reconstruct a stub command (``cygor scan -o /path``) and
            # the Restart button produces a "No hosts specified" no-op.
            try:
                import json as _json
                sidecar = task.output_dir / "cygor-task.json"
                sidecar.write_text(_json.dumps({
                    "task_id": task.task_id,
                    "task_type": task.task_type,
                    "command": list(task.command),
                    "is_ondemand": task.is_ondemand,
                    "description": task.description,
                    "created_at": task.created_at.isoformat() + "Z",
                }, indent=2))
            except Exception as e:
                logger.warning(f"Task {task.task_id}: could not write cygor-task.json sidecar: {e}")

            # Check if we need sudo for this command
            # Scans typically require elevated privileges
            needs_sudo = any(cmd in task.command for cmd in ['scan'])

            # Check if we're already running as root
            try:
                import os as os_check
                is_root = os_check.geteuid() == 0
            except (AttributeError, OSError):
                is_root = False

            # Check if tools have Linux capabilities set (no sudo needed)
            tools_have_caps = False
            if needs_sudo and not is_root:
                try:
                    from cygor.privileges import get_privilege_status
                    priv_status = get_privilege_status()
                    installed_tools = [t for t in priv_status.get("tools", []) if t["installed"]]
                    tools_have_caps = all(t.get("has_caps") for t in installed_tools) if installed_tools else False
                    if tools_have_caps:
                        logger.info("Scan tools have Linux capabilities set — running without sudo")
                        needs_sudo = False
                except Exception as e:
                    logger.debug(f"Could not check tool capabilities: {e}")

            # Prepare the command and environment
            command = task.command
            env = os.environ.copy()

            # Force unbuffered Python stdout/stderr in the child so the live
            # task console actually streams output instead of waiting for
            # 4–8 KB block buffers to fill. Without this, parallel scans
            # (e.g. nmap -p- across many hosts) appear frozen because each
            # short-running subprocess's output sits in the parent
            # ``cygor``'s pipe buffer until the whole batch finishes.
            env['PYTHONUNBUFFERED'] = '1'

            # Forward the active workspace explicitly so modules/plugins that
            # read CYGOR_WORKSPACE (e.g. CygorModule._get_default_output_dir)
            # write to the correct directory even when the parent process
            # didn't set it itself.
            workspace_root = getattr(task, "workspace_root", None)
            if workspace_root and not env.get("CYGOR_WORKSPACE"):
                env["CYGOR_WORKSPACE"] = str(workspace_root)

            # Add SOCKS proxy environment if jumpbox tunnel is active
            try:
                from cygor.proxy_config import format_socks_proxy_for_subprocess, is_jumpbox_routing_active
                proxy_env = format_socks_proxy_for_subprocess()
                if proxy_env:
                    env.update(proxy_env)
                    logger.info("Task will route through jumpbox (SOCKS proxy env set)")
            except ImportError:
                pass  # Proxy config not available - run normally

            if needs_sudo and not is_root:
                # Set CYGOR_NO_SUDO=1 to prevent the cygor CLI from trying to re-exec with sudo
                env['CYGOR_NO_SUDO'] = '1'

                # Convert 'cygor' command to 'python -m cygor.cli' for sudo compatibility
                # This avoids PATH issues since we use the full python interpreter path
                import sys
                if command and command[0] == 'cygor':
                    # Replace 'cygor <subcommand>' with 'python -m cygor.cli <subcommand>'
                    python_path = sys.executable
                    command = [python_path, '-m', 'cygor.cli'] + command[1:]
                    logger.debug(f"Converted command to use python module: {command[:4]}...")

                # Use sudo -n (non-interactive) with -E to preserve environment
                # The sudo timestamp should be kept alive by the background refresh task
                # started with --sudo-auth
                if os.environ.get('CYGOR_SUDO_VALIDATED') == '1':
                    # Credentials should be cached, use non-interactive sudo
                    command = ['sudo', '-n', '-E'] + command
                    logger.debug("Using cached sudo credentials (non-interactive mode)")
                else:
                    # No cached credentials - still try but warn user
                    command = ['sudo', '-n', '-E'] + command
                    logger.warning("No sudo credentials cached - scan may fail. Run 'sudo cygor setup-privileges' or authenticate via Settings > Scan Privileges.")

            # start_new_session=True puts the child in its own process group so
            # that cancel_task() can SIGKILL the entire tree (including any
            # nmap/curl subprocesses the plugin launches) instead of leaking
            # orphan children.
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(task.output_dir.parent),
                env=env,
                start_new_session=True,
            )

            task.process = process
            start_time = datetime.utcnow()

            # Open the sidecar files for streaming. The in-memory deques
            # cap at MAX_OUTPUT_LINES so the UI doesn't blow up RAM on
            # long scans, but if we only wrote the deque contents at end
            # of run (the old behaviour), anything beyond 100k lines was
            # silently dropped from stdout.txt. Streaming straight to disk
            # captures everything. Best-effort: if the open fails we still
            # populate the in-memory deque and the legacy fallback in
            # _save_output_to_disk catches anything left.
            try:
                task._stdout_fh = open(task.output_dir / "stdout.txt", "w", encoding="utf-8")
                task._stderr_fh = open(task.output_dir / "stderr.txt", "w", encoding="utf-8")
            except Exception as e:
                logger.warning(f"Task {task.task_id}: could not open sidecar files: {e}")
                task._stdout_fh = task._stderr_fh = None

            def _persist(line: str, target_stream: str) -> None:
                """Append `line` to the matching sidecar file and flush so the
                bytes survive a process kill. `target_stream` is 'stdout' or
                'stderr'."""
                fh = task._stdout_fh if target_stream == "stdout" else task._stderr_fh
                if fh is None:
                    return
                try:
                    fh.write(line + "\n")
                    fh.flush()
                except Exception:
                    pass  # best-effort; closed/broken handle shouldn't kill the scan

            # --- Enhanced stream readers ---
            async def read_stream(stream, lines_list, redirect_to_output=False):
                """Read and filter process output in real time."""
                last_line = ""
                # 'stdout' lines coming through stderr after redirection still
                # belong in stdout.txt -- track which sidecar each line lands in.
                target = "stderr" if redirect_to_output else "stdout"
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode("utf-8", errors="ignore").strip()

                    # Skip empty lines
                    if not decoded:
                        continue

                    task.last_output_at = datetime.utcnow()

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
                            _persist(decoded, "stdout")
                        else:
                            lines_list.append(decoded)
                            _persist(decoded, "stderr")
                    else:
                        lines_list.append(decoded)
                        _persist(decoded, target)

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
            # Stream the summary line to disk too, so the sidecar matches
            # what the UI's output buffer shows.
            if task._stdout_fh is not None:
                try:
                    task._stdout_fh.write(summary + "\n")
                    task._stdout_fh.flush()
                except Exception:
                    pass

            if task.exit_code == 0:
                task.set_status(TaskStatus.COMPLETED)
                # Refresh the findings index after a successful enumeration so
                # per-host next steps and triage reflect the new results. Best
                # effort: never let a findings hiccup affect the task outcome.
                if getattr(task, "task_type", None) == "module":
                    try:
                        from cygor.webapp.findings import ingest_findings_safe
                        # Always refresh from the active workspace the web UI
                        # serves -- ingest does a full replace, so deriving the
                        # path from a scheduled run's isolated timestamped output
                        # dir would wipe the main findings index. Fall back to the
                        # output-dir-derived workspace only if no env is set.
                        ws = (os.environ.get("CYGOR_WORKSPACE")
                              or os.environ.get("CYGOR_RESULTS_DIR")
                              or os.environ.get("CYGOR_LOAD_DIR") or "")
                        if not ws:
                            ws = str(getattr(task, "output_dir", "") or "")
                            if "cygor-enumeration-modules" in ws:
                                ws = ws.split("cygor-enumeration-modules")[0].rstrip("/")
                        if ws:
                            await ingest_findings_safe(ws)
                    except Exception:
                        pass
            else:
                task.set_status(TaskStatus.FAILED)
                # Check for permission-related errors and add helpful guidance
                all_output = " ".join(list(task.error_lines) + list(task.output_lines)[-10:]).lower()
                permission_indicators = [
                    "permission denied", "operation not permitted",
                    "requires root", "requires elevated",
                    "sudo:", "must be run as root",
                    "socket: operation not permitted",
                    "failed to open raw socket",
                ]
                if any(ind in all_output for ind in permission_indicators):
                    task.error_lines.append("")
                    task.error_lines.append("--- Cygor Privilege Hint ---")
                    task.error_lines.append("This scan failed due to insufficient privileges.")
                    task.error_lines.append("To fix this permanently, run from your terminal:")
                    task.error_lines.append("  sudo cygor setup-privileges")
                    task.error_lines.append("Or authenticate temporarily via Settings > Scan Privileges in the web UI.")
                    logger.warning(f"Task {task.task_id} failed due to permission issues")

        except asyncio.CancelledError:
            task.set_status(TaskStatus.CANCELLED)
            logger.info(f"Task {task.task_id} was cancelled")
            if task.process:
                task.process.kill()
                await task.process.wait()
        except Exception as e:
            if task.status != TaskStatus.FAILED:
                task.set_status(TaskStatus.FAILED)
            task.error_lines.append(f"Exception: {str(e)}")
            logger.error(f"Task {task.task_id} failed with exception: {e}", exc_info=True)
        finally:
            task.completed_at = datetime.utcnow()
            logger.info(f"Task {task.task_id} finished with status: {task.status.value}, exit_code: {task.exit_code}")
            # Close the streaming sidecar handles before the fallback write
            # so the fallback can re-open if needed.
            for attr in ("_stdout_fh", "_stderr_fh"):
                fh = getattr(task, attr, None)
                if fh is not None:
                    try:
                        fh.close()
                    except Exception:
                        pass
                    setattr(task, attr, None)
            # Fallback: if streaming-to-disk never started (e.g. setup failed
            # before the open()), flush whatever's still in the deque so we
            # don't lose the small early lines completely. When streaming
            # worked, the sidecar files already exist with the FULL output
            # (including anything past MAX_OUTPUT_LINES) -- don't overwrite.
            self._save_output_to_disk(task)
            # Notify any registered callbacks that the task has completed
            await self._notify_completion(task)

    def _save_output_to_disk(self, task: "Task"):
        """Fallback persistence: dump the in-memory deque only when the
        streaming sidecars don't already exist on disk.

        During a normal run, _run_task() streams every line to
        ``stdout.txt`` / ``stderr.txt`` directly, capturing the full output
        even beyond MAX_OUTPUT_LINES. This method is the safety net for
        runs where opening the sidecar files failed -- in that case the
        bounded deque is all we have, and a truncated record is better
        than nothing.
        """
        try:
            if not task.output_dir or not task.output_dir.exists():
                return
            stdout_path = task.output_dir / "stdout.txt"
            stderr_path = task.output_dir / "stderr.txt"
            stdout_lines = list(task.output_lines)
            stderr_lines = list(task.error_lines)
            # Only write if streaming didn't already produce these files
            # -- otherwise we'd truncate the full sidecar back down to
            # the deque window.
            if stdout_lines and not stdout_path.exists():
                stdout_path.write_text("\n".join(stdout_lines) + "\n")
            if stderr_lines and not stderr_path.exists():
                stderr_path.write_text("\n".join(stderr_lines) + "\n")
        except Exception as e:
            logger.warning(f"Failed to save output to disk for task {task.task_id}: {e}")

    async def get_task(self, task_id: str) -> Optional[Task]:
        """Get a task by ID."""
        async with self._lock:
            return self.tasks.get(task_id)

    async def list_tasks(self, username: Optional[str] = None, user_id: Optional[int] = None, is_admin: bool = False) -> List[Dict]:
        """List all tasks. If username/user_id provided and not admin, filter to user's tasks only."""
        async with self._lock:
            tasks = list(self.tasks.values())
            # If user is admin, return all tasks
            if is_admin:
                return [task.to_dict() for task in tasks]
            
            # If user is not admin, filter to their tasks only
            # Also include tasks with no username/user_id (created before tracking was enabled)
            if username or user_id:
                filtered_tasks = []
                for task in tasks:
                    # Include tasks with no user info (created before tracking)
                    if task.username is None and task.user_id is None:
                        filtered_tasks.append(task)
                    # Include tasks that match the current user
                    elif (username and task.username == username) or (user_id and task.user_id == user_id):
                        filtered_tasks.append(task)
                tasks = filtered_tasks
            return [task.to_dict() for task in tasks]

    async def cancel_task(self, task_id: str) -> bool:
        """Cancel a running task."""
        async with self._lock:
            task = self.tasks.get(task_id)
            if not task or task.status != TaskStatus.RUNNING:
                return False

            if task.process:
                # Kill the entire process group so any subprocesses the task
                # spawned (nmap, curl, etc.) die too. Falls back to
                # process.kill() if we somehow can't resolve the PGID.
                pid = task.process.pid
                try:
                    pgid = os.getpgid(pid)
                    os.killpg(pgid, signal.SIGKILL)
                    logger.info(f"Killed process group {pgid} for task {task_id}")
                except (ProcessLookupError, PermissionError) as e:
                    logger.warning(f"killpg failed for task {task_id}: {e}; falling back to process.kill()")
                    try:
                        task.process.kill()
                    except Exception:
                        pass
                task.status = TaskStatus.CANCELLED
                return True
            return False

    async def delete_task(self, task_id: str) -> str:
        """Delete a task from the manager.

        Returns:
            'deleted' on success, 'running' if task is active, 'not_found' if not in dict.
        """
        async with self._lock:
            if task_id in self.tasks:
                task = self.tasks[task_id]
                # Don't delete running tasks
                if task.status == TaskStatus.RUNNING:
                    return "running"
                del self.tasks[task_id]
                return "deleted"
            return "not_found"

    async def restore_historical_tasks(self, results_dir: str) -> int:
        """
        Restore completed tasks from the ondemand-scans directory.
        This is called on startup to populate the task list with historical on-demand scans.
        Returns the number of tasks restored.
        """
        ondemand_base = Path(results_dir) / "ondemand-scans"
        if not ondemand_base.exists():
            return 0

        restored_count = 0
        async with self._lock:
            # Iterate through timestamped directories
            logger.debug(f"Restoring historical tasks from: {ondemand_base}")
            scan_dirs = [d for d in ondemand_base.iterdir() if d.is_dir()]
            logger.debug(f"Found {len(scan_dirs)} scan directories")
            for scan_dir in sorted(scan_dirs, reverse=True):
                # Generate a task ID based on the directory name for consistency
                task_id = f"historical-{scan_dir.name}"

                # Skip if already loaded
                if task_id in self.tasks:
                    logger.debug(f"Skipping already loaded task: {task_id}")
                    continue

                # Try to determine the scan command and timing from the directory
                nmap_dir = scan_dir / "nmap"
                if not nmap_dir.exists():
                    logger.debug(f"No nmap directory found in {scan_dir}, skipping")
                    continue

                logger.debug(f"Restoring task from {scan_dir.name}")

                # Try to recover the original command from the sidecar written
                # by ``_run_task``. If present, the restored task is
                # restartable with the exact same args. If absent (legacy scan
                # dirs from before the sidecar existed), fall back to a stub
                # command and flag the task as non-restartable so the UI can
                # hide the Restart button instead of producing a no-op task.
                sidecar_path = scan_dir / "cygor-task.json"
                sidecar_command: Optional[List[str]] = None
                sidecar_task_type: Optional[str] = None
                if sidecar_path.exists():
                    try:
                        import json as _json
                        sidecar_data = _json.loads(sidecar_path.read_text())
                        cmd_raw = sidecar_data.get("command")
                        if isinstance(cmd_raw, list) and cmd_raw:
                            sidecar_command = [str(x) for x in cmd_raw]
                        sidecar_task_type = sidecar_data.get("task_type")
                    except Exception as e:
                        logger.warning(f"Could not read sidecar {sidecar_path}: {e}")

                task = Task(
                    task_id=task_id,
                    task_type=sidecar_task_type or "scan",
                    command=sidecar_command or ["cygor", "scan", "-o", str(scan_dir)],
                    output_dir=scan_dir,
                    is_ondemand=True
                )
                if sidecar_command is None:
                    task.restartable = False

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
                restored_count += 1
        
        return restored_count

# Global task manager instance
task_manager = TaskManager()
