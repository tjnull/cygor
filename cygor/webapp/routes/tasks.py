"""Task-related routes: UI pages and API endpoints for scans, modules, parse, enrich, and task management."""

import asyncio
import json
import logging
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..config import settings
from ..tasks import task_manager, TaskStatus, Task, ModuleAlreadyRunningError
from ..credrecon_tasks import credrecon_manager
from .. import db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["tasks"])

templates = None


def set_templates(tmpl):
    """Set the Jinja2 templates instance for this router."""
    global templates
    templates = tmpl


# ============================================================================
# Pydantic models
# ============================================================================

class ScanRequest(BaseModel):
    targets: List[str]
    interface: Optional[str] = None
    discover: Optional[List[str]] = ["masscan"]
    scan_type: str = "top-ports"
    ports: Optional[str] = None
    nmap_options: Optional[str] = None
    output_dir: Optional[str] = None
    exclusions: Optional[List[str]] = None
    is_ondemand: bool = True  # Default to True for web UI scans
    sudo_password: Optional[str] = None  # Sudo password for privileged scans
    discover_only: bool = False  # Run discovery only, skip Nmap scanning
    fingerprint: bool = False  # Enable device fingerprinting during scan
    # New options from scan.py
    masscan_ports: Optional[str] = None  # Custom ports for Masscan discovery
    naabu_ports: Optional[str] = None  # Custom ports for Naabu discovery
    processes: int = 10  # Number of parallel Nmap scans
    nmap_source: str = "merge"  # Which discovery results to use: masscan, naabu, merge
    sync_fp: bool = False  # Sync fingerprint databases before scanning


class ModuleRequest(BaseModel):
    module_name: str
    targets_file: str
    output_dir: Optional[str] = None
    uploaded_content: Optional[str] = None  # For file uploads from web UI
    module_options: Optional[Dict[str, Any]] = {}  # Module-specific options as key-value pairs
    sudo_password: Optional[str] = None  # Sudo password for privileged operations


class TaskEditRequest(BaseModel):
    command: Optional[List[str]] = None
    output_dir: Optional[str] = None


# ============================================================================
# UI Pages
# ============================================================================

@router.get("/tasks", response_class=HTMLResponse)
async def tasks_page(request: Request):
    """Tasks dashboard page."""
    return templates.TemplateResponse(request, "tasks.html")

@router.get("/tasks/scan/new", response_class=HTMLResponse)
async def new_scan_page(request: Request):
    """New scan form page.

    Passes the effective workspace path (CYGOR_LOAD_DIR override falling back
    to RESULTS_DIR) so the Output Directory field can show the user where
    output will land if they leave the field empty.
    """
    workspace_path = os.environ.get("CYGOR_LOAD_DIR") or str(settings.RESULTS_DIR)
    return templates.TemplateResponse(request, "scan_new.html", {
        "workspace_path": workspace_path,
    })

@router.get("/tasks/parse/new", response_class=HTMLResponse)
async def new_parse_page(request: Request):
    """New parse task form page."""
    return templates.TemplateResponse(request, "parse_new.html")

@router.get("/tasks/enrich/new", response_class=HTMLResponse)
async def new_enrich_page(request: Request):
    """New enrichment task form page."""
    return templates.TemplateResponse(request, "enrich_new.html")


@router.get("/tasks/{task_id}")
async def task_detail_page(task_id: str, request: Request):
    """Resolve a task by ID and render the appropriate detail view.

    Templates across the app (scan_new, enrich_new, module_run, schedule_detail,
    schedules, tasks list) hand the user to ``/tasks/<uuid>``. Credrecon tasks
    have their own dedicated detail page, so we redirect those. Everything else
    (port_scan, parse, enrich, module, unknown) renders the generic
    ``task_detail.html`` page with a live output console.
    """
    # In-memory task manager first
    task = await task_manager.get_task(task_id)
    task_type = (task.task_type if task else "").lower()

    # Schedule history — reconstructs after restart
    if not task and not task_type:
        try:
            history_task = await get_task_from_schedule_history(task_id)
            if history_task:
                task_type = (history_task.get("task_type") or "").lower()
        except Exception:
            pass

    if task_type in {"credrecon", "credential_test"}:
        return RedirectResponse(url=f"/credrecon/scans/{task_id}", status_code=303)

    # Generic / port_scan / parse / enrich / module / unknown — render the
    # restored task detail page (templates/task_detail.html). The page extracts
    # task_id from window.location.pathname client-side and polls
    # /api/tasks/<id> + /api/tasks/<id>/output, so no template context is
    # needed here.
    return templates.TemplateResponse(request, "task_detail.html")


# ============================================================================
# Helper: gather on-demand scan times
# ============================================================================

def gather_ondemand_scan_times(results_dir: str):
    """Gather on-demand scan timestamps from the results directory.

    This is a lightweight re-implementation kept local to this module so that it
    does not depend on the monolithic ``main.py`` helper.  It scans
    ``{results_dir}/ondemand-scans`` for timestamped sub-directories and returns
    a list of dicts with at least a ``timestamp`` key.
    """
    from ..main import gather_ondemand_scan_times as _gather
    return _gather(results_dir)


# ============================================================================
# Helper: load task output from disk (schedule history fallback)
# ============================================================================

def _load_task_output_from_disk(task_id: str, history_task: dict) -> Optional[dict]:
    """Load task output from disk using the output_path stored in schedule history.
    Falls back to credrecon-specific loader for credrecon tasks."""
    task_type = history_task.get("task_type", "")

    # For credrecon tasks, use the dedicated loader
    if task_type == "credrecon":
        return _load_credrecon_output_from_disk(task_id)

    # For other task types, check the output_path directory from history
    output_path = history_task.get("output_path")
    if not output_path:
        return None

    scan_dir = Path(output_path)
    if not scan_dir.exists():
        return None

    output_text = ""
    error_text = ""

    # Look for stdout/stderr files saved by TaskManager
    for name in ("stdout.txt", "output.txt", "log.txt"):
        p = scan_dir / name
        if p.exists():
            try:
                output_text = p.read_text()
            except Exception:
                pass
            break

    for name in ("stderr.txt", "errors.txt"):
        p = scan_dir / name
        if p.exists():
            try:
                error_text = p.read_text()
            except Exception:
                pass
            break

    if not output_text and not error_text:
        return None

    output_lines = [l for l in output_text.split('\n') if l] if output_text else []
    error_lines = [l for l in error_text.split('\n') if l] if error_text else []

    return {"output": output_lines, "errors": error_lines}


def _load_credrecon_output_from_disk(scan_id: str) -> Optional[dict]:
    """Search for credrecon scan output files on disk by scan_id.
    Works for sched-, historic-, and regular scan IDs."""
    # Compute the short ID used in directory names
    if scan_id.startswith("sched-"):
        short_id = scan_id.replace("sched-", "")[:8]
    elif scan_id.startswith("historic-"):
        short_id = scan_id.replace("historic-", "")
    else:
        short_id = scan_id[:8]

    scan_dir = None
    for results_dir in [
        Path("schedule-scans") / "credrecon",
        Path(settings.RESULTS_DIR) / "schedule-scans" / "credrecon",
        Path("credrecon") / "credrecon-tasks",
        Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks",
        Path("credrecon-tasks"),
        Path(settings.RESULTS_DIR) / "credrecon-tasks",
        Path("credrecon"),
        Path(settings.RESULTS_DIR) / "credrecon",
    ]:
        if not results_dir.exists():
            continue
        for child in results_dir.iterdir():
            if child.is_dir() and short_id in child.name:
                scan_dir = child
                break
        if scan_dir:
            break

    if not scan_dir:
        return None

    output_text = ""
    error_text = ""

    # Look for output files
    for name in ("output.txt", "stdout.txt", "log.txt", "credrecon.log"):
        p = scan_dir / name
        if p.exists():
            try:
                output_text = p.read_text()
            except Exception:
                pass
            break

    # Look for error files
    for name in ("errors.txt", "stderr.txt"):
        p = scan_dir / name
        if p.exists():
            try:
                error_text = p.read_text()
            except Exception:
                pass
            break

    # If no output files, build summary from JSON results
    if not output_text:
        json_file = scan_dir / "credrecon_results.json"
        if json_file.exists():
            try:
                results = json.loads(json_file.read_text())
                if isinstance(results, list) and results:
                    output_text = f"Scan results loaded from disk ({scan_dir.name}).\n"
                    output_text += f"Total results: {len(results)}\n"
                    output_text += f"Successful: {len([r for r in results if r.get('status') == 'success'])}\n"
                    output_text += f"Failed: {len([r for r in results if r.get('status') == 'failed'])}\n"
                    output_text += f"Errors: {len([r for r in results if r.get('status') == 'error'])}\n"
                    output_text += f"\n--- Results Preview ---\n"
                    for i, result in enumerate(results[:20], 1):
                        target = result.get('ip') or result.get('target', 'N/A')
                        port = result.get('port', 'N/A')
                        protocol = result.get('protocol', 'N/A')
                        username = result.get('username', 'N/A')
                        status = result.get('status', 'N/A')
                        reason = result.get('details') or result.get('reason', 'N/A')
                        output_text += f"{i}. {target}:{port} ({protocol}) - {username} - {status} - {reason}\n"
                    if len(results) > 20:
                        output_text += f"\n... and {len(results) - 20} more results (see Results tab)\n"
            except Exception:
                output_text = f"Scan results found on disk at {scan_dir.name}. See Results tab for details."
        else:
            return None  # No JSON results either, nothing useful found

    output_lines = [l for l in output_text.split('\n') if l] if output_text else []
    error_lines = [l for l in error_text.split('\n') if l] if error_text else []

    return {
        "output": output_lines,
        "errors": error_lines
    }


# ============================================================================
# Helper: schedule info lookup
# ============================================================================

async def get_schedule_info_for_task(task_id: str) -> Optional[dict]:
    """Look up schedule information for a task by its task_id."""
    try:
        async with AsyncSession(db.engine) as session:
            from sqlalchemy import select
            from ..models import ScheduledTaskHistory, ScheduledTask

            # Find the scheduled task history entry for this task_id
            stmt = select(ScheduledTaskHistory).where(ScheduledTaskHistory.task_id == task_id)
            result = await session.execute(stmt)
            history = result.scalar_one_or_none()

            if history:
                # Get the parent scheduled task
                parent_stmt = select(ScheduledTask).where(ScheduledTask.id == history.scheduled_task_id)
                parent_result = await session.execute(parent_stmt)
                scheduled_task = parent_result.scalar_one_or_none()

                if scheduled_task:
                    return {
                        "schedule_id": scheduled_task.id,
                        "schedule_name": scheduled_task.name
                    }
    except Exception as e:
        pass
    return None


async def get_task_from_schedule_history(task_id: str) -> Optional[dict]:
    """Reconstruct task info from ScheduledTaskHistory + ScheduledTask when in-memory
    managers are empty (e.g., after server restart). Returns a dict suitable for API
    response, or None if no matching history record is found."""
    try:
        async with AsyncSession(db.engine) as session:
            from sqlalchemy import select
            from ..models import ScheduledTaskHistory, ScheduledTask

            stmt = select(ScheduledTaskHistory).where(ScheduledTaskHistory.task_id == task_id)
            result = await session.execute(stmt)
            history = result.scalar_one_or_none()

            if not history:
                return None

            # Get the parent scheduled task for config/type info
            parent_stmt = select(ScheduledTask).where(ScheduledTask.id == history.scheduled_task_id)
            parent_result = await session.execute(parent_stmt)
            scheduled_task = parent_result.scalar_one_or_none()

            if not scheduled_task:
                return None

            config = scheduled_task.config if isinstance(scheduled_task.config, dict) else {}

            return {
                "task_id": task_id,
                "task_type": scheduled_task.task_type,
                "command": config.get("command", f"{scheduled_task.task_type} (scheduled)"),
                "status": history.status if history.status != "success" else "completed",
                "created_at": history.scheduled_time.isoformat() + "Z" if history.scheduled_time else None,
                "started_at": history.started_at.isoformat() + "Z" if history.started_at else None,
                "completed_at": history.completed_at.isoformat() + "Z" if history.completed_at else None,
                "exit_code": 0 if history.status == "success" else (1 if history.status == "failed" else None),
                "output_lines": 0,
                "error_lines": 0,
                "output_path": history.output_path,
                "schedule_id": scheduled_task.id,
                "schedule_name": scheduled_task.name,
                "num_targets": len(config.get("targets", [])) if isinstance(config.get("targets"), list) else 0,
                "message": history.message,
                "error": history.error,
                "duration_seconds": history.duration_seconds,
                "_from_history": True,  # Flag to indicate this is reconstructed from history
                # The parent ScheduledTask still has the full config in the DB,
                # so the restart endpoint can re-trigger via the scheduler. Tell
                # the frontend to keep the Restart button visible.
                "restartable": True,
            }
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to lookup task {task_id} in schedule history: {e}")
    return None


# ============================================================================
# API Routes
# ============================================================================

@router.post("/api/scans")
async def create_scan(req: ScanRequest, request: Request):
    """Create a new scan task."""
    if not req.targets:
        raise HTTPException(status_code=400, detail="No targets provided")

    # Validate discovery tools
    valid_discover_tools = {"masscan", "naabu", "icmp-naabu", "icmp-fping"}
    for tool in req.discover or []:
        if tool not in valid_discover_tools:
            raise HTTPException(status_code=400, detail=f"Invalid discovery tool: {tool}. Valid options: {', '.join(sorted(valid_discover_tools))}")

    output_dir = req.output_dir or str(settings.RESULTS_DIR)

    # Get user info if task user tracking is enabled
    username = None
    user_id = None
    from ..task_config import is_task_user_tracking_enabled
    if is_task_user_tracking_enabled():
        current_user = getattr(request.state, 'current_user', None)
        if current_user:
            username = current_user.get('username')
            user_id = current_user.get('user_id')

    task_id = await task_manager.create_scan_task(
        targets=req.targets,
        interface=req.interface,
        discover=req.discover,
        scan_type=req.scan_type,
        ports=req.ports,
        nmap_options=req.nmap_options,
        output_dir=output_dir,
        exclusions=req.exclusions,
        is_ondemand=req.is_ondemand,
        username=username,
        user_id=user_id,
        sudo_password=req.sudo_password,
        discover_only=req.discover_only,
        fingerprint=req.fingerprint,
        masscan_ports=req.masscan_ports,
        naabu_ports=req.naabu_ports,
        processes=req.processes,
        nmap_source=req.nmap_source,
        sync_fp=req.sync_fp
    )

    return JSONResponse({"task_id": task_id, "status": "created"})

@router.get("/api/ondemand-scans")
async def get_ondemand_scans():
    """Get ondemand scan times for the timeline."""
    try:
        ondemand_scan_times = gather_ondemand_scan_times(settings.RESULTS_DIR)
        return JSONResponse(ondemand_scan_times)
    except Exception as e:
        logger.error(f"Error gathering ondemand scans: {e}", exc_info=True)
        return JSONResponse([])

@router.post("/api/modules")
async def create_module_task(req: ModuleRequest, request: Request):
    """Create a new enumeration module task."""
    try:
        if not req.targets_file:
            raise HTTPException(status_code=400, detail="No targets file provided")

        # Validate module_name against the actual registered modules. Without
        # this gate, the value flows into both an os.path.join (which would
        # path-traverse on `../foo`) AND a subprocess argv (which would let an
        # untrusted caller invoke any binary cygor's PATH can find by name).
        # Defense-in-depth: this webapp is meant for trusted operators, but
        # validating user-supplied strings before they reach exec is cheap.
        from cygor.module_loader import discover_modules
        known_slugs = {spec.slug for spec in discover_modules()}
        if req.module_name not in known_slugs:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown module '{req.module_name}'. "
                       f"Available: {', '.join(sorted(known_slugs))}",
            )

        targets_file_path = req.targets_file

        # Handle uploaded file content
        if req.uploaded_content:
            # Create a temporary file for uploaded content
            import tempfile
            temp_dir = Path(tempfile.gettempdir()) / "cygor-uploads"
            temp_dir.mkdir(parents=True, exist_ok=True)

            temp_file = temp_dir / f"module-targets-{uuid.uuid4()}.txt"
            temp_file.write_text(req.uploaded_content)
            targets_file_path = str(temp_file)
        else:
            # Resolve path relative to RESULTS_DIR if it's a relative path
            file_path = Path(targets_file_path)
            if not file_path.is_absolute():
                # Try resolving relative to RESULTS_DIR first
                resolved_path = Path(settings.RESULTS_DIR) / targets_file_path
                if resolved_path.exists():
                    targets_file_path = str(resolved_path)
                elif not file_path.exists():
                    raise HTTPException(status_code=400, detail=f"Targets file not found: {targets_file_path}")
            else:
                # Validate absolute path
                if not file_path.exists():
                    raise HTTPException(status_code=400, detail=f"Targets file not found: {targets_file_path}")

        output_dir = req.output_dir or str(settings.RESULTS_DIR)

        # Get user info if task user tracking is enabled
        username = None
        user_id = None
        from ..task_config import is_task_user_tracking_enabled
        if is_task_user_tracking_enabled():
            current_user = getattr(request.state, 'current_user', None)
            if current_user:
                username = current_user.get('username')
                user_id = current_user.get('user_id')

        try:
            task_id = await task_manager.create_module_task(
                module_name=req.module_name,
                targets_file=targets_file_path,
                output_dir=output_dir,
                module_options=req.module_options or {},
                username=username,
                user_id=user_id,
                sudo_password=req.sudo_password
            )
        except ModuleAlreadyRunningError as e:
            raise HTTPException(
                status_code=409,
                detail=f"A task for module '{e.module_name}' is already running (task {e.existing_task_id}). Cancel it first or wait for it to finish.",
            )

        return JSONResponse({"task_id": task_id, "status": "created"})
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating module task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.post("/api/credrecon")
async def create_credrecon_task(request: Request, db_session: AsyncSession = Depends(get_session)):
    """Create a new credential scanner task."""
    try:
        data = await request.json()

        targets = data.get("targets", [])
        protocol = data.get("protocol", "auto")
        threads = data.get("threads", 10)
        max_attempts = data.get("max_attempts", 3)
        timeout = data.get("timeout", 5)
        creds_file = data.get("creds_file", "")
        uploaded_targets = data.get("uploaded_targets", "")
        uploaded_usernames = data.get("uploaded_usernames", "")
        uploaded_passwords = data.get("uploaded_passwords", "")
        # Support for file browser content (new UI)
        usernames_content = data.get("usernames_content", "")
        passwords_content = data.get("passwords_content", "")

        # Attack mode parameters
        attack_mode = data.get("attack_mode", "default")
        spray_password = data.get("spray_password", "")
        stuff_username = data.get("stuff_username", "")
        single_username = data.get("single_username", "")
        single_password = data.get("single_password", "")
        usernames_file = data.get("usernames_file", "")
        passwords_file = data.get("passwords_file", "")
        key_usernames = data.get("key_usernames", "")

        # Credential file parameters
        credfile_content = data.get("credfile_content", "")
        credfile_path = data.get("credfile_path", "")
        # Multi-protocol support for credfile mode
        protocols = data.get("protocols", [])  # list of services to test

        # SSH key authentication parameters
        ssh_key_path = data.get("ssh_key_path", "")
        ssh_key_content = data.get("ssh_key_content", "")
        ssh_key_passphrase = data.get("ssh_key_passphrase", "")
        ssh_cert_path = data.get("ssh_cert_path", "")
        ssh_cert_content = data.get("ssh_cert_content", "")

        # Service probing (default: enabled)
        probe_services = data.get("probe_services", True)

        # New CredRecon args
        jitter = data.get("jitter", 0)
        max_attempts_per_user = data.get("max_attempts_per_user", 0)
        smb_hash = data.get("smb_hash", "")
        domain = data.get("domain", "")
        snmp_tier = data.get("snmp_tier", "default")
        badkeys = data.get("badkeys", True)

        if not targets and not uploaded_targets and attack_mode != "credfile":
            raise HTTPException(status_code=400, detail="No targets provided")

        # Generate scan ID first (needed for directory name)
        scan_id = str(uuid.uuid4())

        # Create output directory: {workspace}/credrecon/credrecon-tasks/credrecon-taskid-timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        # Use short scan ID (first 8 chars) for directory name
        short_scan_id = scan_id[:8]
        # Create credrecon directory under workspace/results dir
        credrecon_base = Path(os.environ.get("CYGOR_LOAD_DIR") or settings.RESULTS_DIR) / "credrecon"
        credrecon_base.mkdir(parents=True, exist_ok=True)
        output_dir = credrecon_base / "credrecon-tasks" / f"credrecon-{short_scan_id}-{timestamp}"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save targets file in the output directory instead of /tmp
        if uploaded_targets:
            targets_content = uploaded_targets
        else:
            targets_content = "\n".join(targets)

        targets_file = output_dir / "targets.txt"
        with open(targets_file, 'w') as f:
            f.write(targets_content)

        # For credfile mode, if no explicit targets provided, extract unique IPs from credential file
        if attack_mode == "credfile" and not targets_content.strip():
            cred_source = credfile_content or (Path(credfile_path).read_text() if credfile_path and Path(credfile_path).exists() else "")
            unique_ips = set()
            for line in cred_source.strip().splitlines():
                parts = line.split(",")
                if parts and parts[0].strip() and parts[0].strip().lower() not in ("ip", "host", "target", "address"):
                    unique_ips.add(parts[0].strip())
            targets_content = "\n".join(sorted(unique_ips))
            with open(targets_file, 'w') as f:
                f.write(targets_content)

        # Build command
        cmd = ["cygor", "credrecon", "-i", str(targets_file)]

        # Multi-protocol support: --protocols flag for parallel testing
        if protocols and len(protocols) > 1:
            cmd.extend(["--protocols", ",".join(protocols)])
        elif protocols and len(protocols) == 1 and protocols[0] != "auto":
            cmd.extend(["--protocol", protocols[0]])
        elif protocol and protocol != "auto":
            cmd.extend(["--protocol", protocol])

        if threads:
            cmd.extend(["--threads", str(threads)])

        if max_attempts:
            cmd.extend(["--max-attempts", str(max_attempts)])

        if timeout:
            cmd.extend(["--timeout", str(timeout)])

        if creds_file:
            cmd.extend(["--creds-file", creds_file])

        # Handle service probing (enabled by default)
        if not probe_services:
            cmd.append("--no-probe")

        # Handle attack mode
        if attack_mode and attack_mode != "default":
            cmd.extend(["--attack-mode", attack_mode])

        # Handle attack mode specific parameters
        if attack_mode == "single":
            if single_username:
                cmd.extend(["--single-username", single_username])
            if single_password:
                cmd.extend(["--single-password", single_password])
        elif attack_mode == "spray":
            if spray_password:
                cmd.extend(["--spray-password", spray_password])
            if usernames_file:
                cmd.extend(["--usernames-file", usernames_file])
        elif attack_mode == "stuff":
            if stuff_username:
                cmd.extend(["--stuff-username", stuff_username])
            if passwords_file:
                cmd.extend(["--passwords-file", passwords_file])
        elif attack_mode == "key":
            # Key Authentication mode - usernames from comma-separated input or file
            if key_usernames:
                # Convert comma-separated usernames to a temp file
                usernames_list = [u.strip() for u in key_usernames.split(",") if u.strip()]
                if usernames_list:
                    key_usernames_file_path = output_dir / "key_usernames.txt"
                    with open(key_usernames_file_path, 'w') as f:
                        f.write("\n".join(usernames_list))
                    cmd.extend(["--usernames-file", str(key_usernames_file_path)])
            elif usernames_file:
                cmd.extend(["--usernames-file", usernames_file])
        elif attack_mode == "credfile":
            # Credential file mode -- save uploaded content or use server path
            # When multiple protocols selected, expand the credfile so each entry
            # is duplicated per service (the scanner resolves service per-row).
            raw_credfile = credfile_content
            if not raw_credfile and credfile_path and Path(credfile_path).exists():
                raw_credfile = Path(credfile_path).read_text(encoding="utf-8", errors="replace")

            if not raw_credfile:
                raise HTTPException(status_code=400, detail="Credential file mode requires a credential file (upload or server path)")

            # Expand for multi-protocol: duplicate rows with service column
            if protocols and len(protocols) > 1:
                from cygor.credrecon.credfile_parser import parse_content as _parse_cred
                parsed = _parse_cred(raw_credfile)
                expanded_lines = ["ip,port,username,password,service"]
                for entry in parsed.entries:
                    for svc in protocols:
                        p = entry.port or ""
                        expanded_lines.append(f"{entry.ip},{p},{entry.username},{entry.password},{svc}")
                raw_credfile = "\n".join(expanded_lines)

            credfile_file_path = output_dir / "credfile.csv"
            with open(credfile_file_path, 'w') as f:
                f.write(raw_credfile)
            cmd.extend(["--credfile-path", str(credfile_file_path)])
        elif attack_mode == "default":
            # Default mode - handle custom wordlists if provided
            if usernames_file:
                cmd.extend(["--usernames-file", usernames_file])
            if passwords_file:
                cmd.extend(["--passwords-file", passwords_file])

        # Handle username/password file uploads - save in output directory
        # Priority: usernames_content/passwords_content (file browser) > uploaded_usernames/uploaded_passwords (legacy)
        final_usernames_content = usernames_content or uploaded_usernames
        final_passwords_content = passwords_content or uploaded_passwords

        if final_usernames_content:
            usernames_file_path = output_dir / "usernames.txt"
            with open(usernames_file_path, 'w') as f:
                f.write(final_usernames_content)
            # Only add if not already added by attack mode handling
            if "--usernames-file" not in cmd:
                cmd.extend(["--usernames-file", str(usernames_file_path)])

        if final_passwords_content:
            passwords_file_path = output_dir / "passwords.txt"
            with open(passwords_file_path, 'w') as f:
                f.write(final_passwords_content)
            # Only add if not already added by attack mode handling
            if "--passwords-file" not in cmd:
                cmd.extend(["--passwords-file", str(passwords_file_path)])

        # Handle new CredRecon args
        if jitter and float(jitter) > 0:
            cmd.extend(["--jitter", str(jitter)])

        if max_attempts_per_user and int(max_attempts_per_user) > 0:
            cmd.extend(["--max-attempts-per-user", str(max_attempts_per_user)])

        if smb_hash:
            cmd.extend(["--smb-hash", smb_hash])

        if domain:
            cmd.extend(["--domain", domain])

        if snmp_tier and snmp_tier != "default":
            cmd.extend(["--snmp-tier", snmp_tier])

        if not badkeys:
            cmd.append("--no-badkeys")

        # Handle SSH key authentication
        if ssh_key_content:
            # SSH key uploaded via browser - save to output directory
            ssh_key_file_path = output_dir / "ssh_key"
            with open(ssh_key_file_path, 'w') as f:
                f.write(ssh_key_content)
            os.chmod(ssh_key_file_path, 0o600)
            cmd.extend(["--ssh-key", str(ssh_key_file_path)])
        elif ssh_key_path:
            # SSH key path provided directly
            cmd.extend(["--ssh-key", ssh_key_path])

        if ssh_key_passphrase:
            cmd.extend(["--ssh-key-passphrase", ssh_key_passphrase])

        # Handle SSH certificate (-cert.pub) for CA-signed authentication
        if ssh_cert_content:
            ssh_cert_file_path = output_dir / "ssh_cert.pub"
            with open(ssh_cert_file_path, 'w') as f:
                f.write(ssh_cert_content)
            os.chmod(ssh_cert_file_path, 0o600)
            cmd.extend(["--ssh-cert", str(ssh_cert_file_path)])
        elif ssh_cert_path:
            cmd.extend(["--ssh-cert", ssh_cert_path])

        # Add output directory and scan-id to command
        cmd.extend(["-o", str(output_dir)])
        cmd.extend(["--scan-id", scan_id])

        # Create scan record in database
        from ..models import CredReconScan

        try:
            db_scan = CredReconScan(
                scan_id=scan_id,
                created_at=datetime.utcnow().isoformat(),
                status="pending",
                command=" ".join(cmd),
                num_targets=len(targets_content.splitlines())
                # Note: output_dir column doesn't exist in database, so we don't set it here
                # The output directory path is stored in the command string and can be reconstructed from created_at timestamp
            )
            db_session.add(db_scan)
            await db_session.commit()
        except Exception as e:
            print(f"Error creating scan record in database: {e}", file=sys.stderr)

        # Create credential scanner task using dedicated manager
        await credrecon_manager.create_scan(
            command=cmd,
            num_targets=len(targets_content.splitlines()),
            scan_id=scan_id
        )

        return JSONResponse({"scan_id": scan_id, "status": "created", "redirect": f"/credrecon/scans/{scan_id}"})
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error creating credrecon task: {str(e)}")

@router.get("/api/browse")
async def browse_server_directory(path: str = Query(""), file_types: str = Query("")):
    """
    Browse server filesystem for selecting input/output directories.
    Returns list of directories and scan files.
    Optional file_types: comma-separated extensions (e.g. ".txt,.pem,.list")
    to override the default scan-file filter.
    """
    try:
        logger.info(f"Browse request received with path: '{path}'")

        # Default to current working directory if no path provided
        if not path or path == "/":
            browse_path = Path.cwd()
            logger.info(f"Using current working directory: {browse_path}")
        else:
            browse_path = Path(path)
            logger.info(f"Using provided path: {browse_path}")

        # Security: Prevent directory traversal attacks
        # Only allow browsing within certain safe directories
        safe_roots = []

        # Build safe_roots list, skipping any invalid paths
        for root_path in [
            Path.home(),
            Path("/workspace"),
            Path("/tmp"),
            Path(settings.RESULTS_DIR) if settings.RESULTS_DIR else None,
            Path.cwd()
        ]:
            if root_path:
                try:
                    # Test if we can resolve the path
                    _ = root_path.resolve()
                    safe_roots.append(root_path)
                except Exception as e:
                    logger.warning(f"Skipping invalid safe root: {root_path} - {e}")
                    continue

        # Check if path is within allowed roots
        is_safe = False
        try:
            resolved_path = browse_path.resolve()
            for safe_root in safe_roots:
                try:
                    safe_root_resolved = safe_root.resolve()
                    if resolved_path == safe_root_resolved or safe_root_resolved in resolved_path.parents:
                        is_safe = True
                        break
                except Exception as e:
                    logger.warning(f"Error checking safe root {safe_root}: {e}")
                    continue
        except Exception as e:
            logger.error(f"Error resolving browse path {browse_path}: {e}")
            is_safe = False

        if not is_safe:
            # Default to home directory if path is unsafe
            browse_path = Path.home()

        if not browse_path.exists() or not browse_path.is_dir():
            browse_path = Path.home()

        items = []

        # Add parent directory link if not at root
        if browse_path.parent != browse_path:
            items.append({
                "name": "..",
                "path": str(browse_path.parent),
                "type": "parent",
                "size": 0
            })

        # Determine which file extensions to show
        default_exts = {'.xml', '.nmap', '.gnmap', '.zip'}
        if file_types:
            allowed_exts = {ext.strip().lower() if ext.strip().startswith('.') else f'.{ext.strip().lower()}' for ext in file_types.split(',') if ext.strip()}
        else:
            allowed_exts = default_exts

        # Show all files when filter is "*"
        show_all_files = file_types.strip() == "*"

        # List directories and files
        try:
            for item in sorted(browse_path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
                try:
                    if item.is_dir():
                        items.append({
                            "name": item.name,
                            "path": str(item),
                            "type": "directory",
                            "size": 0
                        })
                    elif show_all_files or item.suffix.lower() in allowed_exts:
                        items.append({
                            "name": item.name,
                            "path": str(item),
                            "type": "file",
                            "size": item.stat().st_size
                        })
                except (PermissionError, OSError):
                    continue
        except PermissionError:
            pass

        logger.info(f"Returning {len(items)} items for path: {browse_path}")
        return JSONResponse({
            "current_path": str(browse_path),
            "items": items
        })

    except Exception as e:
        logger.error(f"Error browsing directory: {e}", exc_info=True)
        return JSONResponse({
            "current_path": str(Path.home()),
            "items": [],
            "error": str(e)
        }, status_code=500)

@router.post("/api/parse")
async def create_parse_task(req: Dict[str, Any], request: Request):
    """Create a new parse task from server path."""
    try:
        input_path = req.get("input_path", "").strip()
        output_dir = req.get("output_dir", "").strip()
        format_type = req.get("format", "txt")
        path_type = req.get("path_type", "file")

        if not input_path:
            raise HTTPException(status_code=400, detail="Input path is required")

        # Validate input path exists
        input_path_obj = Path(input_path)
        if not input_path_obj.exists():
            raise HTTPException(status_code=400, detail=f"Input path does not exist: {input_path}")

        # Determine output directory
        if not output_dir:
            # Default to input file's parent directory for files, or the directory itself
            if input_path_obj.is_file():
                output_dir = str(input_path_obj.parent)
            else:
                output_dir = str(input_path_obj)

        # Build parse command
        cmd = ["cygor", "parse", input_path]

        if output_dir:
            cmd.extend(["-o", output_dir])

        if format_type and format_type != "txt":
            cmd.extend(["--format", format_type])

        # Get user info if task user tracking is enabled
        username = None
        user_id = None
        from ..task_config import is_task_user_tracking_enabled
        if is_task_user_tracking_enabled():
            current_user = getattr(request.state, 'current_user', None)
            if current_user:
                username = current_user.get('username')
                user_id = current_user.get('user_id')

        # Create task
        task_id = await task_manager.create_generic_task(
            task_name="parse",
            command=cmd,
            description=f"Parse scan results: {input_path}",
            output_dir=output_dir,
            username=username,
            user_id=user_id
        )

        return JSONResponse({"task_id": task_id, "status": "created"})

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating parse task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/api/parse/upload")
async def create_parse_task_from_upload(
    files: List[UploadFile] = File(...),
    output_dir: str = Form(""),
    format: str = Form("txt"),
    request: Request = None
):
    """Create a new parse task from uploaded files."""
    import tempfile
    import zipfile

    try:
        if not files:
            raise HTTPException(status_code=400, detail="No files uploaded")

        # Create temporary directory for uploads
        temp_dir = Path(tempfile.mkdtemp(prefix="cygor_parse_"))
        logger.info(f"Created temp directory: {temp_dir}")

        uploaded_files = []

        for file in files:
            file_path = temp_dir / file.filename

            # Save uploaded file
            with open(file_path, 'wb') as f:
                content = await file.read()
                f.write(content)

            # If it's a zip file, extract it
            if file.filename.endswith('.zip'):
                logger.info(f"Extracting zip file: {file.filename}")
                try:
                    with zipfile.ZipFile(file_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_dir)
                    # Remove the zip file after extraction
                    file_path.unlink()
                    # Add all extracted files
                    for extracted_file in temp_dir.rglob('*'):
                        if extracted_file.is_file() and extracted_file.suffix.lower() in ['.xml', '.nmap', '.gnmap']:
                            uploaded_files.append(str(extracted_file))
                except zipfile.BadZipFile:
                    logger.error(f"Invalid zip file: {file.filename}")
                    raise HTTPException(status_code=400, detail=f"Invalid zip file: {file.filename}")
            else:
                uploaded_files.append(str(file_path))

        if not uploaded_files:
            raise HTTPException(status_code=400, detail="No valid scan files found")

        # Determine output directory
        if not output_dir:
            output_dir = str(temp_dir)

        # Build parse command - parse the temp directory
        cmd = ["cygor", "parse", str(temp_dir)]

        if output_dir:
            cmd.extend(["-o", output_dir])

        if format and format != "txt":
            cmd.extend(["--format", format])

        # Get user info if task user tracking is enabled
        username = None
        user_id = None
        from ..task_config import is_task_user_tracking_enabled
        if is_task_user_tracking_enabled() and request:
            current_user = getattr(request.state, 'current_user', None)
            if current_user:
                username = current_user.get('username')
                user_id = current_user.get('user_id')

        # Create task
        task_id = await task_manager.create_generic_task(
            task_name="parse-upload",
            command=cmd,
            description=f"Parse uploaded files ({len(uploaded_files)} files)",
            output_dir=output_dir,
            username=username,
            user_id=user_id
        )

        return JSONResponse({
            "task_id": task_id,
            "status": "created",
            "files_uploaded": len(uploaded_files),
            "temp_dir": str(temp_dir)
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating parse task from upload: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/enrich/sources")
async def list_enrich_sources():
    """
    Return the list of enrichment sources, marking which have an API key
    configured (or are keyless). The Run Enrichment form polls this so the
    user knows what will actually run before they click Start.
    """
    from cygor.enrich import EnrichmentConfig
    from cygor.enrich_config import SOURCES as _SOURCE_REGISTRY
    cfg = EnrichmentConfig()
    out = []
    for slug, info in _SOURCE_REGISTRY.items():
        keyless = bool(info.get("no_api_key_required"))
        configured = keyless or bool(cfg.get(slug))
        out.append({
            "slug": slug,
            "name": info.get("name", slug),
            "configured": configured,
            "no_api_key_required": keyless,
            "env_var": info.get("env_var"),
        })
    # Free historical sources that aren't in the SOURCES registry
    out.append({"slug": "wayback", "name": "Wayback Machine", "configured": True, "no_api_key_required": True, "env_var": None})
    out.append({"slug": "commoncrawl", "name": "Common Crawl", "configured": True, "no_api_key_required": True, "env_var": None})
    return JSONResponse({"sources": out})


@router.post("/api/enrich")
async def create_enrich_task(req: Dict[str, Any], request: Request):
    """Create a new enrichment task for IOCs."""
    import tempfile

    try:
        iocs = req.get("iocs", [])
        output_format = req.get("format", "json")
        sources = req.get("sources", ["all"])

        # Enrichment options
        extract_subdomains = req.get("extract_subdomains", False)
        spray_lists = req.get("spray_lists", False)
        timeout = req.get("timeout")  # Optional timeout in seconds
        retries = req.get("retries")  # Optional retry count

        if not iocs:
            raise HTTPException(status_code=400, detail="No IOCs provided")

        # ── Pre-flight: refuse to start if no usable sources are configured ──
        # The CLI also bails out, but checking here means the user gets an
        # immediate 400 with actionable detail instead of a failed task in
        # their task list. Keys come from ~/.cygor/enrich_config.json or env
        # vars; sources that don't need a key (e.g. crt_sh) are always OK.
        from cygor.enrich import EnrichmentConfig
        from cygor.enrich_config import SOURCES as _SOURCE_REGISTRY
        cfg = EnrichmentConfig()
        # Sources that work without an API key.
        _NO_KEY_SOURCES = {
            slug for slug, info in _SOURCE_REGISTRY.items()
            if info.get("no_api_key_required")
        } | {"wayback", "commoncrawl"}  # historically free

        # Resolve "all" to "every source the user has a key for", plus the
        # keyless ones. This is how the CLI behaves at runtime.
        if sources in (None, [], ["all"]):
            requested = sorted(set(cfg.config.keys()) | _NO_KEY_SOURCES)
        else:
            # Normalize the vt alias the CLI accepts.
            requested = ["virustotal" if s == "vt" else s for s in sources]

        usable = [s for s in requested if s in _NO_KEY_SOURCES or cfg.get(s)]
        missing = [s for s in requested if s not in usable]
        if not usable:
            # Build a helpful error: tell the user which sources need keys
            # and how to set them.
            cmds = "\n".join(
                f"  cygor enrich config-manager set {s} YOUR_API_KEY"
                for s in (sorted(missing) or ["shodan"])[:5]
            )
            raise HTTPException(
                status_code=400,
                detail=(
                    "No usable enrichment sources are configured. "
                    f"Requested: {', '.join(requested) or '(none)'}. "
                    f"Configure at least one API key:\n{cmds}\n"
                    "Or set environment variables (e.g. SHODAN_API_KEY) and restart the web server."
                ),
            )

        # Drop any unconfigured sources from the request so the CLI doesn't
        # try them and emit per-source errors. Keep the user's intent on
        # the validated subset.
        sources = usable
        if missing:
            logger.info(
                f"Enrich pre-flight: dropping unconfigured sources {missing}; "
                f"running with {usable}"
            )

        # Create temporary file with IOCs
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
        temp_file.write('\n'.join(iocs))
        temp_file.close()

        # Determine output file path with correct extension.
        # The on-disk subdir is 'enrich/' (matches `cygor enrich` CLI and the
        # workspace SUBDIRS list); both producers must write to the same
        # location so the ingestor sees every run.
        output_dir = str(Path(settings.RESULTS_DIR) / "enrich")
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')

        # Set file extension based on format
        file_ext = {
            'json': 'json',
            'csv': 'csv',
            'xml': 'xml',
            'text': 'txt'
        }.get(output_format, 'json')

        output_file = str(Path(output_dir) / f"enrichment-{timestamp}.{file_ext}")

        # Build enrichment command
        cmd = ["cygor", "enrich", temp_file.name, "--output", output_file, "--format", output_format]

        # Add sources if not "all"
        if sources and sources != ["all"]:
            cmd.extend(["--sources"] + sources)

        # Add enrichment feature options
        if extract_subdomains:
            cmd.append("--extract-subdomains")

        if spray_lists:
            cmd.append("--spray-lists")

        if timeout is not None and timeout > 0:
            cmd.extend(["--timeout", str(timeout)])

        if retries is not None and retries > 0:
            cmd.extend(["--retries", str(retries)])

        # Build description with sources info
        sources_str = ", ".join(sources) if sources != ["all"] else "all sources"
        description = f"Enrich {len(iocs)} IOC(s) using {sources_str}"

        # Add extra features to description
        extras = []
        if extract_subdomains:
            extras.append("subdomain extraction")
        if spray_lists:
            extras.append("spray list generation")
        if extras:
            description += f" (with {', '.join(extras)})"

        # Get user info if task user tracking is enabled
        username = None
        user_id = None
        from ..task_config import is_task_user_tracking_enabled
        if is_task_user_tracking_enabled():
            current_user = getattr(request.state, 'current_user', None)
            if current_user:
                username = current_user.get('username')
                user_id = current_user.get('user_id')

        # Create task
        task_id = await task_manager.create_generic_task(
            task_name="enrich",
            command=cmd,
            description=description,
            output_dir=output_dir,
            username=username,
            user_id=user_id
        )

        # Register a post-completion hook that ingests the enrichment JSON
        # into the EnrichmentRun / EnrichmentFinding tables. This runs only
        # on success and only for the .json output (the other formats are
        # operator-facing artifacts).
        if output_format == "json":
            requested_sources = list(sources) if sources and sources != ["all"] else None

            async def _ingest_on_complete(task):
                if task.status != TaskStatus.COMPLETED:
                    return
                try:
                    from ..enrichment_ingest import ingest_enrichment_file
                    from ..db import get_session
                    async for s in get_session():
                        await ingest_enrichment_file(
                            s,
                            output_file,
                            task_id=task_id,
                            sources=requested_sources,
                        )
                        await s.commit()
                        break
                except Exception as e:
                    logger.warning(f"Enrichment ingest failed for task {task_id}: {e}", exc_info=True)

            task_manager.register_completion_callback(task_id, _ingest_on_complete)

        return JSONResponse({
            "task_id": task_id,
            "status": "created",
            "ioc_count": len(iocs),
            "sources": sources,
            "output_file": output_file
        })

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating enrichment task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/tasks")
async def list_tasks(request: Request):
    """List all tasks with unified task types."""
    # Get user info and check if tracking is enabled
    from ..task_config import is_task_user_tracking_enabled
    tracking_enabled = is_task_user_tracking_enabled()

    username = None
    user_id = None
    is_admin = False

    # If tracking is disabled, treat all authenticated users as admins (can see all tasks)
    # If tracking is enabled, check user role
    if tracking_enabled:
        current_user = getattr(request.state, 'current_user', None)
        if current_user:
            username = current_user.get('username')
            user_id = current_user.get('user_id')
            # Check if user is admin - handle both global admin token and user accounts
            role = current_user.get('role')
            is_admin = role == 'admin'
            # If no user_id and role is admin, it's the global admin token - still an admin
            if not user_id and role == 'admin':
                is_admin = True
    else:
        # When tracking is disabled, authenticated users can see all tasks
        # Check if user is authenticated (even if tracking is off, auth might still be enabled)
        current_user = getattr(request.state, 'current_user', None)
        if current_user:
            # If authenticated, treat as admin for task viewing
            is_admin = True
        else:
            # If not authenticated and auth is disabled, also treat as admin (public access)
            is_admin = True

    # Get raw tasks from task manager (filtered by user if tracking enabled and not admin)
    raw_tasks = await task_manager.list_tasks(
        username=username if tracking_enabled else None,
        user_id=user_id if tracking_enabled else None,
        is_admin=is_admin
    )

    # Convert task types for better categorization
    unified_tasks = []
    for task_dict in raw_tasks:
        # Make a copy to avoid modifying original
        task = task_dict.copy()

        # Detect parse and enrich tasks by command
        if task.get('task_type') == 'generic':
            cmd_str = task.get('command', '')
            if 'cygor parse' in cmd_str:
                task['task_type'] = 'parse'
            elif 'cygor enrich' in cmd_str:
                task['task_type'] = 'enrich'
            else:
                task['task_type'] = 'module'
        elif task.get('task_type') == 'scan':
            task['task_type'] = 'port_scan'

        unified_tasks.append(task)

    # Track all task IDs we've seen to prevent duplicates
    seen_task_ids = set(t.get('task_id') for t in unified_tasks if t.get('task_id'))

    # Fetch CredRecon scans from in-memory manager
    try:
        in_memory_credrecon = await credrecon_manager.get_all_scans()
        for scan in in_memory_credrecon:
            # Check if we already have this scan (avoid duplicates)
            if scan.scan_id in seen_task_ids:
                continue
            seen_task_ids.add(scan.scan_id)

            unified_tasks.append({
                "task_id": scan.scan_id,
                "task_type": "credential_test",
                "scanner": "credrecon",
                "command": " ".join(scan.command) if isinstance(scan.command, list) else scan.command,
                "status": scan.status.value,
                "username": "System",
                "user_id": None,
                "num_targets": scan.num_targets,
                "total_findings": None,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "output_dir": None,
            })
    except ImportError:
        pass
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to fetch in-memory credrecon scans: {e}")

    # Fetch CredRecon scans from database (for historical/completed scans)
    try:
        from ..models import CredReconScan
        from sqlalchemy import select

        async for session in get_session():
            try:
                statement = select(CredReconScan).order_by(CredReconScan.created_at.desc())
                result = await session.execute(statement)
                db_scans = result.scalars().all()

                for scan in db_scans:
                    # Check if we already have this scan (avoid duplicates)
                    if scan.scan_id in seen_task_ids:
                        continue
                    seen_task_ids.add(scan.scan_id)

                    unified_tasks.append({
                        "task_id": scan.scan_id,
                        "task_type": "credential_test",
                        "scanner": "credrecon",
                        "command": scan.command or "cygor credrecon",
                        "status": scan.status,
                        "username": None,
                        "user_id": None,
                        "num_targets": scan.num_targets,
                        "total_findings": None,
                        "created_at": scan.created_at if scan.created_at else None,
                        "started_at": scan.started_at if scan.started_at else None,
                        "completed_at": scan.completed_at if scan.completed_at else None,
                        "output_dir": None,
                    })
            finally:
                break

    except ImportError:
        pass
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning(f"Failed to fetch credrecon scans from database: {e}")

    # Sort all tasks by created_at descending
    unified_tasks.sort(
        key=lambda t: t.get('created_at') or '',
        reverse=True
    )

    return JSONResponse(unified_tasks)

@router.get("/api/tasks/{task_id}")
async def get_task_status(task_id: str, request: Request):
    """Get status of a specific task."""
    task = await task_manager.get_task(task_id)
    if not task:
        # Fallback: reconstruct from schedule history (after server restart)
        history_task = await get_task_from_schedule_history(task_id)
        if history_task:
            return JSONResponse(history_task)

        raise HTTPException(status_code=404, detail="Task not found")

    # Check if user can access this task (if tracking enabled and not admin)
    from ..task_config import is_task_user_tracking_enabled
    if is_task_user_tracking_enabled():
        current_user = getattr(request.state, 'current_user', None)
        if current_user and current_user.get('role') != 'admin':
            # User can only see their own tasks
            user_id = current_user.get('user_id')
            username = current_user.get('username')
            if task.user_id and task.user_id != user_id and task.username != username:
                raise HTTPException(status_code=403, detail="Access denied: You can only view your own tasks")

    task_dict = task.to_dict()
    # Add schedule info if this task was triggered by a schedule
    schedule_info = await get_schedule_info_for_task(task_id)
    if schedule_info:
        task_dict["schedule_id"] = schedule_info["schedule_id"]
        task_dict["schedule_name"] = schedule_info["schedule_name"]
    return JSONResponse(task_dict)

@router.get("/api/tasks/{task_id}/output")
async def get_task_output(task_id: str, request: Request):
    """Get output of a specific task.

    Honors ``?since=N`` and ``?errors_since=N`` so the UI can poll only for
    new lines on long-running scans. The response always carries
    ``total_output_lines`` and ``total_error_lines`` — the absolute number
    of lines ever produced, which keeps growing past the in-memory buffer
    cap. The UI should use those counters (not ``len(output)``) to decide
    whether new lines arrived.
    """
    try:
        since = int(request.query_params.get("since", "0") or 0)
    except (TypeError, ValueError):
        since = 0
    try:
        errors_since = int(request.query_params.get("errors_since", "0") or 0)
    except (TypeError, ValueError):
        errors_since = 0

    task = await task_manager.get_task(task_id)
    if not task:
        # Fallback: check schedule history and load output from disk
        history_task = await get_task_from_schedule_history(task_id)
        if history_task:
            disk_output = _load_task_output_from_disk(task_id, history_task)
            if disk_output:
                return JSONResponse({
                    "task_id": task_id,
                    "status": history_task.get("status", "completed"),
                    "output": disk_output["output"],
                    "errors": disk_output["errors"],
                    "exit_code": history_task.get("exit_code"),
                    "output_offset": 0,
                    "total_output_lines": len(disk_output["output"]),
                    "total_error_lines": len(disk_output["errors"]),
                    "dropped_output_lines": 0,
                    "dropped_error_lines": 0,
                })
            return JSONResponse({
                "task_id": task_id,
                "status": history_task.get("status", "completed"),
                "output": [f"Scheduled task completed. Output is no longer available after server restart."],
                "errors": [history_task["error"]] if history_task.get("error") else [],
                "exit_code": history_task.get("exit_code"),
                "output_offset": 0,
                "total_output_lines": 1,
                "total_error_lines": 1 if history_task.get("error") else 0,
                "dropped_output_lines": 0,
                "dropped_error_lines": 0,
            })

        raise HTTPException(status_code=404, detail="Task not found")

    # Check if user can access this task (if tracking enabled and not admin)
    from ..task_config import is_task_user_tracking_enabled
    if is_task_user_tracking_enabled():
        current_user = getattr(request.state, 'current_user', None)
        if current_user and current_user.get('role') != 'admin':
            # User can only see their own tasks
            user_id = current_user.get('user_id')
            username = current_user.get('username')
            if task.user_id and task.user_id != user_id and task.username != username:
                raise HTTPException(status_code=403, detail="Access denied: You can only view your own tasks")

    # Slice based on the absolute counter. Lines below ``dropped`` were
    # rotated out of the bounded buffer; the UI sees ``output_offset`` so
    # it can stitch its local buffer correctly even after a rotation.
    out_total = getattr(task.output_lines, "total_appended", len(task.output_lines))
    err_total = getattr(task.error_lines,  "total_appended", len(task.error_lines))
    dropped_out = max(0, out_total - len(task.output_lines))
    dropped_err = max(0, err_total - len(task.error_lines))
    out_start = max(since,        dropped_out)
    err_start = max(errors_since, dropped_err)
    out_local = max(0, out_start - dropped_out)
    err_local = max(0, err_start - dropped_err)
    output_tail = list(task.output_lines)[out_local:]
    errors_tail = list(task.error_lines)[err_local:]

    return JSONResponse({
        "task_id": task_id,
        "status": task.status.value,
        "output": output_tail,
        "errors": errors_tail,
        "output_offset": out_start,
        "errors_offset": err_start,
        "total_output_lines": out_total,
        "total_error_lines": err_total,
        "dropped_output_lines": dropped_out,
        "dropped_error_lines": dropped_err,
    })

@router.post("/api/tasks/{task_id}/cancel")
async def cancel_task(task_id: str):
    """Cancel a running task."""
    success = await task_manager.cancel_task(task_id)
    if not success:
        raise HTTPException(status_code=400, detail="Cannot cancel task (not running or not found)")
    return JSONResponse({"status": "cancelled"})

@router.delete("/api/tasks/{task_id}")
async def delete_task(task_id: str):
    """Delete a task."""
    result = await task_manager.delete_task(task_id)

    if result == "deleted":
        return JSONResponse({"status": "deleted"})

    if result == "running":
        raise HTTPException(status_code=400, detail="Cannot delete a running task. Cancel it first.")

    # Task not found anywhere
    raise HTTPException(status_code=404, detail="Task not found")

@router.post("/api/tasks/{task_id}/restart")
async def restart_task(task_id: str):
    """Restart a completed or failed task with the same parameters."""
    task = task_manager.tasks.get(task_id)

    # Fallback for scheduled tasks whose past execution is no longer in
    # memory (server restart, in-memory task evicted, etc.). The task_id
    # belongs to a ScheduledTaskHistory row; the parent ScheduledTask still
    # has the full config in the DB, so re-firing it via the scheduler
    # produces a brand new task_id with the original parameters intact.
    if not task:
        history_task = await get_task_from_schedule_history(task_id)
        if history_task and history_task.get("schedule_id"):
            from ..scheduler import get_scheduler_manager
            try:
                async with db.SessionLocal() as session:
                    scheduler_mgr = get_scheduler_manager()
                    new_task_id = await scheduler_mgr.trigger_now(session, history_task["schedule_id"])
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to re-trigger scheduled task: {e}")
            if not new_task_id:
                raise HTTPException(status_code=500, detail="Scheduler did not return a task id")
            return JSONResponse({
                "status": "restarted",
                "old_task_id": task_id,
                "new_task_id": new_task_id,
                "message": f"Scheduled task re-triggered as: {new_task_id}"
            })
        raise HTTPException(status_code=404, detail="Task not found")

    # Only allow restart for completed, failed, or cancelled tasks
    if task.status not in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot restart task with status '{task.status}'. Only completed, failed, or cancelled tasks can be restarted."
        )

    # Tasks reconstructed from a scan directory without a cygor-task.json
    # sidecar carry only a stub command (``cygor scan -o /path``) and would
    # produce a "No hosts specified" no-op if re-run. Reject the request with
    # a useful message so the UI can explain the situation to the user.
    if not getattr(task, "restartable", True):
        raise HTTPException(
            status_code=400,
            detail="Cannot restart this historic task: original scan parameters (targets, ports, options) were not recorded. Re-create the scan from the New Scan page."
        )

    # Create a new task with the same parameters
    new_task_id = str(uuid.uuid4())

    # Clone the task
    new_task = Task(
        task_id=new_task_id,
        task_type=task.task_type,
        command=task.command.copy(),
        output_dir=task.output_dir,
        is_ondemand=task.is_ondemand,
        username=task.username,
        user_id=task.user_id
    )

    # Add to task manager
    async with task_manager._lock:
        task_manager.tasks[new_task_id] = new_task

    # Start the task
    asyncio.create_task(task_manager._run_task(new_task))

    return JSONResponse({
        "status": "restarted",
        "old_task_id": task_id,
        "new_task_id": new_task_id,
        "message": f"Task restarted with new ID: {new_task_id}"
    })

@router.put("/api/tasks/{task_id}")
async def edit_task(task_id: str, req: TaskEditRequest):
    """Edit a pending task's parameters."""
    task = task_manager.tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    # Only allow editing pending tasks
    if task.status != TaskStatus.PENDING:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot edit task with status '{task.status}'. Only pending tasks can be edited."
        )

    # Update task parameters
    if req.command:
        task.command = req.command

    if req.output_dir:
        task.output_dir = Path(req.output_dir)

    return JSONResponse({
        "status": "updated",
        "task_id": task_id,
        "task": task.to_dict()
    })
