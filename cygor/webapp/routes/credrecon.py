"""Credential Reconnaissance (CredRecon) routes.

Extracted from main.py — contains all /credrecon page routes and
/api/credrecon/* API routes.
"""

import asyncio
import json
import logging
import os
import sys
import time as _time
from datetime import datetime
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import (
    Host, Port, CredReconScan, CredReconResult,
    ScheduledTaskHistory, ScheduledTask,
)
from ..config import settings
from ..credrecon_tasks import credrecon_manager
from .. import db

router = APIRouter(tags=["credrecon"])

logger = logging.getLogger(__name__)

# Templates instance — set once from main.py via set_templates()
templates = None


def set_templates(tmpl):
    """Called from main.py to inject the shared Jinja2Templates instance."""
    global templates
    templates = tmpl


# ---------------------------------------------------------------------------
# Helper: schedule info look-ups (duplicated from main.py helpers; if those
# are already extracted to a shared module, import from there instead)
# ---------------------------------------------------------------------------

async def _get_schedule_info_for_task(task_id: str) -> Optional[dict]:
    """Look up schedule information for a task by its task_id."""
    try:
        async with AsyncSession(db.engine) as session:
            stmt = select(ScheduledTaskHistory).where(ScheduledTaskHistory.task_id == task_id)
            result = await session.execute(stmt)
            history = result.scalar_one_or_none()

            if history:
                parent_stmt = select(ScheduledTask).where(ScheduledTask.id == history.scheduled_task_id)
                parent_result = await session.execute(parent_stmt)
                scheduled_task = parent_result.scalar_one_or_none()

                if scheduled_task:
                    return {
                        "schedule_id": scheduled_task.id,
                        "schedule_name": scheduled_task.name,
                    }
    except Exception:
        pass
    return None


async def _get_task_from_schedule_history(task_id: str) -> Optional[dict]:
    """Reconstruct task info from ScheduledTaskHistory + ScheduledTask."""
    try:
        async with AsyncSession(db.engine) as session:
            stmt = select(ScheduledTaskHistory).where(ScheduledTaskHistory.task_id == task_id)
            result = await session.execute(stmt)
            history = result.scalar_one_or_none()

            if not history:
                return None

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
                "_from_history": True,
            }
    except Exception as e:
        logging.getLogger(__name__).warning(f"Failed to lookup task {task_id} in schedule history: {e}")
    return None


# ---------------------------------------------------------------------------
# Results cache (module-level)
# ---------------------------------------------------------------------------

_credrecon_results_cache: dict = {"data": None, "ts": 0}
_CREDRECON_CACHE_TTL = 30  # seconds


def _load_aggregated_credrecon_results():
    """Load and deduplicate all credrecon results from disk. Returns (successful, failed, errors) lists.
    Results are cached for 10 seconds to avoid repeated filesystem scans during lazy-load pagination."""
    now = _time.monotonic()
    if _credrecon_results_cache["data"] and (now - _credrecon_results_cache["ts"]) < _CREDRECON_CACHE_TTL:
        return _credrecon_results_cache["data"]
    results_dirs = [
        Path("schedule-scans") / "credrecon",
        Path(settings.RESULTS_DIR) / "schedule-scans" / "credrecon",
        Path("credrecon") / "credrecon-tasks",
        Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks",
        Path("credrecon-tasks"),
        Path(settings.RESULTS_DIR) / "credrecon-tasks",
        Path(settings.RESULTS_DIR) / "credrecon",
        Path("credrecon"),
    ]

    loaded_files: set = set()
    all_results: list = []
    for results_dir in results_dirs:
        if results_dir.exists():
            for json_file in sorted(results_dir.rglob("credrecon_results.json")):
                abs_path = json_file.resolve()
                if abs_path in loaded_files:
                    continue
                loaded_files.add(abs_path)
                try:
                    data = json.loads(json_file.read_text())
                    if isinstance(data, list):
                        all_results.extend(data)
                except Exception as e:
                    print(f"Error loading {json_file}: {e}", file=sys.stderr)

    seen_results: set = set()
    unique_results: list = []
    for result in all_results:
        target = result.get("ip") or result.get("target", "")
        port = result.get("port", 0)
        protocol = result.get("protocol", "")
        username = result.get("username", "")
        password = result.get("password", "")
        status = result.get("status", "")
        timestamp = result.get("timestamp", "")
        result_key = (target, port, protocol, username, password, status, timestamp)
        if result_key not in seen_results:
            seen_results.add(result_key)
            unique_results.append(result)

    successful = [r for r in unique_results if r.get("status") == "success"]
    failed = [r for r in unique_results if r.get("status") == "failed"]
    errors = [r for r in unique_results if r.get("status") == "error"]
    result = (successful, failed, errors)
    _credrecon_results_cache["data"] = result
    _credrecon_results_cache["ts"] = _time.monotonic()
    return result


# ---------------------------------------------------------------------------
# Disk-output loader helper
# ---------------------------------------------------------------------------

def _load_credrecon_output_from_disk(scan_id: str) -> Optional[dict]:
    """Search for credrecon scan output files on disk by scan_id.
    Works for sched-, historic-, and regular scan IDs."""
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

    for name in ("output.txt", "stdout.txt", "log.txt", "credrecon.log"):
        p = scan_dir / name
        if p.exists():
            try:
                output_text = p.read_text()
            except Exception:
                pass
            break

    for name in ("errors.txt", "stderr.txt"):
        p = scan_dir / name
        if p.exists():
            try:
                error_text = p.read_text()
            except Exception:
                pass
            break

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
            return None

    output_lines = [l for l in output_text.split('\n') if l] if output_text else []
    error_lines = [l for l in error_text.split('\n') if l] if error_text else []

    return {
        "output": output_lines,
        "errors": error_lines,
    }


# ===================================================================
# Page routes
# ===================================================================

@router.get("/credrecon", response_class=RedirectResponse)
async def credrecon_redirect(request: Request):
    """Redirect to credential reconnaissance scan page."""
    return RedirectResponse(url="/credrecon/new", status_code=302)


@router.get("/credrecon/new", response_class=HTMLResponse)
async def credrecon_new_scan(request: Request):
    """Credential reconnaissance new scan page."""
    return templates.TemplateResponse(request, "credrecon.html")


@router.get("/credrecon/scans/{scan_id}", response_class=HTMLResponse)
async def credrecon_scan_detail(request: Request, scan_id: str):
    """Credential reconnaissance scan details page."""
    return templates.TemplateResponse(request, "credrecon_scan_detail.html", {
        "scan_id": scan_id
    })


@router.get("/credrecon/results", response_class=HTMLResponse)
async def credrecon_results_page(request: Request):
    """Credential reconnaissance results page - passes only counts, JS fetches data via API."""
    successful, failed, errors = await asyncio.get_event_loop().run_in_executor(
        None, _load_aggregated_credrecon_results
    )
    return templates.TemplateResponse(request, "credrecon_results.html", {
        "successful_count": len(successful),
        "failed_count": len(failed),
        "errors_count": len(errors),
        "total": len(successful) + len(failed) + len(errors),
    })


# ===================================================================
# API routes
# ===================================================================

@router.get("/api/credrecon/results/aggregated")
async def get_aggregated_credrecon_results(
    page: int = Query(1, ge=1),
    per_page: int = Query(100, ge=1, le=50000),
    status_filter: Optional[str] = Query(None, description="Filter: success, failed, error"),
):
    """Paginated API for aggregated credrecon results across all scans."""
    successful, failed, errors = await asyncio.get_event_loop().run_in_executor(
        None, _load_aggregated_credrecon_results
    )

    if status_filter == "success":
        data = successful
    elif status_filter == "failed":
        data = failed
    elif status_filter == "error":
        data = errors
    else:
        data = successful + failed + errors

    total = len(data)
    start = (page - 1) * per_page
    page_data = data[start:start + per_page]

    return JSONResponse({
        "total": total,
        "successful_count": len(successful),
        "failed_count": len(failed),
        "error_count": len(errors),
        "page": page,
        "per_page": per_page,
        "total_pages": (total + per_page - 1) // per_page if total > 0 else 0,
        "results": page_data,
    })


@router.post("/api/credrecon")
async def create_credrecon_task(request: Request, db_session: AsyncSession = Depends(get_session)):
    """Create a new credential scanner task."""
    # Gate before the try: no workspace configured -> clean 400.
    from cygor.workspace import resolve_workspace
    _ws = resolve_workspace()
    if _ws is None:
        raise HTTPException(status_code=400, detail="No workspace configured. Set one in Settings > Workspaces before running scans.")
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
        import uuid
        scan_id = str(uuid.uuid4())

        # Create output directory: {workspace}/credrecon/credrecon-tasks/credrecon-taskid-timestamp
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        # Use short scan ID (first 8 chars) for directory name
        short_scan_id = scan_id[:8]
        # Create credrecon directory under workspace/results dir
        credrecon_base = Path(os.environ.get("CYGOR_LOAD_DIR") or _ws) / "credrecon"
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
        try:
            db_scan = CredReconScan(
                scan_id=scan_id,
                created_at=datetime.utcnow().isoformat(),
                status="pending",
                command=" ".join(cmd),
                num_targets=len(targets_content.splitlines())
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
    except HTTPException:
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error creating credrecon task: {str(e)}")


@router.get("/api/credrecon/stats")
async def get_credrecon_stats(session: AsyncSession = Depends(get_session)):
    """Get credential scanner statistics for dashboard."""
    # Search in both old and new directory structures (for backward compatibility)
    results_dirs = [
        Path("schedule-scans") / "credrecon",
        Path(settings.RESULTS_DIR) / "schedule-scans" / "credrecon",
        Path("credrecon") / "credrecon-tasks",
        Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks",
        Path("credrecon-tasks"),
        Path(settings.RESULTS_DIR) / "credrecon-tasks",
        Path(settings.RESULTS_DIR) / "credrecon",
        Path("credrecon"),
    ]

    # Load all credential scanner results from disk (completed scans)
    loaded_files: set = set()
    all_results: list = []
    for results_dir in results_dirs:
        if results_dir.exists():
            for json_file in sorted(results_dir.rglob("credrecon_results.json")):
                abs_path = json_file.resolve()
                if abs_path in loaded_files:
                    continue
                loaded_files.add(abs_path)

                try:
                    data = json.loads(json_file.read_text())
                    if isinstance(data, list):
                        all_results.extend(data)
                except Exception as e:
                    print(f"Error loading {json_file}: {e}", file=sys.stderr)

    # Deduplicate results based on unique combination of fields
    seen_results: set = set()
    unique_results: list = []
    for result in all_results:
        target = result.get("ip") or result.get("target", "")
        port = result.get("port", 0)
        protocol = result.get("protocol", "")
        username = result.get("username", "")
        password = result.get("password", "")
        status = result.get("status", "")
        timestamp = result.get("timestamp", "")
        result_key = (target, port, protocol, username, password, status, timestamp)

        if result_key not in seen_results:
            seen_results.add(result_key)
            unique_results.append(result)

    all_results = unique_results

    # Calculate stats
    successful = [r for r in all_results if r.get("status") == "success"]
    failed = [r for r in all_results if r.get("status") == "failed"]
    errors = [r for r in all_results if r.get("status") == "error"]

    # Get recent scans (last 20 results for dashboard, prioritize successful)
    recent = sorted(successful, key=lambda x: x.get("timestamp", ""), reverse=True)[:20]

    # Get ALL scan tasks from credrecon_manager (including completed ones that might not be in DB yet)
    all_task_scans = await credrecon_manager.get_all_scans()
    active_scan_info = []

    # Only include pending/running scans (current active tasks)
    active_scans = [s for s in all_task_scans if s.status.value in ['pending', 'running']]

    # Also include recently completed scans from task manager (in case DB hasn't been updated yet)
    recently_completed = [s for s in all_task_scans if s.status.value in ['completed', 'failed']]

    # Sort: running first, then pending
    def scan_sort_key(scan):
        status_priority = {'running': 0, 'pending': 1}
        return (status_priority.get(scan.status.value, 99), -scan.created_at.timestamp())

    for scan in sorted(active_scans, key=scan_sort_key):
        active_scan_info.append({
            "scan_id": scan.scan_id,
            "status": scan.status.value,
            "num_targets": scan.num_targets,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "command": " ".join(scan.command),
        })

    # Get historical scans (completed/failed) from database
    historical_scan_info = []
    db_scan_ids: set = set()

    try:
        statement = (
            select(
                CredReconScan.id,
                CredReconScan.scan_id,
                CredReconScan.created_at,
                CredReconScan.started_at,
                CredReconScan.completed_at,
                CredReconScan.status,
                CredReconScan.command,
                CredReconScan.num_targets
            )
            .where(CredReconScan.status.in_(['completed', 'failed']))
            .order_by(CredReconScan.created_at.desc())
            .limit(50)
        )
        result = await session.execute(statement)
        db_scans = result.all()

        for scan in db_scans:
            db_scan_ids.add(scan.scan_id)
            historical_scan_info.append({
                "scan_id": scan.scan_id,
                "status": scan.status,
                "num_targets": scan.num_targets,
                "created_at": scan.created_at if scan.created_at else None,
                "started_at": scan.started_at if scan.started_at else None,
                "completed_at": scan.completed_at if scan.completed_at else None,
                "command": scan.command,
            })
    except Exception as e:
        print(f"Error fetching historical scans from database: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()

    # Add recently completed scans from task manager that aren't in database yet
    for scan in recently_completed:
        if scan.scan_id not in db_scan_ids:
            historical_scan_info.append({
                "scan_id": scan.scan_id,
                "status": scan.status.value,
                "num_targets": scan.num_targets,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "command": " ".join(scan.command),
            })
            db_scan_ids.add(scan.scan_id)

    # Discover scans from JSON files on disk that aren't in database or task manager
    discovered_dirs: set = set()
    all_known_scan_ids = db_scan_ids.copy()

    for scan in all_task_scans:
        all_known_scan_ids.add(scan.scan_id)

    for results_dir in results_dirs:
        if results_dir.exists():
            for json_file in sorted(results_dir.rglob("credrecon_results.json")):
                try:
                    parent_dir = json_file.parent.name
                    if parent_dir.startswith("credrecon-") and len(parent_dir) > 10:
                        parts = parent_dir.split("-")
                        if len(parts) >= 2:
                            short_id = parts[1]

                            file_scan_id = None
                            for known_scan_id in all_known_scan_ids:
                                if known_scan_id.startswith(short_id):
                                    file_scan_id = known_scan_id
                                    break

                            if not file_scan_id:
                                try:
                                    search_statement = (
                                        select(CredReconScan.scan_id)
                                        .where(CredReconScan.scan_id.like(f"{short_id}%"))
                                        .limit(1)
                                    )
                                    search_result = await session.execute(search_statement)
                                    found_scan = search_result.scalar_one_or_none()
                                    if found_scan:
                                        file_scan_id = found_scan
                                        all_known_scan_ids.add(found_scan)
                                except Exception as e:
                                    print(f"Error searching for scan_id starting with {short_id}: {e}", file=sys.stderr)

                            if parent_dir not in discovered_dirs:
                                scan_id_to_check = file_scan_id if file_scan_id else f"discovered-{short_id}"
                                already_added = any(s.get('scan_id') == scan_id_to_check for s in historical_scan_info)

                                if not already_added:
                                    discovered_dirs.add(parent_dir)

                                    file_mtime = json_file.stat().st_mtime
                                    file_time = datetime.fromtimestamp(file_mtime)

                                    try:
                                        json_data = json.loads(json_file.read_text())
                                        num_results = len(json_data) if isinstance(json_data, list) else 0
                                    except Exception:
                                        num_results = 0

                                    scan_id_to_use = file_scan_id if file_scan_id else f"historic-{short_id}"

                                    historical_scan_info.append({
                                        "scan_id": scan_id_to_use,
                                        "status": "completed",
                                        "num_targets": num_results,
                                        "created_at": file_time.isoformat(),
                                        "started_at": file_time.isoformat(),
                                        "completed_at": file_time.isoformat(),
                                        "command": f"cygor credrecon -o {parent_dir}",
                                    })
                                    db_scan_ids.add(scan_id_to_use)
                except Exception as e:
                    print(f"Error discovering scan from {json_file}: {e}", file=sys.stderr)
                    continue

    if historical_scan_info:
        scan_ids = [s['scan_id'][:8] if s.get('scan_id') else 'N/A' for s in historical_scan_info[:5]]

    return JSONResponse({
        "successful": len(successful),
        "failed": len(failed),
        "errors": len(errors),
        "total": len(all_results),
        "recent": recent,
        "active_scans": active_scan_info,
        "historical_scans": historical_scan_info
    })


@router.get("/api/credrecon/scans")
async def list_credrecon_scans():
    """List all credential scanner scans from task manager and database."""
    # Get scans from in-memory task manager
    memory_scans = await credrecon_manager.get_all_scans()
    memory_scan_ids = {scan.scan_id for scan in memory_scans}
    result_list = [scan.to_dict() for scan in memory_scans]

    # Also get scans from database (for persistence across restarts)
    try:
        async with AsyncSession(db.engine) as session:
            stmt = select(CredReconScan).order_by(CredReconScan.created_at.desc())
            result = await session.execute(stmt)
            db_scans = result.scalars().all()

            for db_scan in db_scans:
                # Skip if already in memory (avoid duplicates)
                if db_scan.scan_id in memory_scan_ids:
                    continue

                result_list.append({
                    "scan_id": db_scan.scan_id,
                    "command": db_scan.command,
                    "num_targets": db_scan.num_targets,
                    "status": db_scan.status,
                    "created_at": db_scan.created_at,
                    "started_at": db_scan.started_at,
                    "completed_at": db_scan.completed_at,
                    "exit_code": 0 if db_scan.status == "completed" else None,
                    "output_lines": 0,
                    "error_lines": 0,
                })
    except Exception:
        pass

    # Sort by created_at descending (newest first)
    result_list.sort(key=lambda x: x.get("created_at", ""), reverse=True)

    return JSONResponse(result_list)


@router.get("/api/credrecon/scans/{scan_id}")
async def get_credrecon_scan(scan_id: str):
    """Get details of a specific credential scanner scan."""
    # Handle historic scans (from disk discovery)
    if scan_id.startswith("historic-"):
        short_id = scan_id.replace("historic-", "")

        # Find the directory matching this short_id
        discovered_json_file = None
        discovered_dir = None

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
            if results_dir.exists():
                for json_file in results_dir.rglob("credrecon_results.json"):
                    parent_dir = json_file.parent.name
                    if parent_dir.startswith("credrecon-") and short_id in parent_dir:
                        discovered_json_file = json_file
                        discovered_dir = parent_dir
                        break
                if discovered_json_file:
                    break

        if discovered_json_file:
            file_mtime = discovered_json_file.stat().st_mtime
            file_time = datetime.fromtimestamp(file_mtime)

            try:
                json_data = json.loads(discovered_json_file.read_text())
                num_results = len(json_data) if isinstance(json_data, list) else 0
            except Exception:
                num_results = 0

            scan_dict = {
                "scan_id": scan_id,
                "status": "completed",
                "num_targets": num_results,
                "created_at": file_time.isoformat(),
                "started_at": file_time.isoformat(),
                "completed_at": file_time.isoformat(),
                "command": [f"cygor", "credrecon", "-o", discovered_dir],
            }
            return JSONResponse(scan_dict)
        else:
            raise HTTPException(status_code=404, detail="Historic scan not found on disk")

    # Regular scan from task manager (in-memory)
    try:
        scan = await credrecon_manager.get_scan(scan_id)
        if scan:
            scan_dict = scan.to_dict()
            schedule_info = await _get_schedule_info_for_task(scan_id)
            if schedule_info:
                scan_dict["schedule_id"] = schedule_info["schedule_id"]
                scan_dict["schedule_name"] = schedule_info["schedule_name"]
            return JSONResponse(scan_dict)
    except Exception:
        pass

    # Fallback to database for completed/historical scans (after server restart)
    try:
        async with AsyncSession(db.engine) as session:
            stmt = select(CredReconScan).where(CredReconScan.scan_id == scan_id)
            result = await session.execute(stmt)
            db_scan = result.scalar_one_or_none()

            if db_scan:
                scan_dict = {
                    "scan_id": db_scan.scan_id,
                    "command": db_scan.command,
                    "num_targets": db_scan.num_targets,
                    "status": db_scan.status,
                    "created_at": db_scan.created_at,
                    "started_at": db_scan.started_at,
                    "completed_at": db_scan.completed_at,
                    "exit_code": 0 if db_scan.status == "completed" else None,
                    "output_lines": 0,
                    "error_lines": 0,
                }
                schedule_info = await _get_schedule_info_for_task(scan_id)
                if schedule_info:
                    scan_dict["schedule_id"] = schedule_info["schedule_id"]
                    scan_dict["schedule_name"] = schedule_info["schedule_name"]
                return JSONResponse(scan_dict)
    except Exception:
        pass

    # Last resort: reconstruct from schedule history
    history_task = await _get_task_from_schedule_history(scan_id)
    if history_task:
        return JSONResponse(history_task)

    raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/api/credrecon/scans/{scan_id}/output")
async def get_credrecon_scan_output(scan_id: str):
    """Get the output of a specific credential scanner scan."""
    # Handle historic scans (from disk discovery) - try to load output from files
    if scan_id.startswith("historic-"):
        short_id = scan_id.replace("historic-", "")

        # Find the directory matching this short_id
        historic_dir = None
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
            if results_dir.exists():
                for json_file in results_dir.rglob("credrecon_results.json"):
                    parent_dir = json_file.parent.name
                    if parent_dir.startswith("credrecon-") and short_id in parent_dir:
                        historic_dir = json_file.parent
                        break
                if historic_dir:
                    break

        if historic_dir:
            output_text = ""
            error_text = ""

            output_files = [
                historic_dir / "output.txt",
                historic_dir / "stdout.txt",
                historic_dir / "log.txt",
                historic_dir / "credrecon.log",
            ]

            for output_file in output_files:
                if output_file.exists():
                    try:
                        output_text = output_file.read_text()
                        break
                    except Exception:
                        pass

            error_files = [
                historic_dir / "errors.txt",
                historic_dir / "stderr.txt",
            ]

            for error_file in error_files:
                if error_file.exists():
                    try:
                        error_text = error_file.read_text()
                        break
                    except Exception:
                        pass

            if not output_text:
                json_file = historic_dir / "credrecon_results.json"
                if json_file.exists():
                    try:
                        results = json.loads(json_file.read_text())
                        if isinstance(results, list):
                            output_text = f"Historic scan results loaded from disk.\n"
                            output_text += f"Total results: {len(results)}\n"
                            output_text += f"Successful: {len([r for r in results if r.get('status') == 'success'])}\n"
                            output_text += f"Failed: {len([r for r in results if r.get('status') == 'failed'])}\n"
                            output_text += f"Errors: {len([r for r in results if r.get('status') == 'error'])}\n"

                            output_text += f"\n--- Detailed Results ---\n"
                            for i, result in enumerate(results[:20], 1):
                                target = result.get('ip') or result.get('target', 'N/A')
                                port = result.get('port', 'N/A')
                                protocol = result.get('protocol', 'N/A')
                                username = result.get('username', 'N/A')
                                status = result.get('status', 'N/A')
                                reason = result.get('details') or result.get('reason', 'N/A')
                                output_text += f"{i}. {target}:{port} ({protocol}) - {username} - {status} - {reason}\n"
                            if len(results) > 20:
                                output_text += f"\n... and {len(results) - 20} more results (see Results tab for full details)\n"
                    except Exception as e:
                        output_text = f"Historic scan discovered from disk. Results are available in the Results tab.\nError loading details: {str(e)}"
                else:
                    output_text = "Historic scan discovered from disk. Results are available in the Results tab."

            output_lines = output_text.split('\n') if output_text else []
            error_lines = error_text.split('\n') if error_text else []

            if output_lines and output_lines[-1] == '':
                output_lines = output_lines[:-1]
            if error_lines and error_lines[-1] == '':
                error_lines = error_lines[:-1]

            return JSONResponse({
                "output": output_lines,
                "errors": error_lines
            })
        else:
            return JSONResponse({
                "output": ["Historic scan discovered from disk. Results are available in the Results tab."],
                "errors": []
            })

    # Regular scan from task manager (in-memory)
    output = await credrecon_manager.get_scan_output(scan_id)
    if "error" not in output:
        return JSONResponse(output)

    # Fallback: try to load output from disk (scheduled scans store output files)
    disk_output = _load_credrecon_output_from_disk(scan_id)
    if disk_output:
        return JSONResponse(disk_output)

    # Fallback to database for completed/historical scans (after server restart)
    try:
        async with AsyncSession(db.engine) as session:
            stmt = select(CredReconScan).where(CredReconScan.scan_id == scan_id)
            result = await session.execute(stmt)
            db_scan = result.scalar_one_or_none()

            if db_scan:
                return JSONResponse({
                    "scan_id": scan_id,
                    "status": db_scan.status,
                    "output": [f"Scan completed. Results are available in the Results tab."],
                    "errors": [],
                    "exit_code": 0 if db_scan.status == "completed" else 1
                })
    except Exception:
        pass

    # Last resort: return empty output if task exists in schedule history
    history_task = await _get_task_from_schedule_history(scan_id)
    if history_task:
        return JSONResponse({
            "scan_id": scan_id,
            "status": history_task.get("status", "completed"),
            "output": [f"Scheduled scan completed. Output is no longer available after server restart."],
            "errors": [history_task["error"]] if history_task.get("error") else [],
            "exit_code": history_task.get("exit_code"),
        })

    raise HTTPException(status_code=404, detail="Scan not found")


@router.get("/api/credrecon/scans/{scan_id}/results")
async def get_credrecon_scan_results(
    scan_id: str,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(100, ge=1, le=1000, description="Results per page"),
    status_filter: Optional[str] = Query(None, description="Filter by status: success, failed, error, skipped"),
    session: AsyncSession = Depends(get_session),
):
    """Get parsed credential test results from database or local JSON file (paginated)."""
    try:
        # First, try to get scan from task manager (in case it's not in DB yet)
        scan_from_manager = None
        try:
            scan_from_manager = await credrecon_manager.get_scan(scan_id)
        except Exception:
            pass

        # Get the scan from database
        statement = (
            select(
                CredReconScan.id,
                CredReconScan.scan_id,
                CredReconScan.created_at,
                CredReconScan.started_at,
                CredReconScan.completed_at,
                CredReconScan.status,
                CredReconScan.command,
                CredReconScan.num_targets
            )
            .where(CredReconScan.scan_id == scan_id)
        )
        result = await session.execute(statement)
        scan_row = result.first()

        # If not in database, try to create a mock scan_row from task manager data or discovered scan
        if not scan_row:
            if scan_from_manager:
                class MockScanRow:
                    def __init__(self, scan):
                        self.id = None
                        self.scan_id = scan.scan_id
                        self.created_at = scan.created_at.isoformat() if scan.created_at else None
                        self.started_at = scan.started_at.isoformat() if scan.started_at else None
                        self.completed_at = scan.completed_at.isoformat() if scan.completed_at else None
                        self.status = scan.status.value
                        self.command = " ".join(scan.command) if scan.command else ""
                        self.num_targets = scan.num_targets

                scan_row = MockScanRow(scan_from_manager)
            elif scan_id.startswith("historic-"):
                short_id = scan_id.replace("historic-", "")

                discovered_json_file = None
                discovered_dir = None

                for results_dir in [
                    Path("schedule-scans") / "credrecon",
                    Path(settings.RESULTS_DIR) / "schedule-scans" / "credrecon",
                    Path("credrecon-tasks"),
                    Path(settings.RESULTS_DIR) / "credrecon-tasks",
                    Path("credrecon"),
                    Path(settings.RESULTS_DIR) / "credrecon",
                ]:
                    if results_dir.exists():
                        for json_file in results_dir.rglob("credrecon_results.json"):
                            parent_dir = json_file.parent.name
                            if parent_dir.startswith("credrecon-") and short_id in parent_dir:
                                discovered_json_file = json_file
                                discovered_dir = parent_dir
                                break
                        if discovered_json_file:
                            break

                if discovered_json_file:
                    file_mtime = discovered_json_file.stat().st_mtime
                    file_time = datetime.fromtimestamp(file_mtime)

                    class DiscoveredScanRow:
                        def __init__(self, scan_id, dir_name, file_time):
                            self.id = None
                            self.scan_id = scan_id
                            self.created_at = file_time.isoformat()
                            self.started_at = file_time.isoformat()
                            self.completed_at = file_time.isoformat()
                            self.status = "completed"
                            self.command = f"cygor credrecon -o {dir_name}"
                            self.num_targets = 0

                    scan_row = DiscoveredScanRow(scan_id, discovered_dir, file_time)
                else:
                    raise HTTPException(status_code=404, detail="Historic scan not found on disk")
            else:
                raise HTTPException(status_code=404, detail="Scan not found")

        # Get results for this scan from database with pagination (only if scan has a DB ID)
        db_results = []
        db_total = 0
        db_counts = {"success": 0, "failed": 0, "error": 0, "skipped": 0}
        if scan_row.id is not None:
            try:
                count_stmt = (
                    select(CredReconResult.status, func.count(CredReconResult.id))
                    .where(CredReconResult.scan_id == scan_row.id)
                    .group_by(CredReconResult.status)
                )
                count_result = await session.execute(count_stmt)
                for status_val, cnt in count_result.all():
                    db_counts[status_val] = cnt
                    db_total += cnt

                stmt = select(CredReconResult).where(CredReconResult.scan_id == scan_row.id)
                if status_filter:
                    stmt = stmt.where(CredReconResult.status == status_filter)
                stmt = stmt.order_by(CredReconResult.id).offset((page - 1) * per_page).limit(per_page)
                result = await session.execute(stmt)
                db_results = result.scalars().all()
            except Exception as e:
                print(f"Error fetching results from database: {e}", file=sys.stderr)
                db_results = []

        # If no database results, try reading from JSON file
        results = []
        if db_results:
            results = db_results
        else:
            json_file = None

            if scan_id:
                try:
                    if scan_id.startswith("historic-"):
                        short_scan_id = scan_id.replace("historic-", "")
                    elif scan_id.startswith("sched-"):
                        short_scan_id = scan_id.replace("sched-", "")[:8]
                    else:
                        short_scan_id = scan_id[:8]

                    base_dirs = [
                        Path("schedule-scans") / "credrecon",
                        Path(settings.RESULTS_DIR) / "schedule-scans" / "credrecon",
                        Path("credrecon") / "credrecon-tasks",
                        Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks",
                        Path("credrecon-tasks"),
                        Path(settings.RESULTS_DIR) / "credrecon-tasks",
                    ]

                    for base_dir in base_dirs:
                        if base_dir.exists():
                            for task_dir in base_dir.iterdir():
                                if task_dir.is_dir() and short_scan_id in task_dir.name:
                                    potential_json = task_dir / "credrecon_results.json"
                                    if potential_json.exists():
                                        json_file = potential_json
                                        break
                            if json_file:
                                break

                    if not json_file and scan_row.created_at:
                        try:
                            created_dt = datetime.fromisoformat(scan_row.created_at.replace('Z', '+00:00'))
                            timestamp = created_dt.strftime("%Y%m%d_%H%M%S")
                            new_format_paths = [
                                Path("credrecon") / "credrecon-tasks" / f"credrecon-{short_scan_id}-{timestamp}" / "credrecon_results.json",
                                Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks" / f"credrecon-{short_scan_id}-{timestamp}" / "credrecon_results.json",
                                Path("credrecon-tasks") / f"credrecon-{short_scan_id}-{timestamp}" / "credrecon_results.json",
                                Path(settings.RESULTS_DIR) / "credrecon-tasks" / f"credrecon-{short_scan_id}-{timestamp}" / "credrecon_results.json",
                            ]
                            for potential_path in new_format_paths:
                                if potential_path.exists():
                                    json_file = potential_path
                                    break
                        except Exception as e:
                            print(f"Error reconstructing timestamp path: {e}", file=sys.stderr)
                except Exception as e:
                    print(f"Error reconstructing new format path: {e}", file=sys.stderr)

            # Method 1b: Try old format paths (for backward compatibility)
            if not json_file and scan_row.created_at:
                try:
                    created_dt = datetime.fromisoformat(scan_row.created_at.replace('Z', '+00:00'))
                    timestamp1 = created_dt.strftime("%Y-%m-%d_%H-%M-%S")
                    timestamp2 = created_dt.strftime("%Y%m%d_%H%M%S")

                    potential_paths = [
                        Path("credrecon") / timestamp1 / "credrecon_results.json",
                        Path(settings.RESULTS_DIR) / "credrecon" / timestamp1 / "credrecon_results.json",
                        Path("credrecon") / timestamp1 / timestamp2 / "credrecon_results.json",
                        Path(settings.RESULTS_DIR) / "credrecon" / timestamp1 / timestamp2 / "credrecon_results.json",
                        Path("credrecon") / timestamp2 / "credrecon_results.json",
                        Path(settings.RESULTS_DIR) / "credrecon" / timestamp2 / "credrecon_results.json",
                    ]

                    for potential_path in potential_paths:
                        if potential_path.exists():
                            json_file = potential_path
                            break
                except Exception as e:
                    print(f"Error parsing timestamp: {e}", file=sys.stderr)

            # Method 2: Search for JSON files in credrecon directories and match by timestamp or scan_id
            if not json_file:
                base_dirs = [
                    Path("schedule-scans") / "credrecon",
                    Path(settings.RESULTS_DIR) / "schedule-scans" / "credrecon",
                    Path("credrecon") / "credrecon-tasks",
                    Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks",
                    Path("credrecon-tasks"),
                    Path(settings.RESULTS_DIR) / "credrecon-tasks",
                    Path(settings.RESULTS_DIR) / "credrecon",
                    Path("credrecon"),
                    Path(settings.RESULTS_DIR),
                ]

                for base_dir in base_dirs:
                    if not base_dir.exists():
                        continue

                    for json_path in base_dir.rglob("credrecon_results.json"):
                        try:
                            parent_dir = json_path.parent.name
                            match_id = scan_id
                            if scan_id.startswith("sched-"):
                                match_id = scan_id.replace("sched-", "")
                            elif scan_id.startswith("historic-"):
                                match_id = scan_id.replace("historic-", "")
                            if match_id and match_id[:8] in parent_dir:
                                json_file = json_path
                                break

                            file_mtime = datetime.fromtimestamp(json_path.stat().st_mtime)
                            if scan_row.created_at:
                                try:
                                    scan_time = datetime.fromisoformat(scan_row.created_at.replace('Z', '+00:00'))
                                    time_diff = abs((file_mtime - scan_time.replace(tzinfo=None)).total_seconds())
                                    if time_diff < 600:
                                        json_file = json_path
                                        break
                                except Exception:
                                    pass
                        except Exception:
                            continue

                    if json_file:
                        break

            # Read JSON file if found
            if json_file and json_file.exists():
                try:
                    file_results = json.loads(json_file.read_text())
                    if not isinstance(file_results, list):
                        file_results = []

                    class FileResult:
                        def __init__(self, data):
                            self.target = data.get('ip', data.get('target', ''))
                            self.port = data.get('port', 0)
                            self.protocol = data.get('protocol', '')
                            self.service = data.get('service')
                            self.username = data.get('username', '')
                            self.password = data.get('password')
                            self.status = data.get('status', '')
                            self.reason = data.get('details', data.get('reason'))
                            self.tested_at = data.get('timestamp')
                            self.source_ip = data.get('source_ip')

                    results = [FileResult(r) for r in file_results]
                except Exception as e:
                    print(f"Error reading JSON results from {json_file}: {e}", file=sys.stderr)
                    results = []
            else:
                results = []

        # Helper function to serialize result with fingerprint
        def serialize_result(r):
            result_dict = {
                "target": r.target,
                "port": r.port,
                "protocol": r.protocol,
                "service": r.service,
                "username": r.username,
                "password": r.password,
                "reason": r.reason,
                "tested_at": r.tested_at,
            }
            if hasattr(r, 'fingerprint_product'):
                result_dict["fingerprint"] = {
                    "product": getattr(r, 'fingerprint_product', None),
                    "version": getattr(r, 'fingerprint_version', None),
                    "confidence": getattr(r, 'fingerprint_confidence', None),
                    "details": None
                }
                if getattr(r, 'fingerprint_raw', None):
                    try:
                        result_dict["fingerprint"]["details"] = json.loads(r.fingerprint_raw)
                    except Exception:
                        pass
                result_dict["credential_selection"] = getattr(r, 'credential_selection', None)
            if hasattr(r, 'source_ip') and getattr(r, 'source_ip', None):
                result_dict["source_ip"] = r.source_ip
            return result_dict

        # If we have DB results with counts, use paginated response
        if db_total > 0:
            return JSONResponse({
                "scan_id": scan_id,
                "total": db_total,
                "successful": db_counts.get("success", 0),
                "failed": db_counts.get("failed", 0),
                "errors": db_counts.get("error", 0),
                "skipped": db_counts.get("skipped", 0),
                "page": page,
                "per_page": per_page,
                "total_pages": (db_total + per_page - 1) // per_page,
                "results": {
                    "successful": [serialize_result(r) for r in db_results if r.status == "success"],
                    "failed": [serialize_result(r) for r in db_results if r.status == "failed"],
                    "errors": [serialize_result(r) for r in db_results if r.status == "error"],
                    "skipped": [serialize_result(r) for r in db_results if r.status == "skipped"],
                }
            })

        # For file-based results, apply pagination in memory
        if status_filter:
            results = [r for r in results if r.status == status_filter]

        total = len(results)
        start = (page - 1) * per_page
        end = start + per_page
        page_results = results[start:end]

        successful_count = sum(1 for r in results if r.status == "success")
        failed_count = sum(1 for r in results if r.status == "failed")
        error_count = sum(1 for r in results if r.status == "error")
        skipped_count = sum(1 for r in results if r.status == "skipped")

        successful = [r for r in page_results if r.status == "success"]
        failed = [r for r in page_results if r.status == "failed"]
        errors_list = [r for r in page_results if r.status == "error"]
        skipped = [r for r in page_results if r.status == "skipped"]

        return JSONResponse({
            "scan_id": scan_id,
            "total": total,
            "successful": successful_count,
            "failed": failed_count,
            "errors": error_count,
            "skipped": skipped_count,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page if total > 0 else 0,
            "results": {
                "successful": [serialize_result(r) for r in successful],
                "failed": [serialize_result(r) for r in failed],
                "errors": [serialize_result(r) for r in errors_list],
                "skipped": [serialize_result(r) for r in skipped],
            }
        })
    except HTTPException:
        # Re-raise framework exceptions (404 "not found", etc.) untouched
        # so they don't get re-wrapped as a 500 by the catch-all below.
        raise
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error fetching results: {str(e)}")


@router.delete("/api/credrecon/scans/{scan_id}")
async def cancel_credrecon_scan(scan_id: str):
    """Cancel a running credential scanner scan."""
    success = await credrecon_manager.cancel_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found or cannot be cancelled")
    return JSONResponse({"status": "cancelled"})


@router.get("/api/credrecon/scans/{scan_id}/stream")
async def stream_credrecon_scan(scan_id: str):
    """Server-Sent Events stream for live scan status and result count updates.
    Clients connect once and receive incremental updates instead of polling."""
    from starlette.responses import StreamingResponse

    async def event_generator():
        last_status = None
        last_total = -1
        while True:
            try:
                scan = await credrecon_manager.get_scan(scan_id)
                if not scan:
                    yield f"data: {json.dumps({'event': 'error', 'message': 'Scan not found'})}\n\n"
                    break

                current_status = scan.status.value if hasattr(scan.status, 'value') else scan.status
                current_total = scan.results_count if hasattr(scan, 'results_count') else 0

                if current_status != last_status or current_total != last_total:
                    payload = {
                        "event": "update",
                        "status": current_status,
                        "results_count": current_total,
                        "progress": getattr(scan, 'progress', None),
                    }
                    yield f"data: {json.dumps(payload)}\n\n"
                    last_status = current_status
                    last_total = current_total

                if current_status in ('completed', 'failed', 'cancelled'):
                    yield f"data: {json.dumps({'event': 'done', 'status': current_status})}\n\n"
                    break

                await asyncio.sleep(2)
            except Exception as e:
                yield f"data: {json.dumps({'event': 'error', 'message': str(e)})}\n\n"
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ============================================================
# CREDRECON CREDENTIAL DATABASE API ENDPOINTS
# ============================================================

@router.post("/api/credrecon/credentials/sync")
async def sync_external_credentials(request: Request):
    """Sync credentials from external sources."""
    try:
        from cygor.credrecon.sources.sync import CredentialSyncEngine

        body = await request.json()
        sources = body.get("sources", ["defaultcreds"])
        force = body.get("force", False)

        sync_engine = CredentialSyncEngine()
        result = sync_engine.sync_sources(sources, force=force)

        return JSONResponse({
            "success": result.success,
            "sources_synced": result.sources_synced,
            "sources_failed": result.sources_failed,
            "total_credentials": result.total_credentials,
            "errors": result.errors,
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({
            "success": False,
            "error": str(e),
        }, status_code=500)


@router.get("/api/credrecon/credentials/stats")
async def get_credential_database_stats():
    """Get statistics about the credential database."""
    try:
        from cygor.credrecon.credentials.loader import load_all_credentials, get_credential_stats
        from cygor.credrecon.sources.sync import CredentialSyncEngine

        # Get builtin credential stats
        cred_db = load_all_credentials()
        stats = get_credential_stats(cred_db)

        # Get external source cache stats
        sync_engine = CredentialSyncEngine()
        cache_stats = sync_engine.get_cache_stats()
        sync_status = sync_engine.get_sync_status()

        # Get counts by source from stats (builtin vs external)
        by_source = stats.get("by_source", {})
        builtin_count = by_source.get("builtin", 0)
        external_count = by_source.get("external", 0) + by_source.get("defaultcreds", 0) + by_source.get("cirt", 0)

        return JSONResponse({
            "builtin": {
                "total_credentials": builtin_count,
                "total_profiles": stats["total_profiles"],
                "by_category": stats["by_category"],
                "by_protocol": stats["by_protocol"],
                "by_vendor": stats.get("by_vendor", {}),
            },
            "external": {
                "cache_dir": cache_stats["cache_dir"],
                "num_sources": cache_stats["num_sources"],
                "total_credentials": external_count,
                "sources": sync_status,
            },
            "combined": {
                "total": stats["total_credentials"],
            }
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return JSONResponse({
            "error": str(e),
            "builtin": {"total_credentials": 0},
            "external": {"total_credentials": 0},
            "combined": {"total": 0}
        })
