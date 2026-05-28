"""
Scheduler routes -- schedule UI pages and schedule API endpoints.

Extracted from cygor.webapp.main to keep the main module manageable.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from .. import db
from ..db import get_session
from ..config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["scheduler"])

# ---------------------------------------------------------------------------
# Templates -- injected at app startup via ``set_templates``
# ---------------------------------------------------------------------------
templates = None


def set_templates(tmpl):
    """Set the Jinja2Templates instance used by the UI page routes."""
    global templates
    templates = tmpl


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class SyncRequest(BaseModel):
    scan_dir: Optional[str] = None  # Optional specific directory to sync (e.g., ondemand-scans/2025-01-06_12-34-56)
    verbose: bool = False  # When true, emit per-file/per-host ingest output to stdout. Default is a one-line summary.


class CreateScheduledTaskRequest(BaseModel):
    name: str
    description: Optional[str] = None
    task_type: str  # 'port_scan', 'module_scan', 'credrecon'
    config: dict  # Task-specific configuration
    schedule_type: str  # 'cron', 'interval', 'date'
    schedule_config: dict  # Schedule-specific configuration
    timezone: str = "UTC"
    max_runs: Optional[int] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    allow_concurrent: bool = False
    max_concurrent_runs: int = 1
    check_resources: bool = True
    max_cpu_percent: Optional[float] = 80.0
    max_memory_percent: Optional[float] = 80.0
    max_retries: int = 3
    retry_delay_seconds: int = 300
    retry_backoff: bool = True
    misfire_grace_time: Optional[int] = None
    stall_timeout_seconds: Optional[int] = None


class UpdateScheduledTaskRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    config: Optional[dict] = None
    schedule_type: Optional[str] = None
    schedule_config: Optional[dict] = None
    timezone: Optional[str] = None
    max_runs: Optional[int] = None
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    allow_concurrent: Optional[bool] = None
    max_concurrent_runs: Optional[int] = None
    check_resources: Optional[bool] = None
    max_cpu_percent: Optional[float] = None
    max_memory_percent: Optional[float] = None
    is_active: Optional[bool] = None
    is_paused: Optional[bool] = None
    max_retries: Optional[int] = None
    retry_delay_seconds: Optional[int] = None
    retry_backoff: Optional[bool] = None
    misfire_grace_time: Optional[int] = None
    stall_timeout_seconds: Optional[int] = None


class RescheduleRequest(BaseModel):
    schedule_config: Optional[dict] = None
    schedule_type: Optional[str] = None
    end_date: Optional[str] = None
    start_date: Optional[str] = None
    timezone: Optional[str] = None
    max_runs: Optional[int] = -1


class ReactivateRequest(BaseModel):
    reset_run_count: bool = False
    end_date: Optional[str] = None
    max_runs: Optional[int] = -1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _naive_local_to_utc_iso(naive_dt, tz_name: str) -> str:
    """Convert a naive datetime (in a schedule's local timezone) to a UTC ISO string with 'Z'."""
    import pytz as _pytz
    try:
        tz = _pytz.timezone(tz_name or 'UTC')
        localized = tz.localize(naive_dt)
        utc_dt = localized.astimezone(_pytz.utc)
        return utc_dt.strftime('%Y-%m-%dT%H:%M:%SZ')
    except Exception:
        # Fallback: treat as UTC
        return naive_dt.isoformat() + 'Z'


# ============================================================================
# Schedule UI Pages
# ============================================================================


@router.get("/schedules", response_class=HTMLResponse)
async def schedules_page(request: Request):
    """Scheduled tasks list page."""
    return templates.TemplateResponse(request, "schedules.html")


@router.get("/schedules/new", response_class=HTMLResponse)
async def new_schedule_page(request: Request):
    """New schedule form page."""
    return templates.TemplateResponse(request, "schedule_form.html")


@router.get("/schedules/{schedule_id}", response_class=HTMLResponse)
async def schedule_detail_page(request: Request, schedule_id: int):
    """Schedule detail and history page."""
    return templates.TemplateResponse(request, "schedule_detail.html", {
        "schedule_id": schedule_id
    })


# ============================================================================
# Scheduled Tasks API Endpoints
# ============================================================================


@router.get("/api/schedules")
async def list_scheduled_tasks(
    request: Request,
    session: AsyncSession = Depends(db.get_session),
    task_type: Optional[str] = None,
    is_active: Optional[bool] = None,
    is_paused: Optional[bool] = None
):
    """List all scheduled tasks with optional filtering."""
    from sqlmodel import select
    from ..models import ScheduledTask

    statement = select(ScheduledTask)

    # Apply filters
    if task_type:
        statement = statement.where(ScheduledTask.task_type == task_type)
    if is_active is not None:
        statement = statement.where(ScheduledTask.is_active == is_active)
    if is_paused is not None:
        statement = statement.where(ScheduledTask.is_paused == is_paused)

    statement = statement.order_by(ScheduledTask.created_at.desc())

    result = await session.execute(statement)
    scheduled_tasks = result.scalars().all()

    return JSONResponse({
        "schedules": [
            {
                "id": task.id,
                "name": task.name,
                "description": task.description,
                "task_type": task.task_type,
                "schedule_type": task.schedule_type,
                "timezone": task.timezone,
                "is_active": task.is_active,
                "is_paused": task.is_paused,
                "next_run": task.next_run.isoformat() + "Z" if task.next_run else None,
                "last_run": task.last_run.isoformat() + "Z" if task.last_run else None,
                "last_run_status": task.last_run_status,
                "run_count": task.run_count,
                "max_retries": task.max_retries,
                "retry_delay_seconds": task.retry_delay_seconds,
                "retry_backoff": task.retry_backoff,
                "misfire_grace_time": task.misfire_grace_time,
                "stall_timeout_seconds": task.stall_timeout_seconds,
                "created_at": task.created_at.isoformat() + "Z",
                "user_id": task.user_id
            }
            for task in scheduled_tasks
        ]
    })


@router.post("/api/schedules")
async def create_scheduled_task(
    request: Request,
    req: CreateScheduledTaskRequest,
    session: AsyncSession = Depends(db.get_session)
):
    """Create a new scheduled task."""
    from ..scheduler import get_scheduler_manager

    try:
        scheduler_mgr = get_scheduler_manager()

        # Parse dates if provided
        # These should be naive local datetimes matching the schedule's timezone.
        # Strip trailing 'Z' if present (legacy format) -- the scheduler will
        # localize naive datetimes to the schedule's configured timezone.
        start_date = None
        end_date = None
        if req.start_date:
            sd_str = req.start_date.rstrip('Z')
            start_date = datetime.fromisoformat(sd_str)
            if start_date.tzinfo is not None:
                # If timezone-aware, convert to naive in schedule's timezone
                import pytz as _pytz
                sched_tz = _pytz.timezone(req.timezone or 'UTC')
                start_date = start_date.astimezone(sched_tz).replace(tzinfo=None)
        if req.end_date:
            ed_str = req.end_date.rstrip('Z')
            end_date = datetime.fromisoformat(ed_str)
            if end_date.tzinfo is not None:
                import pytz as _pytz
                sched_tz = _pytz.timezone(req.timezone or 'UTC')
                end_date = end_date.astimezone(sched_tz).replace(tzinfo=None)

        scheduled_task = await scheduler_mgr.create_scheduled_task(
            session=session,
            name=req.name,
            task_type=req.task_type,
            config=req.config,
            schedule_type=req.schedule_type,
            schedule_config=req.schedule_config,
            user_id=None,
            description=req.description,
            timezone_str=req.timezone,
            max_runs=req.max_runs,
            start_date=start_date,
            end_date=end_date,
            allow_concurrent=req.allow_concurrent,
            max_concurrent_runs=req.max_concurrent_runs,
            check_resources=req.check_resources,
            max_cpu_percent=req.max_cpu_percent,
            max_memory_percent=req.max_memory_percent,
            max_retries=req.max_retries,
            retry_delay_seconds=req.retry_delay_seconds,
            retry_backoff=req.retry_backoff,
            misfire_grace_time=req.misfire_grace_time,
            stall_timeout_seconds=req.stall_timeout_seconds
        )

        return JSONResponse({
            "status": "created",
            "schedule": {
                "id": scheduled_task.id,
                "name": scheduled_task.name,
                "task_type": scheduled_task.task_type,
                "is_active": scheduled_task.is_active,
                "is_paused": scheduled_task.is_paused,
                "next_run": scheduled_task.next_run.isoformat() + "Z" if scheduled_task.next_run else None,
                "apscheduler_job_id": scheduled_task.apscheduler_job_id
            }
        })
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Failed to create scheduled task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to create scheduled task: {str(e)}")


@router.get("/api/schedules/{schedule_id}")
async def get_scheduled_task(
    request: Request,
    schedule_id: int,
    session: AsyncSession = Depends(db.get_session)
):
    """Get details of a specific scheduled task."""
    from sqlmodel import select
    from ..models import ScheduledTask

    statement = select(ScheduledTask).where(ScheduledTask.id == schedule_id)
    result = await session.execute(statement)
    scheduled_task = result.scalar_one_or_none()

    if not scheduled_task:
        raise HTTPException(status_code=404, detail="Scheduled task not found")


    return JSONResponse({
        "id": scheduled_task.id,
        "name": scheduled_task.name,
        "description": scheduled_task.description,
        "task_type": scheduled_task.task_type,
        "config": json.loads(scheduled_task.config),
        "schedule_type": scheduled_task.schedule_type,
        "schedule_config": json.loads(scheduled_task.schedule_config),
        "timezone": scheduled_task.timezone,
        "is_active": scheduled_task.is_active,
        "is_paused": scheduled_task.is_paused,
        "next_run": scheduled_task.next_run.isoformat() + "Z" if scheduled_task.next_run else None,
        "last_run": scheduled_task.last_run.isoformat() + "Z" if scheduled_task.last_run else None,
        "last_run_status": scheduled_task.last_run_status,
        "last_task_id": scheduled_task.last_task_id,
        "run_count": scheduled_task.run_count,
        "max_runs": scheduled_task.max_runs,
        "start_date": _naive_local_to_utc_iso(scheduled_task.start_date, scheduled_task.timezone) if scheduled_task.start_date else None,
        "end_date": _naive_local_to_utc_iso(scheduled_task.end_date, scheduled_task.timezone) if scheduled_task.end_date else None,
        "allow_concurrent": scheduled_task.allow_concurrent,
        "max_concurrent_runs": scheduled_task.max_concurrent_runs,
        "check_resources": scheduled_task.check_resources,
        "max_cpu_percent": scheduled_task.max_cpu_percent,
        "max_memory_percent": scheduled_task.max_memory_percent,
        "max_retries": scheduled_task.max_retries,
        "retry_delay_seconds": scheduled_task.retry_delay_seconds,
        "retry_backoff": scheduled_task.retry_backoff,
        "misfire_grace_time": scheduled_task.misfire_grace_time,
        "stall_timeout_seconds": scheduled_task.stall_timeout_seconds,
        "created_at": scheduled_task.created_at.isoformat() + "Z",
        "updated_at": scheduled_task.updated_at.isoformat() + "Z",
        "user_id": scheduled_task.user_id
    })


@router.put("/api/schedules/{schedule_id}")
async def update_scheduled_task(
    request: Request,
    schedule_id: int,
    req: UpdateScheduledTaskRequest,
    session: AsyncSession = Depends(db.get_session)
):
    """Update a scheduled task."""
    from sqlmodel import select
    from ..models import ScheduledTask
    from ..scheduler import get_scheduler_manager

    statement = select(ScheduledTask).where(ScheduledTask.id == schedule_id)
    result = await session.execute(statement)
    scheduled_task = result.scalar_one_or_none()

    if not scheduled_task:
        raise HTTPException(status_code=404, detail="Scheduled task not found")


    try:
        scheduler_mgr = get_scheduler_manager()

        # Build updates dict
        # Determine schedule timezone for date parsing
        update_tz_str = req.timezone or (scheduled_task.timezone if scheduled_task else 'UTC')
        updates = {}
        for field, value in req.dict(exclude_unset=True).items():
            # Allow clearing start_date/end_date by passing null
            if field in ['start_date', 'end_date']:
                if isinstance(value, str):
                    # Strip trailing 'Z' -- dates should be naive in the schedule's timezone
                    clean = value.rstrip('Z')
                    dt = datetime.fromisoformat(clean)
                    if dt.tzinfo is not None:
                        import pytz as _pytz
                        sched_tz = _pytz.timezone(update_tz_str)
                        dt = dt.astimezone(sched_tz).replace(tzinfo=None)
                    updates[field] = dt
                else:
                    updates[field] = None  # Explicitly clear the date
            elif value is not None:
                updates[field] = value

        updated_task = await scheduler_mgr.update_scheduled_task(
            session=session,
            task_id=schedule_id,
            **updates
        )

        if not updated_task:
            raise HTTPException(status_code=404, detail="Scheduled task not found")

        return JSONResponse({
            "status": "updated",
            "schedule": {
                "id": updated_task.id,
                "name": updated_task.name,
                "next_run": updated_task.next_run.isoformat() + "Z" if updated_task.next_run else None
            }
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update scheduled task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to update scheduled task: {str(e)}")


@router.delete("/api/schedules/{schedule_id}")
async def delete_scheduled_task(
    request: Request,
    schedule_id: int,
    session: AsyncSession = Depends(db.get_session)
):
    """Delete a scheduled task."""
    from sqlmodel import select
    from ..models import ScheduledTask
    from ..scheduler import get_scheduler_manager

    statement = select(ScheduledTask).where(ScheduledTask.id == schedule_id)
    result = await session.execute(statement)
    scheduled_task = result.scalar_one_or_none()

    if not scheduled_task:
        raise HTTPException(status_code=404, detail="Scheduled task not found")


    try:
        scheduler_mgr = get_scheduler_manager()
        success = await scheduler_mgr.delete_scheduled_task(session, schedule_id)

        if not success:
            raise HTTPException(status_code=404, detail="Scheduled task not found")

        return JSONResponse({"status": "deleted"})
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete scheduled task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to delete scheduled task: {str(e)}")


@router.post("/api/schedules/{schedule_id}/pause")
async def pause_scheduled_task(
    request: Request,
    schedule_id: int,
    session: AsyncSession = Depends(db.get_session)
):
    """Pause a scheduled task."""
    from sqlmodel import select
    from ..models import ScheduledTask
    from ..scheduler import get_scheduler_manager

    statement = select(ScheduledTask).where(ScheduledTask.id == schedule_id)
    result = await session.execute(statement)
    scheduled_task = result.scalar_one_or_none()

    if not scheduled_task:
        raise HTTPException(status_code=404, detail="Scheduled task not found")


    try:
        scheduler_mgr = get_scheduler_manager()
        success = await scheduler_mgr.pause_scheduled_task(session, schedule_id)

        if not success:
            raise HTTPException(status_code=404, detail="Scheduled task not found")

        return JSONResponse({"status": "paused"})
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to pause scheduled task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to pause scheduled task: {str(e)}")


@router.post("/api/schedules/{schedule_id}/resume")
async def resume_scheduled_task(
    request: Request,
    schedule_id: int,
    session: AsyncSession = Depends(db.get_session)
):
    """Resume a paused scheduled task."""
    from sqlmodel import select
    from ..models import ScheduledTask
    from ..scheduler import get_scheduler_manager

    statement = select(ScheduledTask).where(ScheduledTask.id == schedule_id)
    result = await session.execute(statement)
    scheduled_task = result.scalar_one_or_none()

    if not scheduled_task:
        raise HTTPException(status_code=404, detail="Scheduled task not found")


    try:
        scheduler_mgr = get_scheduler_manager()
        success = await scheduler_mgr.resume_scheduled_task(session, schedule_id)

        if not success:
            raise HTTPException(status_code=404, detail="Scheduled task not found")

        return JSONResponse({"status": "resumed"})
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to resume scheduled task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to resume scheduled task: {str(e)}")


@router.post("/api/schedules/{schedule_id}/trigger")
async def trigger_scheduled_task_now(
    request: Request,
    schedule_id: int,
    session: AsyncSession = Depends(db.get_session)
):
    """Manually trigger a scheduled task to run immediately."""
    from sqlmodel import select
    from ..models import ScheduledTask
    from ..scheduler import get_scheduler_manager

    statement = select(ScheduledTask).where(ScheduledTask.id == schedule_id)
    result = await session.execute(statement)
    scheduled_task = result.scalar_one_or_none()

    if not scheduled_task:
        raise HTTPException(status_code=404, detail="Scheduled task not found")


    try:
        scheduler_mgr = get_scheduler_manager()
        task_id = await scheduler_mgr.trigger_now(session, schedule_id)

        if not task_id:
            raise HTTPException(status_code=500, detail="Failed to trigger task")

        return JSONResponse({
            "status": "triggered",
            "task_id": task_id,
            "task_type": scheduled_task.task_type
        })
    except Exception as e:
        logger.error(f"Failed to trigger scheduled task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to trigger scheduled task: {str(e)}")


@router.post("/api/schedules/{schedule_id}/reschedule")
async def reschedule_task(
    request: Request,
    schedule_id: int,
    req: RescheduleRequest,
    session: AsyncSession = Depends(db.get_session)
):
    """Reschedule a task - change schedule config, dates, or timezone."""
    from sqlmodel import select
    from ..models import ScheduledTask
    from ..scheduler import get_scheduler_manager

    statement = select(ScheduledTask).where(ScheduledTask.id == schedule_id)
    result = await session.execute(statement)
    scheduled_task = result.scalar_one_or_none()

    if not scheduled_task:
        raise HTTPException(status_code=404, detail="Scheduled task not found")


    try:
        scheduler_mgr = get_scheduler_manager()

        updates = {}
        if req.schedule_config is not None:
            updates['schedule_config'] = req.schedule_config
        if req.schedule_type is not None:
            updates['schedule_type'] = req.schedule_type
        if req.timezone is not None:
            updates['timezone'] = req.timezone
        if req.max_runs != -1:
            updates['max_runs'] = req.max_runs

        if req.start_date is not None:
            sd_str = req.start_date.rstrip('Z')
            updates['start_date'] = datetime.fromisoformat(sd_str) if sd_str else None
        if req.end_date is not None:
            ed_str = req.end_date.rstrip('Z')
            updates['end_date'] = datetime.fromisoformat(ed_str) if ed_str else None

        updated = await scheduler_mgr.update_scheduled_task(session, schedule_id, **updates)
        if not updated:
            raise HTTPException(status_code=404, detail="Scheduled task not found")

        return JSONResponse({
            "status": "rescheduled",
            "next_run": updated.next_run.isoformat() + "Z" if updated.next_run else None
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reschedule task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to reschedule: {str(e)}")


@router.post("/api/schedules/{schedule_id}/reactivate")
async def reactivate_task(
    request: Request,
    schedule_id: int,
    req: ReactivateRequest,
    session: AsyncSession = Depends(db.get_session)
):
    """Reactivate a task that was auto-deactivated by max_runs or end_date."""
    from sqlmodel import select
    from ..models import ScheduledTask
    from ..scheduler import get_scheduler_manager

    statement = select(ScheduledTask).where(ScheduledTask.id == schedule_id)
    result = await session.execute(statement)
    scheduled_task = result.scalar_one_or_none()

    if not scheduled_task:
        raise HTTPException(status_code=404, detail="Scheduled task not found")


    try:
        scheduler_mgr = get_scheduler_manager()

        end_date = None
        if req.end_date:
            ed_str = req.end_date.rstrip('Z')
            end_date = datetime.fromisoformat(ed_str)

        result = await scheduler_mgr.reactivate_scheduled_task(
            session, schedule_id,
            reset_run_count=req.reset_run_count,
            end_date=end_date,
            max_runs=req.max_runs
        )

        if not result:
            raise HTTPException(status_code=404, detail="Scheduled task not found")

        return JSONResponse({
            "status": "reactivated",
            "next_run": result.next_run.isoformat() + "Z" if result.next_run else None
        })
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reactivate task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to reactivate: {str(e)}")


@router.post("/api/schedules/{schedule_id}/clear-stuck")
async def clear_stuck_scheduled_task(
    request: Request,
    schedule_id: int,
    session: AsyncSession = Depends(db.get_session)
):
    """Clear a stuck scheduled task from the running tasks tracking."""
    from sqlmodel import select
    from ..models import ScheduledTask, ScheduledTaskHistory
    from ..scheduler import get_scheduler_manager


    statement = select(ScheduledTask).where(ScheduledTask.id == schedule_id)
    result = await session.execute(statement)
    scheduled_task = result.scalar_one_or_none()

    if not scheduled_task:
        raise HTTPException(status_code=404, detail="Scheduled task not found")


    try:
        scheduler_mgr = get_scheduler_manager()

        # Get the current running task ID if any
        old_task_id = scheduler_mgr.running_tasks.get(schedule_id)

        # Clear from running tasks
        if schedule_id in scheduler_mgr.running_tasks:
            scheduler_mgr.running_tasks.pop(schedule_id)

        # Update any stuck history records to 'failed'
        history_statement = (
            select(ScheduledTaskHistory)
            .where(ScheduledTaskHistory.scheduled_task_id == schedule_id)
            .where(ScheduledTaskHistory.status == 'running')
        )
        history_result = await session.execute(history_statement)
        stuck_records = history_result.scalars().all()

        from datetime import datetime
        for record in stuck_records:
            record.status = 'failed'
            record.completed_at = datetime.utcnow()
            record.error = 'Manually cleared as stuck'
            if record.started_at:
                record.duration_seconds = (record.completed_at - record.started_at).total_seconds()

        # Update scheduled task status
        if scheduled_task.last_run_status == 'running':
            scheduled_task.last_run_status = 'failed'

        await session.commit()

        return JSONResponse({
            "status": "cleared",
            "cleared_task_id": old_task_id,
            "stuck_records_updated": len(stuck_records)
        })
    except Exception as e:
        logger.error(f"Failed to clear stuck scheduled task: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to clear stuck task: {str(e)}")


@router.get("/api/schedules/{schedule_id}/history")
async def get_scheduled_task_history(
    request: Request,
    schedule_id: int,
    session: AsyncSession = Depends(db.get_session),
    limit: int = 50,
    offset: int = 0,
    page: int = 1
):
    """Get execution history for a scheduled task with pagination."""
    from sqlmodel import select
    from ..models import ScheduledTask
    from ..scheduler import get_scheduler_manager

    statement = select(ScheduledTask).where(ScheduledTask.id == schedule_id)
    result = await session.execute(statement)
    scheduled_task = result.scalar_one_or_none()

    if not scheduled_task:
        raise HTTPException(status_code=404, detail="Scheduled task not found")


    try:
        scheduler_mgr = get_scheduler_manager()

        # Calculate offset from page if offset not explicitly provided
        if offset == 0 and page > 1:
            offset = (page - 1) * limit

        history, total_count = await scheduler_mgr.get_scheduled_task_history(session, schedule_id, limit, offset)

        # Calculate pagination metadata
        total_pages = (total_count + limit - 1) // limit if limit > 0 else 1
        current_page = (offset // limit) + 1 if limit > 0 else 1

        return JSONResponse({
            "history": [
                {
                    "id": h.id,
                    "task_id": h.task_id,
                    "status": h.status,
                    "scheduled_time": h.scheduled_time.isoformat() + "Z",
                    "started_at": h.started_at.isoformat() + "Z" if h.started_at else None,
                    "completed_at": h.completed_at.isoformat() + "Z" if h.completed_at else None,
                    "duration_seconds": h.duration_seconds,
                    "message": h.message,
                    "error": h.error,
                    "cpu_percent": h.cpu_percent,
                    "memory_percent": h.memory_percent,
                    "resources_ok": h.resources_ok,
                    "output_path": h.output_path,
                    "retry_attempt": h.retry_attempt,
                    "retry_of_history_id": h.retry_of_history_id
                }
                for h in history
            ],
            "pagination": {
                "total_count": total_count,
                "total_pages": total_pages,
                "current_page": current_page,
                "page_size": limit,
                "has_next": current_page < total_pages,
                "has_prev": current_page > 1
            }
        })
    except Exception as e:
        logger.error(f"Failed to get scheduled task history: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to get history: {str(e)}")


# ============================================================================
# End Scheduled Tasks API Endpoints
# ============================================================================


@router.post("/api/sync-database")
async def sync_database(req: Optional[SyncRequest] = None):
    """
    Sync database by ingesting scan results.

    If scan_dir is provided, only syncs that specific directory (fast, for on-demand scans).
    Otherwise, syncs the entire results directory (slower, for full refresh).
    """
    from ..ingest import ingest_directory
    from ..models import Host, Port

    # Import SYNC_HISTORY from the main module so the list stays shared
    from ..main import SYNC_HISTORY

    base_dir = os.environ.get("CYGOR_LOAD_DIR") or settings.RESULTS_DIR
    verbose_flag = bool(req and req.verbose)
    verbose_level = 1 if verbose_flag else 0

    # Determine which directory to sync
    if req and req.scan_dir:
        load_dir = Path(base_dir) / req.scan_dir
        sync_label = req.scan_dir
        if not load_dir.exists():
            return JSONResponse({
                "status": "error",
                "error": f"Scan directory not found: {load_dir}"
            }, status_code=404)
        if verbose_flag:
            print(f"[*] Fast sync: ingesting only {req.scan_dir}")
    else:
        load_dir = Path(base_dir)
        sync_label = "full"
        if verbose_flag:
            print(f"[*] Full database sync started from: {load_dir}")
        if not load_dir.exists():
            return JSONResponse({
                "status": "error",
                "error": f"Results directory not found: {load_dir}. Please set CYGOR_LOAD_DIR or ensure RESULTS_DIR exists."
            }, status_code=404)

    import time as _time
    _t0 = _time.monotonic()
    try:
        async with db.SessionLocal() as session:
            from sqlalchemy import func, select
            hosts_before = await session.scalar(select(func.count(Host.id))) or 0
            ports_before = await session.scalar(select(func.count(Port.id))) or 0

        if verbose_flag:
            print(f"[i] Database state before sync: {hosts_before} hosts, {ports_before} ports")

        async with db.SessionLocal() as session:
            count = await ingest_directory(load_dir, session, dedupe=True, verbose=verbose_level)
            await session.commit()

        if verbose_flag:
            print(f"[✓] Ingested {count} file(s)")

        async with db.SessionLocal() as session:
            hosts_after = await session.scalar(select(func.count(Host.id))) or 0
            ports_after = await session.scalar(select(func.count(Port.id))) or 0

        hosts_added = hosts_after - hosts_before
        ports_added = ports_after - ports_before
        elapsed = _time.monotonic() - _t0

        if verbose_flag:
            print(f"[✓] Database state after sync: {hosts_after} hosts (+{hosts_added}), {ports_after} ports (+{ports_added})")
        else:
            print(f"[+] auto-sync {sync_label} → +{hosts_added} hosts, +{ports_added} ports ({elapsed:.1f}s)")

        # Create sync result object
        sync_result = {
            "status": "success",
            "ingested_files": count,
            "directory": str(load_dir),
            "hosts_before": hosts_before,
            "hosts_after": hosts_after,
            "hosts_added": hosts_added,
            "ports_before": ports_before,
            "ports_after": ports_after,
            "ports_added": ports_added,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Add to sync history (keep last 50 syncs)
        SYNC_HISTORY.insert(0, sync_result)
        if len(SYNC_HISTORY) > 50:
            SYNC_HISTORY.pop()

        return JSONResponse(sync_result)
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"[!] Sync error: {error_details}")
        return JSONResponse({
            "status": "error",
            "error": str(e),
            "details": error_details
        }, status_code=500)
