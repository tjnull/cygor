"""
Scheduler Manager for Cygor - Handles scheduled task execution using APScheduler.

This module provides scheduling capabilities for:
- Port scans
- Module scans
- Credential reconnaissance

Uses APScheduler with PostgreSQL job store for persistence.
"""

import asyncio
import json
import logging
import os
import uuid
import psutil
from datetime import datetime
from typing import Optional, Dict, Any, List
from pathlib import Path

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.executors.asyncio import AsyncIOExecutor
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.triggers.date import DateTrigger
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR, EVENT_JOB_MISSED
from pytz import timezone as pytz_timezone, utc

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select

from .models import ScheduledTask, ScheduledTaskHistory
from .db import get_database_url
from .config import settings

logger = logging.getLogger(__name__)


class SchedulerManager:
    """Manages scheduled task execution for Cygor."""

    def __init__(self, task_manager=None, credrecon_manager=None):
        """
        Initialize the scheduler manager.

        Args:
            task_manager: TaskManager instance for port/module scans
            credrecon_manager: CredReconManager instance for credential scans
        """
        self.scheduler: Optional[AsyncIOScheduler] = None
        self.task_manager = task_manager
        self.credrecon_manager = credrecon_manager
        self.running_tasks: Dict[int, str] = {}  # scheduled_task_id -> current task_id
        self._initialized = False

    def initialize(self, database_url: Optional[str] = None):
        """
        Initialize APScheduler with PostgreSQL job store.

        Args:
            database_url: Database URL (if None, uses get_database_url())
        """
        if self._initialized:
            logger.warning("Scheduler already initialized")
            return

        if database_url is None:
            database_url = get_database_url()

        # Use MemoryJobStore instead of SQLAlchemy to avoid async/sync issues
        # Our scheduled tasks are already persisted in the database via ScheduledTask model
        # APScheduler jobs will be recreated from database on startup
        from apscheduler.jobstores.memory import MemoryJobStore

        jobstores = {
            'default': MemoryJobStore()
        }

        executors = {
            'default': AsyncIOExecutor()
        }

        job_defaults = {
            'coalesce': True,  # Combine multiple missed runs into one
            'max_instances': 10,  # Max concurrent job instances globally
            'misfire_grace_time': 3600  # Allow 1 hour grace for missed jobs (long-running scans)
        }

        self.scheduler = AsyncIOScheduler(
            jobstores=jobstores,
            executors=executors,
            job_defaults=job_defaults,
            timezone=utc
        )

        # Add event listeners
        self.scheduler.add_listener(
            self._job_executed_listener,
            EVENT_JOB_EXECUTED | EVENT_JOB_ERROR | EVENT_JOB_MISSED
        )

        self._initialized = True
        logger.info("Scheduler initialized with PostgreSQL job store")

    async def _insert_running_record(self, task_id: str, scheduled_task_id: int, task_type: str, pid: Optional[int] = None):
        """Insert a RunningTaskRecord and update in-memory cache."""
        from .db import SessionLocal
        from .models import RunningTaskRecord
        import socket

        async with SessionLocal() as session:
            record = RunningTaskRecord(
                task_id=task_id,
                scheduled_task_id=scheduled_task_id,
                task_type=task_type,
                pid=pid,
                started_at=datetime.utcnow(),
                hostname=socket.gethostname(),
            )
            session.add(record)
            await session.commit()

        self.running_tasks[scheduled_task_id] = task_id
        logger.info(f"[TRACK] Inserted RunningTaskRecord: task_id={task_id}, scheduled_task_id={scheduled_task_id}, pid={pid}")

    async def _delete_running_record(self, scheduled_task_id: int):
        """Delete a RunningTaskRecord and remove from in-memory cache."""
        from .db import SessionLocal
        from .models import RunningTaskRecord
        from sqlalchemy import delete as sa_delete

        try:
            async with SessionLocal() as session:
                stmt = sa_delete(RunningTaskRecord).where(RunningTaskRecord.scheduled_task_id == scheduled_task_id)
                await session.execute(stmt)
                await session.commit()
        except Exception as e:
            logger.warning(f"[TRACK] Failed to delete RunningTaskRecord for scheduled_task_id={scheduled_task_id}: {e}")

        self.running_tasks.pop(scheduled_task_id, None)
        logger.info(f"[TRACK] Deleted RunningTaskRecord for scheduled_task_id={scheduled_task_id}")

    async def _rebuild_running_tasks_cache(self):
        """Rebuild in-memory running_tasks dict from RunningTaskRecord table."""
        from .db import SessionLocal
        from .models import RunningTaskRecord

        async with SessionLocal() as session:
            result = await session.execute(select(RunningTaskRecord))
            records = result.scalars().all()

        self.running_tasks = {}
        for record in records:
            if record.scheduled_task_id is not None:
                self.running_tasks[record.scheduled_task_id] = record.task_id

        logger.info(f"[TRACK] Rebuilt running_tasks cache: {len(self.running_tasks)} entries")
        return records

    def start(self):
        """Start the scheduler."""
        if not self._initialized:
            raise RuntimeError("Scheduler not initialized. Call initialize() first.")

        if not self.scheduler.running:
            self.scheduler.start()
            logger.info("Scheduler started")

    def shutdown(self, wait: bool = True):
        """
        Shutdown the scheduler.

        Args:
            wait: Wait for running jobs to complete
        """
        if self.scheduler and self.scheduler.running:
            self.scheduler.shutdown(wait=wait)
            logger.info("Scheduler shutdown")

    async def load_scheduled_tasks(self, session: AsyncSession):
        """
        Load all active scheduled tasks from database and add them to scheduler.

        Args:
            session: Database session
        """
        statement = select(ScheduledTask).where(
            ScheduledTask.is_active == True,
            ScheduledTask.is_paused == False
        )
        result = await session.execute(statement)
        scheduled_tasks = result.scalars().all()

        for task in scheduled_tasks:
            try:
                await self._add_job_to_scheduler(task)
                logger.info(f"Loaded scheduled task: {task.name} (ID: {task.id})")
            except Exception as e:
                logger.error(f"Failed to load scheduled task {task.id}: {e}")

        logger.info(f"Loaded {len(scheduled_tasks)} scheduled tasks")

        # Rebuild running tasks cache from persistent records
        await self._rebuild_running_tasks_cache()

        # Recover stale "running" statuses from previous runs
        await self._recover_stale_running_tasks(session)

    async def _recover_stale_running_tasks(self, session: AsyncSession):
        """
        Recover from stale running tasks using the persistent RunningTaskRecord table.
        Uses stored PID to check if the process is still alive.
        Falls back to ScheduledTaskHistory for records not in RunningTaskRecord.
        """
        from .models import RunningTaskRecord
        from sqlalchemy import delete as sa_delete

        try:
            # Phase 1: Check RunningTaskRecord (persistent tracking)
            result = await session.execute(select(RunningTaskRecord))
            running_records = result.scalars().all()

            if not running_records:
                logger.info("No RunningTaskRecord entries to recover")
            else:
                logger.info(f"Found {len(running_records)} RunningTaskRecord entries to check")

            recovered_count = 0
            for record in running_records:
                process_alive = False

                # Check if process is still alive using PID
                if record.pid:
                    try:
                        os.kill(record.pid, 0)
                        process_alive = True
                    except (ProcessLookupError, PermissionError):
                        process_alive = False
                    except OSError:
                        process_alive = False

                if process_alive:
                    self.running_tasks[record.scheduled_task_id] = record.task_id
                    logger.info(f"[RECOVER] Task {record.task_id} (PID {record.pid}) still alive, re-registering")

                    # Re-register completion callback based on task type
                    if record.task_type in ('port_scan', 'module_scan', 'scan', 'module') and self.task_manager:
                        task = await self.task_manager.get_task(record.task_id)
                        if task:
                            self.task_manager.register_completion_callback(
                                record.task_id,
                                lambda t, sid=record.scheduled_task_id: asyncio.create_task(
                                    self._on_task_completed(sid, t)
                                )
                            )
                    elif record.task_type == 'credrecon' and self.credrecon_manager:
                        scan = await self.credrecon_manager.get_scan(record.task_id)
                        if scan:
                            self.credrecon_manager.register_completion_callback(
                                record.task_id,
                                lambda s, sid=record.scheduled_task_id: asyncio.create_task(
                                    self._on_scan_completed(sid, s)
                                )
                            )
                else:
                    logger.warning(f"[RECOVER] Task {record.task_id} (PID {record.pid}) is dead, marking as failed")

                    # Update history record
                    history_stmt = (
                        select(ScheduledTaskHistory)
                        .where(ScheduledTaskHistory.task_id == record.task_id)
                        .order_by(ScheduledTaskHistory.id.desc())
                        .limit(1)
                    )
                    history_result = await session.execute(history_stmt)
                    history_record = history_result.scalar_one_or_none()

                    if history_record and history_record.status == 'running':
                        history_record.status = 'failed'
                        history_record.completed_at = datetime.utcnow()
                        history_record.message = f'Task process died (PID {record.pid} not found on scheduler restart)'
                        if history_record.started_at:
                            history_record.duration_seconds = (history_record.completed_at - history_record.started_at).total_seconds()

                    # Update parent scheduled task
                    parent_stmt = select(ScheduledTask).where(ScheduledTask.id == record.scheduled_task_id)
                    parent_result = await session.execute(parent_stmt)
                    parent_task = parent_result.scalar_one_or_none()
                    if parent_task and parent_task.last_run_status == 'running':
                        parent_task.last_run_status = 'failed'

                    # Delete the RunningTaskRecord
                    await session.execute(
                        sa_delete(RunningTaskRecord).where(RunningTaskRecord.id == record.id)
                    )
                    recovered_count += 1

            # Phase 2: Check ScheduledTaskHistory for orphaned 'running' records
            running_task_ids = {r.task_id for r in running_records}
            history_stmt = (
                select(ScheduledTaskHistory)
                .where(ScheduledTaskHistory.status == 'running')
            )
            history_result = await session.execute(history_stmt)
            orphaned_history = [h for h in history_result.scalars().all() if h.task_id not in running_task_ids]

            for record in orphaned_history:
                task_found = False
                actual_status = None

                if self.task_manager and record.task_id:
                    task = await self.task_manager.get_task(record.task_id)
                    if task:
                        task_found = True
                        actual_status = task.status.value

                if not task_found and self.credrecon_manager and record.task_id:
                    scan = await self.credrecon_manager.get_scan(record.task_id)
                    if scan:
                        task_found = True
                        actual_status = scan.status.value

                if actual_status in ('completed', 'failed', 'cancelled'):
                    record.status = actual_status
                    record.completed_at = datetime.utcnow()
                    record.message = f'Recovered on restart (status: {actual_status})'
                    recovered_count += 1
                elif not task_found:
                    record.status = 'failed'
                    record.completed_at = datetime.utcnow()
                    record.message = 'Task not found on scheduler restart'
                    recovered_count += 1

            await session.commit()
            logger.info(f"Recovered {recovered_count} stale tasks")

        except Exception as e:
            logger.error(f"Error recovering stale running tasks: {e}", exc_info=True)

    async def create_scheduled_task(
        self,
        session: AsyncSession,
        name: str,
        task_type: str,
        config: Dict[str, Any],
        schedule_type: str,
        schedule_config: Dict[str, Any],
        user_id: Optional[int] = None,
        description: Optional[str] = None,
        timezone_str: str = "UTC",
        **kwargs
    ) -> ScheduledTask:
        """
        Create a new scheduled task.

        Args:
            session: Database session
            name: Task name
            task_type: Type of task ('port_scan', 'module_scan', 'credrecon')
            config: Task configuration dict
            schedule_type: Schedule type ('cron', 'interval', 'date')
            schedule_config: Schedule configuration dict
            user_id: Owner user ID
            description: Task description
            timezone_str: User timezone string (e.g., 'America/New_York')
            **kwargs: Additional optional fields

        Returns:
            Created ScheduledTask instance
        """
        # Validate task type
        valid_task_types = ['port_scan', 'module_scan', 'credrecon']
        if task_type not in valid_task_types:
            raise ValueError(f"Invalid task_type. Must be one of: {valid_task_types}")

        # Validate schedule type
        valid_schedule_types = ['cron', 'interval', 'date']
        if schedule_type not in valid_schedule_types:
            raise ValueError(f"Invalid schedule_type. Must be one of: {valid_schedule_types}")

        # Create scheduled task - explicitly set is_active=True to ensure it's active
        scheduled_task = ScheduledTask(
            name=name,
            description=description,
            task_type=task_type,
            config=json.dumps(config),
            schedule_type=schedule_type,
            schedule_config=json.dumps(schedule_config),
            user_id=user_id,
            timezone=timezone_str,
            is_active=True,
            is_paused=False,
            **kwargs
        )

        session.add(scheduled_task)
        await session.commit()
        await session.refresh(scheduled_task)

        logger.info(f"Created scheduled task in DB: {name} (ID: {scheduled_task.id}, is_active={scheduled_task.is_active})")

        # Add job to scheduler
        await self._add_job_to_scheduler(scheduled_task)

        # Verify the task is still active after adding to scheduler
        await session.refresh(scheduled_task)
        logger.info(f"Scheduled task after job added: {name} (ID: {scheduled_task.id}, is_active={scheduled_task.is_active}, next_run={scheduled_task.next_run})")

        return scheduled_task

    async def update_scheduled_task(
        self,
        session: AsyncSession,
        task_id: int,
        **updates
    ) -> Optional[ScheduledTask]:
        """
        Update an existing scheduled task.

        Args:
            session: Database session
            task_id: Scheduled task ID
            **updates: Fields to update

        Returns:
            Updated ScheduledTask or None if not found
        """
        statement = select(ScheduledTask).where(ScheduledTask.id == task_id)
        result = await session.execute(statement)
        scheduled_task = result.scalar_one_or_none()

        if not scheduled_task:
            return None

        # Update fields
        for key, value in updates.items():
            if hasattr(scheduled_task, key):
                # Convert dicts to JSON strings for JSON columns
                if key in ['config', 'schedule_config'] and isinstance(value, dict):
                    value = json.dumps(value)
                setattr(scheduled_task, key, value)

        scheduled_task.updated_at = datetime.utcnow()

        await session.commit()
        await session.refresh(scheduled_task)

        # Update job in scheduler
        if scheduled_task.apscheduler_job_id:
            try:
                # Try to remove existing job - it may not exist if webapp was restarted
                existing_job = self.scheduler.get_job(scheduled_task.apscheduler_job_id)
                if existing_job:
                    self.scheduler.remove_job(scheduled_task.apscheduler_job_id)
                    logger.info(f"Removed existing APScheduler job: {scheduled_task.apscheduler_job_id}")
                else:
                    logger.info(f"APScheduler job {scheduled_task.apscheduler_job_id} not found (webapp may have restarted)")
            except Exception as e:
                logger.warning(f"Could not remove APScheduler job {scheduled_task.apscheduler_job_id}: {e}")

        if scheduled_task.is_active and not scheduled_task.is_paused:
            await self._add_job_to_scheduler(scheduled_task)

        logger.info(f"Updated scheduled task: {scheduled_task.name} (ID: {task_id})")
        return scheduled_task

    async def delete_scheduled_task(self, session: AsyncSession, task_id: int) -> bool:
        """
        Delete a scheduled task.

        Args:
            session: Database session
            task_id: Scheduled task ID

        Returns:
            True if deleted, False if not found
        """
        statement = select(ScheduledTask).where(ScheduledTask.id == task_id)
        result = await session.execute(statement)
        scheduled_task = result.scalar_one_or_none()

        if not scheduled_task:
            return False

        # Remove from scheduler
        if scheduled_task.apscheduler_job_id:
            try:
                self.scheduler.remove_job(scheduled_task.apscheduler_job_id)
            except Exception as e:
                logger.warning(f"Failed to remove job from scheduler: {e}")

        # Clear any RunningTaskRecord rows that point at this scheduled task.
        # The FK has no ON DELETE CASCADE, so a row from a still-running (or
        # never-reaped) execution would block the parent delete with a 500.
        # Set scheduled_task_id NULL rather than deleting the run record so the
        # task can still finish and surface its status via the tasks API.
        from sqlalchemy import update
        from .models import RunningTaskRecord
        await session.execute(
            update(RunningTaskRecord)
            .where(RunningTaskRecord.scheduled_task_id == task_id)
            .values(scheduled_task_id=None)
        )

        # Delete from database
        await session.delete(scheduled_task)
        await session.commit()

        logger.info(f"Deleted scheduled task: {scheduled_task.name} (ID: {task_id})")
        return True

    async def pause_scheduled_task(self, session: AsyncSession, task_id: int) -> bool:
        """Pause a scheduled task."""
        return await self.update_scheduled_task(session, task_id, is_paused=True) is not None

    async def resume_scheduled_task(self, session: AsyncSession, task_id: int) -> bool:
        """Resume a paused scheduled task."""
        return await self.update_scheduled_task(session, task_id, is_paused=False) is not None

    async def reactivate_scheduled_task(
        self,
        session: AsyncSession,
        task_id: int,
        reset_run_count: bool = False,
        end_date: Optional[datetime] = None,
        max_runs: Optional[int] = -1
    ) -> Optional[ScheduledTask]:
        """Reactivate a task that was auto-deactivated by max_runs or end_date."""
        statement = select(ScheduledTask).where(ScheduledTask.id == task_id)
        result = await session.execute(statement)
        scheduled_task = result.scalar_one_or_none()

        if not scheduled_task:
            return None

        scheduled_task.is_active = True
        scheduled_task.is_paused = False

        if reset_run_count:
            scheduled_task.run_count = 0

        if end_date is not None:
            scheduled_task.end_date = end_date

        if max_runs != -1:
            scheduled_task.max_runs = max_runs

        scheduled_task.updated_at = datetime.utcnow()
        await session.commit()
        await session.refresh(scheduled_task)

        # Re-add job to scheduler
        await self._add_job_to_scheduler(scheduled_task)

        logger.info(f"Reactivated scheduled task: {scheduled_task.name} (ID: {task_id})")
        return scheduled_task

    async def trigger_now(self, session: AsyncSession, task_id: int) -> Optional[str]:
        """
        Manually trigger a scheduled task to run immediately.

        Args:
            session: Database session
            task_id: Scheduled task ID

        Returns:
            Task ID if triggered, None if failed
        """
        logger.info(f"Manual trigger requested for scheduled task {task_id}")

        statement = select(ScheduledTask).where(ScheduledTask.id == task_id)
        result = await session.execute(statement)
        scheduled_task = result.scalar_one_or_none()

        if not scheduled_task:
            logger.error(f"Scheduled task {task_id} not found in database")
            return None

        logger.info(f"Found scheduled task: {scheduled_task.name} (type: {scheduled_task.task_type})")

        # Execute the task
        task_id_result = await self._execute_scheduled_task(
            scheduled_task.id,
            scheduled_time=datetime.utcnow(),
            manual_trigger=True
        )

        if task_id_result:
            logger.info(f"Manual trigger successful: task_id={task_id_result}")
        else:
            logger.error(f"Manual trigger failed for scheduled task {task_id} - _execute_scheduled_task returned None")

        return task_id_result

    async def _add_job_to_scheduler(self, scheduled_task: ScheduledTask):
        """
        Add a scheduled task to APScheduler.

        Args:
            scheduled_task: ScheduledTask instance
        """
        # Parse timezone - default to UTC if empty or invalid
        if not scheduled_task.timezone or not scheduled_task.timezone.strip():
            tz = utc
        else:
            try:
                tz = pytz_timezone(scheduled_task.timezone)
            except Exception:
                logger.warning(f"Invalid timezone '{scheduled_task.timezone}', using UTC")
                tz = utc

        # Parse schedule config
        # schedule_config is stored as JSON column, so it may already be a dict or a string
        schedule_config = scheduled_task.schedule_config
        if isinstance(schedule_config, str):
            schedule_config = json.loads(schedule_config)

        # Create trigger based on schedule type
        trigger = None
        if scheduled_task.schedule_type == 'cron':
            logger.info(
                f"[SCHED] Creating CronTrigger for task {scheduled_task.id}: "
                f"config={schedule_config}, timezone={tz}"
            )
            trigger = CronTrigger(timezone=tz, **schedule_config)
        elif scheduled_task.schedule_type == 'interval':
            # For interval triggers, we need to include start_date if specified
            # The start_date determines when the FIRST run happens
            interval_kwargs = dict(schedule_config)
            if scheduled_task.start_date:
                # Localize naive start_date to the schedule's timezone
                sd = scheduled_task.start_date
                if sd.tzinfo is None and hasattr(tz, 'localize'):
                    sd = tz.localize(sd)
                interval_kwargs['start_date'] = sd
            logger.info(
                f"[SCHED] Creating IntervalTrigger for task {scheduled_task.id}: "
                f"config={interval_kwargs}, timezone={tz}"
            )
            trigger = IntervalTrigger(timezone=tz, **interval_kwargs)
        elif scheduled_task.schedule_type == 'date':
            run_date = schedule_config.get('run_date')
            if isinstance(run_date, str):
                run_date = datetime.fromisoformat(run_date)
            # Explicitly localize naive datetime to the schedule's timezone
            # so APScheduler interprets it as the user's intended local time
            if run_date and run_date.tzinfo is None and hasattr(tz, 'localize'):
                run_date = tz.localize(run_date)
            logger.info(
                f"[SCHED] Creating DateTrigger for task {scheduled_task.id}: "
                f"run_date={run_date}, timezone={tz}"
            )
            trigger = DateTrigger(run_date=run_date, timezone=tz)

        if not trigger:
            raise ValueError(f"Failed to create trigger for schedule type: {scheduled_task.schedule_type}")

        # Add job to scheduler
        job_id = f"scheduled_task_{scheduled_task.id}"

        # Determine max_instances based on allow_concurrent
        max_instances = scheduled_task.max_concurrent_runs if scheduled_task.allow_concurrent else 1

        # Per-task misfire grace time override
        extra_kwargs = {}
        if scheduled_task.misfire_grace_time:
            extra_kwargs['misfire_grace_time'] = scheduled_task.misfire_grace_time

        job = self.scheduler.add_job(
            self._execute_scheduled_task,
            trigger=trigger,
            args=[scheduled_task.id, None, False, 0, None],  # scheduled_task_id, scheduled_time, manual_trigger, retry_attempt, retry_of_history_id
            id=job_id,
            name=scheduled_task.name,
            max_instances=max_instances,
            replace_existing=True,
            **extra_kwargs
        )

        # Update scheduled task with job ID and next run time
        from .db import SessionLocal
        async with SessionLocal() as session:
            statement = select(ScheduledTask).where(ScheduledTask.id == scheduled_task.id)
            result = await session.execute(statement)
            task = result.scalar_one_or_none()
            if task:
                task.apscheduler_job_id = job_id
                task.next_run = job.next_run_time.astimezone(utc).replace(tzinfo=None) if job.next_run_time else None
                await session.commit()

        # Log with both UTC and the schedule's timezone for clarity
        if job.next_run_time:
            next_utc = job.next_run_time.astimezone(utc)
            next_local = job.next_run_time.astimezone(tz) if tz != utc else next_utc
            logger.info(
                f"[SCHED] Added job {job_id}: "
                f"next_run={next_utc.isoformat()} UTC "
                f"({next_local.strftime('%Y-%m-%d %H:%M %Z')} in {scheduled_task.timezone})"
            )
        else:
            logger.info(f"[SCHED] Added job {job_id}: no next run time (trigger: {trigger})")

    async def _execute_scheduled_task(
        self,
        scheduled_task_id: int,
        scheduled_time: Optional[datetime] = None,
        manual_trigger: bool = False,
        retry_attempt: int = 0,
        retry_of_history_id: Optional[int] = None
    ) -> Optional[str]:
        """
        Execute a scheduled task.

        Args:
            scheduled_task_id: Scheduled task ID
            scheduled_time: Time the task was scheduled to run
            manual_trigger: Whether this was manually triggered

        Returns:
            Task ID if execution started, None otherwise
        """
        from .db import SessionLocal

        logger.info(f"[EXEC] Starting _execute_scheduled_task: id={scheduled_task_id}, manual_trigger={manual_trigger}")

        if scheduled_time is None:
            scheduled_time = datetime.utcnow()

        async with SessionLocal() as session:
            # Load scheduled task
            logger.debug(f"[EXEC] Querying database for scheduled_task_id={scheduled_task_id}")
            statement = select(ScheduledTask).where(ScheduledTask.id == scheduled_task_id)
            result = await session.execute(statement)
            scheduled_task = result.scalar_one_or_none()

            if not scheduled_task:
                logger.error(f"[EXEC] FAIL: Scheduled task {scheduled_task_id} not found in database")
                return None

            logger.info(f"[EXEC] Found task: name='{scheduled_task.name}', type={scheduled_task.task_type}, active={scheduled_task.is_active}")

            # Check if task should run
            if not manual_trigger:
                logger.debug(f"[EXEC] Checking run conditions (not manual trigger)")
                # Check if max_runs reached
                if scheduled_task.max_runs and scheduled_task.run_count >= scheduled_task.max_runs:
                    logger.info(f"[EXEC] FAIL: Scheduled task {scheduled_task_id} reached max_runs ({scheduled_task.run_count}/{scheduled_task.max_runs}), deactivating")
                    scheduled_task.is_active = False
                    await session.commit()
                    return None

                # Check if within date range
                now = datetime.utcnow()
                if scheduled_task.start_date and now < scheduled_task.start_date:
                    logger.info(f"[EXEC] FAIL: Scheduled task {scheduled_task_id} not yet started (start_date={scheduled_task.start_date})")
                    return None
                if scheduled_task.end_date and now > scheduled_task.end_date:
                    logger.info(f"[EXEC] FAIL: Scheduled task {scheduled_task_id} ended (end_date={scheduled_task.end_date}), deactivating")
                    scheduled_task.is_active = False
                    await session.commit()
                    return None
            else:
                logger.info(f"[EXEC] Manual trigger - skipping max_runs and date range checks")

            # Check if already running (if not allowing concurrent)
            logger.debug(f"[EXEC] Checking concurrent run: allow_concurrent={scheduled_task.allow_concurrent}, running_tasks={self.running_tasks}")
            if not scheduled_task.allow_concurrent:
                if scheduled_task_id in self.running_tasks:
                    current_task_id = self.running_tasks[scheduled_task_id]
                    logger.info(f"[EXEC] Task {scheduled_task_id} has a tracked running task: {current_task_id}")

                    # Double-check the task is actually still running
                    # Check the appropriate manager based on task type
                    task_still_running = False
                    current_status = None

                    if scheduled_task.task_type == 'credrecon' and self.credrecon_manager:
                        scan = await self.credrecon_manager.get_scan(current_task_id)
                        if scan:
                            current_status = scan.status.value
                        else:
                            logger.info(f"[EXEC] Task {current_task_id} not found in credrecon_manager")
                    elif self.task_manager:
                        current_task = await self.task_manager.get_task(current_task_id)
                        if current_task:
                            current_status = current_task.status.value
                        else:
                            logger.info(f"[EXEC] Task {current_task_id} not found in task manager")
                    else:
                        logger.warning(f"[EXEC] No manager available to check running task")

                    if current_status == 'running':
                        task_still_running = True
                        logger.info(f"[EXEC] Task {current_task_id} is still running")
                    elif current_status and current_status in ('completed', 'failed', 'cancelled'):
                        logger.info(f"[EXEC] Task {current_task_id} finished with status {current_status}")
                        # Update history if we have a task manager task
                        if scheduled_task.task_type in ('port_scan', 'module_scan') and self.task_manager:
                            current_task = await self.task_manager.get_task(current_task_id)
                            if current_task:
                                await self._update_history_on_completion(session, current_task_id, current_task)

                    if task_still_running:
                        logger.warning(f"[EXEC] FAIL: Scheduled task {scheduled_task_id} already running (task {current_task_id}), skipping")
                        # Record as skipped with detailed message
                        await self._record_execution(
                            session,
                            scheduled_task,
                            scheduled_time,
                            status='skipped',
                            message=f'Previous execution still running (Task ID: {current_task_id})',
                            retry_attempt=retry_attempt,
                            retry_of_history_id=retry_of_history_id
                        )
                        # Schedule retry if enabled
                        if retry_attempt < (scheduled_task.max_retries or 0):
                            await self._schedule_retry(
                                scheduled_task_id,
                                retry_attempt + 1,
                                f'Previous execution still running (Task ID: {current_task_id})'
                            )
                        return None
                    else:
                        # Task no longer running, clear it from tracking
                        logger.info(f"[EXEC] Clearing stale task {current_task_id} from running tasks")
                        await self._delete_running_record(scheduled_task_id)
                        # Also update the scheduled task status if it's still showing 'running'
                        if scheduled_task.last_run_status == 'running' and current_status:
                            scheduled_task.last_run_status = current_status
                            await session.commit()
            else:
                logger.debug(f"[EXEC] Concurrent runs allowed, skipping running task check")

            # Check resources
            resources_ok = True
            cpu_percent = None
            memory_percent = None

            logger.info(f"[EXEC] Resource check: check_resources={scheduled_task.check_resources}, max_cpu={scheduled_task.max_cpu_percent}, max_memory={scheduled_task.max_memory_percent}")

            # Skip resource checks for manual triggers - user explicitly wants to run now
            if scheduled_task.check_resources and not manual_trigger:
                # Average multiple short CPU samples to avoid transient spikes
                # Run in thread to avoid blocking the async event loop (each sample blocks 0.5s)
                def _sample_cpu():
                    samples = []
                    for _ in range(3):
                        samples.append(psutil.cpu_percent(interval=0.5))
                    return round(sum(samples) / len(samples), 1), samples

                cpu_percent, cpu_samples = await asyncio.get_event_loop().run_in_executor(None, _sample_cpu)
                memory_percent = psutil.virtual_memory().percent
                logger.info(f"[EXEC] Current resources: CPU={cpu_percent}% (samples: {cpu_samples}), Memory={memory_percent}%")

                if scheduled_task.max_cpu_percent and cpu_percent > scheduled_task.max_cpu_percent:
                    resources_ok = False
                    logger.warning(f"[EXEC] CPU usage too high: {cpu_percent}% > {scheduled_task.max_cpu_percent}%")

                if scheduled_task.max_memory_percent and memory_percent > scheduled_task.max_memory_percent:
                    resources_ok = False
                    logger.warning(f"[EXEC] Memory usage too high: {memory_percent}% > {scheduled_task.max_memory_percent}%")

                if not resources_ok:
                    logger.warning(f"[EXEC] FAIL: Resources exceeded limits, skipping task")
                    await self._record_execution(
                        session,
                        scheduled_task,
                        scheduled_time,
                        status='skipped',
                        message=f'Resources exceeded limits (CPU: {cpu_percent}%, Memory: {memory_percent}%)',
                        cpu_percent=cpu_percent,
                        memory_percent=memory_percent,
                        resources_ok=False,
                        retry_attempt=retry_attempt,
                        retry_of_history_id=retry_of_history_id
                    )
                    # Schedule retry if enabled
                    if retry_attempt < (scheduled_task.max_retries or 0):
                        await self._schedule_retry(
                            scheduled_task_id,
                            retry_attempt + 1,
                            f'Resources exceeded (CPU: {cpu_percent}%, Memory: {memory_percent}%)'
                        )
                    return None
            elif manual_trigger and scheduled_task.check_resources:
                # For manual triggers, log current resources but don't block
                cpu_percent = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: psutil.cpu_percent(interval=0.1)
                )
                memory_percent = psutil.virtual_memory().percent
                logger.info(f"[EXEC] Manual trigger - bypassing resource limits (CPU={cpu_percent}%, Memory={memory_percent}%)")
            else:
                logger.debug(f"[EXEC] Resource checking disabled for this task")

            # Parse task configuration
            # Config is stored as JSON column, so it may already be a dict or a string
            config = scheduled_task.config
            logger.debug(f"[EXEC] Raw config type: {type(config)}, value: {config}")
            if isinstance(config, str):
                config = json.loads(config)
            logger.info(f"[EXEC] Executing scheduled task {scheduled_task_id} ({scheduled_task.task_type}): {scheduled_task.name}")
            logger.info(f"[EXEC] Task config: {config}")

            # Execute based on task type
            task_id = None
            output_path = None
            try:
                logger.info(f"[EXEC] About to execute task type: {scheduled_task.task_type}")
                logger.info(f"[EXEC] task_manager={self.task_manager}, credrecon_manager={self.credrecon_manager}")

                if scheduled_task.task_type == 'port_scan':
                    logger.info(f"[EXEC] Starting port scan for scheduled task {scheduled_task_id}")
                    task_id, output_path = await self._execute_port_scan(config)
                elif scheduled_task.task_type == 'module_scan':
                    logger.info(f"[EXEC] Starting module scan for scheduled task {scheduled_task_id}")
                    task_id, output_path = await self._execute_module_scan(config)
                elif scheduled_task.task_type == 'credrecon':
                    logger.info(f"[EXEC] Starting credrecon for scheduled task {scheduled_task_id}")
                    task_id, output_path = await self._execute_credrecon(config)
                else:
                    logger.error(f"[EXEC] FAIL: Unknown task type: {scheduled_task.task_type}")
                    raise ValueError(f"Unknown task type: {scheduled_task.task_type}")

                logger.info(f"[EXEC] SUCCESS: Created task {task_id} for scheduled task {scheduled_task_id}, output: {output_path}")

                # Track running task persistently
                pid = None
                if scheduled_task.task_type in ('port_scan', 'module_scan') and self.task_manager:
                    t = await self.task_manager.get_task(task_id)
                    if t and t.process:
                        pid = t.process.pid
                elif scheduled_task.task_type == 'credrecon' and self.credrecon_manager:
                    s = await self.credrecon_manager.get_scan(task_id)
                    if s and s.process:
                        pid = s.process.pid
                await self._insert_running_record(task_id, scheduled_task_id, scheduled_task.task_type, pid)

                # Register a callback to be notified when the task completes
                # This provides immediate status updates without waiting for the monitoring loop
                if scheduled_task.task_type in ('port_scan', 'module_scan') and self.task_manager:
                    self.task_manager.register_completion_callback(
                        task_id,
                        lambda task, sid=scheduled_task_id: asyncio.create_task(
                            self._on_task_completed(sid, task)
                        )
                    )
                elif scheduled_task.task_type == 'credrecon' and self.credrecon_manager:
                    self.credrecon_manager.register_completion_callback(
                        task_id,
                        lambda scan, sid=scheduled_task_id: asyncio.create_task(
                            self._on_scan_completed(sid, scan)
                        )
                    )

                # Update scheduled task
                scheduled_task.last_run = datetime.utcnow()
                scheduled_task.last_run_status = 'running'
                scheduled_task.last_task_id = task_id
                # Don't count retries against run_count
                if retry_attempt == 0:
                    scheduled_task.run_count += 1

                # Update next_run if job exists
                if scheduled_task.apscheduler_job_id:
                    job = self.scheduler.get_job(scheduled_task.apscheduler_job_id)
                    if job:
                        scheduled_task.next_run = job.next_run_time.astimezone(utc).replace(tzinfo=None) if job.next_run_time else None

                await session.commit()

                # Refresh the scheduled_task to ensure it's attached to the session
                await session.refresh(scheduled_task)

                # Record execution start with output_path
                await self._record_execution(
                    session,
                    scheduled_task,
                    scheduled_time,
                    task_id=task_id,
                    status='running',
                    message='Task started successfully',
                    cpu_percent=cpu_percent,
                    memory_percent=memory_percent,
                    resources_ok=resources_ok,
                    output_path=output_path,
                    retry_attempt=retry_attempt,
                    retry_of_history_id=retry_of_history_id
                )

                logger.info(f"Started scheduled task {scheduled_task_id}: {task_id}")
                return task_id

            except Exception as e:
                logger.error(f"[EXEC] EXCEPTION: Failed to execute scheduled task {scheduled_task_id}: {e}", exc_info=True)
                scheduled_task.last_run_status = 'failed'
                await session.commit()

                await self._record_execution(
                    session,
                    scheduled_task,
                    scheduled_time,
                    status='failed',
                    message='Task execution failed',
                    error=str(e),
                    cpu_percent=cpu_percent,
                    memory_percent=memory_percent,
                    resources_ok=resources_ok,
                    retry_attempt=retry_attempt,
                    retry_of_history_id=retry_of_history_id
                )
                return None

    def _scheduled_base_dir(self) -> str:
        """Where scheduled tasks should write.

        Precedence:
          1. The active workspace from cygor.workspace (the runtime source of
             truth -- gets updated when the user switches via the UI).
          2. settings.RESULTS_DIR (mirror of #1; set on startup AND on switch
             via _apply_workspace_to_process). Kept as a safety net for
             plugins that bypass cygor.workspace.
          3. CYGOR_LOAD_DIR env (only set when 'cygor web start --load-dir'
             was used at startup). This used to be checked FIRST, but a user
             who started with --load-dir A and then switched the workspace
             to B via the UI was silently still writing to A. Demoting it
             to last-resort fixes that drift.
        Always returns a string path; never None.
        """
        try:
            from cygor.workspace import active_workspace_path
            ws = active_workspace_path()
            if ws is not None:
                return str(ws)
        except Exception:
            pass
        if getattr(settings, "RESULTS_DIR", None):
            return str(settings.RESULTS_DIR)
        return os.environ.get("CYGOR_LOAD_DIR") or ""

    def _scheduled_subdir(self, prefix: str, task_id: str | None = None) -> str:
        """Build a unique-per-task scheduled output subdir under prefix/.

        Two scheduled tasks firing within the same wall-clock second used
        to land in the same '<prefix>/<ts>' directory and clobber each
        other's output. Append a short suffix derived from the task_id
        (or a fresh uuid if not provided) so collisions can't happen even
        on a cron with multiple-per-second runs.
        """
        timestamp = datetime.utcnow().strftime("%Y-%m-%d_%H-%M-%S")
        # First 8 chars of the uuid are enough to disambiguate within a
        # second (collision probability ~1 in 4 billion per second).
        suffix = (task_id or str(uuid.uuid4())).split("-")[0][:8]
        return f"{self._scheduled_base_dir()}/schedule-scans/{prefix}/{timestamp}-{suffix}"

    async def _execute_port_scan(self, config: Dict[str, Any]) -> tuple[str, str]:
        """Execute a port scan task. Returns (task_id, output_path)."""

        logger.info(f"[PORT_SCAN] Starting _execute_port_scan")
        logger.info(f"[PORT_SCAN] task_manager available: {self.task_manager is not None}")

        if not self.task_manager:
            logger.error("[PORT_SCAN] FAIL: TaskManager not configured")
            raise RuntimeError("TaskManager not configured")

        # Generate task ID with 'sched-' prefix for scheduled tasks
        task_id = f"sched-{uuid.uuid4()}"

        # Per-run output dir under the active workspace. _scheduled_subdir
        # picks the LIVE active workspace (was: stale CYGOR_LOAD_DIR env)
        # and adds a uuid suffix so two scheduled runs firing in the same
        # second can't share a directory.
        scheduled_output_dir = self._scheduled_subdir("port-scan", task_id=None)

        logger.info(f"[PORT_SCAN] Output directory: {scheduled_output_dir}")
        logger.info(f"[PORT_SCAN] Config: targets={config.get('targets', [])}, discover={config.get('discover')}, scan_type={config.get('scan_type', 'top-ports')}, discover_only={config.get('discover_only', False)}")

        try:
            task_id = await self.task_manager.create_scan_task(
                targets=config.get('targets', []),
                interface=config.get('interface'),
                discover=config.get('discover'),
                scan_type=config.get('scan_type', 'top-ports'),
                ports=config.get('ports'),
                nmap_options=config.get('nmap_options'),
                output_dir=scheduled_output_dir,
                exclusions=config.get('exclusions'),
                is_ondemand=False,  # This is a scheduled scan, not on-demand
                username=None,  # Scheduled scans don't have a user context
                user_id=None,
                discover_only=config.get('discover_only', False),
                task_id=task_id
            )
            logger.info(f"[PORT_SCAN] SUCCESS: Created task_id={task_id}")
            return task_id, scheduled_output_dir
        except Exception as e:
            logger.error(f"[PORT_SCAN] EXCEPTION in create_scan_task: {e}", exc_info=True)
            raise

    async def _execute_module_scan(self, config: Dict[str, Any]) -> tuple[str, str]:
        """Execute a module scan task. Returns (task_id, output_path)."""

        if not self.task_manager:
            raise RuntimeError("TaskManager not configured")

        # Generate task ID with 'sched-' prefix for scheduled tasks
        task_id = f"sched-{uuid.uuid4()}"

        # Determine output directory based on module type. Every scheduled
        # task must land somewhere under schedule-scans/ so it never overlaps
        # with the ad-hoc cygor-enumeration-modules/<slug>/ tree (which is
        # owned by interactive CLI + /api/modules runs). _scheduled_subdir
        # picks the LIVE active workspace (was: stale CYGOR_LOAD_DIR env)
        # and adds a uuid suffix to prevent same-second collisions.
        module_name = config.get('module_name', '')

        # Lockon uses a stable (non-timestamped) output directory so its
        # screenshots/ folder accumulates and its built-in archive mechanism
        # (screenshots/archive/<ts>/) can preserve previous runs. Other
        # modules get a per-run timestamped dir for full isolation.
        if module_name == "lockon":
            scheduled_output_dir = f"{self._scheduled_base_dir()}/schedule-scans/lockon"
        else:
            scheduled_output_dir = self._scheduled_subdir("module-scan", task_id=None)

        logger.info(f"Scheduled module scan output directory: {scheduled_output_dir}")

        task_id = await self.task_manager.create_module_task(
            module_name=config.get('module_name'),
            targets_file=config.get('targets_file'),
            output_dir=scheduled_output_dir,
            module_options=config.get('module_options'),
            username=None,
            user_id=None,
            task_id=task_id
        )
        return task_id, scheduled_output_dir

    async def _execute_credrecon(self, config: Dict[str, Any]) -> tuple[str, str]:
        """Execute a credential recon task. Returns (task_id, output_path)."""
        if not self.credrecon_manager:
            raise RuntimeError("CredReconManager not configured")


        # Generate scan ID with 'sched-' prefix for scheduled tasks
        base_id = str(uuid.uuid4())
        scan_id = f"sched-{base_id}"
        short_scan_id = base_id[:8]

        # Create timestamped workspace directory organized by task type
        # ALWAYS use CYGOR_LOAD_DIR for scheduled scans
        # credrecon already disambiguates its dir with short_scan_id + ts;
        # this implicit guarantees uniqueness without needing _scheduled_subdir.
        # Use _scheduled_base_dir() so we get the LIVE active workspace
        # (was: stale CYGOR_LOAD_DIR env if the user switched workspaces).
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        scheduled_workspace = (
            Path(self._scheduled_base_dir())
            / "schedule-scans" / "credrecon"
            / f"credrecon-{short_scan_id}-{timestamp}"
        )
        scheduled_workspace.mkdir(parents=True, exist_ok=True)

        logger.info(f"Scheduled credrecon workspace: {scheduled_workspace}")

        # Get targets from config and write to file
        targets = config.get('targets', [])
        targets_file_path = config.get('targets_file', '')  # server path from "Targets File" method
        if isinstance(targets, str):
            targets_content = targets
        else:
            targets_content = "\n".join(targets)

        targets_file = scheduled_workspace / "targets.txt"
        if targets_file_path and Path(targets_file_path).exists():
            # Use the server-side targets file directly
            import shutil
            shutil.copy2(targets_file_path, targets_file)
            targets_content = Path(targets_file_path).read_text(encoding="utf-8", errors="replace")
        else:
            with open(targets_file, 'w') as f:
                f.write(targets_content)

        num_targets = len(targets_content.strip().splitlines()) if targets_content.strip() else 0

        # Build command
        cmd = ["cygor", "credrecon", "-i", str(targets_file)]

        # Protocol — multi-protocol support
        protocols = config.get('protocols', [])
        protocol = config.get('protocol')
        if protocols and len(protocols) > 1:
            cmd.extend(["--protocols", ",".join(protocols)])
        elif protocols and len(protocols) == 1 and protocols[0] != 'auto':
            cmd.extend(["--protocol", protocols[0]])
        elif protocol and protocol != 'auto':
            cmd.extend(["--protocol", protocol])

        # Threads
        threads = config.get('threads')
        if threads:
            cmd.extend(["--threads", str(threads)])

        # Max attempts
        max_attempts = config.get('max_attempts')
        if max_attempts:
            cmd.extend(["--max-attempts", str(max_attempts)])

        # Timeout
        timeout = config.get('timeout')
        if timeout:
            cmd.extend(["--timeout", str(timeout)])

        # Service probing
        probe = config.get('probe', True)
        if not probe:
            cmd.append("--no-probe")

        # Attack mode
        attack_mode = config.get('attack_mode', 'default')
        if attack_mode and attack_mode != 'default':
            cmd.extend(["--attack-mode", attack_mode])

        # Attack mode specific parameters
        if attack_mode == 'single':
            username = config.get('username')
            password = config.get('password')
            if username:
                cmd.extend(["--single-username", username])
            if password:
                cmd.extend(["--single-password", password])
        elif attack_mode == 'spray':
            spray_password = config.get('spray_password')
            usernames_file = config.get('usernames_file')
            if spray_password:
                cmd.extend(["--spray-password", spray_password])
            if usernames_file:
                cmd.extend(["--usernames-file", usernames_file])
        elif attack_mode == 'stuff':
            stuff_username = config.get('stuff_username')
            passwords_file = config.get('passwords_file')
            if stuff_username:
                cmd.extend(["--stuff-username", stuff_username])
            if passwords_file:
                cmd.extend(["--passwords-file", passwords_file])
        elif attack_mode == 'key':
            ssh_key = config.get('ssh_key')
            if ssh_key:
                cmd.extend(["--ssh-key", ssh_key])

            ssh_cert = config.get('ssh_cert')
            if ssh_cert:
                cmd.extend(["--ssh-cert", ssh_cert])

            ssh_key_passphrase = config.get('ssh_key_passphrase')
            if ssh_key_passphrase:
                cmd.extend(["--ssh-key-passphrase", ssh_key_passphrase])

            # Handle usernames: comma-separated string or file path
            key_usernames = config.get('key_usernames')
            key_usernames_file = config.get('key_usernames_file')
            if key_usernames_file:
                cmd.extend(["--usernames-file", key_usernames_file])
            elif key_usernames:
                # If comma-separated usernames provided, write to a temp file
                usernames_list = [u.strip() for u in key_usernames.split(',') if u.strip()]
                if len(usernames_list) == 1:
                    cmd.extend(["--single-username", usernames_list[0]])
                elif len(usernames_list) > 1:
                    usernames_file_path = scheduled_workspace / "key_usernames.txt"
                    with open(usernames_file_path, 'w') as f:
                        f.write("\n".join(usernames_list))
                    cmd.extend(["--usernames-file", str(usernames_file_path)])
        elif attack_mode == 'credfile':
            credfile_path = config.get('credfile_path', '')
            credfile_content = config.get('credfile_content', '')

            # If content was pasted/uploaded, save it to a file first
            if credfile_content and not credfile_path:
                credfile_path = str(scheduled_workspace / "credfile.csv")
                with open(credfile_path, 'w') as f:
                    f.write(credfile_content)

            if credfile_path:
                protocols = config.get('protocols', [])
                # Multi-protocol: expand credfile with service column per entry
                if protocols and len(protocols) > 1:
                    from cygor.credrecon.credfile_parser import parse as _parse_cred
                    parsed = _parse_cred(credfile_path)
                    expanded_lines = ["ip,port,username,password,service"]
                    for entry in parsed.entries:
                        for svc in protocols:
                            p = entry.port or ""
                            expanded_lines.append(f"{entry.ip},{p},{entry.username},{entry.password},{svc}")
                    expanded_path = scheduled_workspace / "credfile_expanded.csv"
                    with open(expanded_path, 'w') as f:
                        f.write("\n".join(expanded_lines))
                    cmd.extend(["--credfile-path", str(expanded_path)])
                else:
                    cmd.extend(["--credfile-path", credfile_path])

                # Extract IPs from credfile for targets if targets are empty
                if not targets_content.strip():
                    from cygor.credrecon.credfile_parser import parse as _parse_cred_targets
                    parsed_targets = _parse_cred_targets(credfile_path)
                    unique_ips = {entry.ip for entry in parsed_targets.entries if entry.ip}
                    if unique_ips:
                        targets_content = "\n".join(sorted(unique_ips))
                        with open(targets_file, 'w') as f:
                            f.write(targets_content)

                # Fallback port
                port = config.get('port')
                if port:
                    cmd.extend(["--port", str(port)])
        elif attack_mode == 'default':
            # Default mode - custom wordlists
            usernames_file = config.get('usernames_file')
            passwords_file = config.get('passwords_file')
            if usernames_file:
                cmd.extend(["--usernames-file", usernames_file])
            if passwords_file:
                cmd.extend(["--passwords-file", passwords_file])

        # New CredRecon options
        jitter = config.get('jitter')
        if jitter and float(jitter) > 0:
            cmd.extend(["--jitter", str(jitter)])

        max_attempts_per_user = config.get('max_attempts_per_user')
        if max_attempts_per_user and int(max_attempts_per_user) > 0:
            cmd.extend(["--max-attempts-per-user", str(max_attempts_per_user)])

        smb_hash = config.get('smb_hash')
        if smb_hash:
            cmd.extend(["--smb-hash", smb_hash])

        domain = config.get('domain')
        if domain:
            cmd.extend(["--domain", domain])

        snmp_tier = config.get('snmp_tier')
        if snmp_tier and snmp_tier != 'default':
            cmd.extend(["--snmp-tier", snmp_tier])

        badkeys = config.get('badkeys', True)
        if not badkeys:
            cmd.append("--no-badkeys")

        # Add output directory and scan-id
        cmd.extend(["-o", str(scheduled_workspace)])
        cmd.extend(["--scan-id", scan_id])

        logger.info(f"Scheduled credrecon command: {' '.join(cmd)}")

        # Create database record first (same as /api/credrecon endpoint)
        try:
            from .models import CredReconScan
            from .db import SessionLocal

            async with SessionLocal() as db_session:
                db_scan = CredReconScan(
                    scan_id=scan_id,
                    created_at=datetime.utcnow().isoformat(),
                    status="pending",
                    command=" ".join(cmd),
                    num_targets=num_targets
                )
                db_session.add(db_scan)
                await db_session.commit()
                logger.info(f"Created database record for scheduled credrecon scan {scan_id}")
        except Exception as e:
            logger.warning(f"Failed to create database record for credrecon scan {scan_id}: {e}")
            # Continue anyway - the scan will still run, just won't have DB persistence

        # Create scan using the manager with proper parameters
        await self.credrecon_manager.create_scan(
            command=cmd,
            num_targets=num_targets,
            scan_id=scan_id
        )

        return scan_id, str(scheduled_workspace)

    async def _record_execution(
        self,
        session: AsyncSession,
        scheduled_task: ScheduledTask,
        scheduled_time: datetime,
        task_id: Optional[str] = None,
        status: str = 'running',
        message: Optional[str] = None,
        error: Optional[str] = None,
        cpu_percent: Optional[float] = None,
        memory_percent: Optional[float] = None,
        resources_ok: bool = True,
        output_path: Optional[str] = None,
        retry_attempt: int = 0,
        retry_of_history_id: Optional[int] = None
    ):
        """Record task execution in history."""
        # Always set started_at to the current time when recording execution
        # This ensures the "Started" time in the UI reflects when the task actually started
        now = datetime.utcnow()

        history = ScheduledTaskHistory(
            scheduled_task_id=scheduled_task.id,
            task_id=task_id,
            status=status,
            scheduled_time=scheduled_time,
            started_at=now,  # Always set started_at to current time
            message=message,
            error=error,
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            resources_ok=resources_ok,
            output_path=output_path,
            retry_attempt=retry_attempt,
            retry_of_history_id=retry_of_history_id
        )

        session.add(history)
        await session.commit()
        await session.refresh(history)

        logger.info(f"Recorded execution history: scheduled_task_id={scheduled_task.id}, task_id={task_id}, status={status}, history_id={history.id}")

    async def _schedule_retry(
        self,
        scheduled_task_id: int,
        retry_attempt: int,
        reason: str,
        history_id: Optional[int] = None
    ):
        """Schedule a retry for a failed/skipped task using a one-shot DateTrigger."""
        from .db import SessionLocal
        from datetime import timedelta

        async with SessionLocal() as session:
            statement = select(ScheduledTask).where(ScheduledTask.id == scheduled_task_id)
            result = await session.execute(statement)
            scheduled_task = result.scalar_one_or_none()

            if not scheduled_task:
                logger.warning(f"[RETRY] Scheduled task {scheduled_task_id} not found, skipping retry")
                return

            if scheduled_task.max_retries <= 0 or retry_attempt > scheduled_task.max_retries:
                logger.info(f"[RETRY] Task {scheduled_task_id}: max retries reached ({retry_attempt}/{scheduled_task.max_retries})")
                return

            if scheduled_task.end_date and datetime.utcnow() > scheduled_task.end_date:
                logger.info(f"[RETRY] Task {scheduled_task_id}: past end_date, skipping retry")
                return

            base_delay = scheduled_task.retry_delay_seconds
            if scheduled_task.retry_backoff:
                delay = base_delay * (2 ** (retry_attempt - 1))
            else:
                delay = base_delay

            retry_time = datetime.utcnow() + timedelta(seconds=delay)

            if scheduled_task.end_date and retry_time > scheduled_task.end_date:
                logger.info(f"[RETRY] Task {scheduled_task_id}: retry time past end_date, skipping")
                return

            logger.info(f"[RETRY] Scheduling retry {retry_attempt}/{scheduled_task.max_retries} for task {scheduled_task_id} at {retry_time} (delay: {delay}s, reason: {reason})")

            job_id = f"retry_{scheduled_task_id}_{retry_attempt}"
            try:
                existing = self.scheduler.get_job(job_id)
                if existing:
                    self.scheduler.remove_job(job_id)
            except Exception:
                pass

            self.scheduler.add_job(
                self._execute_scheduled_task,
                trigger=DateTrigger(run_date=retry_time, timezone=utc),
                args=[scheduled_task_id, retry_time, False, retry_attempt, history_id],
                id=job_id,
                name=f"Retry {retry_attempt} for {scheduled_task.name}",
                replace_existing=True
            )

    async def _update_history_on_completion(self, session: AsyncSession, task_id: str, task) -> None:
        """
        Update history record when a task completes.
        This is called when we detect a task has completed outside the regular monitoring cycle.
        """
        try:
            # Find the history record for this task
            history_statement = (
                select(ScheduledTaskHistory)
                .where(ScheduledTaskHistory.task_id == task_id)
                .order_by(ScheduledTaskHistory.id.desc())
                .limit(1)
            )
            history_result = await session.execute(history_statement)
            history_record = history_result.scalar_one_or_none()

            if history_record and history_record.status == 'running':
                history_record.status = task.status.value
                history_record.completed_at = task.completed_at or datetime.utcnow()

                if history_record.started_at and history_record.completed_at:
                    duration = (history_record.completed_at - history_record.started_at).total_seconds()
                    history_record.duration_seconds = duration

                if task.output_dir:
                    history_record.output_path = str(task.output_dir)

                if task.status.value == 'failed':
                    error_msg = '\n'.join(list(task.error_lines)[-10:]) if task.error_lines else 'Task failed'
                    history_record.error = error_msg[:1000]
                elif task.status.value == 'completed':
                    history_record.message = 'Task completed successfully'

                await session.commit()
                logger.info(f"Updated history record for task {task_id} to status {task.status.value}")
        except Exception as e:
            logger.error(f"Error updating history on completion for task {task_id}: {e}", exc_info=True)

    async def _on_task_completed(self, scheduled_task_id: int, task) -> None:
        """
        Callback method called when a task completes.
        This provides immediate status updates without waiting for the monitoring loop.
        """
        from .db import SessionLocal

        logger.info(f"Task completion callback: scheduled_task_id={scheduled_task_id}, task_id={task.task_id}, status={task.status.value}")

        try:
            async with SessionLocal() as session:
                # Update scheduled task status
                statement = select(ScheduledTask).where(ScheduledTask.id == scheduled_task_id)
                result = await session.execute(statement)
                scheduled_task = result.scalar_one_or_none()

                if scheduled_task:
                    scheduled_task.last_run_status = task.status.value
                    await session.commit()

                # Update history record
                history_statement = (
                    select(ScheduledTaskHistory)
                    .where(ScheduledTaskHistory.task_id == task.task_id)
                    .order_by(ScheduledTaskHistory.id.desc())
                    .limit(1)
                )
                history_result = await session.execute(history_statement)
                history_record = history_result.scalar_one_or_none()

                if history_record and history_record.status == 'running':
                    history_record.status = task.status.value
                    history_record.completed_at = task.completed_at or datetime.utcnow()

                    if history_record.started_at and history_record.completed_at:
                        duration = (history_record.completed_at - history_record.started_at).total_seconds()
                        history_record.duration_seconds = duration

                    if task.output_dir:
                        history_record.output_path = str(task.output_dir)

                    if task.status.value == 'failed':
                        error_msg = '\n'.join(list(task.error_lines)[-10:]) if task.error_lines else 'Task failed'
                        history_record.error = error_msg[:1000]
                    elif task.status.value == 'completed':
                        history_record.message = 'Task completed successfully'

                    await session.commit()
                    logger.info(f"Updated history via callback for scheduled_task_id={scheduled_task_id}")

                # Schedule retry on failure if configured
                if task.status.value == 'failed' and scheduled_task:
                    if scheduled_task.max_retries and scheduled_task.max_retries > 0:
                        current_attempt = history_record.retry_attempt if history_record else 0
                        if current_attempt < scheduled_task.max_retries:
                            await self._schedule_retry(
                                scheduled_task_id,
                                current_attempt + 1,
                                f'Task failed',
                                history_id=history_record.id if history_record else None
                            )

                # Remove from running tasks tracking
                await self._delete_running_record(scheduled_task_id)

        except Exception as e:
            logger.error(f"Error in task completion callback for scheduled_task_id={scheduled_task_id}: {e}", exc_info=True)
            # Still clean up running_tasks even on error
            await self._delete_running_record(scheduled_task_id)

    async def _on_scan_completed(self, scheduled_task_id: int, scan) -> None:
        """
        Callback method called when a credrecon scan completes.
        Handles scan objects that use scan_id and enum status attributes.
        """
        from .db import SessionLocal

        scan_id = scan.scan_id
        status = scan.status.value

        logger.info(f"Scan completion callback: scheduled_task_id={scheduled_task_id}, scan_id={scan_id}, status={status}")

        try:
            async with SessionLocal() as session:
                # Update scheduled task status
                statement = select(ScheduledTask).where(ScheduledTask.id == scheduled_task_id)
                result = await session.execute(statement)
                scheduled_task = result.scalar_one_or_none()

                if scheduled_task:
                    scheduled_task.last_run_status = status
                    await session.commit()

                # Update history record
                history_statement = (
                    select(ScheduledTaskHistory)
                    .where(ScheduledTaskHistory.task_id == scan_id)
                    .order_by(ScheduledTaskHistory.id.desc())
                    .limit(1)
                )
                history_result = await session.execute(history_statement)
                history_record = history_result.scalar_one_or_none()

                if history_record and history_record.status == 'running':
                    history_record.status = status
                    history_record.completed_at = scan.completed_at or datetime.utcnow()

                    if history_record.started_at and history_record.completed_at:
                        duration = (history_record.completed_at - history_record.started_at).total_seconds()
                        history_record.duration_seconds = duration

                    if status == 'failed':
                        error_msg = '\n'.join(list(scan.error_lines)[-10:]) if scan.error_lines else 'Scan failed'
                        history_record.error = error_msg[:1000]
                    elif status == 'completed':
                        history_record.message = 'Scan completed successfully'

                    await session.commit()
                    logger.info(f"Updated history via scan callback for scheduled_task_id={scheduled_task_id}")

                # Schedule retry on failure if configured
                if status == 'failed' and scheduled_task:
                    if scheduled_task.max_retries and scheduled_task.max_retries > 0:
                        current_attempt = history_record.retry_attempt if history_record else 0
                        if current_attempt < scheduled_task.max_retries:
                            await self._schedule_retry(
                                scheduled_task_id,
                                current_attempt + 1,
                                f'Scan failed',
                                history_id=history_record.id if history_record else None
                            )

                # Remove from running tasks tracking
                await self._delete_running_record(scheduled_task_id)

        except Exception as e:
            logger.error(f"Error in scan completion callback for scheduled_task_id={scheduled_task_id}: {e}", exc_info=True)
            # Still clean up running_tasks even on error
            await self._delete_running_record(scheduled_task_id)

    def _job_executed_listener(self, event):
        """Listen to job execution events."""
        # This runs in the scheduler's thread
        logger.debug(f"Job event: {event}")

    async def monitor_running_tasks(self):
        """
        Background task to monitor running scheduled tasks and update their status.
        This should be called periodically to check task completion.
        """
        from .db import SessionLocal

        if not self.running_tasks:
            return

        # Make a copy of running tasks to avoid modification during iteration
        running_tasks_copy = dict(self.running_tasks)

        async with SessionLocal() as session:
            for scheduled_task_id, task_id in running_tasks_copy.items():
                try:
                    # First, get the scheduled task to determine its type
                    sched_statement = select(ScheduledTask).where(ScheduledTask.id == scheduled_task_id)
                    sched_result = await session.execute(sched_statement)
                    scheduled_task_record = sched_result.scalar_one_or_none()

                    task = None
                    task_status = None
                    task_completed_at = None
                    task_output_dir = None
                    task_error_lines = []

                    # Check the appropriate manager based on task type
                    if scheduled_task_record and scheduled_task_record.task_type == 'credrecon':
                        # Check credrecon manager for credrecon tasks
                        if self.credrecon_manager:
                            credrecon_task = await self.credrecon_manager.get_scan(task_id)
                            if credrecon_task:
                                task_status = credrecon_task.status.value
                                task_completed_at = credrecon_task.completed_at
                                task_error_lines = credrecon_task.error_lines
                                # Get output dir from command if available
                                if credrecon_task.command:
                                    try:
                                        cmd_str = ' '.join(credrecon_task.command) if isinstance(credrecon_task.command, list) else credrecon_task.command
                                        if '-o ' in cmd_str:
                                            parts = cmd_str.split('-o ')
                                            if len(parts) > 1:
                                                task_output_dir = parts[1].split()[0]
                                    except Exception:
                                        pass
                    else:
                        # Check general task manager for port_scan and module_scan
                        if self.task_manager:
                            task = await self.task_manager.get_task(task_id)
                            if task:
                                task_status = task.status.value
                                task_completed_at = task.completed_at
                                task_output_dir = task.output_dir
                                task_error_lines = task.error_lines if hasattr(task, 'error_lines') else []

                    if not task_status:
                        # Task not found - might have been cleaned up
                        logger.warning(f"Task {task_id} for scheduled task {scheduled_task_id} not found")
                        await self._delete_running_record(scheduled_task_id)
                        continue

                    # Check if task is still running
                    if task_status in ['completed', 'failed', 'cancelled']:
                        # Task finished - update scheduled task and history
                        statement = select(ScheduledTask).where(ScheduledTask.id == scheduled_task_id)
                        result = await session.execute(statement)
                        scheduled_task = result.scalar_one_or_none()

                        if scheduled_task:
                            # Update scheduled task status
                            scheduled_task.last_run_status = task_status
                            await session.commit()

                            # Update history record
                            history_statement = (
                                select(ScheduledTaskHistory)
                                .where(ScheduledTaskHistory.task_id == task_id)
                                .order_by(ScheduledTaskHistory.id.desc())
                                .limit(1)
                            )
                            history_result = await session.execute(history_statement)
                            history_record = history_result.scalar_one_or_none()

                            if history_record:
                                history_record.status = task_status
                                history_record.completed_at = task_completed_at or datetime.utcnow()

                                if history_record.started_at and history_record.completed_at:
                                    duration = (history_record.completed_at - history_record.started_at).total_seconds()
                                    history_record.duration_seconds = duration

                                # Store output path for offline viewing
                                if task_output_dir:
                                    history_record.output_path = str(task_output_dir)

                                if task_status == 'failed':
                                    error_msg = '\n'.join(list(task_error_lines)[-10:]) if task_error_lines else 'Task failed'
                                    history_record.error = error_msg[:1000]  # Limit error message length
                                elif task_status == 'completed':
                                    history_record.message = 'Task completed successfully'

                                await session.commit()

                        # Remove from running tasks
                        await self._delete_running_record(scheduled_task_id)
                        logger.info(f"Updated scheduled task {scheduled_task_id}: task {task_id} {task_status}")

                    elif task_status == 'running':
                        # Watchdog: check for stalled tasks
                        if scheduled_task_record and scheduled_task_record.stall_timeout_seconds:
                            stall_timeout = scheduled_task_record.stall_timeout_seconds

                            # Get last_output_at from the task object in the appropriate manager
                            last_output = None
                            if scheduled_task_record.task_type in ('port_scan', 'module_scan') and self.task_manager:
                                t = await self.task_manager.get_task(task_id)
                                if t:
                                    last_output = getattr(t, 'last_output_at', None)
                            elif scheduled_task_record.task_type == 'credrecon' and self.credrecon_manager:
                                s = await self.credrecon_manager.get_scan(task_id)
                                if s:
                                    last_output = getattr(s, 'last_output_at', None)

                            if last_output:
                                elapsed = (datetime.utcnow() - last_output).total_seconds()
                                if elapsed > stall_timeout:
                                    logger.warning(
                                        f"[WATCHDOG] Task {task_id} stalled: no output for {int(elapsed)}s "
                                        f"(timeout: {stall_timeout}s). Killing process."
                                    )

                                    # Kill the stalled process
                                    process = None
                                    if scheduled_task_record.task_type in ('port_scan', 'module_scan') and self.task_manager:
                                        t = await self.task_manager.get_task(task_id)
                                        if t and t.process:
                                            process = t.process
                                    elif scheduled_task_record.task_type == 'credrecon' and self.credrecon_manager:
                                        s = await self.credrecon_manager.get_scan(task_id)
                                        if s and s.process:
                                            process = s.process

                                    if process:
                                        try:
                                            process.terminate()
                                            try:
                                                await asyncio.wait_for(process.wait(), timeout=10)
                                            except asyncio.TimeoutError:
                                                process.kill()
                                        except ProcessLookupError:
                                            pass

                                    # Update status in database
                                    stall_msg = f'Stalled: no output for {int(elapsed / 60)} minutes'

                                    statement = select(ScheduledTask).where(ScheduledTask.id == scheduled_task_id)
                                    result = await session.execute(statement)
                                    sched_task = result.scalar_one_or_none()
                                    if sched_task:
                                        sched_task.last_run_status = 'failed'
                                        await session.commit()

                                    # Update history record
                                    history_statement = (
                                        select(ScheduledTaskHistory)
                                        .where(ScheduledTaskHistory.task_id == task_id)
                                        .order_by(ScheduledTaskHistory.id.desc())
                                        .limit(1)
                                    )
                                    history_result = await session.execute(history_statement)
                                    history_record = history_result.scalar_one_or_none()
                                    if history_record:
                                        history_record.status = 'failed'
                                        history_record.completed_at = datetime.utcnow()
                                        history_record.error = stall_msg
                                        if history_record.started_at:
                                            history_record.duration_seconds = (history_record.completed_at - history_record.started_at).total_seconds()
                                        await session.commit()

                                        # Schedule retry if configured
                                        current_attempt = history_record.retry_attempt
                                        if sched_task and sched_task.max_retries > 0 and current_attempt < sched_task.max_retries:
                                            await self._schedule_retry(
                                                scheduled_task_id,
                                                current_attempt + 1,
                                                stall_msg,
                                                history_id=history_record.id
                                            )

                                    # Clean up tracking
                                    await self._delete_running_record(scheduled_task_id)
                                    logger.info(f"[WATCHDOG] Killed stalled task {task_id} for scheduled task {scheduled_task_id}")

                except Exception as e:
                    logger.error(f"Error monitoring task {task_id} for scheduled task {scheduled_task_id}: {e}", exc_info=True)
                    # Clean up to prevent the task from being stuck in running_tasks forever
                    await self._delete_running_record(scheduled_task_id)

    async def get_scheduled_task_history(
        self,
        session: AsyncSession,
        task_id: int,
        limit: int = 50,
        offset: int = 0
    ) -> tuple[List[ScheduledTaskHistory], int]:
        """
        Get execution history for a scheduled task with pagination.

        Args:
            session: Database session
            task_id: Scheduled task ID
            limit: Maximum number of history records to return
            offset: Number of records to skip (for pagination)

        Returns:
            Tuple of (list of ScheduledTaskHistory records, total count)
        """
        from sqlalchemy import func

        # Get total count
        count_statement = (
            select(func.count(ScheduledTaskHistory.id))
            .where(ScheduledTaskHistory.scheduled_task_id == task_id)
        )
        count_result = await session.execute(count_statement)
        total_count = count_result.scalar() or 0

        # Get paginated records
        statement = (
            select(ScheduledTaskHistory)
            .where(ScheduledTaskHistory.scheduled_task_id == task_id)
            .order_by(ScheduledTaskHistory.scheduled_time.desc())
            .offset(offset)
            .limit(limit)
        )
        result = await session.execute(statement)
        return list(result.scalars().all()), total_count


# Global scheduler manager instance
scheduler_manager: Optional[SchedulerManager] = None


def get_scheduler_manager() -> SchedulerManager:
    """Get the global scheduler manager instance."""
    global scheduler_manager
    if scheduler_manager is None:
        raise RuntimeError("Scheduler manager not initialized")
    return scheduler_manager


def initialize_scheduler_manager(
    task_manager=None,
    credrecon_manager=None
) -> SchedulerManager:
    """
    Initialize the global scheduler manager.

    Args:
        task_manager: TaskManager instance
        credrecon_manager: CredReconManager instance

    Returns:
        Initialized SchedulerManager instance
    """
    global scheduler_manager
    if scheduler_manager is None:
        scheduler_manager = SchedulerManager(
            task_manager=task_manager,
            credrecon_manager=credrecon_manager
        )
    return scheduler_manager
