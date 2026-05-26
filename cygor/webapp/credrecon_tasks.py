"""
Dedicated task management for credential reconnaissancener operations.
Separate from the main on-demand scanner to avoid overlap.
"""
import asyncio
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from enum import Enum
import uuid


class CredReconStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class CredReconTask:
    """Represents a credential reconnaissancener task."""
    def __init__(self, scan_id: str, command: List[str], num_targets: int):
        self.scan_id = scan_id
        self.command = command
        self.num_targets = num_targets
        self.status = CredReconStatus.PENDING
        self.created_at = datetime.utcnow()
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.process: Optional[asyncio.subprocess.Process] = None
        self.output_lines: List[str] = []
        self.error_lines: List[str] = []
        self.exit_code: Optional[int] = None
        self.last_output_at: Optional[datetime] = None  # Watchdog: last time output was produced

    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "command": " ".join(self.command),
            "num_targets": self.num_targets,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "exit_code": self.exit_code,
            "output_lines": len(self.output_lines),
            "error_lines": len(self.error_lines),
        }


class CredScannerManager:
    """Manages credential reconnaissancener tasks independently."""
    def __init__(self):
        self.scans: Dict[str, CredReconTask] = {}
        self._lock = asyncio.Lock()
        self._completion_callbacks: Dict[str, List[callable]] = {}

    def register_completion_callback(self, scan_id: str, callback: callable):
        """Register a callback to be called when a scan completes."""
        if scan_id not in self._completion_callbacks:
            self._completion_callbacks[scan_id] = []
        self._completion_callbacks[scan_id].append(callback)

    async def _notify_completion(self, scan: CredReconTask):
        """Notify registered callbacks that a scan has completed."""
        if scan.scan_id in self._completion_callbacks:
            for callback in self._completion_callbacks[scan.scan_id]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        await callback(scan)
                    else:
                        callback(scan)
                except Exception as e:
                    print(f"Error in completion callback for scan {scan.scan_id}: {e}", file=__import__('sys').stderr)
            del self._completion_callbacks[scan.scan_id]

    async def create_scan(
        self,
        command: List[str],
        num_targets: int,
        scan_id: str = None
    ) -> str:
        """Create a new credential reconnaissancener task."""
        if not scan_id:
            scan_id = str(uuid.uuid4())

        scan = CredReconTask(
            scan_id=scan_id,
            command=command,
            num_targets=num_targets
        )

        async with self._lock:
            self.scans[scan_id] = scan

        # Start the scan in the background
        asyncio.create_task(self._run_scan(scan))

        return scan_id

    async def _run_scan(self, scan: CredReconTask):
        """Execute a credential reconnaissance in the background with real-time output capture."""
        try:
            scan.status = CredReconStatus.RUNNING
            scan.started_at = datetime.utcnow()
            # Update database when scan starts
            await self._update_scan_in_database(scan)

            # Run the command
            process = await asyncio.create_subprocess_exec(
                *scan.command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=os.environ.copy()
            )
            scan.process = process

            # Stream output in real-time
            async def read_stream(stream, line_list):
                """Read from stream line by line and append to list."""
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded_line = line.decode('utf-8', errors='replace').rstrip()
                    if decoded_line:
                        scan.last_output_at = datetime.utcnow()
                    line_list.append(decoded_line)

            # Read stdout and stderr concurrently
            await asyncio.gather(
                read_stream(process.stdout, scan.output_lines),
                read_stream(process.stderr, scan.error_lines)
            )

            # Wait for process to complete
            await process.wait()
            scan.exit_code = process.returncode

            if process.returncode == 0:
                scan.status = CredReconStatus.COMPLETED
            else:
                scan.status = CredReconStatus.FAILED

        except Exception as e:
            scan.status = CredReconStatus.FAILED
            scan.error_lines.append(f"Exception during scan: {str(e)}")
        finally:
            scan.completed_at = datetime.utcnow()
            scan.process = None  # Release process reference
            # Persist output to disk so it survives server restarts
            self._save_output_to_disk(scan)
            # Update database record when scan completes
            await self._update_scan_in_database(scan)
            # Notify registered callbacks that scan has completed
            await self._notify_completion(scan)

    def _save_output_to_disk(self, scan: CredReconTask):
        """Persist stdout/stderr to disk so output survives server restarts."""
        try:
            # Extract output directory from command's -o flag
            workspace = None
            cmd = scan.command
            for i, arg in enumerate(cmd):
                if arg == "-o" and i + 1 < len(cmd):
                    workspace = Path(cmd[i + 1])
                    break
            if not workspace or not workspace.exists():
                return
            stdout_lines = list(scan.output_lines)
            stderr_lines = list(scan.error_lines)
            if stdout_lines:
                (workspace / "stdout.txt").write_text("\n".join(stdout_lines) + "\n")
            if stderr_lines:
                (workspace / "stderr.txt").write_text("\n".join(stderr_lines) + "\n")
        except Exception:
            pass  # Best-effort, don't fail the scan

    async def get_scan(self, scan_id: str) -> Optional[CredReconTask]:
        """Get a scan by ID."""
        async with self._lock:
            return self.scans.get(scan_id)

    async def get_all_scans(self) -> List[CredReconTask]:
        """Get all scans."""
        async with self._lock:
            return list(self.scans.values())

    async def get_scan_output(self, scan_id: str) -> Dict:
        """Get the output of a specific scan."""
        scan = await self.get_scan(scan_id)
        if not scan:
            return {"error": "Scan not found"}

        return {
            "scan_id": scan_id,
            "status": scan.status.value,
            "output": scan.output_lines,
            "errors": scan.error_lines,
            "exit_code": scan.exit_code
        }

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan."""
        scan = await self.get_scan(scan_id)
        if not scan:
            return False

        if scan.process and scan.status == CredReconStatus.RUNNING:
            try:
                scan.process.terminate()
                try:
                    await asyncio.wait_for(scan.process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    scan.process.kill()
                    await scan.process.wait()
                scan.status = CredReconStatus.FAILED
                scan.completed_at = datetime.utcnow()
                scan.process = None  # Release process reference
                # Update database record when scan is cancelled
                await self._update_scan_in_database(scan)
                # Notify registered callbacks
                await self._notify_completion(scan)
                return True
            except Exception:
                return False
        return False

    async def _update_scan_in_database(self, scan: CredReconTask):
        """Update the database record for a scan when it completes or is cancelled."""
        try:
            from sqlalchemy import select
            from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
            from sqlalchemy.orm import sessionmaker
            from cygor.webapp.models import CredReconScan
            from cygor.webapp import db
            import os
            
            # Use the same database connection logic as the main app
            # Try to use the existing engine if available, otherwise create a new one
            db_url = os.environ.get("CYGOR_DB_URL") or db.get_default_database_url()
            
            # Convert to async URL format if needed
            if db_url.startswith("postgresql://"):
                db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)
            elif db_url.startswith("postgresql+psycopg_async://"):
                # Already in async format
                pass
            elif db_url.startswith("sqlite:///"):
                db_url = db_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
            elif not db_url.startswith("sqlite+aiosqlite://"):
                # Default to SQLite if format is unknown
                db_url = "sqlite+aiosqlite:///cygor.db"
            
            engine = create_async_engine(db_url, echo=False, pool_pre_ping=True)
            async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
            
            try:
                async with async_session() as session:
                    # Find the scan record by scan_id
                    statement = select(CredReconScan).where(CredReconScan.scan_id == scan.scan_id)
                    result = await session.execute(statement)
                    db_scan = result.scalar_one_or_none()
                    
                    if db_scan:
                        # Update the database record
                        db_scan.status = scan.status.value
                        if scan.started_at:
                            db_scan.started_at = scan.started_at.isoformat()
                        if scan.completed_at:
                            db_scan.completed_at = scan.completed_at.isoformat()
                        
                        await session.commit()
                    else:
                        # Table might not exist yet - this is okay, just log it
                        print(f"Info: Scan {scan.scan_id} not found in database (table may not exist yet)", file=__import__('sys').stderr)
            finally:
                await engine.dispose()
        except Exception as e:
            # Don't fail the scan if database update fails, just log it
            # This can happen if the table doesn't exist yet or database isn't initialized
            error_msg = str(e)
            if "no such table" in error_msg.lower():
                print(f"Info: Database table not found for scan {scan.scan_id} - table may need to be created", file=__import__('sys').stderr)
            else:
                print(f"Warning: Failed to update scan {scan.scan_id} in database: {e}", file=__import__('sys').stderr)


# Global instance
credrecon_manager = CredScannerManager()
