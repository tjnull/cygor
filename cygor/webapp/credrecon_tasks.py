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
                await asyncio.sleep(1)
                if scan.process.returncode is None:
                    scan.process.kill()
                scan.status = CredReconStatus.FAILED
                scan.completed_at = datetime.utcnow()
                return True
            except Exception:
                return False
        return False


# Global instance
credrecon_manager = CredScannerManager()
