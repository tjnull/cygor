"""
Unified task abstraction for Cygor web UI.
Combines port_scan, credential_test, parse, and module tasks into a single interface.
"""
from enum import Enum
from typing import Optional, Dict, Any, List
from datetime import datetime


class UnifiedTaskType(str, Enum):
    """Type of task"""
    PORT_SCAN = "port_scan"
    CREDENTIAL_TEST = "credential_test"
    MODULE = "module"
    PARSE = "parse"
    ENRICH = "enrich"


class UnifiedTask:
    """Unified task representation for web UI"""

    def __init__(
        self,
        task_id: str,
        task_type: UnifiedTaskType,
        status: str,
        created_at: str,
        command: Optional[List[str]] = None,
        targets: Optional[str] = None,
        output_dir: Optional[str] = None,
        num_targets: Optional[int] = None,
        progress: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        self.task_id = task_id
        self.task_type = task_type
        self.status = status
        self.created_at = created_at
        self.command = command or []
        self.targets = targets
        self.output_dir = output_dir
        self.num_targets = num_targets
        self.progress = progress or {}
        self.metadata = kwargs

    @classmethod
    def from_port_scan_task(cls, task) -> "UnifiedTask":
        """Convert a port scan task to unified task"""
        # Determine the unified type based on task properties
        unified_type = UnifiedTaskType.PORT_SCAN

        if hasattr(task, 'task_type'):
            if task.task_type == "scan":
                unified_type = UnifiedTaskType.PORT_SCAN
            elif task.task_type == "module":
                unified_type = UnifiedTaskType.MODULE
            elif task.task_type == "generic":
                # Check if it's a parse command
                cmd_str = " ".join(task.command) if isinstance(task.command, list) else str(task.command)
                if "cygor parse" in cmd_str or (isinstance(task.command, list) and len(task.command) >= 2 and task.command[0:2] == ["cygor", "parse"]):
                    unified_type = UnifiedTaskType.PARSE
                else:
                    unified_type = UnifiedTaskType.MODULE

        return cls(
            task_id=task.task_id,
            task_type=unified_type,
            status=task.status,
            created_at=task.created_at,
            command=task.command if isinstance(task.command, list) else [str(task.command)],
            targets=getattr(task, 'targets', None),
            output_dir=getattr(task, 'output_dir', None),
            num_targets=getattr(task, 'num_targets', None),
            progress=getattr(task, 'progress', {}),
        )

    @classmethod
    def from_credrecon_task(cls, task) -> "UnifiedTask":
        """Convert a credential recon task to unified task"""
        return cls(
            task_id=task.scan_id,
            task_type=UnifiedTaskType.CREDENTIAL_TEST,
            status=task.status,
            created_at=task.created_at,
            command=task.command.split() if isinstance(task.command, str) else task.command,
            num_targets=getattr(task, 'num_targets', None),
            progress=getattr(task, 'progress', {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "task_id": self.task_id,
            "task_type": self.task_type.value,
            "status": self.status,
            "created_at": self.created_at,
            "command": self.command,
            "targets": self.targets,
            "output_dir": self.output_dir,
            "num_targets": self.num_targets,
            "progress": self.progress,
            **self.metadata
        }

    @property
    def display_name(self) -> str:
        """Get a human-readable display name for the task"""
        if self.task_type == UnifiedTaskType.PORT_SCAN:
            return f"Port Scan - {self.task_id[:8]}"
        elif self.task_type == UnifiedTaskType.CREDENTIAL_TEST:
            return f"Credential Test - {self.task_id[:8]}"
        elif self.task_type == UnifiedTaskType.PARSE:
            return f"Parse Results - {self.task_id[:8]}"
        elif self.task_type == UnifiedTaskType.MODULE:
            # Try to extract module name from command
            if self.command and len(self.command) > 2:
                module_name = self.command[2] if self.command[0] == "cygor" else "Unknown"
                return f"Module: {module_name} - {self.task_id[:8]}"
            return f"Module - {self.task_id[:8]}"
        return f"Task - {self.task_id[:8]}"
