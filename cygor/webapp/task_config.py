"""
Task configuration management - handles task user tracking settings.
"""
import os
import json
from pathlib import Path
from typing import Optional


def _get_task_config() -> dict:
    """Load task configuration from file if it exists."""
    config_path = Path.home() / ".cygor" / "task_config.json"
    if config_path.exists():
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save_task_config(config: dict):
    """Save task configuration to file."""
    config_path = Path.home() / ".cygor" / "task_config.json"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    config_path.chmod(0o600)  # Read/write for owner only


def is_task_user_tracking_enabled() -> bool:
    """Check if task user tracking is enabled."""
    # First check environment variable
    env_value = os.getenv("CYGOR_TASK_USER_TRACKING", "").lower()
    if env_value in ("true", "1", "yes", "on"):
        return True
    if env_value in ("false", "0", "no", "off"):
        return False

    # Fall back to config file (when env_value is empty or unset)
    config = _get_task_config()
    return config.get("track_user_tasks", False)


def set_task_user_tracking(enabled: bool):
    """Set task user tracking enabled/disabled."""
    config = _get_task_config()
    config["track_user_tasks"] = enabled
    _save_task_config(config)


def get_task_config() -> dict:
    """Get current task configuration."""
    return {
        "track_user_tasks": is_task_user_tracking_enabled()
    }

