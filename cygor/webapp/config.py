from dataclasses import dataclass
from pathlib import Path
import os
import json

def _get_default_workspace():
    """Load the default workspace from cygor config if set."""
    config_dir = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "cygor"
    config_file = config_dir / "config.json"

    if config_file.exists():
        try:
            cfg = json.loads(config_file.read_text())
            workspace = cfg.get("default_workspace")
            if workspace and Path(workspace).exists():
                return Path(workspace)
        except Exception:
            pass
    return None

@dataclass
class Settings:
    # First check CYGOR_WORKSPACE env var, then default workspace, then fallback to 'results'
    RESULTS_DIR: Path = Path(
        os.environ.get("CYGOR_WORKSPACE") or
        os.environ.get("CYGOR_RESULTS_DIR") or
        str(_get_default_workspace() or "results")
    )
    DATABASE_URL: str = os.environ.get(
        "CYGOR_DATABASE_URL",
        f"sqlite+aiosqlite:///{RESULTS_DIR}/cygor.db"
    )
    DEBUG: bool = os.environ.get("CYGOR_DEBUG", "0") == "1"

    # Pagination settings
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 500

settings = Settings()
