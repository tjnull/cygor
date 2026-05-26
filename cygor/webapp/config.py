from dataclasses import dataclass
from pathlib import Path
import os

from cygor.workspace import resolve_workspace, app_data_dir


def _resolve_results_dir():
    """Resolve the web app's scan-output directory.

    Returns (path, configured). When no workspace is configured we return a
    sentinel path that is never written to -- scan launches are gated on a live
    re-resolve (see tasks.py), so reads simply find nothing and the UI can
    prompt the user to configure a workspace.
    """
    ws = resolve_workspace()
    if ws is not None:
        return ws, True
    return app_data_dir() / "_no_workspace", False


_RESULTS_DIR, _WORKSPACE_CONFIGURED = _resolve_results_dir()
_APP_DB_PATH = app_data_dir() / "cygor.db"

@dataclass
class Settings:
    """
    Configuration settings for Cygor web application.

    Database Configuration:
    -----------------------
    The database system uses an automatic fallback strategy:
    1. PostgreSQL (latest version available) - preferred for production
    2. PostgreSQL (earlier versions) - fallback if latest version fails
    3. SQLite - fallback if PostgreSQL is not available

    Environment Variables:
    ----------------------
    CYGOR_DB_URL: Explicit database URL (overrides auto-detection)
        - PostgreSQL: postgresql+psycopg_async://user:pass@host:port/dbname
        - SQLite: sqlite+aiosqlite:///path/to/db.db

    CYGOR_DB_USER: PostgreSQL user (default: cygor)
    CYGOR_DB_PASSWORD: PostgreSQL password (auto-generated if not set)
    CYGOR_DB_NAME: PostgreSQL database name (default: cygor)
    CYGOR_DB_HOST: PostgreSQL host (default: localhost)
    CYGOR_DB_PORT: PostgreSQL port (default: auto-detected)

    CYGOR_WORKSPACE: Workspace/results directory
    CYGOR_RESULTS_DIR: Alias for CYGOR_WORKSPACE
    CYGOR_DEBUG: Enable debug mode (0 or 1)
    """

    # Scan output directory. Resolved from $CYGOR_WORKSPACE/$CYGOR_RESULTS_DIR
    # or the active workspace config. When nothing is configured this is a
    # sentinel path that is never written to; WORKSPACE_CONFIGURED is False and
    # scan launches are blocked until a workspace is set.
    RESULTS_DIR: Path = _RESULTS_DIR
    WORKSPACE_CONFIGURED: bool = _WORKSPACE_CONFIGURED

    # Database URL - will be set by DatabaseManager during initialization.
    # The SQLite fallback DB is cygor's own state, so it lives in the app data
    # dir (~/.cygor), not in the user's scan workspace.
    DATABASE_URL: str = os.environ.get(
        "CYGOR_DB_URL",
        f"sqlite+aiosqlite:///{_APP_DB_PATH}"
    )

    DEBUG: bool = os.environ.get("CYGOR_DEBUG", "0") == "1"

    # Pagination settings
    DEFAULT_PAGE_SIZE: int = 50
    MAX_PAGE_SIZE: int = 500

settings = Settings()
