from dataclasses import dataclass
from pathlib import Path
import os

@dataclass
class Settings:
    RESULTS_DIR: Path = Path(os.environ.get("CYGOR_RESULTS_DIR", "results"))
    DATABASE_URL: str = os.environ.get(
        "CYGOR_DATABASE_URL",
        f"sqlite+aiosqlite:///{RESULTS_DIR}/cygor.db"
    )
    DEBUG: bool = os.environ.get("CYGOR_DEBUG", "0") == "1"

settings = Settings()
