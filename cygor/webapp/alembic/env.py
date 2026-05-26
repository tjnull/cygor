"""Alembic environment configuration for Cygor.

Reads the database URL from Cygor's own get_database_url() so there is a
single source of truth for connection strings.
"""
import sys
from pathlib import Path
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Ensure the project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from cygor.webapp.db import get_database_url          # noqa: E402
from cygor.webapp.models import SQLModel               # noqa: E402

# Alembic Config object
config = context.config

# Set up logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# SQLModel metadata for autogenerate support
target_metadata = SQLModel.metadata


def _sync_url(url: str) -> str:
    """Convert async driver URLs to sync equivalents for Alembic."""
    return (
        url
        .replace("postgresql+asyncpg", "postgresql+psycopg2")
        .replace("sqlite+aiosqlite", "sqlite")
    )


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (emit SQL to stdout)."""
    url = _sync_url(get_database_url())
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        render_as_batch=True,  # SQLite compatibility
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (connect to DB)."""
    url = _sync_url(get_database_url())
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
        url=url,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=True,  # SQLite compatibility
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
