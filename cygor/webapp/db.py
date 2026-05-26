import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlmodel import SQLModel, select
from .models import (
    Host, Port, Script, OSGuess, SavedSearch,
    DeviceInfo, HostTag, RunningTaskRecord
)
from .db_adapters import DatabaseManager, DatabaseInfo
from sqlalchemy import text
from cygor.workspace import app_data_dir

# -------------------------------------------------------------------
# Globals and One-Time Guards
# -------------------------------------------------------------------
engine = None
SessionLocal = None
db_manager: Optional[DatabaseManager] = None

_engine_initialized = False
_db_initialized = False


# -------------------------------------------------------------------
# Database Manager Initialization
# -------------------------------------------------------------------
def get_db_manager(workspace: Optional[Path] = None, verbose: int = 0) -> DatabaseManager:
    """Get or create the global database manager instance."""
    global db_manager
    if db_manager is None:
        db_manager = DatabaseManager(workspace=workspace, verbose=verbose)
    return db_manager


def initialize_database(
    workspace: Optional[Path] = None,
    prefer_postgres: bool = True,
    auto_start_postgres: bool = False,
    verbose: int = 0
) -> DatabaseInfo:
    """
    Initialize database with automatic fallback from PostgreSQL to SQLite.

    Args:
        workspace: Workspace directory for SQLite database
        prefer_postgres: Try PostgreSQL before SQLite
        auto_start_postgres: Automatically start PostgreSQL cluster if not running
        verbose: Verbosity level (0=quiet, 1=info, 2=debug)

    Returns:
        DatabaseInfo object with connection details
    """
    manager = get_db_manager(workspace=workspace, verbose=verbose)
    info = manager.initialize(
        prefer_postgres=prefer_postgres,
        auto_start_postgres=auto_start_postgres
    )
    return info


def get_database_url() -> str:
    """Get the current database URL from the manager."""
    global db_manager

    # Check environment variable first
    env_url = os.getenv("CYGOR_DB_URL")
    if env_url:
        return env_url

    # Use database manager if initialized
    if db_manager:
        return db_manager.get_connection_url()

    # Not initialized yet: resolve through the standard initializer so PostgreSQL
    # is preferred (Postgres is cygor's primary backend). This also routes any
    # SQLite fallback through the DatabaseManager, which keeps the file in the app
    # data dir (~/.cygor) -- never a throwaway cygor.db in the current directory.
    try:
        info = initialize_database(prefer_postgres=True)
        if info and getattr(info, "url", None):
            return info.url
    except Exception:
        pass

    # Last-resort fallback: absolute SQLite path in the app data dir.
    from cygor.workspace import app_data_dir
    return f"sqlite+aiosqlite:///{app_data_dir() / 'cygor.db'}"


def get_sync_database_url() -> Optional[str]:
    """
    Get a synchronous-compatible PostgreSQL URL for use with psycopg (not asyncpg).

    Used by code paths that need synchronous database operations.
    Returns None if PostgreSQL is not available.
    """
    global db_manager

    # Check environment variable first (CYGOR_DATABASE_URL for sync operations)
    env_url = os.getenv("CYGOR_DATABASE_URL")
    if env_url:
        return env_url

    # Use database manager if initialized
    if db_manager and db_manager.adapter:
        info = db_manager.get_info()
        if info and info.backend == "postgresql":
            # Build a sync-compatible URL from the adapter's info
            from .db_adapters import PostgreSQLAdapter
            if isinstance(db_manager.adapter, PostgreSQLAdapter):
                adapter = db_manager.adapter
                return f"postgresql://{adapter.user}:{adapter.password}@{adapter.host}:{adapter.port}/{adapter.database}"

    return None


# -------------------------------------------------------------------
# Engine Initialization (Legacy compatibility)
# -------------------------------------------------------------------
def get_default_database_url() -> str:
    """
    Legacy function for compatibility.
    Returns database URL from environment or default SQLite.
    """
    return get_database_url()


def detect_postgresql() -> bool:
    """
    Legacy function for compatibility.
    Detect PostgreSQL installation.
    """
    from .db_adapters import PostgreSQLAdapter
    adapter = PostgreSQLAdapter()
    return adapter.is_available()


def setup_postgres(user=None, password=None, db_name=None, host=None, port=None):
    """
    Legacy function for compatibility.
    Create PostgreSQL role and database if not present.
    """
    from .db_adapters import PostgreSQLAdapter

    adapter = PostgreSQLAdapter(
        user=user,
        password=password,
        database=db_name,
        host=host,
        port=int(port) if port else None,
        auto_detect_port=port is None
    )

    if not adapter.is_available():
        return None

    if adapter.setup():
        return adapter.get_connection_url()

    return None


# -------------------------------------------------------------------
# Engine Initialization
# -------------------------------------------------------------------
def init_engine(database_url: str, debug: bool = False):
    """Initialize SQLAlchemy async engine."""
    global engine, SessionLocal

    if engine is not None:
        try:
            asyncio.get_running_loop().create_task(engine.dispose())
        except Exception:
            pass

    engine = create_async_engine(
        database_url,
        echo=debug,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=25,
        max_overflow=50,
        future=True,
    )

    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    return engine


# -------------------------------------------------------------------
# Snapshot & Hot-Swap
# -------------------------------------------------------------------
SNAPSHOT_DIR = app_data_dir() / "db-snapshots"
MAX_SNAPSHOTS = 10


def _get_dialect_name() -> str:
    """Get the dialect name of the current engine."""
    if engine is None:
        return "unknown"
    return engine.dialect.name  # 'postgresql', 'sqlite', 'mssql', 'mysql', 'oracle'


async def _column_exists(conn, table_name: str, column_name: str) -> bool:
    """Check if a column exists in a table, dialect-aware."""
    dialect = _get_dialect_name()
    if dialect in ("postgresql", "mssql", "mysql"):
        result = await conn.execute(text(
            "SELECT 1 FROM information_schema.columns "
            f"WHERE table_name = '{table_name}' AND column_name = '{column_name}'"
        ))
        return result.first() is not None
    elif dialect == "oracle":
        result = await conn.execute(text(
            "SELECT 1 FROM ALL_TAB_COLUMNS "
            f"WHERE TABLE_NAME = '{table_name.upper()}' AND COLUMN_NAME = '{column_name.upper()}'"
        ))
        return result.first() is not None
    else:  # sqlite
        result = await conn.execute(text(f"PRAGMA table_info({table_name})"))
        columns = [row[1] for row in result.fetchall()]
        return column_name in columns


async def take_snapshot(label: str = "") -> Optional[Path]:
    """Take a JSON snapshot of all tables for backup before database switch."""
    global engine
    if engine is None:
        return None

    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    filename = f"snapshot_{timestamp}_{label}.json" if label else f"snapshot_{timestamp}.json"
    snapshot_path = SNAPSHOT_DIR / filename

    snapshot_data = {}
    try:
        async with engine.begin() as conn:
            # Get all table names
            from sqlalchemy import inspect as sa_inspect
            table_names = await conn.run_sync(lambda sync_conn: sa_inspect(sync_conn).get_table_names())
            for table_name in table_names:
                if table_name.startswith("alembic"):
                    continue
                result = await conn.execute(text(f'SELECT * FROM "{table_name}"'))
                rows = result.mappings().all()
                snapshot_data[table_name] = [
                    {k: str(v) if v is not None else None for k, v in row.items()}
                    for row in rows
                ]
        snapshot_path.write_text(json.dumps(snapshot_data, indent=2, default=str))
        logging.getLogger(__name__).info(f"Snapshot saved to {snapshot_path}")

        # Prune old snapshots
        snapshots = sorted(SNAPSHOT_DIR.glob("snapshot_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        for old in snapshots[MAX_SNAPSHOTS:]:
            old.unlink(missing_ok=True)

        return snapshot_path
    except Exception as e:
        logging.getLogger(__name__).error(f"Failed to take snapshot: {e}")
        return None


def list_snapshots() -> list:
    """List available database snapshots."""
    if not SNAPSHOT_DIR.exists():
        return []
    snapshots = sorted(SNAPSHOT_DIR.glob("snapshot_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    results = []
    for i, s in enumerate(snapshots, 1):
        size_mb = s.stat().st_size / (1024 * 1024)
        results.append({"index": i, "path": str(s), "name": s.name, "size_mb": round(size_mb, 2)})
    return results


async def swap_engine(new_url: str, label: str = "", debug: bool = False) -> bool:
    """
    Hot-swap the database engine. Takes a snapshot of the current DB first.
    Returns True on success, False on failure (old engine preserved).
    """
    global engine, SessionLocal, _db_initialized

    # Take snapshot before switching
    await take_snapshot(label=label)

    # Create new engine
    try:
        new_engine = create_async_engine(
            new_url, echo=debug, pool_pre_ping=True,
            pool_recycle=300, pool_size=25, max_overflow=50, future=True,
        )
        # Test connection
        async with new_engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as e:
        logging.getLogger(__name__).error(f"Hot-swap failed — new database unreachable: {e}")
        return False

    # Swap
    old_engine = engine
    engine = new_engine
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    _db_initialized = False

    # Initialize schema on new database
    await init_db()

    # Dispose old engine
    if old_engine:
        try:
            await old_engine.dispose()
        except Exception:
            pass

    logging.getLogger(__name__).info(f"Engine hot-swapped to {new_url[:60]}...")
    return True


# -------------------------------------------------------------------
# Database Initialization / Reset / Shutdown
# -------------------------------------------------------------------
async def init_db():
    """Create tables if not exist. Must run on FastAPI event loop."""
    global _db_initialized
    if _db_initialized:
        return
    if engine is None:
        raise RuntimeError("Engine not initialized — call init_engine() first.")

    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    # Run migrations for new columns
    await _migrate_port_service_fields()
    await _migrate_host_tracking_fields()
    await _migrate_device_fingerprint_tables()
    await _migrate_host_tag_table()
    await _migrate_scheduler_resilience_fields()
    await _migrate_device_info_certainty_fields()

    # Stamp Alembic head so future migrations start from the right point
    await _stamp_alembic_head()

    _db_initialized = True


async def _stamp_alembic_head():
    """Stamp Alembic version table so future migrations know the starting point."""
    if engine is None:
        return
    try:
        async with engine.begin() as conn:
            # Check if alembic_version table already has a row
            result = await conn.execute(
                text("SELECT version_num FROM alembic_version LIMIT 1")
            )
            row = result.first()
            if row is not None:
                return  # Already stamped — skip
    except Exception:
        pass  # Table doesn't exist yet — let Alembic create it

    try:
        from alembic.config import Config
        from alembic import command
        import asyncio

        def _stamp():
            alembic_cfg = Config(
                str(Path(__file__).resolve().parents[1] / "../../alembic.ini")
            )
            command.stamp(alembic_cfg, "head")

        await asyncio.get_running_loop().run_in_executor(None, _stamp)
        logging.getLogger(__name__).info("Alembic stamped at head")
    except Exception as e:
        logging.getLogger(__name__).warning(f"Alembic stamp skipped: {e}")


async def _migrate_port_service_fields():
    """Add service version detection fields to port table."""
    if engine is None:
        return

    try:
        from sqlalchemy import text

        async with engine.begin() as conn:
            db_url = str(engine.url)

            if "postgresql" in db_url.lower():
                # PostgreSQL migration
                check_query = text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'port'
                """)
                result = await conn.execute(check_query)
                existing_columns = {row[0] for row in result.fetchall()}

                columns_to_add = {
                    'product': 'VARCHAR',
                    'version': 'VARCHAR',
                    'extrainfo': 'VARCHAR',
                    'cpe': 'VARCHAR',
                    'state': 'VARCHAR',
                    'reason': 'VARCHAR',
                    'confidence': 'INTEGER'
                }

                for col_name, col_type in columns_to_add.items():
                    if col_name not in existing_columns:
                        await conn.execute(text(f"""
                            ALTER TABLE port
                            ADD COLUMN {col_name} {col_type}
                        """))
                        logging.debug(f"Added {col_name} column to port table")

            elif "sqlite" in db_url.lower():
                # SQLite migration
                check_query = text("PRAGMA table_info(port)")
                result = await conn.execute(check_query)
                columns = result.fetchall()
                column_names = [col[1] for col in columns]

                columns_to_add = {
                    'product': 'VARCHAR',
                    'version': 'VARCHAR',
                    'extrainfo': 'VARCHAR',
                    'cpe': 'VARCHAR',
                    'state': 'VARCHAR',
                    'reason': 'VARCHAR',
                    'confidence': 'INTEGER'
                }

                for col_name, col_type in columns_to_add.items():
                    if col_name not in column_names:
                        await conn.execute(text(f"""
                            ALTER TABLE port
                            ADD COLUMN {col_name} {col_type}
                        """))
                        logging.debug(f"Added {col_name} column to port table")
    except Exception as e:
        logging.warning(f"Migration for port service fields: {e}")
        pass


async def _migrate_host_tracking_fields():
    """Add timestamp tracking fields to host table."""
    if engine is None:
        return

    try:
        from sqlalchemy import text

        async with engine.begin() as conn:
            db_url = str(engine.url)

            if "postgresql" in db_url.lower():
                # PostgreSQL migration
                check_query = text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'host'
                """)
                result = await conn.execute(check_query)
                existing_columns = {row[0] for row in result.fetchall()}

                if 'first_seen' not in existing_columns:
                    await conn.execute(text("""
                        ALTER TABLE host
                        ADD COLUMN first_seen TIMESTAMP
                    """))
                    logging.debug("Added first_seen column to host table")

                if 'last_seen' not in existing_columns:
                    await conn.execute(text("""
                        ALTER TABLE host
                        ADD COLUMN last_seen TIMESTAMP
                    """))
                    logging.debug("Added last_seen column to host table")

                if 'scan_count' not in existing_columns:
                    await conn.execute(text("""
                        ALTER TABLE host
                        ADD COLUMN scan_count INTEGER DEFAULT 0
                    """))
                    logging.debug("Added scan_count column to host table")

            elif "sqlite" in db_url.lower():
                # SQLite migration
                check_query = text("PRAGMA table_info(host)")
                result = await conn.execute(check_query)
                columns = result.fetchall()
                column_names = [col[1] for col in columns]

                if 'first_seen' not in column_names:
                    await conn.execute(text("""
                        ALTER TABLE host
                        ADD COLUMN first_seen TIMESTAMP
                    """))
                    logging.debug("Added first_seen column to host table")

                if 'last_seen' not in column_names:
                    await conn.execute(text("""
                        ALTER TABLE host
                        ADD COLUMN last_seen TIMESTAMP
                    """))
                    logging.debug("Added last_seen column to host table")

                if 'scan_count' not in column_names:
                    await conn.execute(text("""
                        ALTER TABLE host
                        ADD COLUMN scan_count INTEGER DEFAULT 0
                    """))
                    logging.debug("Added scan_count column to host table")
    except Exception as e:
        logging.warning(f"Migration for host tracking fields: {e}")
        pass


async def reset_db():
    """Drop and recreate tables."""
    if engine is None:
        raise RuntimeError("Engine not initialized — call init_engine() first.")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)
    print("[+] Database reset complete.")


async def dispose_engine():
    """Cleanly dispose of engine on shutdown."""
    global engine
    if engine:
        await engine.dispose()
        engine = None
        print("[+] Database connections closed.")


# -------------------------------------------------------------------
# Async Session Factory
# -------------------------------------------------------------------
async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield a new async session (context manager)."""
    if SessionLocal is None:
        raise RuntimeError("Session factory not initialized. Call init_engine first.")
    async with SessionLocal() as session:
        yield session


# -------------------------------------------------------------------
# ORM Utility Helpers
# -------------------------------------------------------------------
async def get_or_create_host(session: AsyncSession, address: str, hostname: str | None = None,
                             create_if_missing: bool = True) -> Optional[Host]:
    from datetime import datetime
    res = await session.execute(select(Host).where(Host.address == address))
    host = res.scalar_one_or_none()
    now = datetime.utcnow()

    if host:
        # Update hostname only if the new one is longer (prefer FQDN over short name)
        if hostname and len(hostname) > len(host.hostname or ""):
            host.hostname = hostname

        # Update tracking fields
        host.last_seen = now
        host.scan_count = (host.scan_count or 0) + 1
        return host

    if not create_if_missing:
        return None

    # New host - set first_seen and last_seen
    host = Host(
        address=address,
        hostname=hostname,
        first_seen=now,
        last_seen=now,
        scan_count=1
    )
    session.add(host)
    await session.flush()  # Need ID for child records (ports, scripts, etc.)
    return host


async def get_or_create_port(session: AsyncSession, host: Host, port: int,
                             service: str | None = None, protocol: str | None = None,
                             banner: str | None = None,
                             product: str | None = None, version: str | None = None,
                             extrainfo: str | None = None, cpe: str | None = None,
                             state: str | None = None, reason: str | None = None,
                             confidence: int | None = None) -> Port:
    res = await session.execute(select(Port).where(Port.host_id == host.id, Port.port == port))
    p = res.scalar_one_or_none()
    if p:
        changed = False
        if service and p.service != service:
            p.service = service; changed = True
        if protocol and p.protocol != protocol:
            p.protocol = protocol; changed = True
        if banner and p.banner != banner:
            p.banner = banner; changed = True
        if product and p.product != product:
            p.product = product; changed = True
        if version and p.version != version:
            p.version = version; changed = True
        if extrainfo and p.extrainfo != extrainfo:
            p.extrainfo = extrainfo; changed = True
        if cpe and p.cpe != cpe:
            p.cpe = cpe; changed = True
        if state and p.state != state:
            p.state = state; changed = True
        if reason and p.reason != reason:
            p.reason = reason; changed = True
        if confidence is not None and p.confidence != confidence:
            p.confidence = confidence; changed = True
        return p

    p = Port(host_id=host.id, port=port, service=service, protocol=protocol, banner=banner,
             product=product, version=version, extrainfo=extrainfo, cpe=cpe,
             state=state, reason=reason, confidence=confidence)
    session.add(p)
    await session.flush()  # Need ID for child records (scripts)
    return p


async def get_or_create_script(session: AsyncSession, host: Host, port: Port | None,
                               name: str, output: str, url: str | None = None,
                               status_code: int | None = None, screenshot_file: str | None = None,
                               screenshot_failed: bool | None = None) -> Script:
    q = select(Script).where(Script.host_id == host.id, Script.name == name, Script.output == output)
    if port:
        q = q.where(Script.port_id == port.id)
    else:
        q = q.where(Script.port_id.is_(None))

    res = await session.execute(q)
    s = res.scalar_one_or_none()

    if s:
        if url and s.url != url:
            s.url = url
        if status_code and s.status_code != status_code:
            s.status_code = status_code
        if screenshot_file and s.screenshot_file != screenshot_file:
            s.screenshot_file = screenshot_file
        if screenshot_failed is not None and s.screenshot_failed != screenshot_failed:
            s.screenshot_failed = screenshot_failed
        return s

    s = Script(
        host_id=host.id,
        port_id=(port.id if port else None),
        name=name,
        output=output,
        url=url,
        status_code=status_code,
        screenshot_file=screenshot_file,
        screenshot_failed=screenshot_failed,
    )
    session.add(s)
    return s


async def get_or_create_osguess(session: AsyncSession, host: Host, name: str,
                                accuracy: int = 0, type: Optional[str] = None,
                                vendor: Optional[str] = None, family: Optional[str] = None,
                                generation: Optional[str] = None, cpe: Optional[str] = None) -> OSGuess:
    res = await session.execute(select(OSGuess).where(OSGuess.host_id == host.id))
    existing = res.scalar_one_or_none()

    if not existing:
        rec = OSGuess(host_id=host.id, name=name, accuracy=accuracy or 0,
                      type=type, vendor=vendor, family=family,
                      generation=generation, cpe=cpe)
        session.add(rec)
        return rec

    if (accuracy or 0) > (existing.accuracy or 0):
        existing.name = name
        existing.accuracy = accuracy or 0
        existing.type = type
        existing.vendor = vendor
        existing.family = family
        existing.generation = generation
        existing.cpe = cpe

    return existing


async def _migrate_device_fingerprint_tables():
    """
    Ensure device fingerprint tables exist and have all required columns.
    SQLModel handles table creation, this function adds any missing columns and indexes.
    """
    if engine is None:
        return

    try:
        from sqlalchemy import text

        async with engine.begin() as conn:
            db_url = str(engine.url)

            # New columns for enhanced OS validation (added for os_intelligence.py integration)
            new_columns = [
                ("nmap_os_raw", "TEXT"),
                ("inferred_os", "TEXT"),
                ("inferred_firmware", "TEXT"),
                ("validation_status", "VARCHAR(20)"),
                ("validation_reason", "TEXT"),
                ("plausibility_score", "REAL DEFAULT 0.0"),
            ]

            if "postgresql" in db_url.lower():
                # PostgreSQL-specific optimizations

                # Check if device_info table exists
                check_query = text("""
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_name = 'device_info'
                """)
                result = await conn.execute(check_query)
                if result.fetchone() is None:
                    logging.debug("Table device_info not found - SQLModel will create it")
                else:
                    # Add new columns if they don't exist
                    for col_name, col_type in new_columns:
                        try:
                            check_col = text(f"""
                                SELECT column_name
                                FROM information_schema.columns
                                WHERE table_name = 'device_info'
                                AND column_name = '{col_name}'
                            """)
                            result = await conn.execute(check_col)
                            if result.fetchone() is None:
                                await conn.execute(text(f"""
                                    ALTER TABLE device_info
                                    ADD COLUMN {col_name} {col_type}
                                """))
                                logging.debug(f"Added column {col_name} to device_info table")
                        except Exception as col_err:
                            logging.debug(f"Column {col_name} migration: {col_err}")

                # Add composite indexes for common query patterns
                index_definitions = [
                    # Fast lookup by device type and manufacturer
                    ("idx_device_info_type_mfr", "device_info", "device_type, manufacturer"),
                    # Fast lookup by OS family
                    ("idx_device_info_os", "device_info", "os_family"),
                    # Fast lookup by confidence
                    ("idx_device_info_confidence", "device_info", "confidence DESC"),
                    # Fast lookup by validation status (new)
                    ("idx_device_info_validation", "device_info", "validation_status"),
                ]

                for idx_name, table_name, columns in index_definitions:
                    try:
                        # Check if index exists
                        check_idx = text(f"""
                            SELECT indexname FROM pg_indexes
                            WHERE tablename = '{table_name}' AND indexname = '{idx_name}'
                        """)
                        result = await conn.execute(check_idx)
                        if result.fetchone() is None:
                            # Create index
                            create_idx = text(f"""
                                CREATE INDEX IF NOT EXISTS {idx_name}
                                ON {table_name} ({columns})
                            """)
                            await conn.execute(create_idx)
                            logging.debug(f"Created index {idx_name} on {table_name}")
                    except Exception as idx_err:
                        logging.debug(f"Index {idx_name} creation: {idx_err}")

                logging.debug("Device fingerprint tables migration complete (PostgreSQL)")

            elif "sqlite" in db_url.lower():
                # SQLite-specific handling
                check_query = text("""
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name='device_info'
                """)
                result = await conn.execute(check_query)
                if result.fetchone() is None:
                    logging.debug("Table device_info not found - SQLModel will create it")
                else:
                    # Add new columns if they don't exist
                    result = await conn.execute(text("PRAGMA table_info(device_info)"))
                    columns = result.fetchall()
                    existing_columns = [col[1] for col in columns]

                    for col_name, col_type in new_columns:
                        if col_name not in existing_columns:
                            try:
                                await conn.execute(text(f"""
                                    ALTER TABLE device_info
                                    ADD COLUMN {col_name} {col_type}
                                """))
                                logging.debug(f"Added column {col_name} to device_info table")
                            except Exception as col_err:
                                logging.debug(f"Column {col_name} migration: {col_err}")

                logging.debug("Device fingerprint tables migration complete (SQLite)")

    except Exception as e:
        logging.warning(f"Migration for device fingerprint tables: {e}")
        pass


async def _migrate_host_tag_table():
    """Ensure host_tag table exists with unique composite index."""
    if engine is None:
        return

    try:
        async with engine.begin() as conn:
            db_url = str(engine.url)

            if "postgresql" in db_url.lower():
                check_query = text("""
                    SELECT table_name FROM information_schema.tables
                    WHERE table_name = 'host_tag'
                """)
                result = await conn.execute(check_query)
                if result.fetchone() is not None:
                    try:
                        await conn.execute(text("""
                            CREATE UNIQUE INDEX IF NOT EXISTS ix_host_tag_unique
                            ON host_tag (host_id, tag_name)
                        """))
                    except Exception:
                        pass

            elif "sqlite" in db_url.lower():
                check_query = text("""
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name='host_tag'
                """)
                result = await conn.execute(check_query)
                if result.fetchone() is not None:
                    try:
                        await conn.execute(text("""
                            CREATE UNIQUE INDEX IF NOT EXISTS ix_host_tag_unique
                            ON host_tag (host_id, tag_name)
                        """))
                    except Exception:
                        pass

    except Exception as e:
        logging.warning(f"Migration for host_tag table: {e}")


async def _migrate_scheduler_resilience_fields():
    """Add retry, misfire, and watchdog fields to scheduler tables."""
    if engine is None:
        return

    try:
        from sqlalchemy import text

        async with engine.begin() as conn:
            db_url = str(engine.url)

            if "postgresql" in db_url.lower():
                # --- scheduled_task ---
                check_query = text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'scheduled_task'
                """)
                result = await conn.execute(check_query)
                existing = {row[0] for row in result.fetchall()}

                st_columns = {
                    'max_retries': 'INTEGER NOT NULL DEFAULT 3',
                    'retry_delay_seconds': 'INTEGER NOT NULL DEFAULT 300',
                    'retry_backoff': 'BOOLEAN NOT NULL DEFAULT TRUE',
                    'misfire_grace_time': 'INTEGER',
                    'stall_timeout_seconds': 'INTEGER',
                }
                for col_name, col_type in st_columns.items():
                    if col_name not in existing:
                        await conn.execute(text(f"ALTER TABLE scheduled_task ADD COLUMN {col_name} {col_type}"))
                        logging.debug(f"Added {col_name} to scheduled_task")

                # --- scheduled_task_history ---
                check_query = text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'scheduled_task_history'
                """)
                result = await conn.execute(check_query)
                existing = {row[0] for row in result.fetchall()}

                sth_columns = {
                    'retry_attempt': 'INTEGER NOT NULL DEFAULT 0',
                    'retry_of_history_id': 'INTEGER',
                }
                for col_name, col_type in sth_columns.items():
                    if col_name not in existing:
                        await conn.execute(text(f"ALTER TABLE scheduled_task_history ADD COLUMN {col_name} {col_type}"))
                        logging.debug(f"Added {col_name} to scheduled_task_history")

                # --- running_task_record ---
                check_query = text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'running_task_record'
                """)
                result = await conn.execute(check_query)
                existing = {row[0] for row in result.fetchall()}

                if 'last_output_at' not in existing:
                    await conn.execute(text("ALTER TABLE running_task_record ADD COLUMN last_output_at TIMESTAMP"))
                    logging.debug("Added last_output_at to running_task_record")

            elif "sqlite" in db_url.lower():
                # --- scheduled_task ---
                result = await conn.execute(text("PRAGMA table_info(scheduled_task)"))
                existing = {row[1] for row in result.fetchall()}

                st_columns = {
                    'max_retries': 'INTEGER DEFAULT 3',
                    'retry_delay_seconds': 'INTEGER DEFAULT 300',
                    'retry_backoff': 'BOOLEAN DEFAULT 1',
                    'misfire_grace_time': 'INTEGER',
                    'stall_timeout_seconds': 'INTEGER',
                }
                for col_name, col_type in st_columns.items():
                    if col_name not in existing:
                        await conn.execute(text(f"ALTER TABLE scheduled_task ADD COLUMN {col_name} {col_type}"))

                # --- scheduled_task_history ---
                result = await conn.execute(text("PRAGMA table_info(scheduled_task_history)"))
                existing = {row[1] for row in result.fetchall()}

                sth_columns = {
                    'retry_attempt': 'INTEGER DEFAULT 0',
                    'retry_of_history_id': 'INTEGER',
                }
                for col_name, col_type in sth_columns.items():
                    if col_name not in existing:
                        await conn.execute(text(f"ALTER TABLE scheduled_task_history ADD COLUMN {col_name} {col_type}"))

                # --- running_task_record ---
                result = await conn.execute(text("PRAGMA table_info(running_task_record)"))
                existing = {row[1] for row in result.fetchall()}

                if 'last_output_at' not in existing:
                    await conn.execute(text("ALTER TABLE running_task_record ADD COLUMN last_output_at TIMESTAMP"))

    except Exception as e:
        logging.warning(f"Migration for scheduler resilience fields: {e}")
        pass


# -------------------------------------------------------------------
# DeviceInfo ORM Helpers
# -------------------------------------------------------------------
async def get_or_create_device_info(
    session: AsyncSession,
    host: Host,
    device_type: str = "Unknown",
    device_category: str = "Unknown",
    manufacturer: Optional[str] = None,
    model: Optional[str] = None,
    os_family: Optional[str] = None,
    os_name: Optional[str] = None,
    os_version: Optional[str] = None,
    os_kernel: Optional[str] = None,
    os_full: Optional[str] = None,
    netbios_name: Optional[str] = None,
    mac_address: Optional[str] = None,
    mac_vendor: Optional[str] = None,
    validated: bool = False,
    validation_sources: int = 0,
    confidence: float = 0.0,
    evidence: Optional[str] = None,
    sources: Optional[str] = None,
    ssl_common_name: Optional[str] = None,
    smb_os: Optional[str] = None,
    samba_version: Optional[str] = None,
    # Enhanced OS validation fields
    nmap_os_raw: Optional[str] = None,
    inferred_os: Optional[str] = None,
    inferred_firmware: Optional[str] = None,
    validation_status: Optional[str] = None,
    validation_reason: Optional[str] = None,
    plausibility_score: float = 0.0,
    # Per-field certainty from VerdictEngine
    device_type_certainty: float = 0.0,
    manufacturer_certainty: float = 0.0,
    os_family_certainty: float = 0.0,
) -> DeviceInfo:
    """
    Get or create a DeviceInfo record for a host.

    If a record exists, updates it with new information if confidence is higher
    or if the new data has more validation sources.

    Enhanced to support:
    - Detailed OS info (os_kernel, os_full)
    - NetBIOS/SMB computer name
    - Multi-source validation status
    - SSL certificate CommonName
    - Samba version detection
    """
    from datetime import datetime

    res = await session.execute(
        select(DeviceInfo).where(DeviceInfo.host_id == host.id)
    )
    existing = res.scalar_one_or_none()

    now = datetime.utcnow()

    if existing:
        # Update if new confidence is higher, more validation sources, or data is more complete
        should_update = (
            confidence > existing.confidence or
            validation_sources > (existing.validation_sources or 0) or
            (manufacturer and not existing.manufacturer) or
            (os_family and not existing.os_family) or
            (os_name and not existing.os_name) or
            (os_full and not existing.os_full)
        )

        if should_update:
            if device_type and device_type != "Unknown":
                existing.device_type = device_type
            if device_category and device_category != "Unknown":
                existing.device_category = device_category
            if manufacturer:
                existing.manufacturer = manufacturer
            if model:
                existing.model = model
            if os_family:
                existing.os_family = os_family
            if os_name:
                existing.os_name = os_name
            if os_version:
                existing.os_version = os_version
            if os_kernel:
                existing.os_kernel = os_kernel
            if os_full:
                existing.os_full = os_full
            if netbios_name:
                existing.netbios_name = netbios_name
            if mac_address:
                existing.mac_address = mac_address
            if mac_vendor:
                existing.mac_vendor = mac_vendor
            if validated:
                existing.validated = validated
            if validation_sources > (existing.validation_sources or 0):
                existing.validation_sources = validation_sources
            if confidence > existing.confidence:
                existing.confidence = confidence
            if evidence:
                existing.evidence = evidence
            if sources:
                existing.sources = sources
            if ssl_common_name:
                existing.ssl_common_name = ssl_common_name
            if smb_os:
                existing.smb_os = smb_os
            if samba_version:
                existing.samba_version = samba_version
            # Enhanced OS validation fields
            if nmap_os_raw:
                existing.nmap_os_raw = nmap_os_raw
            if inferred_os:
                existing.inferred_os = inferred_os
            if inferred_firmware:
                existing.inferred_firmware = inferred_firmware
            if validation_status:
                existing.validation_status = validation_status
            if validation_reason:
                existing.validation_reason = validation_reason
            if plausibility_score > 0:
                existing.plausibility_score = plausibility_score
            # Per-field certainty from VerdictEngine
            if device_type_certainty > 0:
                existing.device_type_certainty = device_type_certainty
            if manufacturer_certainty > 0:
                existing.manufacturer_certainty = manufacturer_certainty
            if os_family_certainty > 0:
                existing.os_family_certainty = os_family_certainty

        existing.last_fingerprinted = now
        existing.fingerprint_count = (existing.fingerprint_count or 0) + 1
        return existing

    # Create new record
    device_info = DeviceInfo(
        host_id=host.id,
        device_type=device_type,
        device_category=device_category,
        manufacturer=manufacturer,
        model=model,
        os_family=os_family,
        os_name=os_name,
        os_version=os_version,
        os_kernel=os_kernel,
        os_full=os_full,
        netbios_name=netbios_name,
        mac_address=mac_address,
        mac_vendor=mac_vendor,
        validated=validated,
        validation_sources=validation_sources,
        confidence=confidence,
        evidence=evidence,
        sources=sources,
        ssl_common_name=ssl_common_name,
        smb_os=smb_os,
        samba_version=samba_version,
        # Enhanced OS validation fields
        nmap_os_raw=nmap_os_raw,
        inferred_os=inferred_os,
        inferred_firmware=inferred_firmware,
        validation_status=validation_status,
        validation_reason=validation_reason,
        plausibility_score=plausibility_score,
        device_type_certainty=device_type_certainty,
        manufacturer_certainty=manufacturer_certainty,
        os_family_certainty=os_family_certainty,
        first_fingerprinted=now,
        last_fingerprinted=now,
        fingerprint_count=1
    )
    session.add(device_info)
    return device_info


# -------------------------------------------------------------------
# Bulk Ingestion Cache — eliminates per-entity SELECT queries
# -------------------------------------------------------------------
class IngestionCache:
    """
    In-memory cache of existing DB records for fast ingestion.

    Pre-loads all Host, Port, Script, OSGuess, and DeviceInfo records at the
    start of an ingestion session, replacing O(N) individual SELECT queries
    with O(1) dictionary lookups.
    """

    def __init__(self):
        # {address: Host}
        self.hosts: dict[str, Host] = {}
        # {(host_id, port_num): Port}
        self.ports: dict[tuple[int, int], Port] = {}
        # {(host_id, name, output_hash): Script}  — output_hash to avoid huge keys
        self.scripts: dict[tuple[int, str, int], Script] = {}
        # {host_id: OSGuess}
        self.os_guesses: dict[int, OSGuess] = {}
        # {host_id: DeviceInfo}
        self.device_info: dict[int, DeviceInfo] = {}

    @staticmethod
    def _output_hash(output: str) -> int:
        """Fast hash of script output for dict keys."""
        return hash(output)


async def build_ingestion_cache(session: AsyncSession) -> IngestionCache:
    """
    Bulk-load all existing records into an IngestionCache.
    Replaces thousands of individual SELECTs with 5 bulk queries.
    """
    cache = IngestionCache()

    # Load all hosts
    result = await session.execute(select(Host))
    for host in result.scalars().all():
        cache.hosts[host.address] = host

    # Load all ports
    result = await session.execute(select(Port))
    for port in result.scalars().all():
        cache.ports[(port.host_id, port.port)] = port

    # Load all scripts (use hash of output for memory efficiency)
    result = await session.execute(select(Script))
    for script in result.scalars().all():
        key = (script.host_id, script.name, IngestionCache._output_hash(script.output))
        cache.scripts[key] = script

    # Load all OS guesses (one per host)
    result = await session.execute(select(OSGuess))
    for og in result.scalars().all():
        cache.os_guesses[og.host_id] = og

    # Load all device info (one per host)
    result = await session.execute(select(DeviceInfo))
    for di in result.scalars().all():
        cache.device_info[di.host_id] = di

    return cache


# -------------------------------------------------------------------
# Cached get_or_create — O(1) dictionary lookup instead of DB SELECT
# -------------------------------------------------------------------
async def cached_get_or_create_host(
    session: AsyncSession, cache: IngestionCache,
    address: str, hostname: str | None = None,
    create_if_missing: bool = True
) -> Optional[Host]:
    from datetime import datetime
    now = datetime.utcnow()

    host = cache.hosts.get(address)
    if host:
        # Update hostname only if the new one is longer (prefer FQDN over short name)
        if hostname and len(hostname) > len(host.hostname or ""):
            host.hostname = hostname
        host.last_seen = now
        host.scan_count = (host.scan_count or 0) + 1
        return host

    if not create_if_missing:
        return None

    host = Host(
        address=address, hostname=hostname,
        first_seen=now, last_seen=now, scan_count=1
    )
    session.add(host)
    await session.flush()  # Need ID for child records
    cache.hosts[address] = host
    return host


async def cached_get_or_create_port(
    session: AsyncSession, cache: IngestionCache,
    host: Host, port: int,
    service: str | None = None, protocol: str | None = None,
    banner: str | None = None,
    product: str | None = None, version: str | None = None,
    extrainfo: str | None = None, cpe: str | None = None,
    state: str | None = None, reason: str | None = None,
    confidence: int | None = None
) -> Port:
    key = (host.id, port)
    p = cache.ports.get(key)
    if p:
        if service and p.service != service:
            p.service = service
        if protocol and p.protocol != protocol:
            p.protocol = protocol
        if banner and p.banner != banner:
            p.banner = banner
        if product and p.product != product:
            p.product = product
        if version and p.version != version:
            p.version = version
        if extrainfo and p.extrainfo != extrainfo:
            p.extrainfo = extrainfo
        if cpe and p.cpe != cpe:
            p.cpe = cpe
        if state and p.state != state:
            p.state = state
        if reason and p.reason != reason:
            p.reason = reason
        if confidence is not None and p.confidence != confidence:
            p.confidence = confidence
        return p

    p = Port(
        host_id=host.id, port=port, service=service, protocol=protocol,
        banner=banner, product=product, version=version, extrainfo=extrainfo,
        cpe=cpe, state=state, reason=reason, confidence=confidence
    )
    session.add(p)
    await session.flush()  # Need ID for child records (scripts)
    cache.ports[key] = p
    return p


async def cached_get_or_create_script(
    session: AsyncSession, cache: IngestionCache,
    host: Host, port: Port | None,
    name: str, output: str, url: str | None = None,
    status_code: int | None = None, screenshot_file: str | None = None,
    screenshot_failed: bool | None = None
) -> Script:
    out_hash = IngestionCache._output_hash(output)
    key = (host.id, name, out_hash)
    s = cache.scripts.get(key)
    if s:
        if url and s.url != url:
            s.url = url
        if status_code and s.status_code != status_code:
            s.status_code = status_code
        if screenshot_file and s.screenshot_file != screenshot_file:
            s.screenshot_file = screenshot_file
        if screenshot_failed is not None and s.screenshot_failed != screenshot_failed:
            s.screenshot_failed = screenshot_failed
        return s

    s = Script(
        host_id=host.id, port_id=(port.id if port else None),
        name=name, output=output, url=url, status_code=status_code,
        screenshot_file=screenshot_file, screenshot_failed=screenshot_failed,
    )
    session.add(s)
    cache.scripts[key] = s
    return s


async def cached_get_or_create_osguess(
    session: AsyncSession, cache: IngestionCache,
    host: Host, name: str,
    accuracy: int = 0, type: Optional[str] = None,
    vendor: Optional[str] = None, family: Optional[str] = None,
    generation: Optional[str] = None, cpe: Optional[str] = None
) -> OSGuess:
    existing = cache.os_guesses.get(host.id)
    if not existing:
        rec = OSGuess(
            host_id=host.id, name=name, accuracy=accuracy or 0,
            type=type, vendor=vendor, family=family,
            generation=generation, cpe=cpe
        )
        session.add(rec)
        cache.os_guesses[host.id] = rec
        return rec

    if (accuracy or 0) > (existing.accuracy or 0):
        existing.name = name
        existing.accuracy = accuracy or 0
        existing.type = type
        existing.vendor = vendor
        existing.family = family
        existing.generation = generation
        existing.cpe = cpe

    return existing


async def cached_get_or_create_device_info(
    session: AsyncSession, cache: IngestionCache,
    host: Host,
    device_type: str = "Unknown",
    device_category: str = "Unknown",
    manufacturer: Optional[str] = None,
    model: Optional[str] = None,
    os_family: Optional[str] = None,
    os_name: Optional[str] = None,
    os_version: Optional[str] = None,
    os_kernel: Optional[str] = None,
    os_full: Optional[str] = None,
    netbios_name: Optional[str] = None,
    mac_address: Optional[str] = None,
    mac_vendor: Optional[str] = None,
    validated: bool = False,
    validation_sources: int = 0,
    confidence: float = 0.0,
    evidence: Optional[str] = None,
    sources: Optional[str] = None,
    ssl_common_name: Optional[str] = None,
    smb_os: Optional[str] = None,
    samba_version: Optional[str] = None,
    nmap_os_raw: Optional[str] = None,
    inferred_os: Optional[str] = None,
    inferred_firmware: Optional[str] = None,
    validation_status: Optional[str] = None,
    validation_reason: Optional[str] = None,
    plausibility_score: float = 0.0,
    device_type_certainty: float = 0.0,
    manufacturer_certainty: float = 0.0,
    os_family_certainty: float = 0.0,
) -> DeviceInfo:
    from datetime import datetime
    now = datetime.utcnow()

    existing = cache.device_info.get(host.id)
    if existing:
        should_update = (
            confidence > existing.confidence or
            validation_sources > (existing.validation_sources or 0) or
            (manufacturer and not existing.manufacturer) or
            (os_family and not existing.os_family) or
            (os_name and not existing.os_name) or
            (os_full and not existing.os_full)
        )
        if should_update:
            if device_type and device_type != "Unknown":
                existing.device_type = device_type
            if device_category and device_category != "Unknown":
                existing.device_category = device_category
            if manufacturer:
                existing.manufacturer = manufacturer
            if model:
                existing.model = model
            if os_family:
                existing.os_family = os_family
            if os_name:
                existing.os_name = os_name
            if os_version:
                existing.os_version = os_version
            if os_kernel:
                existing.os_kernel = os_kernel
            if os_full:
                existing.os_full = os_full
            if netbios_name:
                existing.netbios_name = netbios_name
            if mac_address:
                existing.mac_address = mac_address
            if mac_vendor:
                existing.mac_vendor = mac_vendor
            if validated:
                existing.validated = validated
            if validation_sources > (existing.validation_sources or 0):
                existing.validation_sources = validation_sources
            if confidence > existing.confidence:
                existing.confidence = confidence
            if evidence:
                existing.evidence = evidence
            if sources:
                existing.sources = sources
            if ssl_common_name:
                existing.ssl_common_name = ssl_common_name
            if smb_os:
                existing.smb_os = smb_os
            if samba_version:
                existing.samba_version = samba_version
            if nmap_os_raw:
                existing.nmap_os_raw = nmap_os_raw
            if inferred_os:
                existing.inferred_os = inferred_os
            if inferred_firmware:
                existing.inferred_firmware = inferred_firmware
            if validation_status:
                existing.validation_status = validation_status
            if validation_reason:
                existing.validation_reason = validation_reason
            if plausibility_score > 0:
                existing.plausibility_score = plausibility_score
            if device_type_certainty > 0:
                existing.device_type_certainty = device_type_certainty
            if manufacturer_certainty > 0:
                existing.manufacturer_certainty = manufacturer_certainty
            if os_family_certainty > 0:
                existing.os_family_certainty = os_family_certainty

        existing.last_fingerprinted = now
        existing.fingerprint_count = (existing.fingerprint_count or 0) + 1
        return existing

    device_info = DeviceInfo(
        host_id=host.id,
        device_type=device_type, device_category=device_category,
        manufacturer=manufacturer, model=model,
        os_family=os_family, os_name=os_name, os_version=os_version,
        os_kernel=os_kernel, os_full=os_full,
        netbios_name=netbios_name, mac_address=mac_address, mac_vendor=mac_vendor,
        validated=validated, validation_sources=validation_sources,
        confidence=confidence, evidence=evidence, sources=sources,
        ssl_common_name=ssl_common_name, smb_os=smb_os, samba_version=samba_version,
        nmap_os_raw=nmap_os_raw, inferred_os=inferred_os,
        inferred_firmware=inferred_firmware,
        validation_status=validation_status, validation_reason=validation_reason,
        plausibility_score=plausibility_score,
        device_type_certainty=device_type_certainty,
        manufacturer_certainty=manufacturer_certainty,
        os_family_certainty=os_family_certainty,
        first_fingerprinted=now, last_fingerprinted=now, fingerprint_count=1,
    )
    session.add(device_info)
    cache.device_info[host.id] = device_info
    return device_info


async def _migrate_device_info_certainty_fields():
    """Add per-field certainty columns to device_info table."""
    if engine is None:
        return

    try:
        from sqlalchemy import text

        async with engine.begin() as conn:
            db_url = str(engine.url)

            if "postgresql" in db_url.lower():
                check_query = text("""
                    SELECT column_name
                    FROM information_schema.columns
                    WHERE table_name = 'device_info'
                """)
                result = await conn.execute(check_query)
                existing = {row[0] for row in result.fetchall()}

                columns = {
                    'device_type_certainty': 'FLOAT NOT NULL DEFAULT 0.0',
                    'manufacturer_certainty': 'FLOAT NOT NULL DEFAULT 0.0',
                    'os_family_certainty': 'FLOAT NOT NULL DEFAULT 0.0',
                }
                for col_name, col_type in columns.items():
                    if col_name not in existing:
                        await conn.execute(text(
                            f"ALTER TABLE device_info ADD COLUMN {col_name} {col_type}"
                        ))
                        logging.debug(f"Added {col_name} to device_info")

            else:
                # SQLite
                try:
                    result = await conn.execute(text("PRAGMA table_info(device_info)"))
                    existing = {row[1] for row in result.fetchall()}

                    for col_name in ['device_type_certainty', 'manufacturer_certainty', 'os_family_certainty']:
                        if col_name not in existing:
                            await conn.execute(text(
                                f"ALTER TABLE device_info ADD COLUMN {col_name} FLOAT NOT NULL DEFAULT 0.0"
                            ))
                except Exception:
                    pass

    except Exception as e:
        logging.warning(f"Migration for device_info certainty fields: {e}")
