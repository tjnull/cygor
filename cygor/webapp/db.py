import asyncio
import logging
import os
import subprocess
from pathlib import Path
from typing import Optional, AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlmodel import SQLModel, select
from .models import Host, Port, Script, OSGuess

# -------------------------------------------------------------------
# Globals and One-Time Guards
# -------------------------------------------------------------------
engine = None
SessionLocal = None

_postgres_initialized = False
_pg_checked = False
_pg_available = False
_engine_initialized = False
_db_initialized = False


# -------------------------------------------------------------------
# Default DB URL
# -------------------------------------------------------------------
def get_default_database_url() -> str:
    """Select database backend. Env > PostgreSQL > SQLite."""
    env_url = os.getenv("CYGOR_DB_URL")
    if env_url:
        return env_url

    if detect_postgresql():
        return f"postgresql+asyncpg://cygor:cygorpass@localhost/cygor"
    return "sqlite+aiosqlite:///cygor.db"


# -------------------------------------------------------------------
# PostgreSQL Detection & Setup
# -------------------------------------------------------------------
def detect_postgresql() -> bool:
    """Detect PostgreSQL installation once per process."""
    global _pg_checked, _pg_available
    if _pg_checked:
        return _pg_available

    try:
        result = subprocess.run(["psql", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[✓] PostgreSQL detected: {result.stdout.strip()}")
            _pg_available = True
        else:
            print("[!] PostgreSQL not detected.")
            _pg_available = False
    except FileNotFoundError:
        print("[!] psql binary not found — PostgreSQL not installed.")
        _pg_available = False

    _pg_checked = True
    return _pg_available


def setup_postgres(user="cygor", password="cygorpass", db_name="cygor", host="localhost") -> str:
    """Ensure PostgreSQL user/database exist (safe/idempotent)."""
    global _postgres_initialized
    if _postgres_initialized:
        return f"postgresql+asyncpg://{user}:{password}@{host}/{db_name}"

    print(f"[*] Setting up PostgreSQL database '{db_name}' for user '{user}'...")

    create_user_cmd = [
        "psql", "-U", "postgres", "-c",
        f"DO $$ BEGIN "
        f"IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '{user}') THEN "
        f"CREATE ROLE {user} LOGIN PASSWORD '{password}'; "
        f"END IF; END $$;"
    ]

    create_db_cmd = [
        "psql", "-U", "postgres", "-c",
        f"DO $$ BEGIN "
        f"IF NOT EXISTS (SELECT FROM pg_database WHERE datname = '{db_name}') THEN "
        f"CREATE DATABASE {db_name} OWNER {user}; "
        f"END IF; END $$;"
    ]

    subprocess.run(["sudo", "-u", "postgres"] + create_user_cmd, check=False)
    subprocess.run(["sudo", "-u", "postgres"] + create_db_cmd, check=False)

    print(f"[✓] PostgreSQL setup complete for user '{user}' and database '{db_name}'.")
    _postgres_initialized = True
    return f"postgresql+asyncpg://{user}:{password}@{host}/{db_name}"


# -------------------------------------------------------------------
# Engine Initialization
# -------------------------------------------------------------------
def init_engine(database_url: str, debug: bool = False):
    """
    Initialize a SQLAlchemy async engine for the current running event loop.
    If an old engine exists from a different loop, it will be disposed safely.
    """
    global engine, SessionLocal

    # Detect and dispose any leftover engine from a previous loop
    if engine is not None:
        try:
            loop = asyncio.get_event_loop()
            if not loop.is_closed():
                loop.create_task(engine.dispose())
            else:
                import anyio
                anyio.from_thread.run(engine.dispose)
        except Exception:
            pass

    # Create a fresh engine attached to this loop
    engine = create_async_engine(
        database_url,
        echo=debug,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=10,
        max_overflow=20,
        future=True,
    )

    # New sessionmaker bound to this engine
    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    print(f"[✓] Engine bound to event loop {id(asyncio.get_running_loop()) if asyncio.get_running_loop().is_running() else 'N/A'}")
    return engine


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
    print("[✓] Database schema ensured.")
    _db_initialized = True


async def reset_db():
    """Drop and recreate tables."""
    if engine is None:
        raise RuntimeError("Engine not initialized — call init_engine() first.")
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
        await conn.run_sync(SQLModel.metadata.create_all)
    print("[✓] Database reset complete.")


async def dispose_engine():
    """Cleanly dispose of engine on shutdown."""
    global engine
    if engine:
        await engine.dispose()
        engine = None
        print("[✓] Database connections closed.")


# -------------------------------------------------------------------
# Async Session Factory
# -------------------------------------------------------------------
async def get_session()-> AsyncGenerator[AsyncSession, None]:
    """Yield a new async session (context manager)."""
    if SessionLocal is None:
        raise RuntimeError("Session factory not initialized. Call init_engine first.")
    async with SessionLocal() as session:
        yield session


# -------------------------------------------------------------------
# ORM Utility Helpers (unchanged)
# -------------------------------------------------------------------
async def get_or_create_host(session: AsyncSession, address: str, hostname: str | None = None,
                             create_if_missing: bool = True) -> Optional[Host]:
    res = await session.execute(select(Host).where(Host.address == address))
    host = res.scalar_one_or_none()
    if host:
        if hostname and (host.hostname or "") != hostname:
            host.hostname = hostname
            await session.flush()
        return host

    if not create_if_missing:
        return None

    host = Host(address=address, hostname=hostname)
    session.add(host)
    await session.flush()
    return host


async def get_or_create_port(session: AsyncSession, host: Host, port: int,
                             service: str | None = None, protocol: str | None = None,
                             banner: str | None = None) -> Port:
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
        if changed:
            await session.flush()
        return p

    p = Port(host_id=host.id, port=port, service=service, protocol=protocol, banner=banner)
    session.add(p)
    await session.flush()
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
        changed = False
        if url and s.url != url:
            s.url = url; changed = True
        if status_code and s.status_code != status_code:
            s.status_code = status_code; changed = True
        if screenshot_file and s.screenshot_file != screenshot_file:
            s.screenshot_file = screenshot_file; changed = True
        if screenshot_failed is not None and s.screenshot_failed != screenshot_failed:
            s.screenshot_failed = screenshot_failed; changed = True
        if changed:
            await session.flush()
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
    await session.flush()
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
        await session.flush()
        return rec

    if (accuracy or 0) > (existing.accuracy or 0):
        existing.name = name
        existing.accuracy = accuracy or 0
        existing.type = type
        existing.vendor = vendor
        existing.family = family
        existing.generation = generation
        existing.cpe = cpe
        await session.flush()

    return existing
