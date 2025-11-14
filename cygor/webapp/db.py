import asyncio
import logging
import os
import shutil
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
        return f"postgresql+psycopg_async://cygor:cygorpass@localhost/cygor"
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


def setup_postgres(user="cygor", password="cygorpass", db_name="cygor", host="localhost"):
    """
    Create PostgreSQL role and database if not present.
    Avoids 'CREATE DATABASE cannot be executed from a function' errors.
    """
    global _postgres_initialized
    if _postgres_initialized:
        return f"postgresql+psycopg_async://{user}:{password}@{host}/{db_name}"

    # Only print setup message if we're actually trying to use PostgreSQL
    # (suppress warnings in Docker where PostgreSQL server isn't running)
    verbose = os.environ.get("CYGOR_VERBOSE", "0") != "0"
    if verbose:
        print(f"[*] Setting up PostgreSQL database '{db_name}' for user '{user}'...")

    # Determine if we need sudo (not needed if running as root or in Docker)
    need_sudo = os.geteuid() != 0 and shutil.which("sudo")
    
    # Try to connect as postgres user first, fallback to current user
    # In Docker, we might be root, so try direct connection first
    base_cmd = []
    if need_sudo:
        base_cmd = ["sudo", "-u", "postgres"]
    else:
        # Try connecting as postgres user directly, or use current user
        # First try: connect as postgres user (if we're root or postgres)
        # Second try: connect as current user (might work if PostgreSQL allows it)
        pass

    # Helper function to run psql commands
    def run_psql(cmd_args, use_postgres_user=True):
        """Run psql command, trying different connection methods."""
        # Method 1: Try with postgres user (if we're root or have sudo)
        if use_postgres_user:
            if need_sudo:
                full_cmd = base_cmd + ["psql"] + cmd_args
            else:
                # Try as postgres user directly (works if we're root)
                full_cmd = ["psql", "-U", "postgres"] + cmd_args
        else:
            # Method 2: Try as current user
            full_cmd = ["psql"] + cmd_args
        
        result = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            cwd="/",
            env=os.environ.copy()
        )
        return result

    # --- Create user if missing ---
    # Try connecting as postgres user first
    check_user = run_psql(["-tAc", f"SELECT 1 FROM pg_roles WHERE rolname='{user}'"], use_postgres_user=True)
    
    # If that failed and we're not using sudo, try without specifying user
    if check_user.returncode != 0 and not need_sudo:
        check_user = run_psql(["-tAc", f"SELECT 1 FROM pg_roles WHERE rolname='{user}'"], use_postgres_user=False)
    
    if not check_user.stdout.strip():
        # Create the user
        create_user_result = run_psql(["-c", f"CREATE ROLE {user} LOGIN PASSWORD '{password}';"], use_postgres_user=True)
        if create_user_result.returncode != 0 and not need_sudo:
            create_user_result = run_psql(["-c", f"CREATE ROLE {user} LOGIN PASSWORD '{password}';"], use_postgres_user=False)
        
        if create_user_result.returncode == 0:
            if verbose:
                print(f"[+] Created PostgreSQL role '{user}'")
        else:
            # Only show warnings in verbose mode
            if verbose:
                print(f"[!] Warning: Could not create role '{user}': {create_user_result.stderr}")

    # --- Create database if missing ---
    check_db = run_psql(["-tAc", f"SELECT 1 FROM pg_database WHERE datname='{db_name}'"], use_postgres_user=True)
    if check_db.returncode != 0 and not need_sudo:
        check_db = run_psql(["-tAc", f"SELECT 1 FROM pg_database WHERE datname='{db_name}'"], use_postgres_user=False)
    
    if not check_db.stdout.strip():
        # Create the database using createdb or psql
        if need_sudo:
            create_db_cmd = base_cmd + ["createdb", "-O", user, db_name]
        else:
            # Try createdb as postgres user, or as current user
            create_db_cmd = ["createdb", "-U", "postgres", "-O", user, db_name]
        
        create_db_result = subprocess.run(
            create_db_cmd,
            capture_output=True,
            text=True,
            cwd="/",
            env=os.environ.copy()
        )
        
        # If that failed, try without specifying user
        if create_db_result.returncode != 0 and not need_sudo:
            create_db_result = subprocess.run(
                ["createdb", "-O", user, db_name],
                capture_output=True,
                text=True,
                cwd="/",
                env=os.environ.copy()
            )
        
        if create_db_result.returncode == 0:
            print(f"[+] Created PostgreSQL database '{db_name}' owned by '{user}'")
        else:
            # Fallback: use psql to create database
            create_db_sql = f"CREATE DATABASE {db_name} OWNER {user};"
            psql_result = run_psql(["-c", create_db_sql], use_postgres_user=True)
            if psql_result.returncode != 0 and not need_sudo:
                psql_result = run_psql(["-c", create_db_sql], use_postgres_user=False)
            
            if psql_result.returncode == 0:
                if verbose:
                    print(f"[+] Created PostgreSQL database '{db_name}' owned by '{user}'")
            else:
                # Only show warnings in verbose mode
                if verbose:
                    print(f"[!] Warning: Could not create database '{db_name}': {psql_result.stderr or create_db_result.stderr}")

    if verbose:
        print(f"[✓] PostgreSQL setup complete for user '{user}' and database '{db_name}'.")
    _postgres_initialized = True
    return f"postgresql+psycopg_async://{user}:{password}@{host}/{db_name}"




# -------------------------------------------------------------------
# Engine Initialization
# -------------------------------------------------------------------
def init_engine(database_url: str, debug: bool = False):
    """Initialize SQLAlchemy async engine (psycopg_async)."""
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
        pool_size=10,
        max_overflow=20,
        future=True,
    )

    SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    # Detect and print the correct driver name
    if "sqlite" in database_url.lower():
        driver_name = "aiosqlite"
    elif "psycopg" in database_url.lower():
        driver_name = "psycopg_async"
    else:
        driver_name = "unknown"
    
    print(f"[✓] Engine bound using {driver_name} driver.")
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
    await session.commit()   # force write to DB
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
