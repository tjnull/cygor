"""Database, timezone, audit log, and retention policy routes."""

import logging
import os
from pathlib import Path
from typing import Optional, Dict, Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.requests import Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ... import db
from ...db import get_session
from ...config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["database"])


@router.get("/api/settings/database")
async def get_database_info(request: Request):
    """Get database connection information."""
    from ... import db as db_module

    # Get database information from the manager
    if db_module.db_manager:
        info = db_module.db_manager.get_info()

        db_info = {
            "backend": info.backend.upper(),
            "status": "Connected",
            "url": info.url if info.backend == "sqlite" else info.url.split('@')[0].split('://')[0] + "://****@" + info.url.split('@')[1] if '@' in info.url else info.url
        }

        if info.backend == "postgresql":
            db_info.update({
                "version": f"PostgreSQL {info.version}" if info.version else "PostgreSQL",
                "host": info.host,
                "port": info.port,
                "database": info.database,
                "user": info.user
            })
        else:
            db_info.update({
                "database_file": info.database
            })

        return JSONResponse(db_info)
    else:
        # Fallback: parse from environment or engine URL
        db_url = os.getenv("CYGOR_DB_URL", "")

        if "postgresql" in db_url.lower():
            # Extract info from URL
            try:
                # Format: postgresql+psycopg_async://user:pass@host:port/dbname
                parts = db_url.split("://")[1].split("@")
                user = parts[0].split(":")[0] if ":" in parts[0] else parts[0]
                host_part = parts[1] if len(parts) > 1 else "localhost"
                host = host_part.split(":")[0].split("/")[0]
                port = host_part.split(":")[1].split("/")[0] if ":" in host_part else "5432"
                database = host_part.split("/")[1] if "/" in host_part else "cygor"

                return JSONResponse({
                    "backend": "POSTGRESQL",
                    "status": "Connected",
                    "version": "PostgreSQL",
                    "host": host,
                    "port": port,
                    "database": database,
                    "user": user,
                    "url": f"postgresql://****@{host}:{port}/{database}"
                })
            except:
                pass

        return JSONResponse({
            "backend": "SQLITE",
            "status": "Connected",
            "database_file": db_url.split("///")[-1] if "///" in db_url else "cygor.db"
        })

@router.get("/api/health/database")
async def database_health():
    """Check database connection health."""
    from ... import db
    from sqlalchemy import text as sa_text
    try:
        if db.engine is None:
            return JSONResponse(content={"status": "error", "message": "No engine"}, status_code=503)
        async with db.engine.begin() as conn:
            await conn.execute(sa_text("SELECT 1"))
        return JSONResponse(content={"status": "healthy"})
    except Exception as e:
        return JSONResponse(content={"status": "unhealthy", "message": str(e)}, status_code=503)


@router.get("/api/server/timezone")
async def get_server_timezone():
    """Return the server's system timezone as an IANA timezone name.

    Works on Linux, macOS, and Windows. Detection order:
      1. tzlocal library (cross-platform, handles Windows registry)
      2. Python 3.9+ zoneinfo / datetime
      3. /etc/timezone or /etc/localtime (Linux/macOS)
      4. TZ environment variable
      5. UTC-offset fallback from C library
    """
    import time as _time
    from pytz import timezone as _pytz_tz

    tz_name = None

    # Method 1: tzlocal -- cross-platform (Linux, macOS, Windows)
    # APScheduler already depends on it, so it should always be available.
    if not tz_name:
        try:
            from tzlocal import get_localzone
            local_tz = get_localzone()
            # tzlocal may return a pytz zone, a zoneinfo zone, or a
            # ZoneInfo-backed object depending on version; normalise to str.
            name = str(getattr(local_tz, 'key', None) or getattr(local_tz, 'zone', None) or local_tz)
            if name and name != 'local':
                _pytz_tz(name)          # validate
                tz_name = name
        except Exception:
            pass

    # Method 2: Python 3.9+ datetime.now().astimezone().tzinfo
    if not tz_name:
        try:
            import sys
            if sys.version_info >= (3, 9):
                from zoneinfo import ZoneInfo   # noqa: F811
                from datetime import datetime as _dt
                local_tz = _dt.now().astimezone().tzinfo
                name = getattr(local_tz, 'key', None)
                if name:
                    _pytz_tz(name)
                    tz_name = name
        except Exception:
            pass

    # Method 3: /etc/timezone (Debian/Ubuntu) or /etc/localtime symlink (most Linux)
    if not tz_name:
        try:
            tz_file = Path("/etc/timezone")
            if tz_file.exists():
                name = tz_file.read_text().strip()
                if name:
                    _pytz_tz(name)
                    tz_name = name
        except Exception:
            pass
    if not tz_name:
        try:
            link = Path("/etc/localtime")
            if link.is_symlink():
                target = str(link.resolve())
                if "zoneinfo/" in target:
                    name = target.split("zoneinfo/", 1)[1]
                    _pytz_tz(name)
                    tz_name = name
        except Exception:
            pass

    # Method 4: TZ environment variable
    if not tz_name:
        try:
            name = os.environ.get("TZ")
            if name:
                _pytz_tz(name)
                tz_name = name
        except Exception:
            pass

    # Method 5: UTC-offset fallback (works everywhere but loses DST name)
    if not tz_name:
        offset_sec = -_time.timezone if _time.daylight == 0 else -_time.altzone
        offset_h = offset_sec // 3600
        tz_name = f"Etc/GMT{-offset_h:+d}" if offset_h != 0 else "UTC"

    return JSONResponse({"timezone": tz_name})




@router.post("/api/settings/database/test")
async def test_database_connection(request: Request):
    """Test a database connection.

    Two modes, distinguished by whether the form's password is supplied:

    - **Empty password** → test the LIVE engine (the connection the running
      app is actually using). This avoids the long-standing surprise where
      the form auto-loads host/port/user/database from saved config but
      cannot echo the password back for security, so a synthetic re-test
      always failed even when the app was perfectly connected.
    - **Password supplied** → build a synthetic adapter from form values
      and test it. This is the right behavior when the user is trying out
      a new credential or a different backend.
    """
    data = await request.json()
    backend = data.get("backend")
    host = data.get("host", "localhost")
    port = data.get("port")
    user = data.get("user", "cygor")
    password = data.get("password") or ""
    database = data.get("database", "cygor")
    ssl_mode = data.get("ssl_mode")
    ssl_ca = data.get("ssl_ca")
    service_name = data.get("service_name")

    # No password → check the live engine instead of building a synthetic one.
    # SQLite needs no password ever, so still go through the live test for it.
    if not password.strip():
        from ... import db as db_module
        from sqlalchemy import text as sa_text
        try:
            if db_module.engine is None:
                return JSONResponse(content={
                    "success": False,
                    "error": "No active database engine. Supply a password to test a new connection.",
                }, status_code=400)
            async with db_module.engine.begin() as conn:
                await conn.execute(sa_text("SELECT 1"))
            label = backend or "active"
            return JSONResponse(content={
                "success": True,
                "message": f"Active connection healthy ({label} at {host or 'local'})",
                "tested": "live",
            })
        except Exception as e:
            return JSONResponse(content={
                "success": False,
                "error": f"Active connection unhealthy: {e}",
                "tested": "live",
            }, status_code=400)

    from ...db_adapters import DatabaseManager
    manager = DatabaseManager()
    adapter = manager._select_adapter(
        backend=backend, host=host, port=int(port) if port else None,
        user=user, password=password, database=database,
        ssl_mode=ssl_mode, ssl_ca=ssl_ca, service_name=service_name,
    )

    if not adapter:
        return JSONResponse(content={"success": False, "error": f"Unknown backend: {backend}"}, status_code=400)

    if not adapter.is_available():
        return JSONResponse(content={"success": False, "error": f"Driver for {backend} is not installed"}, status_code=400)

    if adapter.test_connection():
        return JSONResponse(content={
            "success": True,
            "message": f"Connected to {backend} at {host}",
            "tested": "synthetic",
        })
    else:
        return JSONResponse(content={
            "success": False,
            "error": f"Connection to {backend} at {host} failed",
            "tested": "synthetic",
        }, status_code=400)


@router.post("/api/settings/database/switch")
async def switch_database(request: Request):
    """Hot-swap to a new database connection. Takes automatic snapshot first."""
    data = await request.json()
    backend = data.get("backend")
    host = data.get("host", "localhost")
    port = data.get("port")
    user = data.get("user", "cygor")
    password = data.get("password", "")
    database = data.get("database", "cygor")
    ssl_mode = data.get("ssl_mode")
    ssl_ca = data.get("ssl_ca")
    service_name = data.get("service_name")

    from ...db_adapters import DatabaseManager
    from ... import db

    manager = DatabaseManager()
    adapter = manager._select_adapter(
        backend=backend, host=host, port=int(port) if port else None,
        user=user, password=password, database=database,
        ssl_mode=ssl_mode, ssl_ca=ssl_ca, service_name=service_name,
    )

    if not adapter:
        return JSONResponse(content={"success": False, "error": f"Unknown backend: {backend}"}, status_code=400)

    if not adapter.is_available():
        return JSONResponse(content={"success": False, "error": f"Driver for {backend} not installed"}, status_code=400)

    # Setup (create cygor database if needed)
    if not adapter.setup():
        return JSONResponse(content={"success": False, "error": f"Failed to setup {backend} database"}, status_code=500)

    new_url = adapter.get_connection_url()
    label = f"{backend}_{host}" if host else backend

    success = await db.swap_engine(new_url, label=label)
    if success:
        # Save config
        manager._save_db_config(config={
            "backend": backend, "host": host, "port": port,
            "user": user, "database": database, "ssl_mode": ssl_mode,
            "ssl_ca": ssl_ca, "service_name": service_name,
        })
        os.environ["CYGOR_DB_URL"] = new_url

        from ...audit import record as audit_record
        source_ip = request.client.host if request.client else None
        await audit_record(action="db_switched", detail={"backend": backend, "host": host}, source_ip=source_ip)

        return JSONResponse(content={"success": True, "message": f"Switched to {backend} at {host}"})
    else:
        return JSONResponse(content={"success": False, "error": "Hot-swap failed -- old connection preserved"}, status_code=500)


@router.get("/api/settings/database/snapshots")
async def list_database_snapshots(request: Request):
    """List available database snapshots."""
    from ... import db
    snapshots = db.list_snapshots()
    return JSONResponse(content={"snapshots": snapshots})


@router.post("/api/settings/database/snapshot")
async def create_database_snapshot(request: Request):
    """Take a manual database snapshot."""
    from ... import db
    path = await db.take_snapshot(label="manual")
    if path:
        return JSONResponse(content={"success": True, "path": str(path)})
    return JSONResponse(content={"success": False, "error": "Snapshot failed"}, status_code=500)


@router.post("/api/settings/database/clear")
async def clear_database(request: Request):
    """Drop and recreate every table in the active database.

    Mirrors ``cygor web start --clear-db``. Takes an automatic snapshot
    before destroying anything, requires the caller to send
    ``confirm: "CYGOR"`` in the JSON body, and logs an audit entry.
    """
    try:
        data = await request.json()
    except Exception:
        data = {}
    if (data.get("confirm") or "").strip() != "CYGOR":
        return JSONResponse(content={
            "success": False,
            "error": "Confirmation phrase missing. Send {\"confirm\": \"CYGOR\"} to proceed.",
        }, status_code=400)

    from ... import db as db_module
    if db_module.engine is None:
        return JSONResponse(content={"success": False, "error": "No active database engine"}, status_code=500)

    # Auto-snapshot before destruction so the user has a recovery path.
    snapshot_path = None
    try:
        snapshot_path = await db_module.take_snapshot(label="pre_clear")
    except Exception as snap_err:
        logger.warning(f"pre-clear snapshot failed (continuing): {snap_err}")

    try:
        await db_module.reset_db()
    except Exception as e:
        logger.error(f"clear_database failed: {e}", exc_info=True)
        return JSONResponse(content={
            "success": False,
            "error": f"Reset failed: {e}",
            "snapshot": str(snapshot_path) if snapshot_path else None,
        }, status_code=500)

    try:
        from ...audit import record as audit_record
        source_ip = request.client.host if request.client else None
        await audit_record(
            action="db_cleared",
            detail={"snapshot": str(snapshot_path) if snapshot_path else None},
            source_ip=source_ip,
        )
    except Exception:
        pass

    return JSONResponse(content={
        "success": True,
        "message": "Database cleared. All tables dropped and recreated.",
        "snapshot": str(snapshot_path) if snapshot_path else None,
    })


