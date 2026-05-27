"""
Cygor Web Application - Main entry point.

This module contains app initialization, middleware, lifespan management,
and router registration. Route handlers are in cygor.webapp.routes.*.
"""
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
import os, argparse, asyncio, shutil, json, re, uvicorn, sys, subprocess, logging
import xml.etree.ElementTree as ET
from pathlib import Path
from fastapi import FastAPI, Request, Depends, Query, Form, HTTPException, File, UploadFile, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Optional, Dict, Any

# Optional PostgreSQL support - only import if available
try:
    import psycopg
    from psycopg.rows import dict_row
    PSYCOPG_AVAILABLE = True
except ImportError:
    psycopg = None
    dict_row = None
    PSYCOPG_AVAILABLE = False

from . import db
from .db import get_session, reset_db
from .models import Host, Port, Script, OSGuess, HostTag
from ..module_loader import discover_modules, resolve_legacy_context
from .ingest import ingest_directory
from .config import settings
from .tasks import task_manager, TaskStatus, Task, WorkspaceNotConfiguredError
from .credrecon_tasks import credrecon_manager
from .helpers import (
    normalize_service, _bucket_family, _bucket_family_from_device_info,
    _top_guess, TopItem, _count_hosts_in_nmap_xml, _count_hosts_in_nmap_text,
    _parse_nmap_xml_times, extract_host_key, gather_scan_times,
    gather_ondemand_scan_times, _parse_iso_to_dt,
)

# Route modules
from .routes import core as core_routes
from .routes import modules as modules_routes
from .routes import search as search_routes
from .routes import tasks as tasks_routes
from .routes import hosts as hosts_routes
from .routes import credrecon as credrecon_routes
from .routes import scheduler as scheduler_routes
from .routes import sync as sync_routes
from .routes import enrichment as enrichment_routes
from .routes import docs as docs_routes
from .routes.settings import general as settings_general_routes
from .routes.settings import database as settings_database_routes
from .routes.settings import proxy as settings_proxy_routes
from .routes.settings import plugins as settings_plugins_routes
from .routes.settings import workspaces as settings_workspaces_routes


logger = logging.getLogger(__name__)

templates = None  # will be initialized in lifespan
DISCOVERED_MODULES = []  # filled during startup
SYNC_HISTORY = []  # List of sync events


# --- Temporary workaround for asyncpg+SQLAlchemy Python 3.13 bug ---
def _ignore_event_loop_closed(loop, context):
    msg = context.get("message", "")
    exc = context.get("exception")
    if isinstance(exc, RuntimeError) and "Event loop is closed" in str(exc):
        return  # swallow harmless cleanup noise
    if "Event loop is closed" in msg:
        return
    loop.default_exception_handler(context)

# Patch all asyncio loops created after import
asyncio.get_event_loop().set_exception_handler(_ignore_event_loop_closed)


async def _db_health_monitor():
    """Background task: check database health every 60 seconds."""
    from . import db
    from sqlalchemy import text as sa_text
    while True:
        await asyncio.sleep(60)
        try:
            if db.engine:
                async with db.engine.begin() as conn:
                    await conn.execute(sa_text("SELECT 1"))
        except Exception as e:
            logging.getLogger(__name__).warning(f"Database health check failed: {e}")


# ---------------- Lifespan ----------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    from .startup_logger import get_logger, StartupPhase
    log = get_logger()

    # Configure fingerprinting loggers based on verbosity
    verbosity = int(os.environ.get("CYGOR_VERBOSE", "0"))
    if verbosity < 2:
        logging.getLogger('cygor.fingerprinting').setLevel(logging.WARNING)
        logging.getLogger('cygor.fingerprinting.fingerprint').setLevel(logging.WARNING)
        logging.getLogger('cygor.fingerprinting.lookup').setLevel(logging.WARNING)
        logging.getLogger('cygor.fingerprinting.sync').setLevel(logging.WARNING)
        logging.getLogger('cygor.fingerprinting.cache').setLevel(logging.WARNING)
        logging.getLogger('cygor.fingerprinting.patterns').setLevel(logging.WARNING)
        logging.getLogger('asyncio').setLevel(logging.WARNING)

    global templates
    base_dir = Path(__file__).resolve().parent
    templates_dir = base_dir / "templates"
    static_dir = base_dir / "static"

    # Static
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    else:
        log.warning(f"Static directory not found: {static_dir}")

    templates = Jinja2Templates(directory=str(templates_dir))

    # Add custom Jinja2 filters
    def parse_json_filter(value):
        if isinstance(value, str):
            try:
                return json.loads(value)
            except (json.JSONDecodeError, TypeError):
                return {}
        return value if value else {}

    templates.env.filters['fromjson'] = parse_json_filter

    # Add markdown filter for report content
    import html

    def markdown_filter(text):
        """Convert markdown text to HTML for report rendering"""
        if not text:
            return ''
        result = html.escape(str(text))

        def code_block_replacer(match):
            lang = match.group(1) or 'text'
            code = match.group(2).strip()
            return f'<pre style="background: rgba(0,0,0,0.1); padding: 1rem; border-radius: 8px; overflow-x: auto; margin: 1rem 0;"><code class="language-{lang}">{code}</code></pre>'

        result = re.sub(r'```(\w*)\n([\s\S]*?)```', code_block_replacer, result)
        result = re.sub(r'`([^`]+)`', r'<code style="background: rgba(13, 110, 253, 0.15); padding: 0.15rem 0.4rem; border-radius: 4px; font-family: monospace;">\1</code>', result)
        result = re.sub(r'^### (.*?)$', r'<h3 style="font-size: 1.1rem; font-weight: 600; margin: 1rem 0 0.5rem; color: inherit;">\1</h3>', result, flags=re.MULTILINE)
        result = re.sub(r'^## (.*?)$', r'<h2 style="font-size: 1.25rem; font-weight: 600; margin: 1.25rem 0 0.75rem; color: inherit;">\1</h2>', result, flags=re.MULTILINE)
        result = re.sub(r'^# (.*?)$', r'<h1 style="font-size: 1.5rem; font-weight: 700; margin: 1.5rem 0 1rem; color: inherit; border-bottom: 2px solid rgba(13, 110, 253, 0.3); padding-bottom: 0.5rem;">\1</h1>', result, flags=re.MULTILINE)
        result = re.sub(r'\*\*\*(.*?)\*\*\*', r'<strong><em>\1</em></strong>', result)
        result = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', result)
        result = re.sub(r'\*(.*?)\*', r'<em>\1</em>', result)
        result = re.sub(r'~~(.*?)~~', r'<del>\1</del>', result)
        result = re.sub(r'^&gt; (.*?)$', r'<blockquote style="border-left: 4px solid #0d6efd; padding-left: 1rem; margin: 1rem 0; color: #64748b; font-style: italic;">\1</blockquote>', result, flags=re.MULTILINE)
        result = re.sub(r'^---$', r'<hr style="border: none; border-top: 1px solid #e2e8f0; margin: 1.5rem 0;">', result, flags=re.MULTILINE)
        result = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2" style="color: #0d6efd; text-decoration: none;">\1</a>', result)
        result = re.sub(r'^- \[x\] (.*?)$', r'<li style="list-style: none; margin: 0.35rem 0;"><input type="checkbox" checked disabled style="margin-right: 0.5rem;"> \1</li>', result, flags=re.MULTILINE)
        result = re.sub(r'^- \[ \] (.*?)$', r'<li style="list-style: none; margin: 0.35rem 0;"><input type="checkbox" disabled style="margin-right: 0.5rem;"> \1</li>', result, flags=re.MULTILINE)
        result = re.sub(r'^- (.*?)$', r'<li style="margin: 0.35rem 0;">\1</li>', result, flags=re.MULTILINE)
        result = re.sub(r'^\* (.*?)$', r'<li style="margin: 0.35rem 0;">\1</li>', result, flags=re.MULTILINE)
        result = re.sub(r'^\d+\. (.*?)$', r'<li style="margin: 0.35rem 0;">\1</li>', result, flags=re.MULTILINE)

        def wrap_list_items(match):
            items = match.group(0)
            if 'checkbox' in items:
                return f'<ul style="list-style: none; padding-left: 0; margin: 0.75rem 0;">{items}</ul>'
            return f'<ul style="padding-left: 1.5rem; margin: 0.75rem 0;">{items}</ul>'

        result = re.sub(r'(<li[^>]*>.*?</li>\s*)+', wrap_list_items, result)

        def table_row_replacer(match):
            content = match.group(1)
            cells = [c.strip() for c in content.split('|')]
            if all(re.match(r'^-+$', c) for c in cells if c):
                return '<!-- table-separator -->'
            row_cells = ''.join(f'<td style="border: 1px solid #e2e8f0; padding: 0.5rem 0.75rem;">{c}</td>' for c in cells if c)
            return f'<tr>{row_cells}</tr>'

        result = re.sub(r'^\|(.+)\|$', table_row_replacer, result, flags=re.MULTILINE)

        def wrap_table(match):
            content = match.group(0)
            if '<!-- table-separator -->' in content:
                content = content.replace('<!-- table-separator -->', '')
                rows = content.split('</tr>')
                if len(rows) > 1:
                    rows[0] = rows[0].replace('<td', '<th').replace('</td>', '</th>')
                    rows[0] = rows[0].replace('style="border: 1px solid #e2e8f0; padding: 0.5rem 0.75rem;"',
                                               'style="border: 1px solid #e2e8f0; padding: 0.5rem 0.75rem; background: rgba(13, 110, 253, 0.1); font-weight: 600;"')
                content = '</tr>'.join(rows)
            return f'<table style="width: 100%; border-collapse: collapse; margin: 1rem 0;">{content}</table>'

        result = re.sub(r'(<tr>.*?</tr>\s*)+', wrap_table, result, flags=re.DOTALL)

        paragraphs = result.split('\n\n')
        processed = []
        for p in paragraphs:
            p = p.strip()
            if not p:
                continue
            if re.match(r'^<(h[1-6]|ul|ol|pre|blockquote|table|hr|div)', p):
                processed.append(p)
            else:
                p = p.replace('\n', '<br>')
                processed.append(f'<p style="margin: 0.75rem 0;">{p}</p>')

        return '\n'.join(processed)

    templates.env.filters['markdown'] = markdown_filter
    from markupsafe import Markup
    def markdown_safe_filter(text):
        return Markup(markdown_filter(text))
    templates.env.filters['markdown_safe'] = markdown_safe_filter

    # -------------------------
    # Register all route modules
    # -------------------------
    route_modules = [
        core_routes, modules_routes, search_routes,
        tasks_routes, hosts_routes, credrecon_routes,
        scheduler_routes, sync_routes, enrichment_routes,
        docs_routes,
        settings_general_routes, settings_database_routes,
        settings_proxy_routes, settings_plugins_routes,
        settings_workspaces_routes,
    ]

    for mod in route_modules:
        if hasattr(mod, 'set_templates'):
            mod.set_templates(templates)
        app.include_router(mod.router)

    # -------------------------
    # Database Initialization
    # -------------------------
    try:
        db_url = os.environ.get("CYGOR_DB_URL") or db.get_default_database_url()
        db.init_engine(db_url, debug=(os.environ.get("CYGOR_VERBOSE", "0") > "1"))
        await db.init_db()
        log.success("Database schema verified")

    except Exception as e:
        log.error("Database initialization failed", str(e))

    # Start database health monitor
    asyncio.create_task(_db_health_monitor())

    # Lockon screenshots mount
    _load_dir = os.environ.get("CYGOR_LOAD_DIR") or str(settings.RESULTS_DIR)
    lockon_dir = Path(_load_dir) / "cygor-enumeration-modules" / "lockon" / "screenshots"
    if lockon_dir.exists():
        app.mount("/modules/lockon/screenshots", StaticFiles(directory=str(lockon_dir)), name="lockon_screenshots")
        log.verbose(f"Mounted Lockon screenshots: {lockon_dir}")

    # -------------------------
    # Module Discovery
    # -------------------------
    log.phase(StartupPhase.MODULES)
    global DISCOVERED_MODULES
    try:
        DISCOVERED_MODULES = discover_modules()
        modules_routes._register_module_routes(app, templates_dir, settings.RESULTS_DIR)

        if DISCOVERED_MODULES:
            module_names = [m.slug for m in DISCOVERED_MODULES]
            log.success(f"Registered {len(DISCOVERED_MODULES)} module(s)", ", ".join(module_names))
        else:
            log.info("No enumeration modules found")
    except Exception as e:
        log.error("Module discovery failed", str(e))

    # -------------------------
    # Restore Historical Tasks
    # -------------------------
    log.phase(StartupPhase.DATA)
    verbosity = int(os.environ.get("CYGOR_VERBOSE", "0"))

    try:
        load_dir = os.environ.get("CYGOR_LOAD_DIR")
        dirs_to_check = [str(settings.RESULTS_DIR)]
        if load_dir and load_dir not in dirs_to_check:
            dirs_to_check.append(load_dir)

        log.debug(f"Checking directories for historical tasks: {dirs_to_check}")
        total_restored = 0
        for results_dir in dirs_to_check:
            log.debug(f"Restoring from: {results_dir}")
            restored = await task_manager.restore_historical_tasks(results_dir)
            total_restored += restored

        task_count = len(task_manager.tasks)
        if task_count > 0:
            log.success(f"Restored {task_count} historical task(s)")
        else:
            log.verbose("No historical tasks found")
    except Exception as e:
        log.error("Error restoring historical tasks", str(e))
        if verbosity >= 2:
            import traceback
            traceback.print_exc()

    # -------------------------
    # Scheduler Initialization
    # -------------------------
    try:
        from .scheduler import initialize_scheduler_manager, get_scheduler_manager

        scheduler_mgr = initialize_scheduler_manager(
            task_manager=task_manager,
            credrecon_manager=credrecon_manager,
        )
        scheduler_mgr.initialize(database_url=db.get_database_url())
        scheduler_mgr.start()
        log.success("Scheduler initialized and started")
        log.verbose("Scheduled tasks will be loaded after database ingestion")
    except Exception as e:
        log.error("Scheduler initialization failed", str(e))
        if verbosity >= 2:
            import traceback
            traceback.print_exc()

    # -------------------------
    # Ingestion
    # -------------------------
    load_dir = os.environ.get("CYGOR_LOAD_DIR")

    if load_dir:
        log.info(f"Ingesting scan results from {load_dir}")
        try:
            import time as _time
            _ingest_t0 = _time.monotonic()
            async with db.SessionLocal() as session:
                count = await ingest_directory(Path(load_dir), session, dedupe=True, verbose=verbosity)
                await session.commit()
            _ingest_elapsed = _time.monotonic() - _ingest_t0
            log.success(f"Ingested {count} scan file(s) in {_ingest_elapsed:.1f}s")
        except Exception as e:
            log.error("Ingestion failed", str(e))

    # -------------------------
    # Load Scheduled Tasks (after DB is ready)
    # -------------------------
    try:
        from .scheduler import get_scheduler_manager
        scheduler_mgr = get_scheduler_manager()
        async with db.SessionLocal() as session:
            await scheduler_mgr.load_scheduled_tasks(session)
        log.success("Loaded scheduled tasks")
    except Exception as e:
        log.error("Failed to load scheduled tasks", str(e))
        if verbosity >= 2:
            import traceback
            traceback.print_exc()

    # -------------------------
    # Start Background Task Monitor
    # -------------------------
    monitor_task = None
    try:
        async def task_monitor_loop():
            while True:
                try:
                    await asyncio.sleep(30)
                    from .scheduler import get_scheduler_manager
                    scheduler_mgr = get_scheduler_manager()
                    await scheduler_mgr.monitor_running_tasks()
                except Exception as e:
                    logger.error(f"Error in task monitor: {e}", exc_info=True)

        monitor_task = asyncio.create_task(task_monitor_loop())
        log.success("Started scheduled task monitor")
    except Exception as e:
        log.error("Failed to start task monitor", str(e))

    # -------------------------
    # Yield to FastAPI
    # -------------------------
    try:
        yield
    finally:
        try:
            if monitor_task and not monitor_task.done():
                print("[*] Cancelling task monitor...")
                monitor_task.cancel()
                try:
                    await monitor_task
                except asyncio.CancelledError:
                    pass
                print("[+] Task monitor cancelled.")

            try:
                from .scheduler import get_scheduler_manager
                scheduler_mgr = get_scheduler_manager()
                print("[*] Shutting down scheduler...")
                scheduler_mgr.shutdown(wait=False)
                print("[+] Scheduler shut down.")
            except Exception as e:
                print(f"[!] Scheduler shutdown error: {e}")

            if getattr(db, "engine", None):
                print("[*] Disposing database engine...")
                try:
                    loop = asyncio.get_running_loop()
                    if loop.is_closed():
                        print("[!] Event loop already closed - skipping engine dispose.")
                    else:
                        await db.engine.dispose()
                        print("[+] Database engine disposed cleanly.")
                except (RuntimeError, Exception) as e:
                    if "Event loop is closed" in str(e) or "attached to a different loop" in str(e):
                        print("[!] Ignored psycopg loop-closed cleanup noise.")
                    else:
                        print(f"[!] Unhandled dispose error: {e}")

            try:
                await cleanup_postgresql()
            except (KeyboardInterrupt, SystemExit):
                print("[*] Skipping PostgreSQL cleanup due to shutdown signal.")
            except Exception as e:
                print(f"[!] PostgreSQL cleanup failed: {e}")
        except (KeyboardInterrupt, SystemExit):
            print("[*] Shutdown interrupted - exiting immediately.")
            raise


async def cleanup_postgresql():
    """Fully cleanup PostgreSQL database and role after Cygor Web shutdown."""
    db_url = os.environ.get("CYGOR_DB_URL") or ""
    if not db_url.startswith("postgresql"):
        return

    if os.environ.get("CYGOR_CLEANUP_DB") != "1":
        print("[*] Skipping PostgreSQL cleanup (use --cleanup-db to enable).")
        return

    if os.environ.get("CYGOR_PERSIST_DB") == "1":
        print("[*] Persistent database mode enabled - skipping cleanup.")
        return

    pg_db   = os.getenv("PGDATABASE", os.getenv("CYGOR_DB_NAME", "cygor"))
    pg_user = os.getenv("PGUSER", os.getenv("CYGOR_DB_USER", "cygor_user"))

    # CYGOR_DB_NAME and CYGOR_DB_USER (and their PG* aliases) come from
    # the environment; a value containing `;`, `'`, or a newline would
    # otherwise be executed as superuser SQL when this cleanup path runs
    # `DROP DATABASE {pg_db}` / `DROP ROLE {pg_user}` via the sudo
    # postgres user. Reject anything that isn't a strict Postgres
    # identifier before letting either string near a SQL statement.
    # Same validator the DB adapter uses on its setup() path.
    from cygor.webapp.db_adapters import PostgreSQLAdapter as _PgAdapter
    try:
        _PgAdapter._validate_identifier("PGDATABASE / CYGOR_DB_NAME", pg_db)
        _PgAdapter._validate_identifier("PGUSER / CYGOR_DB_USER", pg_user)
    except ValueError as _id_err:
        print(f"[!] Refusing to run cleanup with unsafe identifier: {_id_err}")
        return

    conn_user = os.getenv("PGADMIN_USER", os.getenv("PGUSER", os.getenv("CYGOR_DB_USER", "cygor")))
    conn_pass = os.getenv("PGADMIN_PASS", os.getenv("PGPASSWORD", os.getenv("CYGOR_DB_PASSWORD", "cygorpass")))
    pg_host   = os.getenv("PGHOST", "localhost")
    pg_port   = int(os.getenv("PGPORT", "5432"))

    if os.getenv("CYGOR_YES") != "1":
        try:
            if not sys.stdin.isatty():
                print("[*] Non-interactive environment; skipping cleanup.")
                return
            answer = input(f"[?] Do you want to delete PostgreSQL database '{pg_db}' "
                           f"and user '{pg_user}' on shutdown? [y/N]: ").strip().lower()
            if answer not in ("y", "yes"):
                print("[*] Cleanup aborted by user - keeping PostgreSQL data.")
                return
        except (EOFError, OSError, KeyboardInterrupt, SystemExit):
            print("\n[*] Skipping cleanup to allow clean shutdown.")
            return

    print(f"[*] Cleaning up PostgreSQL database '{pg_db}' and user '{pg_user}'...")

    db_dropped = False
    role_dropped = False

    try:
        conninfo = f"postgresql://{conn_user}:{conn_pass}@{pg_host}:{pg_port}/postgres"
        async with await psycopg.AsyncConnection.connect(conninfo, autocommit=True) as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user;")
                row = await cur.fetchone()
                is_superuser = bool(row and row["rolsuper"])

                if is_superuser:
                    print("[*] Running as superuser - performing full cleanup.")
                    await cur.execute("""
                        SELECT pg_terminate_backend(pid)
                        FROM pg_stat_activity
                        WHERE datname = %s AND pid <> pg_backend_pid();
                    """, (pg_db,))
                    await cur.execute(f"DROP DATABASE IF EXISTS {pg_db};")
                    db_dropped = True
                    await cur.execute(f"DROP ROLE IF EXISTS {pg_user};")
                    role_dropped = True
                    print("[+] PostgreSQL cleanup completed via superuser.")
                else:
                    print("[*] Current user is not a superuser - limited cleanup mode.")
                    try:
                        await cur.execute(f"DROP DATABASE IF EXISTS {pg_db};")
                        db_dropped = True
                        print(f"[+] Dropped database '{pg_db}'.")
                    except Exception as e:
                        print(f"[!] Cannot drop database: {e}")

                    try:
                        await cur.execute(f"DROP ROLE IF EXISTS {pg_user};")
                        role_dropped = True
                        print(f"[+] Dropped role '{pg_user}'.")
                    except Exception as e:
                        print(f"[!] Cannot drop role: {e}")

    except Exception as e:
        print(f"[!] psycopg cleanup path error: {e}")

    if (not db_dropped or not role_dropped) and shutil.which("sudo"):
        print("[*] Attempting privileged cleanup via sudo (postgres user)...")

        def run_sudo_sql(sql: str):
            return subprocess.run(
                ["sudo", "-u", "postgres", "psql", "-tAc", sql],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )

        try:
            run_sudo_sql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                         f"WHERE datname='{pg_db}' AND pid <> pg_backend_pid();")
            run_sudo_sql(f"DROP DATABASE IF EXISTS {pg_db};")
            db_dropped = True
            run_sudo_sql(f"REASSIGN OWNED BY {pg_user} TO postgres;")
            run_sudo_sql(f"DROP OWNED BY {pg_user};")
            run_sudo_sql(f"DROP ROLE IF EXISTS {pg_user};")
            role_dropped = True
            print("[+] PostgreSQL cleanup completed via sudo.")
        except Exception as e:
            print(f"[!] Sudo cleanup failed: {e}")

    if db_dropped and role_dropped:
        print(f"[+] PostgreSQL database '{pg_db}' and role '{pg_user}' fully removed.")
    elif db_dropped and not role_dropped:
        print(f"[i] Database '{pg_db}' removed, but role '{pg_user}' kept (no privileges).")
    elif not db_dropped and role_dropped:
        print(f"[i] Role '{pg_user}' removed, but database '{pg_db}' kept (locked/in use).")
    else:
        print(f"[!] Cleanup incomplete - manual removal may be required.")


# ---------------- FastAPI App ----------------
# Move FastAPI's auto-generated Swagger UI off /docs so the in-repo wiki at
# /docs/<page> (served by routes/docs.py) doesn't collide with it. OpenAPI
# JSON is still available at /openapi.json for any tooling that wants it.
app = FastAPI(lifespan=lifespan, docs_url="/api-docs", redoc_url="/api-redoc")


@app.exception_handler(WorkspaceNotConfiguredError)
async def _workspace_not_configured_handler(request: Request, exc: WorkspaceNotConfiguredError):
    """Return a clean 400 when a scan is launched with no workspace configured."""
    return JSONResponse(
        status_code=400,
        content={"error": str(exc), "code": "workspace_not_configured"},
    )


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Add security headers to all responses."""
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://d3js.org; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "frame-src 'self' blob:; "
        "frame-ancestors 'none';"
    )

    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), payment=(), "
        "usb=(), magnetometer=(), gyroscope=(), accelerometer=()"
    )

    return response


def _enum_modules_with_data(modules):
    """Slugs of enumeration modules that have results in the active workspace.

    Used to gate the sidebar so 'Enumeration Results' lists only modules the
    user actually has data for, instead of every installed module.
    """
    import json as _json
    ws = (os.environ.get("CYGOR_LOAD_DIR") or os.environ.get("CYGOR_WORKSPACE")
          or str(settings.RESULTS_DIR))
    base = Path(ws) / "cygor-enumeration-modules"
    have = set()
    if not base.is_dir():
        return have
    for m in modules:
        jf = base / m.slug / "cygor-result.json"
        if not jf.is_file():
            continue
        try:
            data = _json.loads(jf.read_text(encoding="utf-8", errors="ignore"))
            if data.get("results"):
                have.add(m.slug)
        except Exception:
            pass
    return have


@app.middleware("http")
async def add_modules_to_request(request: Request, call_next):
    request.state.modules = [m for m in DISCOVERED_MODULES if m.module_type == "enumeration"]

    # Sidebar gating: list only modules that have data in the active workspace.
    # Skip the filesystem check on asset/API requests (no sidebar there).
    _combined = {"lockon", "smbexplorer", "nfsexplorer"}
    if request.url.path.startswith(("/static", "/api")):
        _data = set()
    else:
        _data = _enum_modules_with_data(request.state.modules)
    request.state.show_screenshots = "lockon" in _data
    request.state.show_network_shares = ("smbexplorer" in _data) or ("nfsexplorer" in _data)
    request.state.sidebar_modules = sorted(
        (m for m in request.state.modules if m.slug in _data and m.slug not in _combined),
        key=lambda m: m.name)

    return await call_next(request)


# -------- Entrypoint --------
def exec_argv(argv):
    import uvicorn
    parser = argparse.ArgumentParser(description="Run the Cygor Web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--clear-db", action="store_true", help="Drop and recreate the database schema. WARNING: This will delete all existing data!")
    parser.add_argument("--load-dir", type=str, help="Results directory or database file to load")
    parser.add_argument("--cleanup-db",action="store_true",help="Drop the PostgreSQL database and user after shutdown (default: keep data)")
    parser.add_argument("-v", "--verbose", action="count", default=0,help="Increase verbosity (-v shows more, -vv shows debug details)")
    parser.add_argument("-y", "--yes",action="store_true",help="Automatic yes to cleanup prompts (for non-interactive or CI mode)")
    args = parser.parse_args(argv)

    if args.clear_db:
        os.environ["CYGOR_CLEAR_DB"] = "1"
        from .startup_logger import init_logger, StartupPhase
        log = init_logger(args.verbose)
        log.warning("Clearing database (--clear-db)")

        import asyncio
        db_url = db.get_default_database_url()
        db.init_engine(db_url, debug=(args.verbose > 1))

        async def clear_and_exit():
            await db.reset_db()
            log.success("Database cleared successfully")

        asyncio.run(clear_and_exit())
        return

    load_path = Path(args.load_dir or settings.RESULTS_DIR).expanduser().resolve()
    if not load_path.exists():
        print(f"[!] Specified results directory does not exist: {load_path}")
        return

    settings.RESULTS_DIR = str(load_path)
    os.environ["CYGOR_LOAD_DIR"] = settings.RESULTS_DIR
    os.environ["CYGOR_WORKSPACE"] = settings.RESULTS_DIR
    os.environ["CYGOR_VERBOSE"] = str(args.verbose)

    os.environ["CYGOR_WEB_HOST"] = args.host
    os.environ["CYGOR_WEB_PORT"] = str(args.port)
    os.environ["CYGOR_WEB_HTTPS"] = "0"

    if args.verbose >= 2:
        log_level = logging.DEBUG
    elif args.verbose >= 1:
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    root_logger = logging.getLogger()
    root_logger.handlers.clear()
    root_logger.setLevel(logging.WARNING)

    webapp_logger = logging.getLogger('cygor.webapp')
    webapp_logger.setLevel(log_level)
    tasks_logger = logging.getLogger('cygor.webapp.tasks')
    tasks_logger.setLevel(log_level)

    if args.verbose < 2:
        for name in [
            'aiosqlite', 'sqlalchemy.engine', 'sqlalchemy.pool',
            'apscheduler', 'apscheduler.scheduler', 'apscheduler.executors', 'apscheduler.jobstores',
            'matplotlib', 'matplotlib.pyplot', 'matplotlib.font_manager', 'PIL',
            'httpx', 'httpcore', 'urllib3',
            'python_multipart', 'python_multipart.multipart',
        ]:
            logging.getLogger(name).setLevel(logging.WARNING)

        if args.verbose < 1:
            logging.getLogger('uvicorn').setLevel(logging.WARNING)
            logging.getLogger('uvicorn.access').setLevel(logging.WARNING)
            logging.getLogger('uvicorn.error').setLevel(logging.WARNING)

    from .startup_logger import init_logger, StartupPhase
    log = init_logger(args.verbose)

    database_url = db.get_default_database_url()
    if args.cleanup_db:
        log.warning("Database cleanup enabled (will delete on exit)")

    os.environ["CYGOR_CLEANUP_DB"] = "1" if args.cleanup_db else "0"
    os.environ["CYGOR_YES"] = "1" if args.yes else "0"
    os.environ["CYGOR_DB_URL"] = database_url

    log.phase(StartupPhase.INIT)
    log.verbose(f"Results directory: {load_path}")
    log.verbose(f"Database URL: {database_url}")

    if args.verbose >= 2:
        uvicorn_log_level = "debug"
    elif args.verbose >= 1:
        uvicorn_log_level = "info"
    else:
        uvicorn_log_level = "warning"

    uvicorn_config = {
        "app": "cygor.webapp.main:app",
        "host": args.host,
        "port": args.port,
        "reload": False,
        "log_level": uvicorn_log_level,
        "access_log": args.verbose > 0,
    }

    log.phase(StartupPhase.SERVER)
    log.info(f"Starting server on http://{args.host}:{args.port}")

    uvicorn.run(**uvicorn_config)


if __name__ == "__main__":
    import sys
    exec_argv(sys.argv[1:])
