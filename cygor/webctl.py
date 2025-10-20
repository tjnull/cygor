# cygor/webctl.py
"""
Cygor Web server controller: start/stop/status.

Usage:
  cygor web start [-v] [-H HOST] [-p PORT] [--reset-db] [--load-dir PATH]
  cygor web stop
  cygor web status
"""
from __future__ import annotations
import argparse
import asyncio
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Optional

# These will be set dynamically based on --load-dir
PID_FILE: Path
LOG_FILE: Path


# -----------------------------
#  Utility: Process Management
# -----------------------------
def _pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _read_pid() -> int | None:
    try:
        pid_text = PID_FILE.read_text().strip()
        if pid_text:
            return int(pid_text)
    except Exception:
        return None
    return None


def _write_pid(pid: int) -> None:
    PID_FILE.write_text(str(pid))


def _remove_pidfile() -> None:
    try:
        PID_FILE.unlink(missing_ok=True)
    except Exception:
        pass


# -----------------------------
#  New: Database Initialization
# -----------------------------
def detect_postgresql() -> bool:
    """Check if PostgreSQL is available."""
    try:
        result = subprocess.run(["psql", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"[✓] PostgreSQL detected: {result.stdout.strip()}")
            return True
    except FileNotFoundError:
        pass
    print("[!] PostgreSQL not detected — falling back to SQLite.")
    return False


def setup_postgres(user="cygor", password="cygorpass", db_name="cygor", host="localhost"):
    """
    Delegate PostgreSQL setup to cygor.webapp.db.setup_postgres()
    to avoid using the old DO $$ CREATE DATABASE function.
    """
    from cygor.webapp import db
    return db.setup_postgres(user=user, password=password, db_name=db_name, host=host)



async def initialize_database(database_url: Optional[str] = None, reset: bool = False, verbose: bool = False):
    """
    Initialize or reset the database before web start.
    """
    from cygor.webapp import db

    if not database_url:
        if detect_postgresql():
            database_url = setup_postgres()
        else:
            database_url = "sqlite+aiosqlite:///cygor.db"

    print(f"[*] Using database: {database_url}")
    db.init_engine(database_url, debug=verbose)

    if reset:
        print("[!] Resetting database schema (drop + recreate)...")
        await db.reset_db()
    else:
        await db.init_db()


# -----------------------------
#  Web Server Lifecycle
# -----------------------------
def start(host: str, port: int, extra_args: list[str], load_dir: Optional[str], reset_db: bool, verbose: int) -> int:
    """
    Start the web server in the foreground with logs attached.
    Blocks until stopped with Ctrl+C.
    """
    global PID_FILE, LOG_FILE
    base_path = Path(load_dir) if load_dir else Path("results")
    base_path.mkdir(parents=True, exist_ok=True)
    PID_FILE = base_path / "cygor-web.pid"
    LOG_FILE = base_path / "cygor-web.log"

    print(f"[*] Starting Cygor Web on {host}:{port}")

    # --- Database setup before server ---
    try:
        asyncio.run(initialize_database(reset=reset_db, verbose=verbose > 1))
    except Exception as e:
        print(f"[!] Database initialization failed: {e}")
        return 1

    # --- Launch Web Server ---
    from cygor.webapp import main as web_main
    argv = ["--host", host, "--port", str(port)]
    if load_dir:
        argv += ["--load-dir", str(load_dir)]
    argv.extend(extra_args)

    try:
        web_main.exec_argv(argv)
    except KeyboardInterrupt:
        print("\n[!] Cygor Web stopped by user")
    return 0



def stop() -> int:
    pid = _read_pid()
    if not pid:
        print("Cygor Web is not running (no PID file found)")
        return 1
    if not _pid_is_running(pid):
        print(f"Process {pid} is not running (cleaning up PID file)")
        _remove_pidfile()
        return 0
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Sent SIGTERM to Cygor Web (PID {pid})")
    except Exception as e:
        print(f"Error sending SIGTERM to PID {pid}: {e}")
        return 1
    _remove_pidfile()
    return 0


def status() -> int:
    pid = _read_pid()
    if pid and _pid_is_running(pid):
        print(f"Cygor Web running (PID {pid})")
        print(f"Logs: {LOG_FILE}")
        return 0
    print("Cygor Web not running")
    return 1


def exec_argv(argv: list[str]) -> None:
    """
    Entry point used by cygor.cli to delegate `cygor web ...`.
    """
    parser = argparse.ArgumentParser(prog="cygor web", description="Manage Cygor Web server")
    sub = parser.add_subparsers(dest="cmd")

    # --- start ---
    p_start = sub.add_parser("start", help="Start the web server (foreground)")
    p_start.add_argument("-H", "--host", default="127.0.0.1")
    p_start.add_argument("-p", "--port", type=int, default=8000)
    p_start.add_argument("--reset-db", action="store_true", help="Drop and recreate the database, then exit")
    p_start.add_argument("--load-dir", type=str, help="Preload results directory in the background")
    p_start.add_argument("--cleanup-db", action="store_true",help="Drop the PostgreSQL database and user after shutdown (default: keep data)")
    p_start.add_argument("-y", "--yes", action="store_true",help="Automatic yes to cleanup prompts (for non-interactive mode)")
    p_start.add_argument("--use-sudo-cleanup", action="store_true",help="Use sudo for privileged PostgreSQL cleanup (requires NOPASSWD psql access)")
    p_start.add_argument("-v", "--verbose", action="count", default=0,help="Increase verbosity (-v shows more, -vv shows debug details)")

    # --- stop / status ---
    sub.add_parser("stop", help="Stop the web server")
    sub.add_parser("status", help="Show server status")

    # Auto-add "start" if the user just typed options (e.g. `cygor web -p 8080`)
    if argv and not argv[0] in {"start", "stop", "status"}:
        argv = ["start", *argv]

    args, unknown = parser.parse_known_args(argv)

    if args.cmd == "start":
        passthrough = []

        # Verbosity
        if args.verbose:
            passthrough.extend(["-" + "v" * args.verbose])

        # Database options
        if args.reset_db:
            passthrough.append("--reset-db")
        if args.cleanup_db:
            passthrough.append("--cleanup-db")
        if args.yes:
            passthrough.append("--yes")
        if args.use_sudo_cleanup:
            os.environ["CYGOR_USE_SUDO_CLEANUP"] = "1"

        passthrough.extend(unknown)

        sys.exit(start(args.host, args.port, passthrough, args.load_dir, args.reset_db, args.verbose))

    elif args.cmd == "stop":
        sys.exit(stop())

    elif args.cmd == "status":
        sys.exit(status())

    else:
        parser.print_help()

