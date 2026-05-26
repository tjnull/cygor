# cygor/webctl.py
"""
Cygor Web server controller: start/stop/status.

Usage:
  cygor web start [OPTIONS]
  cygor web stop
  cygor web status

Examples:
  # Start web server on default host/port (127.0.0.1:8000)
  cygor web start

  # Start web server on all interfaces, port 8080
  cygor web start -H 0.0.0.0 -p 8080

  # Start with authentication enabled
  cygor web start --auth-login

  # Start with custom results directory
  cygor web start --load-dir /path/to/results

  # Start with PostgreSQL database URL
  cygor web start --db-url postgresql+psycopg_async://user:pass@localhost/cygor

  # Start with debug mode enabled
  cygor web start --debug

  # Start with verbose output
  cygor web start -vv

  # Clear database (standalone operation, does not start server)
  cygor web start --clear-db

  # Start with all options
  cygor web start -H 0.0.0.0 -p 8080 --auth-login --load-dir ~/scan-results -vv
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
    """Check if PostgreSQL is available (silent check)."""
    try:
        result = subprocess.run(["psql", "--version"], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False


def start_postgresql_cluster(log, verbose=0):
    """
    Start a PostgreSQL cluster if none are running.
    Prefers the latest PostgreSQL version available.
    Returns True if a cluster is now running, False otherwise.
    """
    from cygor.webapp.db_adapters import PostgreSQLAdapter

    adapter = PostgreSQLAdapter()
    if not adapter.is_available():
        log.warning("PostgreSQL client not available")
        log.info("Install PostgreSQL: sudo apt-get install postgresql")
        return False

    # Use the adapter's start_cluster method
    return adapter.start_cluster(verbose=verbose)


def detect_running_postgres_ports():
    """
    Detect running PostgreSQL instances and their ports.
    Returns a list of tuples: [(port, version), ...] sorted by preference.
    Prefers: 5432 (default) first, then by port number.
    """
    from cygor.webapp.db_adapters import PostgreSQLAdapter

    adapter = PostgreSQLAdapter()
    return adapter.detect_running_instances()


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
        print("[!] Clearing database schema (drop + recreate)...")
        await db.reset_db()
    else:
        await db.init_db()


def clear_database(workspace: Optional[str] = None, verbose: int = 0) -> int:
    """
    Clear the database without starting the web server.
    Connects to existing PostgreSQL database without creating directories.
    Always prompts for confirmation.
    """
    from cygor.webapp import db
    from cygor.webapp.db_adapters import PostgreSQLAdapter

    print("[*] Cygor Database Clear Utility")
    print("=" * 50)

    # Check for explicit database URL in environment
    env_url = os.environ.get("CYGOR_DB_URL")
    db_url = None

    if env_url:
        # Use explicit database URL
        db_url = env_url
        print(f"[*] Using database from CYGOR_DB_URL")
    else:
        # Try PostgreSQL (primary database backend)
        pg_adapter = PostgreSQLAdapter()
        if pg_adapter.is_available():
            print("[*] Checking for PostgreSQL...")
            instances = pg_adapter.detect_running_instances()
            if instances:
                port, version = instances[0]
                print(f"[*] Found PostgreSQL {version} on port {port}")
                pg_adapter.port = port
                pg_adapter.version = version
                if pg_adapter.setup():
                    db_url = pg_adapter.get_connection_url()
                    print(f"[*] Database: PostgreSQL at localhost:{port}/cygor")
            else:
                print("[!] No running PostgreSQL instance found.")
                print("[!] Start PostgreSQL first: sudo systemctl start postgresql")
                return 1
        else:
            print("[!] PostgreSQL client not available.")
            return 1

    if not db_url:
        print("[!] No database connection available.")
        return 1

    # Initialize engine
    db.init_engine(db_url, debug=verbose > 1)

    # Confirm with user
    print()
    print("[!] WARNING: This will delete ALL data in the database!")
    confirm = input("Are you sure you want to continue? (yes/no): ").strip().lower()

    if confirm != "yes":
        print("[*] Operation cancelled.")
        return 0

    # Clear the database
    print("[*] Clearing database...")

    try:
        asyncio.run(db.reset_db())
        print("[✓] Database cleared successfully!")
        return 0
    except Exception as e:
        print(f"[!] Error clearing database: {e}")
        return 1


# -----------------------------
#  Web Server Lifecycle
# -----------------------------
def _get_active_workspace() -> Optional[str]:
    """Read the active workspace path from the cygor config file."""
    from cygor.workspace import active_workspace_path
    path = active_workspace_path()
    return str(path) if path else None


def start(host: str, port: int, extra_args: list[str], load_dir: Optional[str],
          clear_db: bool, verbose: int, workspace: Optional[str] = None,
          start_postgres: bool = False) -> int:
    """
    Start the web server in the foreground with PostgreSQL as the primary backend.
    Blocks until stopped with Ctrl+C.
    """
    global PID_FILE, LOG_FILE

    from cygor.workspace import (
        app_data_dir, app_log_dir, resolve_workspace, ensure_workspace_dirs,
        active_workspace_path,
    )

    # --- App data home: cygor's OWN files (pid, logs). Never scan output. ---
    # Same location whether launched in the foreground or as a daemon, so
    # `cygor web stop`/`status` can always find a running server.
    app_data = app_data_dir()
    app_logs = app_log_dir()
    app_data.mkdir(parents=True, exist_ok=True)
    app_logs.mkdir(parents=True, exist_ok=True)
    PID_FILE = app_data / "cygor-web.pid"
    LOG_FILE = app_logs / "cygor-web.log"

    # --- Workspace: where scans are written. User-supplied; may be unset. ---
    # Precedence: --workspace > --load-dir > $CYGOR_WORKSPACE > active workspace.
    # There is no implicit ./results default.
    workspace_path = resolve_workspace(workspace or load_dir)
    if workspace_path is not None:
        ensure_workspace_dirs(workspace_path)
        os.environ["CYGOR_WORKSPACE"] = str(workspace_path)
    else:
        # No workspace configured. The web UI still starts so the user can set
        # one (via the UI or --workspace), but scan-triggering routes refuse to
        # run until a workspace exists.
        os.environ.pop("CYGOR_WORKSPACE", None)
        os.environ.pop("CYGOR_RESULTS_DIR", None)

    # Initialize startup logger
    from cygor.webapp.startup_logger import init_logger, StartupPhase
    log = init_logger(verbose)

    # Startup banner
    log.phase(StartupPhase.INIT)

    workspace_display = (
        str(workspace_path) if workspace_path
        else "(none set - configure one to enable scans)"
    )

    # Print configuration summary
    startup_config = {
        "Host": host,
        "Port": port,
        "Workspace": workspace_display,
        "Verbosity": f"Level {verbose}" if verbose > 0 else "Normal",
    }

    if start_postgres:
        startup_config["PostgreSQL Auto-Start"] = "Enabled"

    log.banner("Cygor Web Server", startup_config)

    log.info(f"Starting Cygor Web on {host}:{port}")
    if workspace_path:
        log.info(f"Results directory: {workspace_path}")
        # Catch the common footgun of `--load-dir .` (or pointing at the wrong
        # directory): a workspace with no scan data renders an empty UI.
        try:
            wp = Path(workspace_path)
            has_data = any((wp / d).is_dir() and any((wp / d).iterdir())
                           for d in ("cygor-enumeration-modules", "nmap", "parsed-hostlists"))
            if not has_data:
                active = active_workspace_path()
                if active and str(active) != str(wp):
                    hint = (f"Your active workspace is {active}. Start without "
                            f"--load-dir, or use --load-dir {active}")
                else:
                    hint = "Run a scan/parse into it, or point --load-dir at a workspace with results"
                log.warning(
                    f"Workspace '{workspace_path}' has no scan results yet - the UI will look empty",
                    hint,
                )
        except Exception:
            pass
    else:
        log.warning(
            "No workspace configured - scans are disabled until one is set",
            "Use --workspace PATH or: cygor workspace init <path> --default",
        )

    # --- Sudo Authentication (automatic at startup) ---
    # This enables scheduled scans and webapp-triggered scans to run with elevated privileges
    # Required for masscan, nmap, naabu which need root access
    sudo_refresh_thread = None
    is_daemon = bool(os.environ.get("CYGOR_DAEMON_MODE"))
    log.divider()
    log.info("Checking scan privileges (sudo access for masscan, nmap, naabu)")

    # Prompt for sudo password
    import getpass
    import threading
    import time as time_module

    def sudo_keepalive(password: str, stop_event: threading.Event):
        """Background thread to keep sudo credentials alive."""
        while not stop_event.is_set():
            try:
                # Refresh sudo timestamp every 4 minutes (default timeout is 5-15 mins)
                subprocess.run(
                    ["sudo", "-S", "-v"],
                    input=f"{password}\n",
                    capture_output=True,
                    text=True,
                    timeout=10
                )
            except Exception:
                pass
            # Wait 4 minutes before next refresh, but check stop_event frequently
            for _ in range(240):  # 240 * 1 second = 4 minutes
                if stop_event.is_set():
                    break
                time_module.sleep(1)

    try:
        # First check if we're already root
        if os.geteuid() == 0:
            log.success("Already running as root - no sudo password needed")
            os.environ["CYGOR_SUDO_VALIDATED"] = "1"
        else:
            # Check if we have passwordless sudo
            test_result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                timeout=5
            )
            if test_result.returncode == 0:
                log.success("Passwordless sudo available - no password needed")
                os.environ["CYGOR_SUDO_VALIDATED"] = "1"
            elif is_daemon:
                # Daemon mode: no terminal available for password prompt
                log.warning("Daemon mode: no terminal for sudo password prompt")
                log.info("Run 'sudo cygor setup-privileges' for permanent configuration")
                log.info("Or authenticate via Settings > Scan Privileges in the web UI")
            else:
                # Need to prompt for password
                print()
                log.info("Elevated privileges are required for network scanning tools.")
                log.info("Enter your sudo password to enable scan privileges, or press Enter to skip.")
                print()
                sudo_password = getpass.getpass("[sudo] password for scan privileges (or Enter to skip): ")

                if sudo_password:
                    # Validate the password works
                    validate_proc = subprocess.run(
                        ["sudo", "-S", "-v"],
                        input=f"{sudo_password}\n",
                        capture_output=True,
                        text=True,
                        timeout=30
                    )

                    if validate_proc.returncode == 0:
                        log.success("Sudo password validated successfully")
                        os.environ["CYGOR_SUDO_VALIDATED"] = "1"

                        # Start background thread to keep sudo credentials alive
                        stop_event = threading.Event()
                        sudo_refresh_thread = threading.Thread(
                            target=sudo_keepalive,
                            args=(sudo_password, stop_event),
                            daemon=True,
                            name="sudo-keepalive"
                        )
                        sudo_refresh_thread.stop_event = stop_event
                        sudo_refresh_thread.start()
                        log.info("Sudo credentials will be kept alive during this session")
                        log.info("Scans will run with elevated privileges automatically")
                    else:
                        log.error("Sudo password validation failed")
                        log.warning("Scans requiring elevated privileges may fail")
                        log.info("You can authenticate later via Settings > Scan Privileges")
                else:
                    log.warning("Skipped sudo authentication")
                    log.info("Scans requiring elevated privileges may fail")
                    log.info("You can authenticate later via Settings > Scan Privileges")
    except subprocess.TimeoutExpired:
        log.error("Sudo validation timed out")
        log.warning("You can authenticate later via Settings > Scan Privileges")
    except KeyboardInterrupt:
        print()
        log.info("Startup cancelled by user")
        return 1
    except Exception as e:
        log.error(f"Sudo authentication error: {e}")
        log.warning("You can authenticate later via Settings > Scan Privileges")

    log.divider()

    # --- PostgreSQL Startup (if requested) ---
    if start_postgres:
        log.phase(StartupPhase.DATABASE)
        log.info("PostgreSQL auto-start requested")
        if start_postgresql_cluster(log, verbose):
            log.success("PostgreSQL cluster is running")
        else:
            log.warning("Could not start PostgreSQL cluster")
            log.info("Continuing with available database backend...")

    # --- Database Setup ---
    if not start_postgres:
        log.phase(StartupPhase.DATABASE)

    from cygor.webapp import db

    # Initialize database using the new DatabaseManager
    if verbose > 0:
        log.info("Initializing database connection")

    # The SQLite fallback DB is cygor's own state (app data), so it lives in
    # the app data dir -- not in the user's scan workspace.
    db_info = db.initialize_database(
        workspace=app_data,
        prefer_postgres=True,
        auto_start_postgres=start_postgres,
        verbose=verbose
    )

    # Log database selection
    if db_info.backend == "postgresql":
        version_str = f" {db_info.version}" if db_info.version and db_info.version.isdigit() else ""
        log.success(f"Using PostgreSQL{version_str}")
        log.info(f"  Host: {db_info.host}:{db_info.port}")
        log.info(f"  Database: {db_info.database}")
        log.info(f"  User: {db_info.user}")
    else:
        log.success("Using SQLite")
        log.info(f"  Database: {db_info.database}")

    # Initialize SQLAlchemy engine with the selected database
    if verbose > 1:
        log.debug("Initializing SQLAlchemy engine")

    db.init_engine(db_info.url, debug=False)

    # Set the database URL in environment so main.py uses the same database
    os.environ["CYGOR_DB_URL"] = db_info.url

    if verbose > 1:
        log.debug(f"Database URL: {db_info.url[:80]}...")

    log.success("Database ready for connections")

    # Note: Schema initialization is handled by main.py's lifespan()
    # We don't initialize here to avoid duplicate logging

    # Print database summary
    log.divider()
    db_summary = {
        "Backend": db_info.backend.upper(),
        "Status": "Connected ✓",
    }

    if db_info.backend == "postgresql":
        db_summary["Version"] = f"PostgreSQL {db_info.version}" if db_info.version else "PostgreSQL"
        db_summary["Host"] = f"{db_info.host}:{db_info.port}"
        db_summary["Database"] = db_info.database
        db_summary["User"] = db_info.user
    else:
        db_summary["Database File"] = db_info.database

    # Print summary
    print(f"\n{'═' * 80}")
    print(f"Database Connection Summary".center(80))
    print(f"{'═' * 80}")
    for key, value in db_summary.items():
        print(f"  {key:20s}: {value}")
    print(f"{'═' * 80}\n")

    # Pause for visibility if verbose
    if verbose > 0:
        import time
        time.sleep(1)

    # Print final startup message
    print()
    print("=" * 80)
    print("Server starting... Press CTRL+C to stop".center(80))
    print("=" * 80)
    print()

    # --- Launch the web server ---
    from cygor.webapp import main as web_main
    # Normalize and sanitize args before passing to FastAPI entrypoint
    argv = [
        "--host", str(host),
        "--port", str(port),
    ]
    if load_dir:
        argv += ["--load-dir", str(load_dir)]

    # Strip out short -H / -p if they were passed; they confuse webapp.main
    argv.extend(a for a in extra_args if a not in ("-H", "-p"))

    # Let uvicorn handle signals directly - don't interfere with its signal handling
    # This ensures clean shutdown on first CTRL+C
    try:
        web_main.exec_argv(argv)
    except KeyboardInterrupt:
        # uvicorn should handle this, but if we catch it, exit cleanly
        print("\n[!] Cygor Web stopped by user")
        sys.exit(0)
    except SystemExit as e:
        # Re-raise SystemExit to allow clean shutdown
        raise
    except Exception as e:
        print(f"[!] Error running web server: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0




def stop() -> int:
    pid = _read_pid()
    daemon_pid_file = None
    if not pid:
        # Check daemon default location
        from cygor.service import PID_FILE as DAEMON_PID
        if DAEMON_PID.exists():
            try:
                pid = int(DAEMON_PID.read_text().strip())
                daemon_pid_file = DAEMON_PID
            except (ValueError, OSError):
                pass
    if not pid:
        print("Cygor Web is not running (no PID file found)")
        return 1
    if not _pid_is_running(pid):
        print(f"Process {pid} is not running (cleaning up PID file)")
        if daemon_pid_file:
            daemon_pid_file.unlink(missing_ok=True)
        else:
            _remove_pidfile()
        return 0
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Sent SIGTERM to Cygor Web (PID {pid})")
    except Exception as e:
        print(f"Error sending SIGTERM to PID {pid}: {e}")
        return 1
    if daemon_pid_file:
        daemon_pid_file.unlink(missing_ok=True)
    else:
        _remove_pidfile()
    return 0


def status() -> int:
    pid = _read_pid()
    log_path = None
    try:
        log_path = LOG_FILE if pid else None
    except NameError:
        pass
    if not pid:
        # Check daemon default location
        from cygor.service import PID_FILE as DAEMON_PID, LOG_FILE as DAEMON_LOG
        if DAEMON_PID.exists():
            try:
                pid = int(DAEMON_PID.read_text().strip())
                log_path = DAEMON_LOG
            except (ValueError, OSError):
                pass
    if pid and _pid_is_running(pid):
        print(f"Cygor Web running (PID {pid})")
        if log_path:
            print(f"Logs: {log_path}")
        return 0
    print("Cygor Web not running")
    return 1


def exec_argv(argv: list[str]) -> None:
    """
    Entry point used by cygor.cli to delegate `cygor web ...`.
    """
    parser = argparse.ArgumentParser(
        prog="cygor web",
        description="Manage the Cygor web interface server",
        epilog="""
Commands:
  start    Start the web server (foreground)
  stop     Stop a running web server
  status   Check if the web server is running

Examples:
  # Start the web server
  cygor web start

  # Start with authentication on port 8080
  cygor web start --auth-login -p 8080

  # Check server status
  cygor web status

  # Stop the server
  cygor web stop

For more information on a specific command, use:
  cygor web <command> --help
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="cmd", metavar="COMMAND")

    # --- start ---
    p_start = sub.add_parser(
        "start",
        help="Start the Cygor web server",
        description="Start the Cygor web interface server. The server will run in the foreground until stopped with Ctrl+C.",
        epilog="""
Examples:
  # Start on default host/port (127.0.0.1:8000)
  cygor web start

  # Start on all interfaces, port 8080
  cygor web start -H 0.0.0.0 -p 8080

  # Start with authentication enabled
  cygor web start --auth-login

  # Start with HTTPS enabled (auto-generates self-signed certificate)
  cygor web start --use-https

  # Start with HTTPS and authentication
  cygor web start --use-https --auth-login -p 8443

  # Start with custom results directory
  cygor web start --load-dir /path/to/nmap/results

  # Start with PostgreSQL database
  cygor web start --db-url postgresql+psycopg_async://user:pass@localhost/cygor

  # Start with debug mode and verbose output
  cygor web start --debug -vv

  # Clear database (standalone operation, exits after clearing)
  cygor web start --clear-db

  # Production setup with HTTPS and authentication
  cygor web start -H 0.0.0.0 -p 8443 --use-https --auth-login --load-dir ~/scan-results
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Network options
    network_group = p_start.add_argument_group("Network Options")
    network_group.add_argument(
        "-H", "--host",
        default="127.0.0.1",
        metavar="HOST",
        help="Host address to bind to (default: 127.0.0.1). Use 0.0.0.0 to bind to all interfaces."
    )
    network_group.add_argument(
        "-p", "--port",
        type=int,
        default=8000,
        metavar="PORT",
        help="Port number to bind to (default: 8000)"
    )
    
    # Data options
    data_group = p_start.add_argument_group("Data Options")
    data_group.add_argument(
        "--load-dir",
        type=str,
        metavar="PATH",
        help="Preload results from a directory containing nmap XML files. This directory will be scanned and ingested into the database on startup."
    )
    data_group.add_argument(
        "--workspace",
        type=str,
        metavar="PATH",
        help="Set the workspace/results directory (overrides CYGOR_WORKSPACE environment variable)"
    )
    data_group.add_argument(
        "--results-dir",
        type=str,
        metavar="PATH",
        dest="workspace",  # Use same destination as --workspace
        help="Alias for --workspace. Set the results directory path."
    )
    
    # Database options
    db_group = p_start.add_argument_group("Database Options")
    db_group.add_argument(
        "--db-url",
        type=str,
        metavar="URL",
        help="Database connection URL (e.g., postgresql+psycopg_async://user:pass@localhost/cygor or sqlite+aiosqlite:///path/to/db.db). Overrides CYGOR_DB_URL environment variable."
    )
    db_group.add_argument(
        "--db-user",
        type=str,
        metavar="USER",
        help="PostgreSQL database user (default: cygor). Overrides CYGOR_DB_USER environment variable."
    )
    db_group.add_argument(
        "--db-password",
        type=str,
        metavar="PASSWORD",
        help="PostgreSQL database password. Overrides CYGOR_DB_PASSWORD environment variable."
    )
    db_group.add_argument(
        "--db-port",
        type=str,
        metavar="PORT",
        help="PostgreSQL database port (default: 5432). Overrides CYGOR_DB_PORT environment variable."
    )
    db_group.add_argument(
        "--db-backend",
        type=str,
        choices=["postgresql", "sqlite", "mssql", "mysql", "oracle"],
        metavar="BACKEND",
        help="Database backend: postgresql, sqlite, mssql, mysql, oracle. Auto-detected if omitted."
    )
    db_group.add_argument(
        "--db-host",
        type=str,
        metavar="HOST",
        help="Database server hostname (default: localhost). Overrides CYGOR_DB_HOST."
    )
    db_group.add_argument(
        "--db-name",
        type=str,
        metavar="NAME",
        help="Database name (default: cygor). Overrides CYGOR_DB_NAME."
    )
    db_group.add_argument(
        "--db-ssl-mode",
        type=str,
        choices=["disable", "require", "verify-ca", "verify-full"],
        metavar="MODE",
        help="Database SSL mode: disable, require, verify-ca, verify-full."
    )
    db_group.add_argument(
        "--db-ssl-ca",
        type=str,
        metavar="PATH",
        help="Path to CA certificate for database SSL."
    )
    db_group.add_argument(
        "--db-service-name",
        type=str,
        metavar="NAME",
        help="Oracle service name (only needed for Oracle backend)."
    )
    db_group.add_argument(
        "--clear-db",
        action="store_true",
        help="Clear the database and exit (does not start the web server). Prompts for confirmation before deleting all data."
    )
    db_group.add_argument(
        "--cleanup-db",
        action="store_true",
        help="Drop the PostgreSQL database and user after shutdown (default: keep data persistent)"
    )
    db_group.add_argument(
        "-y", "--yes",
        action="store_true",
        help="Automatic yes to cleanup prompts (useful for non-interactive/scripted use)"
    )
    db_group.add_argument(
        "--use-sudo-cleanup",
        action="store_true",
        help="Use sudo for privileged PostgreSQL cleanup operations (requires NOPASSWD psql access in sudoers)"
    )
    db_group.add_argument(
        "--start-postgres",
        action="store_true",
        help="Automatically start PostgreSQL cluster if not running (requires sudo password)"
    )

    # Security options
    security_group = p_start.add_argument_group("Security Options")
    security_group.add_argument(
        "--auth-login",
        action="store_true",
        help="Enable authentication/login functionality. When enabled, users must log in with a token to access the web interface. An access token will be generated and displayed on first startup."
    )
    security_group.add_argument(
        "--use-https",
        action="store_true",
        help="Enable HTTPS with SSL/TLS encryption. A self-signed certificate will be auto-generated if no custom certificate is configured. Uses TLS 1.2+ (TLS 1.3 preferred)."
    )
    
    # Debug/Verbose options
    debug_group = p_start.add_argument_group("Debug Options")
    debug_group.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity level. Use -v for more output, -vv for debug details, -vvv for trace-level logging."
    )
    debug_group.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug mode (equivalent to CYGOR_DEBUG=1). Enables detailed error messages and debug logging."
    )

    # Service/daemon options
    daemon_group = p_start.add_argument_group("Daemon Options")
    daemon_group.add_argument(
        "-d", "--daemon",
        action="store_true",
        help="Run the web server as a background daemon. Forks to background and detaches from terminal. Logs to ~/.cygor/logs/ (or /var/log/cygor/ as root). Stop with 'cygor web stop'."
    )

    # --- stop ---
    p_stop = sub.add_parser(
        "stop",
        help="Stop a running web server",
        description="Stop the Cygor web server by sending a SIGTERM signal to the running process.",
        epilog="""
Examples:
  # Stop the web server
  cygor web stop

Note: This command looks for a PID file in the results directory to determine
which process to stop. If the server was started with --load-dir, the PID file
will be in that directory.
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # --- status ---
    p_status = sub.add_parser(
        "status",
        help="Check if the web server is running",
        description="Check the status of the Cygor web server by verifying if the process is running.",
        epilog="""
Examples:
  # Check server status
  cygor web status

The command will display:
  - Whether the server is running
  - The process ID (PID) if running
  - The log file location
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # --- install-service ---
    p_install = sub.add_parser(
        "install-service",
        help="Install Cygor as a systemd service",
        description="Generate and install a systemd service unit for Cygor web server. Requires root.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p_install.add_argument("--user", default="root", help="User to run the service as (default: root)")
    p_install.add_argument("-H", "--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    p_install.add_argument("-p", "--port", type=int, default=8443, help="Bind port (default: 8443)")
    p_install.add_argument("--auth-login", action="store_true", help="Enable authentication")
    p_install.add_argument("--use-https", action="store_true", help="Enable HTTPS")
    p_install.add_argument("--start-postgres", action="store_true", help="Auto-start PostgreSQL")
    p_install.add_argument("--db-url", type=str, help="Database connection URL")
    p_install.add_argument("--load-dir", type=str, help="Results directory to preload")

    # --- uninstall-service ---
    p_uninstall = sub.add_parser(
        "uninstall-service",
        help="Remove Cygor systemd service",
        description="Stop, disable, and remove the Cygor systemd service unit. Requires root.",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p_uninstall.add_argument("--purge", action="store_true", help="Also remove data and log directories")

    # --- db ---
    p_db = sub.add_parser(
        "db",
        help="Database management commands",
        description="Manage the Cygor database (status, backup, restore).",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    db_sub = p_db.add_subparsers(dest="db_cmd", metavar="COMMAND")

    db_sub.add_parser("status", help="Show current database connection info")

    p_db_backup = db_sub.add_parser("backup", help="Export database to file")
    p_db_backup.add_argument("--format", choices=["json", "sql"], default="json", help="Export format")
    p_db_backup.add_argument("--output", "-o", required=True, help="Output file path")

    p_db_restore = db_sub.add_parser("restore", help="Import database from backup")
    p_db_restore.add_argument("--input", "-i", help="Input file path")
    p_db_restore.add_argument("--list", action="store_true", dest="list_snapshots", help="List available snapshots")
    p_db_restore.add_argument("--snapshot", type=int, help="Restore specific snapshot by number")

    # ---- Handle default behavior ----
    if not argv:
        parser.print_help()
        sys.exit(0)

    # If the user only supplied options (e.g. `-H 0.0.0.0 -p 8080`), assume they meant `start`
    if argv[0] not in {"start", "stop", "status", "install-service", "uninstall-service", "db"} and not argv[0].startswith("-"):
        print(f"Unknown command: {argv[0]}")
        parser.print_help()
        sys.exit(1)
    elif argv[0].startswith("-"):
        argv = ["start", *argv]

    args, unknown = parser.parse_known_args(argv)

    # --- Dispatch ---
    if args.cmd == "start":
        # Handle --clear-db first (standalone operation, no server start)
        if args.clear_db:
            # Set environment variables from command-line arguments for database connection
            if args.db_url:
                os.environ["CYGOR_DB_URL"] = args.db_url
            if args.db_user:
                os.environ["CYGOR_DB_USER"] = args.db_user
            if args.db_password:
                os.environ["CYGOR_DB_PASSWORD"] = args.db_password
            if hasattr(args, 'db_port') and args.db_port:
                os.environ["CYGOR_DB_PORT"] = args.db_port
            if args.workspace:
                os.environ["CYGOR_WORKSPACE"] = args.workspace
            sys.exit(clear_database(args.workspace, args.verbose))

        # Set environment variables from command-line arguments
        if args.db_url:
            os.environ["CYGOR_DB_URL"] = args.db_url
        if args.db_user:
            os.environ["CYGOR_DB_USER"] = args.db_user
        if args.db_password:
            os.environ["CYGOR_DB_PASSWORD"] = args.db_password
        if hasattr(args, 'db_port') and args.db_port:
            os.environ["CYGOR_DB_PORT"] = args.db_port
        if args.workspace:
            os.environ["CYGOR_WORKSPACE"] = args.workspace
        if args.debug:
            os.environ["CYGOR_DEBUG"] = "1"
        if args.use_sudo_cleanup:
            os.environ["CYGOR_USE_SUDO_CLEANUP"] = "1"
        if args.auth_login:
            os.environ["CYGOR_AUTH_LOGIN"] = "1"
        if hasattr(args, 'db_backend') and args.db_backend:
            os.environ["CYGOR_DB_BACKEND"] = args.db_backend
        if hasattr(args, 'db_host') and args.db_host:
            os.environ["CYGOR_DB_HOST"] = args.db_host
        if hasattr(args, 'db_name') and args.db_name:
            os.environ["CYGOR_DB_NAME"] = args.db_name
        if hasattr(args, 'db_ssl_mode') and args.db_ssl_mode:
            os.environ["CYGOR_DB_SSL_MODE"] = args.db_ssl_mode
        if hasattr(args, 'db_ssl_ca') and args.db_ssl_ca:
            os.environ["CYGOR_DB_SSL_CA"] = args.db_ssl_ca
        if hasattr(args, 'db_service_name') and args.db_service_name:
            os.environ["CYGOR_DB_SERVICE_NAME"] = args.db_service_name

        # Set verbose level
        if args.verbose:
            os.environ["CYGOR_VERBOSE"] = str(args.verbose)
        
        passthrough = []
        if args.verbose:
            passthrough.extend(["-" + "v" * args.verbose])
        if args.cleanup_db:
            passthrough.append("--cleanup-db")
        if args.yes:
            passthrough.append("--yes")
        if args.auth_login:
            passthrough.append("--auth-login")
        if args.use_https:
            passthrough.append("--use-https")
        if args.debug:
            passthrough.append("--debug")

        # Filter out --start-postgres from unknown args (handled by webctl, not webapp)
        filtered_unknown = [arg for arg in unknown if arg not in ("--start-postgres",)]
        passthrough.extend(filtered_unknown)

        # Handle daemon mode
        if args.daemon:
            os.environ["CYGOR_DAEMON_MODE"] = "1"
            from cygor.service import daemonize
            daemonize()
            # After daemonize(), only the child process reaches here

        sys.exit(start(
            args.host,
            args.port,
            passthrough,
            args.load_dir,
            False,  # clear_db is now handled separately as standalone operation
            args.verbose,
            args.workspace,
            args.start_postgres
        ))

    elif args.cmd == "stop":
        sys.exit(stop())

    elif args.cmd == "status":
        sys.exit(status())

    elif args.cmd == "install-service":
        from cygor.service import install_service
        extra = []
        if args.auth_login:
            extra.append("--auth-login")
        if args.use_https:
            extra.append("--use-https")
        if args.start_postgres:
            extra.append("--start-postgres")
        if args.db_url:
            extra.extend(["--db-url", args.db_url])
        if args.load_dir:
            extra.extend(["--load-dir", args.load_dir])
        sys.exit(install_service(
            user=args.user,
            host=args.host,
            port=args.port,
            extra_flags=extra if extra else None,
        ))

    elif args.cmd == "uninstall-service":
        from cygor.service import uninstall_service
        sys.exit(uninstall_service(purge=args.purge))

    elif args.cmd == "db":
        if not args.db_cmd or args.db_cmd == "status":
            from cygor.webapp.db_adapters import DatabaseManager
            manager = DatabaseManager()
            config = manager._load_db_config()
            if config:
                print(f"[*] Backend: {config.get('backend', 'auto')}")
                print(f"[*] Host: {config.get('host', 'localhost')}")
                print(f"[*] Port: {config.get('port', 'default')}")
                print(f"[*] Database: {config.get('database', 'cygor')}")
                print(f"[*] SSL Mode: {config.get('ssl_mode', 'disable')}")
            else:
                print("[*] No saved database configuration. Using auto-detection.")
                print("[*] Start with --db-backend to configure a specific backend.")
            sys.exit(0)
        elif args.db_cmd == "backup":
            print(f"[*] Backup to {args.output} (format: {args.format}) — not yet implemented")
            sys.exit(1)
        elif args.db_cmd == "restore":
            if hasattr(args, 'list_snapshots') and args.list_snapshots:
                print("[*] Listing snapshots — not yet implemented")
            else:
                print("[*] Restore — not yet implemented")
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(0)


