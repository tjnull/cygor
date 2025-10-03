# cygor/webctl.py
"""
Cygor Web server controller: start/stop/status.

Usage:
  cygor web start [-v] [-H HOST] [-p PORT] [--reset-db] [--load-dir PATH]
  cygor web stop
  cygor web status

Notes:
- Default `start` runs the server in the background and returns to your terminal.
- `-v/--verbose` starts in the foreground with live debug output (no background).
"""
from __future__ import annotations
import argparse
import os
import signal
import sys
from pathlib import Path
from typing import Optional


# These will be set dynamically based on --load-dir
PID_FILE: Path
LOG_FILE: Path


def _pid_is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but not owned by us
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


def start(host: str, port: int, extra_args: list[str], load_dir: Optional[str]) -> int:
    """
    Start the web server in the foreground with logs attached.
    Blocks until stopped with Ctrl+C.
    """
    global PID_FILE, LOG_FILE

    # Ensure results/load_dir exists
    if load_dir:
        base_path = Path(load_dir)
    else:
        base_path = Path("results")

    base_path.mkdir(parents=True, exist_ok=True)
    PID_FILE = base_path / "cygor-web.pid"
    LOG_FILE = base_path / "cygor-web.log"

    print(f"[*] Starting Cygor Web on {host}:{port}")
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

    # Try graceful shutdown
    try:
        os.kill(pid, signal.SIGTERM)
        print(f"Sent SIGTERM to Cygor Web (PID {pid})")
    except Exception as e:
        print(f"Error sending SIGTERM to PID {pid}: {e}")
        return 1

    # Best-effort cleanup; don't block indefinitely
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
    p_start.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v shows more, -vv shows debug details)"
    )

    # --- stop / status ---
    sub.add_parser("stop", help="Stop the web server")
    sub.add_parser("status", help="Show server status")

    # Shorthand: if no subcommand but args exist, assume "start"
    if argv and not argv[0] in {"start", "stop", "status"}:
        argv = ["start", *argv]

    # Parse known args, keep unknown ones to pass through
    args, unknown = parser.parse_known_args(argv)

    if args.cmd == "start":
        passthrough = []
        if args.reset_db:
            passthrough.append("--reset-db")
        if args.verbose:
            passthrough.extend(["-" + "v" * args.verbose])
        passthrough.extend(unknown)  # ✅ forward unknown args directly

        sys.exit(start(args.host, args.port, passthrough, load_dir=args.load_dir))
    elif args.cmd == "stop":
        sys.exit(stop())
    elif args.cmd == "status":
        sys.exit(status())
    else:
        parser.print_help()

