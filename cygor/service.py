# cygor/service.py
"""
Daemon and systemd service management for Cygor web server.
"""
from __future__ import annotations
import os
import sys
import signal
from pathlib import Path

# Resolve daemon paths based on effective user (root vs. regular user).
# These are cygor's OWN application files (pid, logs) -- not scan output.
def _resolve_paths():
    from cygor.workspace import app_data_dir, app_log_dir
    data_dir = app_data_dir()   # root -> /var/lib/cygor, else ~/.cygor
    log_dir = app_log_dir()     # root -> /var/log/cygor, else ~/.cygor/logs
    return data_dir, log_dir, log_dir / "cygor-web.log", data_dir / "cygor-web.pid"


DATA_DIR, LOG_DIR, LOG_FILE, PID_FILE = _resolve_paths()
SERVICE_FILE = Path("/etc/systemd/system/cygor.service")


def daemonize(pid_file: Path = PID_FILE, log_file: Path = LOG_FILE) -> None:
    """
    Double-fork the current process to run as a background daemon.

    Uses the standard Unix double-fork pattern:
    1. First fork  — parent prints PID info and exits
    2. setsid()    — child becomes session leader, detaches from terminal
    3. Second fork — grandchild can never reacquire a controlling terminal
    4. Redirect file descriptors and replace Python streams
    5. Write PID file and register cleanup
    """
    # Ensure directories exist
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    log_file.parent.mkdir(parents=True, exist_ok=True)

    # Flush Python buffers before forking (prevent duplicate output)
    sys.stdout.flush()
    sys.stderr.flush()

    # First fork — parent prints info and exits
    try:
        pid = os.fork()
    except OSError as e:
        print(f"[!] Failed to fork daemon process: {e}", file=sys.stderr)
        sys.exit(1)
    if pid > 0:
        # Parent: print info and exit
        # Note: actual daemon PID (after double-fork) is written to pid_file
        print(f"[*] Cygor Web starting in background...")
        print(f"[*] Logs: {log_file}")
        print(f"[*] PID file: {pid_file}")
        print(f"[*] Stop with: cygor web stop")
        print(f"[*] Status: cygor web status")
        os._exit(0)  # Use os._exit to avoid flushing buffers / running atexit

    # First child: create new session, detach from controlling terminal
    os.setsid()
    os.umask(0o022)

    # Second fork — prevent daemon from ever acquiring a controlling terminal
    try:
        pid = os.fork()
    except OSError:
        os._exit(1)
    if pid > 0:
        os._exit(0)  # First child exits; grandchild is the actual daemon

    # --- Grandchild (actual daemon) continues here ---

    # Redirect file descriptors using os.open (avoids Python file object issues)
    devnull_fd = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull_fd, 0)  # stdin  <- /dev/null
    os.close(devnull_fd)

    log_fd = os.open(str(log_file), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(log_fd, 1)  # stdout -> log file
    os.dup2(log_fd, 2)  # stderr -> log file
    os.close(log_fd)

    # Replace Python stream objects so print()/logging work correctly
    sys.stdin = open(0, "r")
    sys.stdout = open(1, "w", buffering=1)   # line-buffered for log readability
    sys.stderr = open(2, "w", buffering=1)

    # Write PID file
    pid_file.write_text(str(os.getpid()))

    # Register cleanup on exit
    import atexit
    atexit.register(_cleanup_pidfile, pid_file)

    # Handle SIGTERM for clean shutdown
    def _handle_term(signum, frame):
        sys.exit(0)
    signal.signal(signal.SIGTERM, _handle_term)


def _cleanup_pidfile(pid_file: Path) -> None:
    """Remove PID file on exit."""
    try:
        pid_file.unlink(missing_ok=True)
    except Exception:
        pass


UNIT_TEMPLATE = """\
[Unit]
Description=Cygor Security Scanner Web UI
After=network.target postgresql.service
Documentation=https://github.com/tjnull/cygor

[Service]
Type=simple
User={user}
Group={group}
WorkingDirectory={data_dir}
ExecStart={cygor_bin} web start --host {host} --port {port}{extra_flags}
Restart=on-failure
RestartSec=5
StandardOutput=append:{log_file}
StandardError=append:{log_file}
Environment=CYGOR_WORKSPACE={data_dir}

[Install]
WantedBy=multi-user.target
"""


def _find_cygor_binary() -> str:
    """Find the cygor binary path."""
    import shutil
    # Check if running from installed binary
    cygor_path = shutil.which("cygor")
    if cygor_path:
        return cygor_path
    # Fall back to running as a module
    return f"{sys.executable} -m cygor"


def _run_systemctl(*args: str) -> int:
    """Run a systemctl command, return exit code."""
    import subprocess
    result = subprocess.run(["systemctl", *args], capture_output=True, text=True)
    if result.returncode != 0 and result.stderr:
        print(f"[!] systemctl {' '.join(args)}: {result.stderr.strip()}")
    return result.returncode


def install_service(
    user: str = "root",
    host: str = "0.0.0.0",
    port: int = 8443,
    extra_flags: list[str] | None = None,
) -> int:
    """Generate and install a systemd service for Cygor."""
    if os.geteuid() != 0:
        print("[!] install-service requires root. Run with sudo.")
        return 1

    # Resolve group from user
    import grp
    import pwd
    try:
        pw = pwd.getpwnam(user)
        group = grp.getgrgid(pw.pw_gid).gr_name
    except KeyError:
        print(f"[!] User '{user}' does not exist")
        return 1

    # Create directories
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    os.chown(DATA_DIR, pw.pw_uid, pw.pw_gid)
    os.chown(LOG_DIR, pw.pw_uid, pw.pw_gid)

    cygor_bin = _find_cygor_binary()
    if extra_flags:
        for f in extra_flags:
            if "%" in f or "\n" in f:
                print(f"[!] Invalid character in flag: {f!r}")
                return 1
        flags_str = " " + " ".join(extra_flags)
    else:
        flags_str = ""

    # Generate unit file
    unit_content = UNIT_TEMPLATE.format(
        user=user,
        group=group,
        data_dir=DATA_DIR,
        cygor_bin=cygor_bin,
        host=host,
        port=port,
        extra_flags=flags_str,
        log_file=LOG_FILE,
    )

    SERVICE_FILE.write_text(unit_content)
    print(f"[*] Service file written to {SERVICE_FILE}")

    # Reload and enable
    if _run_systemctl("daemon-reload") != 0:
        print("[!] Failed to reload systemd")
        return 1

    if _run_systemctl("enable", "--now", "cygor") != 0:
        print("[!] Failed to enable/start cygor service")
        return 1

    print("[*] Cygor service installed and started")
    print(f"[*] Data directory: {DATA_DIR}")
    print(f"[*] Log file: {LOG_FILE}")
    print()
    print("  Manage with:")
    print("    systemctl status cygor")
    print("    systemctl stop cygor")
    print("    systemctl restart cygor")
    print("    journalctl -u cygor -f")
    return 0


def uninstall_service(purge: bool = False) -> int:
    """Stop, disable, and remove the Cygor systemd service."""
    if os.geteuid() != 0:
        print("[!] uninstall-service requires root. Run with sudo.")
        return 1

    if not SERVICE_FILE.exists():
        print("[!] Cygor service is not installed")
        return 1

    _run_systemctl("stop", "cygor")
    _run_systemctl("disable", "cygor")
    SERVICE_FILE.unlink(missing_ok=True)
    _run_systemctl("daemon-reload")
    print("[*] Cygor service removed")

    if purge:
        import shutil
        if DATA_DIR.exists():
            shutil.rmtree(DATA_DIR)
            print(f"[*] Removed {DATA_DIR}")
        if LOG_DIR.exists():
            shutil.rmtree(LOG_DIR)
            print(f"[*] Removed {LOG_DIR}")

    return 0
