import argparse
import json
import os
import sys
import datetime
import shutil
from pathlib import Path
from typing import Optional

try:
    from colorama import Fore, Style
except Exception:  # colorama is a runtime dep but be defensive in test envs
    class _Stub:
        def __getattr__(self, _): return ""
    Fore = Style = _Stub()

APP_NAME = "cygor"
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"

# msfconsole-style "where do workspaces live by default". Overrideable per host
# via $CYGOR_WORKSPACES_ROOT; mirrors how msfconsole keeps everything under
# ~/.msf4/. 'cygor workspace -a NAME' creates <root>/<name>/ unless --path is
# passed to point somewhere else (shared drives, large engagement folders).
DEFAULT_WORKSPACES_ROOT = Path.home() / ".cygor" / "workspaces"

# Name of the workspace auto-created when the registry is empty. Mirrors
# msfconsole's 'default' -- there is always exactly one active workspace,
# never a "free mode" with nowhere to write output.
DEFAULT_WORKSPACE_NAME = "default"


def workspaces_root() -> Path:
    """Where new `-a NAME` workspaces are created. Env var wins; otherwise
    DEFAULT_WORKSPACES_ROOT. Always resolved + expanded."""
    env = os.environ.get("CYGOR_WORKSPACES_ROOT")
    base = Path(env).expanduser() if env else DEFAULT_WORKSPACES_ROOT
    return base.resolve() if base.exists() else base

# ----------------------------------------------------------------------
# Final, minimal workspace layout
# ----------------------------------------------------------------------
SUBDIRS = [
    "nmap",
    "parsed-hostlists",
    "credrecon",
    "schedule-scans",
    "cygor-enumeration-modules",
    "logs",
]

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            pass
    return {}

def _save_config(cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def _resolve_path(p: str) -> Path:
    return Path(os.path.expanduser(p)).resolve()

def _migrate_old_config(cfg: dict) -> dict:
    """Migrate old config format (single default_workspace) to new format."""
    if "workspaces" in cfg:
        return cfg  # Already migrated
    
    # Check for old format
    if "default_workspace" in cfg and isinstance(cfg.get("default_workspace"), str):
        old_path = cfg["default_workspace"]
        ws_path = _resolve_path(old_path)
        
        if ws_path.exists() and _validate_workspace(ws_path):
            # Generate a name from the path
            ws_name = ws_path.name or "default"
            # Ensure unique name
            base_name = ws_name
            counter = 1
            while ws_name in cfg.get("workspaces", {}):
                ws_name = f"{base_name}-{counter}"
                counter += 1
            
            # Create new structure
            cfg["workspaces"] = {
                ws_name: {
                    "path": str(ws_path),
                    "created_at": _get_workspace_metadata(ws_path).get("created_at", datetime.datetime.utcnow().isoformat() + "Z"),
                    "last_used": datetime.datetime.utcnow().isoformat() + "Z",
                }
            }
            cfg["default_workspace"] = ws_name
            cfg["active_workspace"] = ws_name
            # Keep old key for backward compatibility temporarily
        else:
            # Invalid workspace, remove it
            cfg.pop("default_workspace", None)
            cfg["workspaces"] = {}
    
    if "workspaces" not in cfg:
        cfg["workspaces"] = {}
    
    if "active_workspace" not in cfg:
        cfg["active_workspace"] = cfg.get("default_workspace")
    
    return cfg

def _validate_workspace(path: Path) -> bool:
    """Check if path is a valid workspace (has .cygor-workspace.json)."""
    if not path.exists() or not path.is_dir():
        return False
    meta_file = path / ".cygor-workspace.json"
    return meta_file.exists()

def _get_workspace_metadata(path: Path) -> dict:
    """Read workspace metadata from .cygor-workspace.json."""
    meta_file = path / ".cygor-workspace.json"
    if meta_file.exists():
        try:
            return json.loads(meta_file.read_text())
        except Exception:
            pass
    return {}

def _get_workspace_by_name_or_path(name_or_path: str, cfg: dict = None) -> tuple[str, dict] | None:
    """Find workspace by name or path. Returns (name, workspace_dict) or None."""
    if cfg is None:
        cfg = _load_config()
        cfg = _migrate_old_config(cfg)
    
    workspaces = cfg.get("workspaces", {})
    
    # First try by name
    if name_or_path in workspaces:
        return (name_or_path, workspaces[name_or_path])
    
    # Try by path
    resolved_path = str(_resolve_path(name_or_path))
    for name, ws_data in workspaces.items():
        if str(_resolve_path(ws_data.get("path", ""))) == resolved_path:
            return (name, ws_data)
    
    return None

def _get_workspace_size(path: Path) -> int:
    """Calculate total size of workspace directory in bytes."""
    total = 0
    try:
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total += os.path.getsize(fp)
                except (OSError, FileNotFoundError):
                    pass
    except Exception:
        pass
    return total

def _format_size(size_bytes: int) -> str:
    """Format bytes to human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"

def _path_size(p: Path) -> int:
    """Size in bytes of a file or directory."""
    if p.is_file():
        try:
            return p.stat().st_size
        except OSError:
            return 0
    return _get_workspace_size(p)

def _update_last_used(name: str, cfg: dict = None) -> None:
    """Update last_used timestamp for a workspace."""
    if cfg is None:
        cfg = _load_config()
        cfg = _migrate_old_config(cfg)
    
    if name in cfg.get("workspaces", {}):
        cfg["workspaces"][name]["last_used"] = datetime.datetime.utcnow().isoformat() + "Z"
        _save_config(cfg)


def _set_active(cfg: dict, name: str) -> None:
    """Mark *name* as the active workspace.

    'active' is the single source of truth; the legacy 'default_workspace' key
    is dropped on write so the two can never drift.
    """
    cfg["active_workspace"] = name
    cfg.pop("default_workspace", None)


def _register_workspace(cfg: dict, ws_path: Path, name: str = None,
                        description: str = None) -> str:
    """Add a workspace to the registry (no activation). Returns its unique name."""
    if "workspaces" not in cfg:
        cfg["workspaces"] = {}

    ws_name = name if name else (ws_path.name or "workspace")
    base_name = ws_name
    counter = 1
    while ws_name in cfg["workspaces"]:
        ws_name = f"{base_name}-{counter}"
        counter += 1

    created = _get_workspace_metadata(ws_path).get(
        "created_at", datetime.datetime.utcnow().isoformat() + "Z"
    )
    entry = {
        "path": str(ws_path),
        "created_at": created,
        "last_used": datetime.datetime.utcnow().isoformat() + "Z",
    }
    if description:
        entry["description"] = description
    cfg["workspaces"][ws_name] = entry
    return ws_name

# ----------------------------------------------------------------------
# Application data home (cygor's OWN files: config, db, snapshots, daemon
# state). This is NOT where user scan output goes. Scan output lives in a
# workspace the user chooses (see resolve_workspace / require_workspace).
# ----------------------------------------------------------------------
def app_data_dir() -> Path:
    """Cygor's application data directory.

    Root (system service) -> /var/lib/cygor; otherwise ~/.cygor.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/lib/cygor")
    return Path.home() / ".cygor"


def app_log_dir() -> Path:
    """Cygor's log directory.

    Root (system service) -> /var/log/cygor; otherwise ~/.cygor/logs.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/log/cygor")
    return app_data_dir() / "logs"


# ----------------------------------------------------------------------
# Workspace resolution (single source of truth for "where do scans go").
#
# There is intentionally NO implicit default such as ./results. Output must
# be chosen by the user via -o/--workspace, $CYGOR_WORKSPACE, or an active
# workspace registered with `cygor workspace`.
# ----------------------------------------------------------------------
NO_WORKSPACE_MESSAGE = (
    "No workspace available.\n"
    "  Cygor normally auto-creates a 'default' workspace on first use, but the\n"
    "  auto-create just failed (read-only home directory, full disk, or similar).\n"
    "  Either fix that, or work around it:\n"
    "    - pass an explicit output directory:  -o /path/to/workspace\n"
    "    - or export CYGOR_WORKSPACE=/path/to/workspace"
)


def active_workspace_path() -> Optional[Path]:
    """Path of the active workspace from config.

    msfconsole-style invariant: there is *always* an active workspace. If the
    registry is empty, the 'default' workspace is auto-created at the
    workspaces root and activated -- so every cygor tool always has somewhere
    to write output (no "free mode", no None returns).

    The only situation where this still returns None is if the auto-create
    itself failed (e.g. read-only home directory). Callers should still
    handle the None case defensively.
    """
    cfg = _migrate_old_config(_load_config())
    active = cfg.get("active_workspace")
    workspaces = cfg.get("workspaces", {})

    if active and active in workspaces:
        entry = workspaces[active]
        if entry.get("path"):
            return Path(entry["path"])

    # Registry empty (or active pointer dangling) -> auto-create 'default'.
    # This is the msf invariant: there is always exactly one active workspace.
    if not workspaces:
        try:
            ws_path = workspaces_root() / DEFAULT_WORKSPACE_NAME
            ensure_workspace_dirs(ws_path)
            _register_workspace(cfg, ws_path, name=DEFAULT_WORKSPACE_NAME)
            _set_active(cfg, DEFAULT_WORKSPACE_NAME)
            _save_config(cfg)
            return ws_path
        except Exception:
            # Read-only home, full disk, etc. Don't crash the rest of cygor
            # -- the caller's NO_WORKSPACE_MESSAGE will still fire if needed.
            return None

    return None


def resolve_workspace(explicit: Optional[str] = None, *, use_env: bool = True) -> Optional[Path]:
    """Resolve the scan output / workspace directory, or None when unset.

    Precedence:
      1. explicit argument (e.g. -o/--workspace/--out-dir)
      2. $CYGOR_WORKSPACE / $CYGOR_RESULTS_DIR  (when use_env)
      3. active workspace from `cygor workspace` config
    """
    if explicit:
        return _resolve_path(explicit)
    if use_env:
        env = workspace_env()
        if env:
            return _resolve_path(env)
    return active_workspace_path()


def workspace_env() -> Optional[str]:
    """Return the workspace path from the environment, or None.

    CYGOR_WORKSPACE is canonical; CYGOR_RESULTS_DIR is honored as a deprecated
    back-compat alias.
    """
    return os.environ.get("CYGOR_WORKSPACE") or os.environ.get("CYGOR_RESULTS_DIR")


def ensure_workspace_dirs(path: Path) -> Path:
    """Create the standard workspace layout (idempotent) and return the path."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    for rel in SUBDIRS:
        base = path / rel
        base.mkdir(parents=True, exist_ok=True)
        if rel == "cygor-enumeration-modules":
            for module in ("lockon", "smbexplorer", "nfsexplorer"):
                (base / module).mkdir(parents=True, exist_ok=True)
    meta_file = path / ".cygor-workspace.json"
    if not meta_file.exists():
        meta_file.write_text(json.dumps({
            "workspace": str(path),
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "schema": 3,
        }, indent=2))
    return path


def require_workspace(explicit: Optional[str] = None, *, use_env: bool = True,
                      create: bool = True) -> Path:
    """Resolve the workspace, or print guidance and exit(2) if none is set."""
    ws = resolve_workspace(explicit, use_env=use_env)
    if ws is None:
        print(NO_WORKSPACE_MESSAGE, file=sys.stderr)
        sys.exit(2)
    if create:
        ensure_workspace_dirs(ws)
    return ws


# ----------------------------------------------------------------------
# Display helpers
# ----------------------------------------------------------------------
def _fmt_last_used(iso_ts: str) -> str:
    """Render a 'last_used' timestamp as a friendly relative-or-absolute string."""
    if not iso_ts or iso_ts == "Never":
        return "never"
    try:
        dt = datetime.datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    except Exception:
        return iso_ts
    now = datetime.datetime.now(datetime.timezone.utc)
    delta = now - dt
    secs = int(delta.total_seconds())
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{secs // 60} min ago"
    if secs < 86400:
        return f"{secs // 3600} hr ago"
    if secs < 7 * 86400:
        return f"{secs // 86400} day ago" if secs < 2 * 86400 else f"{secs // 86400} days ago"
    return dt.strftime("%Y-%m-%d")


def _print_workspace_list(cfg: dict) -> None:
    """msfconsole-style list: `* name   path   size · used X ago` per line.

    The asterisk marks the active workspace, same convention as msfconsole's
    `workspace` output (`*default  HR  IT  ACC`). Sorted with the active one
    first, then the rest alphabetically -- 'workspace' is the command you'll
    use most, and seeing the current one at the top matters more than strict
    alphabetic ordering.
    """
    workspaces = cfg.get("workspaces", {})
    if not workspaces:
        print(f"{Fore.CYAN}[i]{Style.RESET_ALL} No workspaces registered.")
        return
    active = cfg.get("active_workspace")
    names = ([active] if active in workspaces else []) + sorted(
        n for n in workspaces if n != active
    )
    # Column-align the names so the path column lines up.
    name_w = min(max(len(n) for n in names), 28)
    for n in names:
        ws = workspaces[n]
        ws_path = _resolve_path(ws["path"])
        marker = f"{Fore.GREEN}*{Style.RESET_ALL}" if n == active else " "
        name_col = (f"{Fore.GREEN}{n:<{name_w}}{Style.RESET_ALL}"
                    if n == active else f"{n:<{name_w}}")
        path_col = ws["path"]
        used = _fmt_last_used(ws.get("last_used", ""))
        if ws_path.exists():
            size = _format_size(_get_workspace_size(ws_path))
            tail = f"  ({size}, used {used})"
        else:
            tail = f"  ({Fore.YELLOW}path missing{Style.RESET_ALL})"
        print(f"  {marker} {name_col}  {path_col}{tail}")


def _ensure_default_workspace(cfg: dict) -> str:
    """Auto-create the 'default' workspace at the workspaces root if the
    registry is empty. Returns the workspace name. Idempotent: no-op when
    workspaces already exist."""
    if cfg.get("workspaces"):
        return cfg.get("active_workspace") or next(iter(cfg["workspaces"]))
    ws_path = workspaces_root() / DEFAULT_WORKSPACE_NAME
    ensure_workspace_dirs(ws_path)
    name = _register_workspace(cfg, ws_path, name=DEFAULT_WORKSPACE_NAME)
    _set_active(cfg, name)
    _save_config(cfg)
    return name


# ----------------------------------------------------------------------
# Commands (msfconsole-style: flat surface, flag-driven)
# ----------------------------------------------------------------------
def cmd_list(args: argparse.Namespace) -> int:
    """Bare `cygor workspace`: list workspaces, asterisk-prefixed active.

    Auto-creates 'default' if the registry is empty so the user has a
    workspace to write to from the very first invocation. After auto-creation
    the list shows the freshly-made entry.
    """
    cfg = _migrate_old_config(_load_config())
    if not cfg.get("workspaces"):
        _ensure_default_workspace(cfg)
        print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Created 'default' workspace at "
              f"{workspaces_root() / DEFAULT_WORKSPACE_NAME}")
        print()
    _print_workspace_list(cfg)
    return 0


def cmd_switch(name: str) -> int:
    """`cygor workspace <name>`: switch the active workspace by name."""
    cfg = _migrate_old_config(_load_config())
    if name not in cfg.get("workspaces", {}):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace not found: {name}", file=sys.stderr)
        known = sorted(cfg.get("workspaces", {}).keys())
        if known:
            print("    Available workspaces:", file=sys.stderr)
            for n in known:
                print(f"      - {n}", file=sys.stderr)
        else:
            print(f"    Create one with: cygor workspace -a <name>", file=sys.stderr)
        return 2

    ws_path = _resolve_path(cfg["workspaces"][name]["path"])
    if not ws_path.exists():
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace path does not exist: {ws_path}",
              file=sys.stderr)
        return 2

    _set_active(cfg, name)
    _update_last_used(name, cfg)
    _save_config(cfg)
    print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Workspace: {Fore.CYAN}{name}{Style.RESET_ALL}  "
          f"({ws_path})")
    return 0


def cmd_add(name: str, custom_path: Optional[str] = None) -> int:
    """`cygor workspace -a <name>`: create a new workspace, register it,
    activate it. Default location is `<workspaces_root>/<name>/`; pass
    `--path /custom/dir` to place it elsewhere (shared drives, large
    engagement folders)."""
    cfg = _migrate_old_config(_load_config())
    if name in cfg.get("workspaces", {}):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace already exists: {name}",
              file=sys.stderr)
        return 2

    if custom_path:
        ws_path = _resolve_path(custom_path)
    else:
        ws_path = workspaces_root() / name

    ws_path.mkdir(parents=True, exist_ok=True)

    # Standard layout + the marker file so future tooling recognises this dir.
    for rel in SUBDIRS:
        base = ws_path / rel
        base.mkdir(parents=True, exist_ok=True)
        if rel == "cygor-enumeration-modules":
            for module in ("lockon", "smbexplorer", "nfsexplorer"):
                (base / module).mkdir(parents=True, exist_ok=True)

    (ws_path / ".cygor-workspace.json").write_text(json.dumps({
        "workspace": str(ws_path),
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "schema": 3,
        "description": "Cygor workspace directory for scan and enumeration data.",
        "subdirectories": {
            "nmap":                       "Nmap scan data and parsed XML output",
            "parsed-hostlists":           "Aggregated and categorized hostlists",
            "credrecon":                  "Credential reconnaissance scan results",
            "schedule-scans":             "Scheduled and automated scan results",
            "cygor-enumeration-modules":  "Per-module output (lockon, smbexplorer, …)",
            "logs":                       "General log output and runtime information",
        },
    }, indent=2))

    ws_name = _register_workspace(cfg, ws_path, name=name)
    # msf semantics: switch into the newly-created workspace.
    _set_active(cfg, ws_name)
    _save_config(cfg)
    print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Added workspace: "
          f"{Fore.CYAN}{ws_name}{Style.RESET_ALL}  ({ws_path})")
    return 0


def cmd_delete(name: str, purge: bool = False) -> int:
    """`cygor workspace -d <name>`: remove a workspace from the registry.

    Default behaviour preserves files on disk -- removal is just unregistering.
    Pass `--purge` to also delete the directory tree.

    If you delete the active workspace, the active pointer falls back to
    'default' (auto-created at the workspaces root if it doesn't exist).
    This preserves the msf invariant: there is always exactly one active
    workspace.
    """
    cfg = _migrate_old_config(_load_config())
    if name not in cfg.get("workspaces", {}):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace not found: {name}", file=sys.stderr)
        return 2

    ws_data = cfg["workspaces"][name]
    ws_path = _resolve_path(ws_data["path"])
    was_active = (name == cfg.get("active_workspace"))

    if purge:
        # Confirmation -- this is destructive even with -y because it deletes
        # whatever scan data is in the directory.
        if not getattr(cmd_delete, "_skip_confirm", False):
            try:
                print(f"{Fore.YELLOW}This will permanently delete:{Style.RESET_ALL} {ws_path}")
                resp = input("Type the workspace name to confirm: ").strip()
            except EOFError:
                resp = ""
            if resp != name:
                print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Aborted -- name did not match.")
                return 1
        if ws_path.exists():
            shutil.rmtree(ws_path, ignore_errors=True)

    cfg["workspaces"].pop(name, None)
    if was_active:
        cfg.pop("active_workspace", None)
    _save_config(cfg)

    if purge:
        print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Deleted workspace: "
              f"{Fore.CYAN}{name}{Style.RESET_ALL}  (files removed)")
    else:
        print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Deleted workspace: "
              f"{Fore.CYAN}{name}{Style.RESET_ALL}")
        print(f"    Files preserved at: {ws_data['path']}")
        print(f"    Use {Fore.CYAN}--purge{Style.RESET_ALL} next time to also delete the directory.")

    # Always-active invariant: if we removed the active workspace, the next
    # active_workspace_path() call will auto-recreate 'default' as needed.
    if was_active:
        remaining = sorted(cfg.get("workspaces", {}).keys())
        if remaining:
            # Auto-promote the first remaining workspace.
            _set_active(cfg, remaining[0])
            _save_config(cfg)
            print(f"    Switched to: {Fore.CYAN}{remaining[0]}{Style.RESET_ALL}")
        else:
            print(f"    Registry is now empty -- next cygor run will auto-create 'default'.")
    return 0


def cmd_rename(old: str, new: str) -> int:
    """`cygor workspace -r <old> <new>`: rename a workspace in the registry.

    Renames the key only; the directory on disk keeps its current name.
    Preserves activation state (if the renamed workspace was active, it stays
    active under the new name). Errors if old doesn't exist or new collides.
    """
    cfg = _migrate_old_config(_load_config())
    if old not in cfg.get("workspaces", {}):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace not found: {old}", file=sys.stderr)
        return 2
    if new in cfg.get("workspaces", {}):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} A workspace named '{new}' already exists.",
              file=sys.stderr)
        return 2

    cfg["workspaces"][new] = cfg["workspaces"].pop(old)
    if cfg.get("active_workspace") == old:
        cfg["active_workspace"] = new
    _save_config(cfg)
    print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Renamed: "
          f"{Fore.CYAN}{old}{Style.RESET_ALL} → {Fore.CYAN}{new}{Style.RESET_ALL}")
    return 0


def cmd_info(name: str) -> int:
    """`cygor workspace --info <name>`: show path/status/timestamps/size +
    per-subdirectory file counts."""
    cfg = _migrate_old_config(_load_config())
    if name not in cfg.get("workspaces", {}):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace not found: {name}", file=sys.stderr)
        return 2

    ws_data = cfg["workspaces"][name]
    ws_path = _resolve_path(ws_data["path"])
    active = (cfg.get("active_workspace") == name)

    print(f"\n{Style.BRIGHT}{Fore.CYAN}Workspace: {name}{Style.RESET_ALL}")
    status = f"{Fore.GREEN}active{Style.RESET_ALL}" if active else "inactive"
    print(f"  Status:      {status}")
    print(f"  Path:        {ws_path}")
    print(f"  Created:     {ws_data.get('created_at', 'Unknown')}")
    print(f"  Last used:   {_fmt_last_used(ws_data.get('last_used', ''))}")
    if "description" in ws_data:
        print(f"  Description: {ws_data['description']}")

    if not ws_path.exists():
        print(f"  {Fore.YELLOW}! path does not exist on disk{Style.RESET_ALL}")
        return 2

    size = _get_workspace_size(ws_path)
    print(f"  Size:        {_format_size(size)}")
    print()
    print(f"  {Style.BRIGHT}Subdirectories{Style.RESET_ALL}")
    for subdir in SUBDIRS:
        subdir_path = ws_path / subdir
        if subdir_path.exists():
            file_count = sum(1 for _ in subdir_path.rglob("*") if _.is_file())
            print(f"    {subdir:<30} {file_count} files")
    return 0


def cmd_print_path() -> int:
    """`cygor workspace --print-path`: print the active workspace path,
    nothing else. Designed for shell substitution:

        cd "$(cygor workspace --print-path)"

    Writes raw bytes to fd 1 to bypass colorama's autoreset wrapper.
    """
    p = active_workspace_path()
    if p is None:
        return 1
    os.write(1, f"{p}\n".encode())
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    """`cygor workspace --clean`: remove generated scan output from a workspace
    (preserves the layout). With no name, operates on the active workspace."""
    cfg = _migrate_old_config(_load_config())
    name = getattr(args, "clean_target", None)
    if name:
        if name not in cfg.get("workspaces", {}):
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace not found: {name}",
                  file=sys.stderr)
            return 2
        ws_path = _resolve_path(cfg["workspaces"][name]["path"])
    else:
        ws_path = active_workspace_path()
        if ws_path is None:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No active workspace and none specified.",
                  file=sys.stderr)
            return 2

    if not ws_path.exists():
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace path does not exist: {ws_path}",
              file=sys.stderr)
        return 2

    keep_last = getattr(args, "keep_last", None)
    to_remove = []
    for sub in SUBDIRS:
        d = ws_path / sub
        if not d.is_dir():
            continue
        children = sorted(d.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
        victims = children[keep_last:] if (keep_last and keep_last > 0) else children
        to_remove.extend(victims)

    if not to_remove:
        print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Nothing to clean in {ws_path}")
        return 0

    total = sum(_path_size(p) for p in to_remove)
    print(f"\nWorkspace: {ws_path}")
    print(f"Mode: {f'keep newest {keep_last} per subdirectory' if keep_last else 'remove all generated output'}")
    print(f"Items: {len(to_remove)}   Reclaimable: {_format_size(total)}\n")
    for p in to_remove[:20]:
        print(f"  - {p.relative_to(ws_path)}")
    if len(to_remove) > 20:
        print(f"  ... and {len(to_remove) - 20} more")

    if getattr(args, "dry_run", False):
        print(f"\n{Fore.CYAN}[i]{Style.RESET_ALL} Dry run - nothing deleted.")
        return 0

    if not getattr(args, "yes", False):
        try:
            resp = input("\nProceed with deletion? [y/N]: ").strip().lower()
        except EOFError:
            resp = ""
        if resp not in ("y", "yes"):
            print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Aborted.")
            return 1

    removed = 0
    for p in to_remove:
        try:
            shutil.rmtree(p) if p.is_dir() else p.unlink()
            removed += 1
        except Exception as e:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Failed to remove {p}: {e}", file=sys.stderr)

    ensure_workspace_dirs(ws_path)
    print(f"\n{Fore.GREEN}[✓]{Style.RESET_ALL} Removed {removed} item(s), "
          f"reclaimed ~{_format_size(total)}")
    return 0


# ----------------------------------------------------------------------
# CLI Parser (msfconsole-style flat surface)
# ----------------------------------------------------------------------
def build_parser(prog="cygor workspace") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Manage Cygor workspaces -- the directories where scan and module "
            "output is saved. Command syntax mirrors msfconsole's `workspace`: "
            "bare command lists, `name` switches, `-a NAME` adds, `-d NAME` "
            "deletes, `-r OLD NEW` renames. There is always exactly one active "
            "workspace; 'default' is auto-created on first use."
        ),
        epilog=f"""
Workspaces live under {DEFAULT_WORKSPACES_ROOT} by default
(override with $CYGOR_WORKSPACES_ROOT). `-a NAME` puts a new workspace there;
pass `--path /custom/dir` to place it elsewhere.

Examples:
  # List workspaces (active marked with *)
  cygor workspace

  # Switch to one
  cygor workspace acme

  # Add a new one (created under the workspaces root by default)
  cygor workspace -a acme

  # Add at a custom location (shared drive, large engagement folder)
  cygor workspace -a acme --path /mnt/engagements/acme

  # Delete (files stay)
  cygor workspace -d acme

  # Delete + wipe the directory on disk
  cygor workspace -d acme --purge

  # Rename
  cygor workspace -r acme acme-2026

  # Detail view + cleanup + scripting
  cygor workspace --info acme
  cygor workspace --clean --keep-last 3
  cd "$(cygor workspace --print-path)"
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # Core CRUD lives in a mutually-exclusive group so the user can't pass
    # `-a foo -d bar` at the same time. The positional `name` is parsed
    # alongside and dispatched in main() based on which (if any) flag was set.
    group = p.add_mutually_exclusive_group()
    group.add_argument("-a", "--add", metavar="NAME",
        help="Add (create) a new workspace named NAME")
    group.add_argument("-d", "--delete", metavar="NAME",
        help="Delete the workspace named NAME (files preserved unless --purge)")
    group.add_argument("-r", "--rename", nargs=2, metavar=("OLD", "NEW"),
        help="Rename a workspace from OLD to NEW")
    group.add_argument("--info", metavar="NAME",
        help="Show subdirectories, sizes, and timestamps for NAME")
    group.add_argument("--print-path", action="store_true",
        help="Print only the active workspace path (for shell scripts)")
    group.add_argument("--clean", action="store_true",
        help="Trim old scan output from a workspace (active one if no name given)")

    # Modifiers for the above:
    p.add_argument("--path", metavar="DIR",
        help="With -a: create the workspace at DIR instead of the default root")
    p.add_argument("--purge", action="store_true",
        help="With -d: also delete the directory on disk (default: files preserved)")
    p.add_argument("--keep-last", type=int, metavar="N",
        help="With --clean: keep the N most recent entries per subdirectory")
    p.add_argument("--dry-run", action="store_true",
        help="With --clean: show what would be removed without deleting")
    p.add_argument("--yes", "-y", action="store_true",
        help="With --clean: skip the confirmation prompt")

    # Positional name: used by `workspace <name>` (switch) and by `--clean
    # <name>` (clean a specific workspace instead of the active one). Made
    # optional so bare `cygor workspace` works.
    p.add_argument("name", nargs="?",
        help="Workspace name -- without other flags, switches to it; "
             "with --clean, scopes the cleanup target")

    return p


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    args = build_parser().parse_args(argv)

    # Dispatch table (order matches the help block above).
    if args.add:
        return cmd_add(args.add, args.path)
    if args.delete:
        return cmd_delete(args.delete, purge=args.purge)
    if args.rename:
        return cmd_rename(args.rename[0], args.rename[1])
    if args.info:
        return cmd_info(args.info)
    if args.print_path:
        return cmd_print_path()
    if args.clean:
        args.clean_target = args.name  # name is the optional clean target
        return cmd_clean(args)

    # No flags -> bare positional = switch, no positional = list.
    if args.name:
        return cmd_switch(args.name)
    return cmd_list(args)


if __name__ == "__main__":
    raise SystemExit(main())
