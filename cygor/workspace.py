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
    "No workspace specified.\n"
    "  Cygor does not write to a default 'results/' directory. Choose where\n"
    "  scan output should be saved using one of:\n"
    "    - pass an output directory:  -o /path/to/workspace\n"
    "    - create + activate a new one:  cygor workspace create /path/to/workspace\n"
    "    - or export CYGOR_WORKSPACE=/path/to/workspace"
)


def active_workspace_path() -> Optional[Path]:
    """Path of the active workspace from config, or None if unset.

    Consolidates the lookup previously duplicated in webctl and webapp.config.
    The configured path is returned even if it does not exist yet; callers
    decide whether to create it. Legacy 'default_workspace' configs are
    promoted to 'active_workspace' by _migrate_old_config() on load, so this
    function only needs to look at the canonical key.
    """
    cfg = _migrate_old_config(_load_config())
    active = cfg.get("active_workspace")
    if active:
        entry = cfg.get("workspaces", {}).get(active)
        if entry and entry.get("path"):
            return Path(entry["path"])
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
# Display helpers (used by `cygor workspace` dashboard + list)
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


def _truncate_path(path: str, max_len: int = 50) -> str:
    """Truncate a path from the left so the tail (the workspace dir) stays visible."""
    if len(path) <= max_len:
        return path
    return "…" + path[-(max_len - 1):]


def _print_workspaces_table(cfg: dict) -> None:
    """Render the two-section view: active workspace, then everything else.

    Called by the no-subcommand dashboard (`cygor workspace`)."""
    workspaces = cfg.get("workspaces", {})
    active = cfg.get("active_workspace")

    if active and active in workspaces:
        ws = workspaces[active]
        ws_path = _resolve_path(ws["path"])
        size = _format_size(_get_workspace_size(ws_path)) if ws_path.exists() else "missing"
        print(f"{Style.BRIGHT}{Fore.CYAN}Active workspace{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}{active}{Style.RESET_ALL}   {ws['path']}")
        print(f"  {size} · last activity {_fmt_last_used(ws.get('last_used', ''))}")
        if not ws_path.exists():
            print(f"  {Fore.YELLOW}! path does not exist on disk{Style.RESET_ALL}")
    else:
        print(f"{Style.BRIGHT}{Fore.CYAN}Active workspace{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}none set{Style.RESET_ALL}")
        print(f"  scan/module output won't be saved to a known location")

    others = sorted(n for n in workspaces if n != active)
    if others:
        print()
        print(f"{Style.BRIGHT}{Fore.CYAN}Other workspaces ({len(others)}){Style.RESET_ALL}")
        # Width the name column to the widest other-name, capped reasonably.
        name_w = min(max((len(n) for n in others), default=8), 24)
        for n in others:
            ws = workspaces[n]
            ws_path = _resolve_path(ws["path"])
            size = _format_size(_get_workspace_size(ws_path)) if ws_path.exists() else "missing"
            disp_path = _truncate_path(ws["path"], 46)
            print(f"  {n:<{name_w}}  {disp_path}")
            print(f"  {'':<{name_w}}  {size} · used {_fmt_last_used(ws.get('last_used', ''))}")


def _print_command_hints(have_workspaces: bool) -> None:
    """Render the 'Commands' section at the bottom of the dashboard.

    Three lines per command -- short and scannable, matches the rest of the
    cygor CLI palette (cyan command, plain description)."""
    print()
    print(f"{Style.BRIGHT}{Fore.CYAN}Commands{Style.RESET_ALL}")
    rows = [
        ("cygor workspace create <path>",    "Make a new workspace"),
        ("cygor workspace use <name|path>",  "Switch to one (or register a path on the fly)"),
        ("cygor workspace info <name>",      "Show subdirectories, size breakdown"),
        ("cygor workspace clean",            "Trim old scan output"),
        ("cygor workspace remove <name>",    "Unregister (files preserved)"),
        ("cygor workspace none",             "Deactivate (stop writing to any workspace)"),
        ("cygor workspace path",             "Print the active path (scripting)"),
    ]
    if not have_workspaces:
        rows = [r for r in rows
                if r[0].startswith("cygor workspace create") or
                   r[0].startswith("cygor workspace use")]
    cmd_w = max(len(c) for c, _ in rows)
    for cmd, desc in rows:
        print(f"  {Fore.CYAN}{cmd:<{cmd_w}}{Style.RESET_ALL}   {desc}")


def _print_no_workspace_guidance() -> None:
    """Tell the user how to make data persist again after they end up with no
    active workspace. Called from `none` and `remove` (anywhere we could leave
    the user in free-mode)."""
    print()
    print(f"{Fore.YELLOW}[!] No active workspace is set.{Style.RESET_ALL}")
    print("    Scan / module data won't be saved to a known location until you do one of:")
    print(f"      {Fore.CYAN}cygor workspace use <name|path>{Style.RESET_ALL}     "
          "(pick an existing one, or register a new path)")
    print(f"      {Fore.CYAN}cygor workspace create <path>{Style.RESET_ALL}       "
          "(create + activate a new one)")
    print(f"      -o /path/to/output                    (per-command override)")
    print(f"      export CYGOR_WORKSPACE=/path/to/dir   (env override for this shell)")


# ----------------------------------------------------------------------
# Commands
# ----------------------------------------------------------------------
def cmd_dashboard(args: argparse.Namespace) -> int:
    """`cygor workspace` with no subcommand: status overview + next-step hints.

    This is the home screen for the workspace surface. It answers the two
    questions users actually have when they type the command:
      1. Which workspace am I on right now (and what's in it)?
      2. What can I do from here?
    """
    cfg = _migrate_old_config(_load_config())
    workspaces = cfg.get("workspaces", {})

    if not workspaces:
        print(f"{Style.BRIGHT}{Fore.CYAN}Active workspace{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}none set{Style.RESET_ALL}")
        print(f"  no workspaces registered yet")
        _print_command_hints(have_workspaces=False)
        return 0

    _print_workspaces_table(cfg)
    _print_command_hints(have_workspaces=True)
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    """`cygor workspace list`: the inventory, nothing else.

    Same active/others layout the dashboard uses but without the trailing
    Commands hint block -- useful when you just want to see what's
    registered, or when piping the output. If nothing is registered yet,
    say so clearly and point at `create`."""
    cfg = _migrate_old_config(_load_config())
    if not cfg.get("workspaces"):
        print(f"{Fore.CYAN}[i]{Style.RESET_ALL} No workspaces registered yet.")
        print(f"    Create one with: {Fore.CYAN}cygor workspace create <path>{Style.RESET_ALL}")
        return 0
    _print_workspaces_table(cfg)
    return 0


def cmd_create(args: argparse.Namespace) -> int:
    """Create a new workspace directory at PATH, lay out the standard
    subdirs, register it, and activate it (unless --no-activate). The first
    workspace ever created is always activated regardless of the flag."""
    ws = _resolve_path(args.path)
    ws.mkdir(parents=True, exist_ok=True)

    # Standard layout + enumeration-module subfolders.
    for rel in SUBDIRS:
        base = ws / rel
        base.mkdir(parents=True, exist_ok=True)
        if rel == "cygor-enumeration-modules":
            for module in ("lockon", "smbexplorer", "nfsexplorer"):
                (base / module).mkdir(parents=True, exist_ok=True)

    # Marker file so other tooling (and future migrations) can recognise the
    # directory as a Cygor workspace.
    meta = {
        "workspace": str(ws),
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "schema": 3,
        "description": "Cygor workspace directory structure for scan and enumeration data.",
        "subdirectories": {
            "nmap":                       "Nmap scan data and parsed XML output",
            "parsed-hostlists":           "Aggregated and categorized hostlists",
            "credrecon":                  "Credential reconnaissance scan results",
            "schedule-scans":             "Scheduled and automated scan results",
            "cygor-enumeration-modules":  "Per-module output (lockon, smbexplorer, …)",
            "logs":                       "General log output and runtime information",
        },
    }
    (ws / ".cygor-workspace.json").write_text(json.dumps(meta, indent=2))

    cfg = _migrate_old_config(_load_config())
    ws_name = _register_workspace(cfg, ws,
                                  name=getattr(args, "name", None),
                                  description=getattr(args, "description", None))

    # First-ever workspace always wins activation. After that, only --activate
    # promotes; --no-activate always wins.
    has_active = bool(cfg.get("active_workspace"))
    activate = (not has_active or getattr(args, "activate", False)) and not getattr(args, "no_activate", False)

    if activate:
        _set_active(cfg, ws_name)
        _save_config(cfg)
        print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Created workspace and set as active: "
              f"{Fore.CYAN}{ws_name}{Style.RESET_ALL}  ({ws})")
    else:
        _save_config(cfg)
        print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Created workspace: "
              f"{Fore.CYAN}{ws_name}{Style.RESET_ALL}  ({ws})")
        print(f"    Activate later with: {Fore.CYAN}cygor workspace use \"{ws_name}\"{Style.RESET_ALL}")

    return 0


def cmd_use(args: argparse.Namespace) -> int:
    """Switch the active workspace. Accepts a registered name OR a path; if
    the path is unknown we register it on the fly (initialising the layout
    if needed). One verb does both 'switch' and 'add' from the old surface."""
    cfg = _migrate_old_config(_load_config())

    result = _get_workspace_by_name_or_path(args.name_or_path, cfg)
    if result:
        name, ws_data = result
        ws_path = _resolve_path(ws_data["path"])
        if not ws_path.exists():
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace path does not exist: {ws_path}",
                  file=sys.stderr)
            return 2
    else:
        candidate = _resolve_path(args.name_or_path)
        if candidate.exists() and candidate.is_dir():
            ensure_workspace_dirs(candidate)
            name = _register_workspace(cfg, candidate)
            ws_path = candidate
            print(f"{Fore.CYAN}[i]{Style.RESET_ALL} Registered new workspace: {name}")
        else:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace not found: {args.name_or_path}",
                  file=sys.stderr)
            known = list(cfg.get("workspaces", {}).keys())
            if known:
                print("    Available workspaces:", file=sys.stderr)
                for n in known:
                    print(f"      - {n}", file=sys.stderr)
            else:
                print(f"    Create one with: cygor workspace create <path>", file=sys.stderr)
            return 2

    _set_active(cfg, name)
    _update_last_used(name, cfg)  # persists cfg
    _save_config(cfg)
    print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Switched to workspace: "
          f"{Fore.CYAN}{name}{Style.RESET_ALL}  ({ws_path})")
    return 0


def cmd_none(args: argparse.Namespace) -> int:
    """Deactivate the current workspace (return to free mode). The workspace
    stays in the registry; only the 'active' pointer is cleared."""
    cfg = _migrate_old_config(_load_config())

    if cfg.get("active_workspace"):
        old_active = cfg.pop("active_workspace")
        _save_config(cfg)
        print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Deactivated workspace: {old_active}")
        print(f"    (still registered, files untouched)")
    else:
        print(f"{Fore.CYAN}[i]{Style.RESET_ALL} No active workspace is currently set.")
    _print_no_workspace_guidance()
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    """Remove a workspace from the registry (does not delete files).

    If the target is the active workspace, deactivate it first -- the user's
    intent is almost always 'stop tracking this; files stay'. After the
    removal, print clear guidance about how to make data persist again.
    """
    cfg = _migrate_old_config(_load_config())

    result = _get_workspace_by_name_or_path(args.name_or_path, cfg)
    if not result:
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace not found: {args.name_or_path}",
              file=sys.stderr)
        return 2

    name, ws_data = result
    was_active = (name == cfg.get("active_workspace"))
    if was_active:
        cfg.pop("active_workspace", None)
    cfg["workspaces"].pop(name, None)
    _save_config(cfg)

    print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Removed workspace from registry: "
          f"{Fore.CYAN}{name}{Style.RESET_ALL}")
    print(f"    Files remain at: {ws_data['path']}")

    if was_active:
        remaining = sorted(cfg.get("workspaces", {}).keys())
        if remaining:
            print()
            print(f"{Fore.CYAN}[i]{Style.RESET_ALL} That was the active workspace. "
                  f"Pick one of the remaining:")
            for other in remaining:
                print(f"      {Fore.CYAN}cygor workspace use \"{other}\"{Style.RESET_ALL}")
        else:
            _print_no_workspace_guidance()
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """Show detailed information about a workspace: path, status, timestamps,
    size, and per-subdirectory file counts."""
    cfg = _migrate_old_config(_load_config())

    result = _get_workspace_by_name_or_path(args.name_or_path, cfg)
    if not result:
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace not found: {args.name_or_path}",
              file=sys.stderr)
        return 2

    name, ws_data = result
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


def cmd_path(args: argparse.Namespace) -> int:
    """Print the active workspace path, nothing else. Designed for shell use:

        cd "$(cygor workspace path)"

    Returns 0 + the path on stdout if active, 1 + nothing on stdout if not.

    Writes raw bytes straight to fd 1 on purpose -- the CLI initialises
    colorama with autoreset=True, which wraps sys.stdout and appends a
    \\x1b[0m reset after every write. That would contaminate the output and
    break shell substitution. Going through os.write bypasses every Python-
    level wrapper.
    """
    p = active_workspace_path()
    if p is None:
        return 1
    os.write(1, f"{p}\n".encode())
    return 0


def _resolve_target_workspace(name_or_path: Optional[str]) -> Optional[Path]:
    """Resolve a workspace path from a name/path argument, or the active one."""
    if name_or_path:
        cfg = _migrate_old_config(_load_config())
        result = _get_workspace_by_name_or_path(name_or_path, cfg)
        if result:
            return _resolve_path(result[1]["path"])
        candidate = _resolve_path(name_or_path)
        return candidate if candidate.exists() else None
    return active_workspace_path()


def cmd_clean(args: argparse.Namespace) -> int:
    """Remove generated scan output from a workspace (keeps the workspace)."""
    ws_path = _resolve_target_workspace(getattr(args, "name_or_path", None))
    if ws_path is None:
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No workspace to clean. Pass a name/path "
              f"or set an active workspace ({Fore.CYAN}cygor workspace use ...{Style.RESET_ALL}).",
              file=sys.stderr)
        return 2
    if not ws_path.exists():
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace path does not exist: {ws_path}",
              file=sys.stderr)
        return 2

    keep_last = getattr(args, "keep_last", None)

    # Build the removal set across the standard data subdirectories.
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

    # Keep the workspace valid: recreate the empty standard structure.
    ensure_workspace_dirs(ws_path)
    print(f"\n{Fore.GREEN}[✓]{Style.RESET_ALL} Removed {removed} item(s), "
          f"reclaimed ~{_format_size(total)}")
    return 0


# ----------------------------------------------------------------------
# CLI Parser
# ----------------------------------------------------------------------
def build_parser(prog="cygor workspace") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Manage Cygor workspaces -- the directories where scan and module "
            "output is saved. Run with no arguments to see the active workspace "
            "and available commands."
        ),
        epilog="""
Examples:
  # Show the active workspace and what else is around (also shows commands)
  cygor workspace

  # Just the inventory (active + others, no command hints -- pipe-friendly)
  cygor workspace list

  # Create a new workspace (the first one becomes active automatically)
  cygor workspace create ~/engagements/acme

  # Activate a workspace by name, or point at any directory to use it
  cygor workspace use acme
  cygor workspace use ~/engagements/beta

  # Detail view of one workspace
  cygor workspace info acme

  # Reclaim space: preview, then keep the newest 3 runs per subdirectory
  cygor workspace clean --dry-run
  cygor workspace clean --keep-last 3

  # Use in scripts
  cd "$(cygor workspace path)"
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # No 'required=True' -- running `cygor workspace` with no subcommand drops
    # into the dashboard view (handled in main()).
    sub = p.add_subparsers(dest="subcmd")

    # create -- new workspace dir + register + activate (if first or --activate)
    pcr = sub.add_parser("create",
        help="Create a new workspace directory and register it.",
        description="Create a new workspace at PATH with the standard subdirectory "
                    "layout. The first workspace ever created is activated automatically.")
    pcr.add_argument("path", help="Path to create as the workspace directory")
    pcr.add_argument("--name", help="Name for the workspace (default: directory name)")
    pcr.add_argument("--description", help="One-line description (shown in info)")
    pcr.add_argument("--activate", action="store_true",
        help="Activate this workspace even if another is already active")
    pcr.add_argument("--no-activate", action="store_true",
        help="Do not activate (useful when scripting multiple creates)")
    pcr.set_defaults(func=cmd_create)

    # use -- activate by name, or register-and-activate a path
    puse = sub.add_parser("use",
        help="Activate a workspace by name or path.",
        description="Activate a registered workspace by name, or point at any "
                    "directory to register it and activate it in one step.")
    puse.add_argument("name_or_path", help="Workspace name or directory path")
    puse.set_defaults(func=cmd_use)

    # list -- inventory of registered workspaces (no Commands footer)
    pls = sub.add_parser("list",
        help="List registered workspaces (active + others).",
        description="Show the active workspace and every other registered one, "
                    "with size and last-used timestamps. Same layout as "
                    "`cygor workspace` but without the trailing command hints, "
                    "so it's friendly to grep/pipe.")
    pls.set_defaults(func=cmd_list)

    # info -- subdirs + sizes for one workspace
    pinfo = sub.add_parser("info",
        help="Show detailed information about one workspace.",
        description="Show path, status, timestamps, total size, and per-subdirectory "
                    "file counts for a workspace.")
    pinfo.add_argument("name_or_path", help="Workspace name or path")
    pinfo.set_defaults(func=cmd_info)

    # clean -- trim old scan output
    pcl = sub.add_parser("clean",
        help="Trim old scan output from a workspace.",
        description="Remove generated scan output from inside a workspace. "
                    "The workspace itself, its layout, and its registration are preserved.")
    pcl.add_argument("name_or_path", nargs="?",
        help="Workspace name or path (default: active workspace)")
    pcl.add_argument("--keep-last", type=int, metavar="N",
        help="Keep the N most recent entries per subdirectory; remove older")
    pcl.add_argument("--dry-run", action="store_true",
        help="Show what would be removed without deleting")
    pcl.add_argument("--yes", "-y", action="store_true",
        help="Do not prompt for confirmation")
    pcl.set_defaults(func=cmd_clean)

    # remove -- unregister (files preserved)
    pr = sub.add_parser("remove",
        help="Unregister a workspace (files preserved).",
        description="Remove a workspace from cygor's registry. Files on disk are "
                    "preserved -- only the entry in cygor's config is removed. If the "
                    "removed workspace was active, the active pointer is cleared too.")
    pr.add_argument("name_or_path", help="Workspace name or path")
    pr.set_defaults(func=cmd_remove)

    # none -- deactivate without removing from registry
    pn = sub.add_parser("none",
        help="Deactivate the current workspace (stop writing to any).",
        description="Clear the active-workspace pointer so scans/modules fall back "
                    "to per-command -o output. The workspace stays in the registry; "
                    "use 'cygor workspace use NAME' to bring it back.")
    pn.set_defaults(func=cmd_none)

    # path -- one-line path output for scripts
    ppath = sub.add_parser("path",
        help="Print the active workspace path (for shell scripting).",
        description="Print only the active workspace path on stdout, with no "
                    "decoration. Exits 1 if no workspace is active.")
    ppath.set_defaults(func=cmd_path)

    return p


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    args = parser.parse_args(argv)
    # No subcommand -> dashboard.
    if not getattr(args, "subcmd", None):
        return cmd_dashboard(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
