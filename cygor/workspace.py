import argparse
import json
import os
import sys
import datetime
import shutil
from pathlib import Path
from typing import Optional

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
    "    - set an active workspace:   cygor workspace init /path/to/workspace --default\n"
    "    - or export CYGOR_WORKSPACE=/path/to/workspace"
)


def active_workspace_path() -> Optional[Path]:
    """Path of the active/default workspace from config, or None if unset.

    Consolidates the lookup previously duplicated in webctl and webapp.config.
    The configured path is returned even if it does not exist yet; callers
    decide whether to create it.
    """
    cfg = _load_config()
    cfg = _migrate_old_config(cfg)

    workspaces = cfg.get("workspaces", {})
    active = cfg.get("active_workspace") or cfg.get("default_workspace")
    if active and active in workspaces:
        path = workspaces[active].get("path")
        if path:
            return Path(path)

    # Old format: default_workspace stored as a bare path string.
    legacy = cfg.get("default_workspace")
    if legacy and isinstance(legacy, str) and legacy not in workspaces:
        return Path(legacy)

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
# Commands
# ----------------------------------------------------------------------
def cmd_init(args: argparse.Namespace) -> int:
    ws = _resolve_path(args.path)
    ws.mkdir(parents=True, exist_ok=True)

    # Create the standardized workspace subdirectories
    for rel in SUBDIRS:
        base = ws / rel
        base.mkdir(parents=True, exist_ok=True)

        # Auto-create subfolders for enumeration modules
        if rel == "cygor-enumeration-modules":
            for module in ["lockon", "smbexplorer", "nfsexplorer"]:
                (base / module).mkdir(parents=True, exist_ok=True)

    # Write metadata file describing the workspace layout
    meta = {
        "workspace": str(ws),
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "schema": 3,
        "description": (
            "Cygor workspace directory structure for scan and enumeration data."
        ),
        "subdirectories": {
            "nmap": "Nmap scan data and parsed XML output",
            "parsed-hostlists": "Aggregated and categorized hostlists",
            "credrecon": "Credential reconnaissance scan results",
            "schedule-scans": "Scheduled and automated scan results",
            "cygor-enumeration-modules": {
                "description": "Output directories for enumeration modules",
                "modules": ["lockon", "smbexplorer", "nfsexplorer", "httpx", "rdpmapper"]
            },
            "logs": "General log output and runtime information"
        },
    }
    (ws / ".cygor-workspace.json").write_text(json.dumps(meta, indent=2))

    # Register workspace in config
    cfg = _load_config()
    cfg = _migrate_old_config(cfg)

    ws_name = _register_workspace(
        cfg, ws,
        name=(args.name if getattr(args, "name", None) else None),
        description=(args.description if getattr(args, "description", None) else None),
    )

    # Activate when explicitly requested (--default), or when no workspace is
    # active yet (the first one), unless the user opted out with --no-activate.
    has_active = bool(cfg.get("active_workspace") or cfg.get("default_workspace"))
    activate = (getattr(args, "default", False) or not has_active) and not getattr(args, "no_activate", False)

    if activate:
        _set_active(cfg, ws_name)
        _save_config(cfg)
        print(f"[✓] Cygor workspace initialized and set as active: {ws_name} ({ws})")
    else:
        _save_config(cfg)
        print(f"[✓] Cygor workspace initialized: {ws_name} ({ws})")
        print(f"[i] To activate it:")
        print(f"    cygor workspace switch \"{ws_name}\"")

    return 0


def cmd_set_default(args: argparse.Namespace) -> int:
    """Deprecated alias for `switch` (kept for back-compat)."""
    print("[i] 'set-default' is deprecated; use: cygor workspace switch <name|path>",
          file=sys.stderr)
    args.name_or_path = args.path
    return cmd_switch(args)


def cmd_show(args: argparse.Namespace) -> int:
    """Deprecated alias for `current` (kept for back-compat)."""
    print("[i] 'show' is deprecated; use: cygor workspace current", file=sys.stderr)
    if not hasattr(args, "verbose"):
        args.verbose = False
    return cmd_current(args)


def cmd_unset(args: argparse.Namespace) -> int:
    """Unset active workspace."""
    cfg = _load_config()
    cfg = _migrate_old_config(cfg)
    
    if cfg.get("active_workspace") or cfg.get("default_workspace"):
        old_active = cfg.get("active_workspace")
        old_default = cfg.get("default_workspace")
        cfg.pop("active_workspace", None)
        cfg.pop("default_workspace", None)
        _save_config(cfg)
        print(f"[✓] Active workspace unset")
        if old_active:
            print(f"[i] Was: {old_active}")
        print("[i] Cygor will now operate without a global workspace.")
        print("    Each scan or module can freely specify its own output location.")
        return 0
    else:
        print("[i] No active workspace is currently set.")
        return 0


def cmd_list(args: argparse.Namespace) -> int:
    """List all registered workspaces."""
    cfg = _load_config()
    cfg = _migrate_old_config(cfg)
    
    workspaces = cfg.get("workspaces", {})
    active = cfg.get("active_workspace") or cfg.get("default_workspace")
    
    if not workspaces:
        print("[i] No workspaces registered.")
        print("[i] Initialize one with: cygor workspace init <path>")
        return 0
    
    print(f"\n{'Name':<20} {'Path':<50} {'Status':<10} {'Last Used':<20}")
    print("=" * 100)
    
    for name, ws_data in sorted(workspaces.items()):
        path = ws_data.get("path", "")
        is_active = "*" if name == active else " "
        status = "ACTIVE" if name == active else ""
        last_used = ws_data.get("last_used", "Never")
        if last_used != "Never":
            try:
                dt = datetime.datetime.fromisoformat(last_used.replace("Z", "+00:00"))
                last_used = dt.strftime("%Y-%m-%d %H:%M")
            except Exception:
                pass
        
        # Truncate path if too long
        display_path = path
        if len(display_path) > 48:
            display_path = "..." + display_path[-45:]
        
        print(f"{is_active}{name:<19} {display_path:<50} {status:<10} {last_used:<20}")
    
    if active:
        print(f"\n[*] Active workspace: {active}")
    else:
        print(f"\n[*] No active workspace set")
    
    return 0


def cmd_add(args: argparse.Namespace) -> int:
    """Add an existing workspace to the registry."""
    ws = _resolve_path(args.path)
    
    if not ws.exists():
        print(f"[!] Workspace does not exist: {ws}", file=sys.stderr)
        return 2
    
    if not _validate_workspace(ws):
        print(f"[!] Path is not a valid workspace: {ws}", file=sys.stderr)
        print(f"[i] Initialize it first with: cygor workspace init \"{ws}\"", file=sys.stderr)
        return 2
    
    cfg = _load_config()
    cfg = _migrate_old_config(cfg)
    
    # Check if already registered
    result = _get_workspace_by_name_or_path(str(ws), cfg)
    if result:
        name, _ = result
        print(f"[i] Workspace already registered as: {name}")
        return 0
    
    ws_name = _register_workspace(cfg, ws, name=args.name, description=args.description)
    _save_config(cfg)
    print(f"[✓] Workspace registered: {ws_name}")
    print(f"[i] Switch to it with: cygor workspace switch \"{ws_name}\"")
    return 0


def cmd_switch(args: argparse.Namespace) -> int:
    """Activate a workspace by name or path (auto-registering an unknown path)."""
    cfg = _load_config()
    cfg = _migrate_old_config(cfg)

    result = _get_workspace_by_name_or_path(args.name_or_path, cfg)
    if result:
        name, ws_data = result
        ws_path = _resolve_path(ws_data["path"])
        if not ws_path.exists():
            print(f"[!] Workspace path does not exist: {ws_path}", file=sys.stderr)
            return 2
    else:
        # Not in the registry. If the user pointed at an existing directory,
        # register it on the fly (initializing the layout) instead of erroring.
        candidate = _resolve_path(args.name_or_path)
        if candidate.exists() and candidate.is_dir():
            ensure_workspace_dirs(candidate)
            name = _register_workspace(cfg, candidate)
            ws_path = candidate
            print(f"[i] Registered new workspace: {name}")
        else:
            print(f"[!] Workspace not found: {args.name_or_path}", file=sys.stderr)
            known = list(cfg.get("workspaces", {}).keys())
            if known:
                print(f"[i] Available workspaces:", file=sys.stderr)
                for n in known:
                    print(f"    - {n}", file=sys.stderr)
            else:
                print(f"[i] Create one with: cygor workspace init <path>", file=sys.stderr)
            return 2

    _set_active(cfg, name)
    _update_last_used(name, cfg)  # persists cfg
    _save_config(cfg)

    print(f"[✓] Switched to workspace: {name}")
    print(f"[i] Path: {ws_path}")
    return 0


def cmd_remove(args: argparse.Namespace) -> int:
    """Remove a workspace from the registry (does not delete files)."""
    cfg = _load_config()
    cfg = _migrate_old_config(cfg)
    
    result = _get_workspace_by_name_or_path(args.name_or_path, cfg)
    if not result:
        print(f"[!] Workspace not found: {args.name_or_path}", file=sys.stderr)
        return 2
    
    name, ws_data = result
    
    # Check if it's the active workspace
    if name == cfg.get("active_workspace"):
        print(f"[!] Cannot remove active workspace: {name}", file=sys.stderr)
        print(f"[i] Switch to another workspace first:", file=sys.stderr)
        for other_name in cfg.get("workspaces", {}).keys():
            if other_name != name:
                print(f"    cygor workspace switch \"{other_name}\"", file=sys.stderr)
                break
        return 2
    
    # Remove from registry
    cfg["workspaces"].pop(name)
    if cfg.get("default_workspace") == name:
        cfg.pop("default_workspace", None)
    
    _save_config(cfg)
    print(f"[✓] Workspace removed from registry: {name}")
    print(f"[i] Files remain at: {ws_data['path']}")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """Show detailed information about a workspace."""
    cfg = _load_config()
    cfg = _migrate_old_config(cfg)
    
    result = _get_workspace_by_name_or_path(args.name_or_path, cfg)
    if not result:
        print(f"[!] Workspace not found: {args.name_or_path}", file=sys.stderr)
        return 2
    
    name, ws_data = result
    ws_path = _resolve_path(ws_data["path"])
    active = cfg.get("active_workspace") == name
    
    print(f"\nWorkspace: {name}")
    print("=" * 60)
    print(f"Path:        {ws_path}")
    print(f"Status:      {'ACTIVE' if active else 'Inactive'}")
    print(f"Created:     {ws_data.get('created_at', 'Unknown')}")
    print(f"Last Used:   {ws_data.get('last_used', 'Never')}")
    
    if "description" in ws_data:
        print(f"Description: {ws_data['description']}")
    
    if ws_path.exists():
        size = _get_workspace_size(ws_path)
        print(f"Size:        {_format_size(size)}")
        
        # Show subdirectory info
        print(f"\nSubdirectories:")
        for subdir in SUBDIRS:
            subdir_path = ws_path / subdir
            if subdir_path.exists():
                file_count = sum(1 for _ in subdir_path.rglob("*") if _.is_file())
                print(f"  {subdir:<30} {file_count} files")
    else:
        print(f"[!] Workspace path does not exist")
        return 2
    
    return 0


def cmd_current(args: argparse.Namespace) -> int:
    """Show current active workspace with details."""
    cfg = _load_config()
    cfg = _migrate_old_config(cfg)
    
    active = cfg.get("active_workspace") or cfg.get("default_workspace")
    if not active:
        print("[i] No active workspace is currently set.")
        return 1
    
    if active not in cfg.get("workspaces", {}):
        # Fallback to old format
        old_ws = cfg.get("default_workspace")
        if old_ws and isinstance(old_ws, str):
            print(old_ws)
            return 0
        print("[i] Active workspace reference is invalid.")
        return 1
    
    ws_data = cfg["workspaces"][active]
    ws_path = _resolve_path(ws_data["path"])
    
    print(f"Active Workspace: {active}")
    print(f"Path: {ws_path}")
    
    if args.verbose:
        print(f"Created: {ws_data.get('created_at', 'Unknown')}")
        print(f"Last Used: {ws_data.get('last_used', 'Never')}")
        if ws_path.exists():
            size = _get_workspace_size(ws_path)
            print(f"Size: {_format_size(size)}")

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
        print("[!] No workspace to clean. Pass a name/path or set an active "
              "workspace (cygor workspace switch ...).", file=sys.stderr)
        return 2
    if not ws_path.exists():
        print(f"[!] Workspace path does not exist: {ws_path}", file=sys.stderr)
        return 2

    keep_last = getattr(args, "keep_last", None)

    # Build the removal set across the standard data subdirectories.
    to_remove = []
    for sub in SUBDIRS:
        d = ws_path / sub
        if not d.is_dir():
            continue
        children = sorted(
            d.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True
        )
        victims = children[keep_last:] if (keep_last and keep_last > 0) else children
        to_remove.extend(victims)

    if not to_remove:
        print(f"[i] Nothing to clean in {ws_path}")
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
        print("\n[i] Dry run - nothing deleted.")
        return 0

    if not getattr(args, "yes", False):
        try:
            resp = input("\nProceed with deletion? [y/N]: ").strip().lower()
        except EOFError:
            resp = ""
        if resp not in ("y", "yes"):
            print("[i] Aborted.")
            return 1

    removed = 0
    for p in to_remove:
        try:
            shutil.rmtree(p) if p.is_dir() else p.unlink()
            removed += 1
        except Exception as e:
            print(f"[!] Failed to remove {p}: {e}", file=sys.stderr)

    # Keep the workspace valid: recreate the empty standard structure.
    ensure_workspace_dirs(ws_path)
    print(f"\n[✓] Removed {removed} item(s), reclaimed ~{_format_size(total)}")
    return 0

# ----------------------------------------------------------------------
# CLI Parser
# ----------------------------------------------------------------------
def build_parser(prog="cygor workspace") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description="Manage Cygor workspaces (optional global directories for storing all scan and module data).",
        epilog="""
Examples:
  # Initialize a workspace (the first one becomes active automatically)
  cygor workspace init ~/workspaces/project-alpha --name project-alpha

  # List all workspaces
  cygor workspace list

  # Activate a workspace by name, or point at any directory to use it
  cygor workspace switch project-alpha
  cygor workspace switch ~/engagements/acme

  # Show the current active workspace
  cygor workspace current

  # Reclaim space: remove old scan output (preview first, then keep newest 3)
  cygor workspace clean --dry-run
  cygor workspace clean --keep-last 3
        """,
    )
    sub = p.add_subparsers(dest="subcmd", required=True)

    # Init command (activates the new workspace when it's the first one, or
    # with --default; opt out with --no-activate).
    pi = sub.add_parser("init", help="Create a new workspace at PATH and standard subfolders.")
    pi.add_argument("path", help="Path to create/use as the workspace directory")
    pi.add_argument("--name", help="Name for the workspace (default: directory name)")
    pi.add_argument("--description", help="Description for the workspace")
    pi.add_argument("--default", action="store_true", help="Set this workspace as active (always, even if another is active)")
    pi.add_argument("--no-activate", action="store_true", help="Do not set the new workspace as active")
    pi.set_defaults(func=cmd_init)

    # Set-default (deprecated alias of switch)
    ps = sub.add_parser("set-default", help="Deprecated: use 'switch'.")
    ps.add_argument("path", help="Existing workspace name or path")
    ps.set_defaults(func=cmd_set_default)

    # Show (deprecated alias of current)
    pg = sub.add_parser("show", help="Deprecated: use 'current'.")
    pg.set_defaults(func=cmd_show)

    # Unset
    pu = sub.add_parser("unset", help="Unset/remove the current active workspace (return to free mode).")
    pu.set_defaults(func=cmd_unset)

    # List
    pl = sub.add_parser("list", help="List all registered workspaces.")
    pl.set_defaults(func=cmd_list)

    # Add
    pa = sub.add_parser("add", help="Add an existing workspace to the registry.")
    pa.add_argument("path", help="Path to existing workspace")
    pa.add_argument("--name", help="Name for the workspace (default: directory name)")
    pa.add_argument("--description", help="Description for the workspace")
    pa.set_defaults(func=cmd_add)

    # Switch
    psw = sub.add_parser("switch", help="Activate a workspace by name or path (auto-registers an unknown path).")
    psw.add_argument("name_or_path", help="Workspace name or path")
    psw.set_defaults(func=cmd_switch)

    # Clean
    pcl = sub.add_parser("clean", help="Remove generated scan output from a workspace (keeps the workspace itself).")
    pcl.add_argument("name_or_path", nargs="?", help="Workspace name or path (default: active workspace)")
    pcl.add_argument("--keep-last", type=int, metavar="N", help="Keep the N most recent entries per subdirectory; remove older")
    pcl.add_argument("--dry-run", action="store_true", help="Show what would be removed without deleting")
    pcl.add_argument("--yes", "-y", action="store_true", help="Do not prompt for confirmation")
    pcl.set_defaults(func=cmd_clean)

    # Remove
    pr = sub.add_parser("remove", help="Remove a workspace from the registry (does not delete files).")
    pr.add_argument("name_or_path", help="Workspace name or path")
    pr.set_defaults(func=cmd_remove)

    # Info
    pinfo = sub.add_parser("info", help="Show detailed information about a workspace.")
    pinfo.add_argument("name_or_path", help="Workspace name or path")
    pinfo.set_defaults(func=cmd_info)

    # Current
    pc = sub.add_parser("current", help="Show current active workspace.")
    pc.add_argument("--verbose", "-v", action="store_true", help="Show detailed information")
    pc.set_defaults(func=cmd_current)

    return p


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
