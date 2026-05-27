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

# Default directory under which `cygor workspace create NAME` will place new
# workspaces (becomes <root>/<name>/). Per-host override via the env var
# below; users can also bypass the root entirely by passing --path on create.
DEFAULT_WORKSPACES_ROOT = Path.home() / ".cygor" / "workspaces"


def workspaces_root() -> Path:
    """Where new `cygor workspace create NAME` workspaces are placed. Env
    var wins; otherwise DEFAULT_WORKSPACES_ROOT. Always resolved + expanded."""
    env = os.environ.get("CYGOR_WORKSPACES_ROOT")
    base = Path(env).expanduser() if env else DEFAULT_WORKSPACES_ROOT
    return base.resolve() if base.exists() else base

# ----------------------------------------------------------------------
# Final, minimal workspace layout
# ----------------------------------------------------------------------
# Workspace subdirectories pre-created by `cygor workspace create`. Each entry
# corresponds to a real tool that writes into it; if a tool doesn't write there,
# it's dead weight and shouldn't be on this list. Comments name the producer.
SUBDIRS = [
    "nmap",                        # cygor scan (default Nmap engine)
    "masscan",                     # cygor scan --discover masscan
    "naabu",                       # cygor scan --discover naabu
    "icmp",                        # cygor scan ICMP host-discovery
    "parsed-hostlists",            # cygor parse
    "enrich",                      # cygor enrich + webapp enrichment route
    "credrecon",                   # cygor credrecon
    "schedule-scans",              # webapp scheduled scans (port/module/credrecon)
    "cygor-enumeration-modules",   # cygor enum <slug>  (lockon, smbexplorer, ...)
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
    "No workspace is selected.\n"
    "  Cygor needs a workspace before it can save scan/module output. Pick\n"
    "  one of:\n"
    "    - create + select a new one:  cygor workspace create <name>\n"
    "    - select an existing one:     cygor workspace select <name>\n"
    "    - pass a one-off output dir:  -o /path/to/output\n"
    "    - or export CYGOR_WORKSPACE=/path/to/workspace"
)


def active_workspace_path() -> Optional[Path]:
    """Path of the active workspace from config, or None if none is set.

    The user must explicitly create + select a workspace before scans /
    modules will have somewhere to write to. Tools that need a workspace
    should call require_workspace() so they get the standard "no workspace"
    error message instead of silently failing.

    Legacy 'default_workspace' configs are promoted to 'active_workspace'
    by _migrate_old_config() on load, so this function only looks at the
    canonical key.
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
    """Create the standard workspace layout (idempotent) and return the path.

    Also runs cheap migrations for workspaces created by older versions:
      - rename 'enrichment/' -> 'enrich/' if only the old one exists (the
        webapp used to write to 'enrichment/' while the CLI used 'enrich/'),
      - remove an empty 'logs/' subdir (logs live in ~/.cygor/logs/; the
        in-workspace one was never written to).
    Existing data is never destroyed: if both 'enrichment/' and 'enrich/'
    exist, both are left alone; only the symlinked-style rename runs when
    'enrich/' is absent.
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)

    # --- migrations (run BEFORE pre-creating SUBDIRS so 'enrich/' isn't
    # created empty next to a populated 'enrichment/') -----------------------
    old_enrich = path / "enrichment"
    new_enrich = path / "enrich"
    # Symlink-safety: lstat/.is_symlink() checks BEFORE Path.exists() (which
    # follows symlinks). If 'enrich/' is a broken symlink, exists() returns
    # False but renaming over it would silently clobber the symlink target.
    # If 'enrichment/' is itself a symlink, leave it alone -- the user
    # pointed it at something on purpose; we shouldn't move the link.
    if (old_enrich.is_dir() and not old_enrich.is_symlink()
            and not new_enrich.exists()
            and not new_enrich.is_symlink()):
        try:
            old_enrich.rename(new_enrich)
        except OSError:
            # Cross-device or permission failure: leave the old dir alone.
            # The ingestor accepts both names so the workspace still works.
            pass

    legacy_logs = path / "logs"
    # Don't follow a symlink for 'logs/' either. If it's a symlink pointing
    # elsewhere, the user explicitly set that up -- leave it. is_dir() on a
    # symlink follows by default, so use a non-followed check.
    if legacy_logs.is_dir() and not legacy_logs.is_symlink():
        try:
            # Only remove if empty -- never blow away log files the user
            # might have copied here manually.
            legacy_logs.rmdir()
        except OSError:
            pass

    # --- standard layout ----------------------------------------------------
    # Per-module subdirs under cygor-enumeration-modules/ are intentionally
    # NOT pre-created. cygor/modules/base.py:_module_outdir() creates the
    # right subdir for whichever module actually runs, so seeding empty
    # folders here would either lie about what's been used or quietly drift
    # out of sync as modules are added/removed.
    for rel in SUBDIRS:
        (path / rel).mkdir(parents=True, exist_ok=True)

    meta_file = path / ".cygor-workspace.json"
    if not meta_file.exists():
        meta_file.write_text(json.dumps({
            "workspace": str(path),
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "schema": 4,
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
    """Asterisk-prefixed list: `* name   path   size · used X ago` per line.

    The active workspace is prefixed with `*` and sorted to the top; other
    workspaces follow alphabetically. Putting the current one at the top
    matters more than strict alphabetic order -- 'list' is the command
    you'll run most when you want to confirm what's active.
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


# ----------------------------------------------------------------------
# Commands (English-verb subcommand surface)
# ----------------------------------------------------------------------
def cmd_list(args: argparse.Namespace) -> int:
    """`cygor workspace list` (or bare `cygor workspace`): list workspaces,
    asterisk-prefixed active. When nothing is registered, print a friendly
    empty-state pointing at `create`."""
    cfg = _migrate_old_config(_load_config())
    if not cfg.get("workspaces"):
        print(f"{Fore.CYAN}[i]{Style.RESET_ALL} No workspaces registered yet.")
        print(f"    Create one with: {Fore.CYAN}cygor workspace create <name>{Style.RESET_ALL}")
        return 0
    _print_workspace_list(cfg)
    if not cfg.get("active_workspace"):
        # Workspaces exist but none is selected -- scans won't have a target.
        print()
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No workspace is currently selected.")
        print(f"    Pick one with: {Fore.CYAN}cygor workspace select <name>{Style.RESET_ALL}")
    return 0


def cmd_select(args: argparse.Namespace) -> int:
    """`cygor workspace select <name>`: switch the active workspace by name."""
    name = args.name
    cfg = _migrate_old_config(_load_config())
    if name not in cfg.get("workspaces", {}):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace not found: {name}", file=sys.stderr)
        known = sorted(cfg.get("workspaces", {}).keys())
        if known:
            print("    Available workspaces:", file=sys.stderr)
            for n in known:
                print(f"      - {n}", file=sys.stderr)
        else:
            print(f"    Create one with: cygor workspace create <name>", file=sys.stderr)
        return 2

    ws_path = _resolve_path(cfg["workspaces"][name]["path"])
    if not ws_path.exists():
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace path does not exist: {ws_path}",
              file=sys.stderr)
        return 2

    # Eagerly bring the workspace up to the current layout: fills in any
    # newly-added SUBDIRS entries and runs the legacy-name migrations
    # (e.g. 'enrichment/' -> 'enrich/'). Idempotent and cheap.
    ensure_workspace_dirs(ws_path)

    _set_active(cfg, name)
    _update_last_used(name, cfg)
    _save_config(cfg)
    print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Selected workspace: "
          f"{Fore.CYAN}{name}{Style.RESET_ALL}  ({ws_path})")
    return 0


def cmd_create(args: argparse.Namespace) -> int:
    """`cygor workspace create <name>`: create a new workspace, register it,
    select it. Default location is `<workspaces_root>/<name>/`; pass
    `--path /custom/dir` to place it elsewhere (shared drives, large
    engagement folders).

    For convenience, the positional may itself be a path: if `<name>`
    looks like a path (contains `/`, or starts with `~`/`.`), it's treated
    as `--path`, and the workspace is named after the trailing directory.
    So `cygor workspace create /opt/engagements/acme` is shorthand for
    `cygor workspace create acme --path /opt/engagements/acme`."""
    raw = args.name
    custom_path = getattr(args, "path", None)

    # Path-shaped positional? Promote it to --path and use the basename
    # as the registry name. Anyone passing both forms is asking ambiguously.
    if "/" in raw or raw.startswith("~") or raw.startswith("."):
        if custom_path:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Pass either a name or a path-shaped "
                  f"positional, not both. Got name={raw!r} and --path={custom_path!r}.",
                  file=sys.stderr)
            return 2
        resolved = _resolve_path(raw)
        # Trailing slash like '/foo/bar/' -> bar; root '/' -> empty -> reject.
        name = resolved.name
        if not name:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Could not derive a workspace name "
                  f"from path: {raw}", file=sys.stderr)
            return 2
        ws_path = resolved
    else:
        name = raw
        ws_path = _resolve_path(custom_path) if custom_path else workspaces_root() / name

    cfg = _migrate_old_config(_load_config())
    if name in cfg.get("workspaces", {}):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace already exists: {name}",
              file=sys.stderr)
        return 2

    # Single source of truth for the layout: ensure_workspace_dirs() pre-creates
    # every SUBDIRS entry, runs the legacy-name migrations, and writes a
    # minimal marker. Then overlay the richer per-subdir description so
    # 'cygor workspace info' and external tooling can introspect the layout.
    ensure_workspace_dirs(ws_path)
    (ws_path / ".cygor-workspace.json").write_text(json.dumps({
        "workspace": str(ws_path),
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
        "schema": 4,
        "description": "Cygor workspace directory for scan and enumeration data.",
        "subdirectories": {
            "nmap":                       "Nmap scan results",
            "masscan":                    "Masscan discovery results",
            "naabu":                      "Naabu port discovery results",
            "icmp":                       "ICMP host-discovery results",
            "parsed-hostlists":           "Aggregated and categorized hostlists",
            "enrich":                     "Enrichment results (Shodan, VT, crt.sh, ...)",
            "credrecon":                  "Credential reconnaissance results",
            "schedule-scans":             "Scheduled / automated scan output",
            "cygor-enumeration-modules":  "Per-module output (lockon, smbexplorer, ...)",
        },
    }, indent=2))

    ws_name = _register_workspace(cfg, ws_path, name=name)
    # Creating a workspace selects it immediately -- saves a follow-up
    # 'select' call for the common case of "make and use".
    _set_active(cfg, ws_name)
    _save_config(cfg)
    print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Created workspace: "
          f"{Fore.CYAN}{ws_name}{Style.RESET_ALL}  ({ws_path})")
    return 0


def cmd_delete(args: argparse.Namespace) -> int:
    """`cygor workspace delete <name>`: remove a workspace from the registry.

    Default behaviour preserves files on disk -- delete is just unregistering.
    Pass `--purge` to also delete the directory tree (asks for confirmation
    first; type the workspace name to proceed).

    If you delete the active workspace, the next remaining one is auto-
    selected so you're never stranded. If the registry ends up empty,
    nothing is selected; the user has to create or select one before
    scans can save output again.
    """
    name = args.name
    purge = getattr(args, "purge", False)
    cfg = _migrate_old_config(_load_config())
    if name not in cfg.get("workspaces", {}):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace not found: {name}", file=sys.stderr)
        return 2

    ws_data = cfg["workspaces"][name]
    ws_path = _resolve_path(ws_data["path"])
    was_active = (name == cfg.get("active_workspace"))

    if purge:
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
        print(f"    Pass {Fore.CYAN}--purge{Style.RESET_ALL} next time to also delete the directory.")

    if was_active:
        remaining = sorted(cfg.get("workspaces", {}).keys())
        if remaining:
            _set_active(cfg, remaining[0])
            _save_config(cfg)
            print(f"    Selected: {Fore.CYAN}{remaining[0]}{Style.RESET_ALL}")
        else:
            print(f"    No workspaces left. Create one with: "
                  f"{Fore.CYAN}cygor workspace create <name>{Style.RESET_ALL}")
    return 0


def cmd_rename(args: argparse.Namespace) -> int:
    """`cygor workspace rename <old> <new>`: rename a workspace in the registry.

    Renames the registry key only; the directory on disk keeps its current
    name. Preserves activation state (if the renamed workspace was active,
    it stays active under the new name). Errors if `old` doesn't exist or
    `new` collides with an existing workspace.
    """
    old, new = args.old, args.new
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


def cmd_info(args: argparse.Namespace) -> int:
    """`cygor workspace info <name>`: show path/status/timestamps/size +
    per-subdirectory file counts."""
    name = args.name
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


def cmd_path(args: argparse.Namespace) -> int:
    """`cygor workspace path`: print the active workspace path, nothing else.

    Designed for shell substitution:  `cd "$(cygor workspace path)"`

    Writes raw bytes to fd 1 to bypass colorama's autoreset wrapper -- the
    CLI initialises colorama with autoreset=True everywhere else, which
    appends a \\x1b[0m reset after every print() and would contaminate
    output meant for `$(...)`.
    """
    p = active_workspace_path()
    if p is None:
        return 1
    os.write(1, f"{p}\n".encode())
    return 0


def cmd_clean(args: argparse.Namespace) -> int:
    """`cygor workspace clean [<name>]`: remove generated scan output from a
    workspace (preserves the layout). With no name, operates on the active
    workspace."""
    cfg = _migrate_old_config(_load_config())
    name = getattr(args, "name", None)
    if name:
        if name not in cfg.get("workspaces", {}):
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Workspace not found: {name}",
                  file=sys.stderr)
            return 2
        ws_path = _resolve_path(cfg["workspaces"][name]["path"])
    else:
        ws_path = active_workspace_path()
        if ws_path is None:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} No workspace is selected, and none was passed.",
                  file=sys.stderr)
            print(f"    Pass a name: {Fore.CYAN}cygor workspace clean <name>{Style.RESET_ALL}",
                  file=sys.stderr)
            print(f"    Or select one first: {Fore.CYAN}cygor workspace select <name>{Style.RESET_ALL}",
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
# CLI Parser  (subcommand style, English verbs)
# ----------------------------------------------------------------------
def build_parser(prog="cygor workspace") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description=(
            "Manage Cygor workspaces -- the directories where scan and module "
            "output is saved. Run with no arguments (or `list`) to see what's "
            "registered. You must create a workspace and select it before "
            "scans can save output; nothing is created automatically. New "
            f"workspaces go under {DEFAULT_WORKSPACES_ROOT} unless you pass "
            "--path on create (or override the root with $CYGOR_WORKSPACES_ROOT)."
        ),
        epilog="""
Examples:
  # List workspaces (the active one is marked with *)
  cygor workspace
  cygor workspace list

  # Create a new workspace (created under the workspaces root by default)
  cygor workspace create acme

  # Create at a custom location (shared drive, large engagement folder)
  cygor workspace create acme --path /mnt/engagements/acme

  # Switch the active workspace
  cygor workspace select acme

  # Detail view of one workspace
  cygor workspace info acme

  # Rename
  cygor workspace rename acme acme-2026

  # Delete from the registry (files preserved)
  cygor workspace delete acme

  # Delete + wipe the directory on disk (asks for confirmation)
  cygor workspace delete acme --purge

  # Trim old scan output (keep the 3 newest per subdir)
  cygor workspace clean --keep-last 3

  # Use in scripts
  cd "$(cygor workspace path)"
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # No required=True: bare `cygor workspace` falls through to cmd_list.
    sub = p.add_subparsers(dest="subcmd", metavar="<command>")

    # list -- bare command's also reaches this via main()'s fall-through
    pls = sub.add_parser("list",
        help="List registered workspaces (* marks active).",
        description="List every registered workspace. The active one is "
                    "prefixed with `*`. Same output as bare `cygor workspace`.")
    pls.set_defaults(func=cmd_list)

    # create -- new workspace + register + select
    pcr = sub.add_parser("create",
        help="Create a new workspace.",
        description=f"Create a new workspace directory at {DEFAULT_WORKSPACES_ROOT}/<name>/ "
                    f"with the standard subdirectory layout, register it, and select it. "
                    f"Use `--path DIR` to put the directory somewhere else.")
    pcr.add_argument("name", help="Name for the new workspace")
    pcr.add_argument("--path", metavar="DIR",
        help="Custom directory location (default: <workspaces_root>/<name>/)")
    pcr.set_defaults(func=cmd_create)

    # select -- switch active workspace
    psel = sub.add_parser("select",
        help="Switch the active workspace.",
        description="Make NAME the active workspace. All subsequent scans / "
                    "module runs write to it until you switch again.")
    psel.add_argument("name", help="Workspace name to select")
    psel.set_defaults(func=cmd_select)

    # info -- subdirs + sizes + timestamps
    pinfo = sub.add_parser("info",
        help="Show subdirectories, sizes, and timestamps for a workspace.",
        description="Show path, status, timestamps, total size, and per-"
                    "subdirectory file counts for the given workspace.")
    pinfo.add_argument("name", help="Workspace name")
    pinfo.set_defaults(func=cmd_info)

    # rename
    prn = sub.add_parser("rename",
        help="Rename a workspace.",
        description="Rename a workspace in cygor's registry. The directory on "
                    "disk keeps its original name; only the registry key changes. "
                    "If the renamed workspace was active, it stays active under "
                    "the new name.")
    prn.add_argument("old", help="Current name")
    prn.add_argument("new", help="New name")
    prn.set_defaults(func=cmd_rename)

    # delete -- unregister; --purge also wipes files
    pdel = sub.add_parser("delete",
        help="Delete a workspace from the registry (files preserved unless --purge).",
        description="Remove the workspace from cygor's registry. Files on disk "
                    "are preserved by default. Pass `--purge` to also delete the "
                    "directory tree (you'll be asked to type the workspace name "
                    "to confirm).")
    pdel.add_argument("name", help="Workspace name to delete")
    pdel.add_argument("--purge", action="store_true",
        help="Also delete the directory on disk (asks for confirmation)")
    pdel.set_defaults(func=cmd_delete)

    # clean -- trim old output
    pcl = sub.add_parser("clean",
        help="Trim old scan output (the layout itself is preserved).",
        description="Remove generated scan output from inside a workspace. "
                    "The workspace itself, its layout, and its registration are "
                    "preserved. With no name argument, operates on the active "
                    "workspace.")
    pcl.add_argument("name", nargs="?",
        help="Workspace name (default: active workspace)")
    pcl.add_argument("--keep-last", type=int, metavar="N",
        help="Keep the N most recent entries per subdirectory; remove older")
    pcl.add_argument("--dry-run", action="store_true",
        help="Show what would be removed without deleting")
    pcl.add_argument("--yes", "-y", action="store_true",
        help="Do not prompt for confirmation")
    pcl.set_defaults(func=cmd_clean)

    # path -- one-line scriptable accessor
    ppath = sub.add_parser("path",
        help="Print the active workspace path (for shell scripting).",
        description="Print only the active workspace path on stdout, with no "
                    "decoration or colour codes. Designed for shell substitution: "
                    "`cd \"$(cygor workspace path)\"`. Exits 1 (with no output) "
                    "when no workspace is selected.")
    ppath.set_defaults(func=cmd_path)

    return p


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    args = build_parser().parse_args(argv)
    # Bare `cygor workspace` -> list.
    if not getattr(args, "subcmd", None):
        return cmd_list(args)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
