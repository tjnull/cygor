import argparse
import json
import os
import sys
import datetime
from pathlib import Path

APP_NAME = "cygor"
CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_NAME
CONFIG_FILE = CONFIG_DIR / "config.json"

# ----------------------------------------------------------------------
# Final, minimal workspace layout
# ----------------------------------------------------------------------
SUBDIRS = [
    "nmap",
    "masscan",
    "naabu",
    "parsed-hostlists",
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
        "schema": 2,
        "description": (
            "Cygor workspace directory structure for scan and enumeration data."
        ),
        "subdirectories": {
            "nmap": "Nmap scan data and parsed XML output",
            "masscan": "Masscan discovery results",
            "naabu": "Naabu discovery results",
            "parsed-hostlists": "Aggregated and categorized hostlists",
            "cygor-enumeration-modules": {
                "description": "Output directories for enumeration modules",
                "modules": ["lockon", "smbexplorer", "nfsexplorer", "httpx", "rdpmapper"]
            },
            "logs": "General log output and runtime information"
        },
    }
    (ws / ".cygor-workspace.json").write_text(json.dumps(meta, indent=2))

    if args.default:
        cfg = _load_config()
        cfg["default_workspace"] = str(ws)
        _save_config(cfg)
        print(f"[✓] Cygor workspace initialized and set as default: {ws}")
    else:
        print(f"[✓] Cygor workspace initialized at: {ws}")
        print(f"[i] To make this the default workspace:")
        print(f"    cygor workspace set-default \"{ws}\"")
    return 0


def cmd_set_default(args: argparse.Namespace) -> int:
    ws = _resolve_path(args.path)
    if not ws.exists():
        print(f"[!] Workspace does not exist: {ws}", file=sys.stderr)
        return 2
    cfg = _load_config()
    cfg["default_workspace"] = str(ws)
    _save_config(cfg)
    print(f"[✓] Default workspace set to: {ws}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    cfg = _load_config()
    ws = cfg.get("default_workspace")
    if ws:
        print(ws)
        return 0
    print("[i] No default workspace is currently set.")
    return 1


def cmd_unset(args: argparse.Namespace) -> int:
    cfg = _load_config()
    if "default_workspace" in cfg:
        old = cfg.pop("default_workspace")
        _save_config(cfg)
        print(f"[✓] Default workspace unset (was: {old})")
        print("[i] Cygor will now operate without a global workspace.")
        print("    Each scan or module can freely specify its own output location.")
        return 0
    else:
        print("[i] No default workspace is currently set.")
        return 0

# ----------------------------------------------------------------------
# CLI Parser
# ----------------------------------------------------------------------
def build_parser(prog="cygor workspace") -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=prog,
        description="Manage Cygor workspaces (optional global directories for storing all scan and module data).",
    )
    sub = p.add_subparsers(dest="subcmd", required=True)

    pi = sub.add_parser("init", help="Create a new workspace at PATH and standard subfolders.")
    pi.add_argument("path", help="Path to create/use as the workspace directory")
    pi.add_argument("--default", action="store_true", help="Also set this workspace as the global default")
    pi.set_defaults(func=cmd_init)

    ps = sub.add_parser("set-default", help="Set an existing directory as the global workspace.")
    ps.add_argument("path", help="Existing workspace path")
    ps.set_defaults(func=cmd_set_default)

    pg = sub.add_parser("show", help="Display the current default workspace path.")
    pg.set_defaults(func=cmd_show)

    pu = sub.add_parser("unset", help="Unset/remove the current default workspace (return to free mode).")
    pu.set_defaults(func=cmd_unset)

    return p


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
