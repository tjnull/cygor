# cygor/enum.py

import argparse
import os
import importlib.util
import runpy
import sys
import pkgutil
import pathlib
from colorama import Fore, Style, init
from argparse import RawTextHelpFormatter

init(autoreset=True)

# --- Workspace propagation ---
import os
import json
from pathlib import Path

def _get_active_workspace() -> str | None:
    """
    Determine the currently active workspace.
    Priority:
      1. CYGOR_RESULTS_DIR (used internally by modules)
      2. CYGOR_WORKSPACE (manual override)
      3. ~/.config/cygor/config.json (default workspace set by user)
    """
    # 1) explicit env var
    ws = os.environ.get("CYGOR_RESULTS_DIR") or os.environ.get("CYGOR_WORKSPACE")
    if ws:
        return ws

    # 2) fallback to config file
    cfg_file = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "cygor" / "config.json"
    if cfg_file.exists():
        try:
            data = json.loads(cfg_file.read_text())
            ws = data.get("default_workspace")
            if ws:
                return ws
        except Exception:
            pass
    return None

# Load or propagate CYGOR_RESULTS_DIR
ws = _get_active_workspace()
if ws and not os.environ.get("CYGOR_RESULTS_DIR"):
    os.environ["CYGOR_RESULTS_DIR"] = ws
    # Optional: print(f"[i] Using workspace: {ws}")



class ColorHelpFormatter(RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    def start_section(self, heading):
        heading = f"{Fore.CYAN}{heading}{Style.RESET_ALL}"
        super().start_section(heading)

    def _format_action_invocation(self, action):
        parts = super()._format_action_invocation(action)
        return f"{Fore.YELLOW}{parts}{Style.RESET_ALL}"

def discover_modules():
    """Discover available enum modules under cygor/modules/."""
    import cygor.modules
    pkgpath = pathlib.Path(cygor.modules.__file__).parent
    modules = []
    for finder, name, ispkg in pkgutil.iter_modules([str(pkgpath)]):
        if not ispkg:
            # Only include modules that actually exist as .py files
            if (pkgpath / f"{name}.py").exists():
                modules.append(name)
    return sorted(modules)

def build_parser():
    banner = f"""
    {Fore.GREEN}{'='*60}
      CYGOR ENUM - Enumeration Modules
    {Fore.GREEN}{'='*60}{Style.RESET_ALL}
    """

    modules = discover_modules()
    modules_list = "\n".join(f"    - {Fore.YELLOW}{m}{Style.RESET_ALL}" for m in modules) or "    (none found)"

    examples = f"""
   {Fore.MAGENTA}Examples:{Style.RESET_ALL}

    {Fore.YELLOW}# List all available modules{Style.RESET_ALL}
    cygor enum --list

    {Fore.YELLOW}# Run lockon module against http hostlist{Style.RESET_ALL}
    cygor enum lockon -f results/parsed-hostlists/http/http-hostlist.txt -o results/enum/lockon

    {Fore.YELLOW}# Run nfsexplorer against NFS targets{Style.RESET_ALL}
    cygor enum nfsexplorer --targets results/parsed-hostlists/nfs/nfs-hostlist.txt --exports-only

    {Fore.YELLOW}# Run smbexplorer with 8 threads{Style.RESET_ALL}
    cygor enum smbexplorer --targets results/parsed-hostlists/smb/smb-hostlist.txt --threads 8

   {Fore.MAGENTA}Available Modules:{Style.RESET_ALL}
{modules_list}
"""

    parser = argparse.ArgumentParser(
        prog="cygor enum",
        usage="cygor enum [--list] <module> [options]",
        description=banner + "\nRun enumeration modules against parsed hostlists or custom targets.\n",
        epilog=examples,
        formatter_class=ColorHelpFormatter,
    )

    parser.add_argument("--list", action="store_true", help="List available modules")
    parser.add_argument("module", nargs="?", help="Module to run (from cygor/modules/)")

    return parser

def main(argv=None):
    parser = build_parser()

    # Only parse the first arg (list or module), leave the rest untouched
    if argv is None:
        argv = sys.argv[1:]

    if "--list" in argv:
        modules = discover_modules()
        print("\n".join(modules))
        return

    if len(argv) > 0 and not argv[0].startswith("-"):
        # First positional = module name
        module = argv[0]
        extra = argv[1:]  # everything after module, including -h
        modname = f"cygor.modules.{module}"
        sys.argv = [f"cygor {module}"] + extra
        try:
            runpy.run_module(modname, run_name="__main__", alter_sys=True)
        except ModuleNotFoundError:
            print(f"{Fore.RED}[!] Module '{module}' not found in cygor/modules/")
        return

    # Otherwise, show enum help
    parser.print_help()

if __name__ == "__main__":
    main()
