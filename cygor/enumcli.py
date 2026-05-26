# cygor/enum.py

import argparse
import os
import importlib.util
import runpy
import sys
import subprocess
import pkgutil
import pathlib
from colorama import Fore, Style, init
from argparse import RawTextHelpFormatter

init(autoreset=True, strip=False)

def _propagate_workspace_env():
    """Ensure CYGOR_WORKSPACE reflects the active workspace at CLI-invocation time.

    Done here (called from ``main()``), NOT at import, so merely importing this
    module has no global side effects -- importing it must never mutate
    ``os.environ`` (that made test runs order-dependent and leaked the user's
    active workspace into unrelated code). CYGOR_WORKSPACE is canonical; the
    legacy CYGOR_RESULTS_DIR alias is honored if already set.
    """
    if os.environ.get("CYGOR_WORKSPACE") or os.environ.get("CYGOR_RESULTS_DIR"):
        return
    from cygor.workspace import resolve_workspace
    ws = resolve_workspace()
    if ws:
        os.environ["CYGOR_WORKSPACE"] = str(ws)


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

    # Framework files that are not runnable modules
    FRAMEWORK_FILES = {
        "base",           # Base class for modules
        "schema",         # Pydantic schema definitions
        "exporters",      # Export helper functions
    }

    # Example/template files (for developers, not production use)
    EXAMPLE_FILES = {
        "example_simple",
        "example_wrapper",
        "template_module",
    }

    # Deprecated modules (merged into other modules)
    DEPRECATED_MODULES = {
        "rdpshot",   # Merged into lockon
        "vncshot",   # Merged into lockon
        "x11shot",   # Merged into lockon
    }

    # Combine all exclusions
    EXCLUDED = FRAMEWORK_FILES | EXAMPLE_FILES | DEPRECATED_MODULES

    modules = []
    for finder, name, ispkg in pkgutil.iter_modules([str(pkgpath)]):
        if not ispkg:
            # Only include modules that actually exist as .py files
            # and are not in the exclusion list
            if (pkgpath / f"{name}.py").exists() and name not in EXCLUDED:
                modules.append(name)

    return sorted(modules)

# Service -> enumeration module dispatch. Keyed by the parsed-hostlists/<service>
# bucket name (see cygor/parse.py SERVICES). Each entry lists the module slug and
# the args that precede the hostlist path on its command line. This is the
# "detect service -> run the right enumeration" layer (cf. AutoRecon), driven by
# cygor's own per-service host bucketing.
SERVICE_MODULES = {
    "snmp":  [("snmpexplorer", ["-f"])],
    # RPC enumeration rides over SMB (445), so it shares the smb bucket; the two
    # modules write to distinct slug dirs, so no result collision.
    "smb":   [("smbexplorer", ["-i"]), ("rpcexplorer", ["-f"])],
    "nfs":   [("nfsexplorer", ["-i"])],
    "ftp":   [("ftpexplorer", ["-f"])],
    "smtp":  [("smtpexplorer", ["-f"])],
    "http":  [("lockon", ["http", "-f"])],
    "https": [("lockon", ["https", "-f"])],
    "rdp":   [("lockon", ["rdp", "-f"])],
    "vnc":   [("lockon", ["vnc", "-f"])],
    "dns":   [("dnsexplorer", ["-f"])],
    "ldap":  [("ldapexplorer", ["-f"])],
    # Databases: one module, dispatched per parsed bucket via --service so it
    # only probes the port cygor already found open on those hosts.
    "redis":         [("dbprobe", ["--service", "redis", "-f"])],
    "mysql":         [("dbprobe", ["--service", "mysql", "-f"])],
    "postgres":      [("dbprobe", ["--service", "postgres", "-f"])],
    "mongodb":       [("dbprobe", ["--service", "mongodb", "-f"])],
    "elasticsearch": [("dbprobe", ["--service", "elasticsearch", "-f"])],
    "couchdb":       [("dbprobe", ["--service", "couchdb", "-f"])],
}


def _run_auto():
    """Auto-dispatch: for each parsed service hostlist, run its mapped module(s).

    Reads <workspace>/parsed-hostlists/<service>/<service>-hostlist.txt and runs
    the enumeration module registered for that service in SERVICE_MODULES. Each
    module runs as an isolated subprocess so one module's failure can't abort the
    rest. Requires `cygor parse` to have produced the hostlists first.
    """
    from cygor.workspace import require_workspace
    ws = require_workspace()
    # Propagate the resolved workspace to the module subprocesses via an explicit
    # env copy rather than mutating this process's os.environ, so callers (and
    # tests) that import/run this aren't left with a leaked CYGOR_WORKSPACE.
    child_env = dict(os.environ)
    child_env["CYGOR_WORKSPACE"] = str(ws)

    parsed = ws / "parsed-hostlists"
    if not parsed.is_dir():
        print(f"{Fore.RED}[!] No parsed-hostlists/ in workspace. "
              f"Run 'cygor parse <scan output>' first.{Style.RESET_ALL}", file=sys.stderr)
        return 1

    available = set(discover_modules())
    dispatched = 0
    skipped_no_module = []

    print(f"{Fore.CYAN}[*] Auto-enumeration: matching parsed services to modules{Style.RESET_ALL}")
    for service, modules in SERVICE_MODULES.items():
        hostlist = parsed / service / f"{service}-hostlist.txt"
        if not hostlist.is_file():
            continue
        n_hosts = sum(1 for line in hostlist.read_text(errors="ignore").splitlines() if line.strip())
        if n_hosts == 0:
            continue
        for module, pre_args in modules:
            if module not in available:
                skipped_no_module.append(f"{service}->{module}")
                continue
            print(f"\n{Fore.MAGENTA}{'='*60}\n[+] {service}: {n_hosts} host(s) -> "
                  f"enum {module}\n{'='*60}{Style.RESET_ALL}")
            cmd = [sys.executable, "-m", "cygor.enumcli", module, *pre_args, str(hostlist)]
            try:
                subprocess.run(cmd, check=False, env=child_env)
                dispatched += 1
            except Exception as e:
                print(f"{Fore.RED}[!] {module} failed for {service}: {e}{Style.RESET_ALL}", file=sys.stderr)

    print()
    if skipped_no_module:
        print(f"{Fore.YELLOW}[i] No module installed for: {', '.join(skipped_no_module)}{Style.RESET_ALL}")
    if dispatched == 0:
        print(f"{Fore.YELLOW}[i] No parsed service hostlists matched a module -- nothing to enumerate.{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[+] Auto-enumeration dispatched {dispatched} module run(s).{Style.RESET_ALL}")
    return 0


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

    {Fore.YELLOW}# Run lockon module against http hostlist (set a workspace first: cygor workspace){Style.RESET_ALL}
    cygor enum lockon -f "$CYGOR_WORKSPACE"/parsed-hostlists/http/http-hostlist.txt

    {Fore.YELLOW}# Run nfsexplorer against NFS targets{Style.RESET_ALL}
    cygor enum nfsexplorer --targets "$CYGOR_WORKSPACE"/parsed-hostlists/nfs/nfs-hostlist.txt --exports-only

    {Fore.YELLOW}# Run smbexplorer with 8 threads{Style.RESET_ALL}
    cygor enum smbexplorer --targets "$CYGOR_WORKSPACE"/parsed-hostlists/smb/smb-hostlist.txt --threads 8

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
    parser.add_argument("--auto", action="store_true",
                        help="Auto-run the right module for each parsed service hostlist in the workspace")
    parser.add_argument("module", nargs="?", help="Module to run (from cygor/modules/)")

    return parser

def main(argv=None):
    _propagate_workspace_env()
    parser = build_parser()

    # Only parse the first arg (list or module), leave the rest untouched
    if argv is None:
        argv = sys.argv[1:]

    if "--list" in argv:
        modules = discover_modules()
        print("\n".join(modules))
        return

    if "--auto" in argv:
        sys.exit(_run_auto() or 0)

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
