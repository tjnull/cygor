# cygor/cli.py
import os
import sys
import shutil
import pathlib
import importlib
import runpy
import json
import subprocess
from typing import Optional
from pathlib import Path
from .precheck import run_once_precheck

# Import colorama for colored output
try:
    from colorama import Fore, Style, init
    init(autoreset=True, strip=False)
    HAS_COLORAMA = True
except ImportError:
    # Fallback if colorama is not available
    class Fore:
        CYAN = ""
        GREEN = ""
        YELLOW = ""
        MAGENTA = ""
        BLUE = ""
        RED = ""
        RESET = ""
    class Style:
        RESET_ALL = ""
        BRIGHT = ""
    HAS_COLORAMA = False


def _print_help():
    """Print styled CLI help using Rich.

    Design principles:
    - Single accent color (cygor blue) — no rainbow per-section colors.
    - Tight vertical rhythm — section header sits one line above its command
      table with no extra padding rows.
    - Section headers marked by weight + a thin rule, not a bright color.
    - Hints (sudo, etc.) live in dim italic at the right of each row, never
      inline-yellow inside the description.
    """
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.text import Text
    except ImportError:
        print(_format_usage_plain())
        print(_workspace_status_plain())
        return

    from . import __version__

    console = Console(highlight=False)
    BLUE = "#3b82f6"
    DIM = "grey50"
    HEADER = "bold white"

    # ── Logo ──
    logo_lines = [
        " ██████╗██╗   ██╗ ██████╗  ██████╗ ██████╗ ",
        "██╔════╝╚██╗ ██╔╝██╔════╝ ██╔═══██╗██╔══██╗",
        "██║      ╚████╔╝ ██║  ███╗██║   ██║██████╔╝",
        "██║       ╚██╔╝  ██║   ██║██║   ██║██╔══██╗",
        "╚██████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║",
        " ╚═════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝",
    ]
    console.print()
    for line in logo_lines:
        console.print(f"  {line}", style=BLUE)
    console.print()

    tagline = Text("  Modular Asset Discovery Framework", style=HEADER)
    tagline.append(f"   v{__version__} · by Tj Null", style=DIM)
    console.print(tagline)
    console.print()

    # ── Usage ──
    usage = Text("  Usage:  ", style=DIM)
    usage.append("cygor", style=f"bold {BLUE}")
    usage.append(" <command> [args]", style="white")
    console.print(usage)
    console.print()

    # ── Active workspace ──
    # Surfaced here because scans/parse/enum require a workspace (there is no
    # implicit ./results default); make it obvious when one isn't set yet.
    ws = _default_workspace()
    ws_line = Text("  Workspace:  ", style=DIM)
    if ws:
        ws_line.append(ws, style="white")
        console.print(ws_line)
    else:
        ws_line.append("not set", style="bold yellow")
        console.print(ws_line)
        hint = Text("              set one with: ", style=DIM)
        hint.append("cygor workspace init <path> --default", style=f"bold {BLUE}")
        console.print(hint)
    console.print()

    # ── Command sections ──
    # (header, [(command, description, hint), ...])
    # Descriptions are kept tight (≈ ≤ 50 chars) so a typical 100-col
    # terminal never wraps; the hint glues onto the description with two
    # spaces of separation in dim italic.
    categories = [
        ("Scanning & Discovery", [
            ("scan", "Discover hosts and services (nmap automation)", "sudo"),
        ]),
        ("Analysis & Processing", [
            ("parse", "Parse NMAP files into categorized hostlists", ""),
            ("enrich", "Look up IOCs via external sources (Shodan, VT, crt.sh, …)", ""),
        ]),
        ("Enumeration & Testing", [
            ("enum", "Run enumeration modules against discovered services", ""),
            ("credrecon", "Test default/weak credentials across protocols", ""),
        ]),
        ("Management", [
            ("workspace", "Manage workspaces (init / set-default / show)", ""),
            ("proxy", "Configure HTTP/HTTPS proxy", ""),
            ("plugin", "Manage community plugins", ""),
            ("sync", "Refresh data sources (fingerprints / plugins)", ""),
            ("web", "Control the Cygor Web UI (start / stop / status)", ""),
            ("setup-privileges", "Configure scan tool privileges (caps / sudoers)", ""),
            ("banner", "Display the full Cygor ASCII art banner", ""),
        ]),
    ]

    def _section_table():
        t = Table(
            show_header=False,
            box=None,
            padding=(0, 0, 0, 0),
            pad_edge=False,
            collapse_padding=True,
        )
        # 4-space indent puts each command visually nested under its
        # section header (which is at 2 spaces).
        t.add_column("indent", width=4)
        t.add_column("cmd", style=f"bold {BLUE}", width=18, no_wrap=True)
        # Single column for description + inline hint — gives Rich one less
        # thing to juggle, and the dim italic hint sits cleanly at the end
        # of each line without competing for width.
        t.add_column("desc", overflow="ellipsis", no_wrap=True)
        return t

    for header, cmds in categories:
        console.print(f"  [{HEADER}]{header}[/{HEADER}]")
        table = _section_table()
        for cmd, desc, hint in cmds:
            row = Text(desc, style="white")
            if hint:
                row.append(f"  [{hint}]", style=f"italic {DIM}")
            table.add_row("", cmd, row)
        console.print(table)
        console.print()

    # ── Environment ── (same column shape as commands so they line up) ──
    console.print(f"  [{HEADER}]Environment[/{HEADER}]")
    env_table = Table(
        show_header=False,
        box=None,
        padding=(0, 0, 0, 0),
        pad_edge=False,
        collapse_padding=True,
    )
    env_table.add_column("indent", width=4)
    env_table.add_column("var", style=f"bold {BLUE}", width=20, no_wrap=True)
    env_table.add_column("desc", style="white", overflow="ellipsis", no_wrap=True)
    env_table.add_row("", "CYGOR_WORKSPACE", "Override the active workspace for this run")
    env_table.add_row("", "CYGOR_NO_SUDO", "Set to '1' to disable automatic sudo escalation")
    console.print(env_table)
    console.print()

    # ── Footer ──
    footer = Text("  ")
    footer.append("cygor <command> --help", style=f"bold {BLUE}")
    footer.append("   for detailed usage", style=DIM)
    console.print(footer)
    console.print()


def _format_usage_plain():
    """Plain-text fallback when Rich is not available."""
    width = 70
    header = "  Cygor - Modular Asset Discovery Framework\n"
    usage = "Usage:\n  cygor <command> [args]\n\n"
    commands = "Commands:\n\n"
    cmd_width = 20

    commands += "  Scanning & Discovery:\n"
    commands += f"    {'scan':<{cmd_width}}Automated scanner to discover hosts and services. [!] Requires root/sudo\n\n"
    commands += "  Analysis & Processing:\n"
    commands += f"    {'parse':<{cmd_width}}Analyze NMAP scan files (nmap, gnmap, xml) and extract categorized hostlists\n"
    commands += f"    {'enrich':<{cmd_width}}Enrich IOCs with passive recon from Shodan, VirusTotal, etc.\n\n"
    commands += "  Enumeration & Testing:\n"
    commands += f"    {'enum':<{cmd_width}}Load enumeration modules from cygor modules directory\n"
    commands += f"    {'credrecon':<{cmd_width}}Test default/weak credentials across protocols (HTTP, SSH, FTP, databases)\n\n"
    commands += "  Management & Interface:\n"
    commands += f"    {'workspace':<{cmd_width}}Manage workspaces (init/set-default/show)\n"
    commands += f"    {'proxy':<{cmd_width}}Configure HTTP/HTTPS proxy settings (status/set/enable/disable/test)\n"
    commands += f"    {'plugin':<{cmd_width}}Manage community plugins (list/install/validate/create/remove)\n"
    commands += f"    {'sync':<{cmd_width}}Refresh data sources: fingerprints, plugins (run with --help for subcommands)\n"
    commands += f"    {'web':<{cmd_width}}Control/launch the Cygor Web UI (start/stop/status)\n"
    commands += f"    {'setup-privileges':<{cmd_width}}Configure scan tool privileges (caps/sudoers) for web UI & daemon mode\n"
    commands += f"    {'banner':<{cmd_width}}Display the full Cygor ASCII art banner. [!] large output\n\n"

    env = "Environment Variables:\n"
    env_var_width = 25
    env += f"  {'CYGOR_WORKSPACE':<{env_var_width}}Override the active workspace for this run\n"
    env += f"  {'CYGOR_NO_SUDO':<{env_var_width}}Set to '1' to disable automatic sudo escalation\n\n"

    footer = f"{'='*width}\n"
    footer += "For more information on a specific command:\n"
    footer += "  cygor <command> --help\n"
    footer += f"{'='*width}\n"

    return header + usage + commands + env + footer


def get_usage():
    """Get the plain-text formatted usage message (for non-interactive use)."""
    return _format_usage_plain()


def _workspace_status_plain() -> str:
    """Plain-text active-workspace status line for the help screen.

    Kept out of get_usage()/_format_usage_plain() so that usage text stays
    static; this reflects current runtime state.
    """
    ws = _default_workspace()
    if ws:
        return f"  Workspace: {ws}\n"
    return (
        "  Workspace: not set\n"
        "    Set one with: cygor workspace init <path> --default\n"
    )

# ---- Workspace helpers ----
_APP_NAME = "cygor"
_CONFIG_DIR = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / _APP_NAME
_CONFIG_FILE = _CONFIG_DIR / "config.json"



def _ensure_root_for_scan(cmd_args: list[str], workspace: str | None = None) -> None:
    """
    If we are not root and the requested scan likely needs raw socket access,
    re-exec the command with sudo and ensure the workspace is propagated.

    We preserve workspace by prefixing it into the sudo environment using 'env'.
    """
    # Help/usage never needs root — don't escalate just to print the help text.
    if "-h" in cmd_args or "--help" in cmd_args:
        return

    # already root — nothing to do
    try:
        if os.geteuid() == 0:
            return
    except AttributeError:
        # Windows / weird environment — skip escalation
        return

    # Check if --use-discovery is provided (skips discovery phase, may not need root)
    args_str = " ".join(cmd_args)
    has_use_discovery = "--use-discovery" in args_str

    # Check for --sync-fp-only which doesn't need root (just downloads data)
    if "--sync-fp-only" in args_str:
        return

    # If --use-discovery is NOT provided, discovery will run with default (masscan),
    # which requires root. Also check for explicit tool mentions.
    privileged_tools = {"masscan", "nmap", "naabu"}
    needs_root = (
        not has_use_discovery  # discovery runs by default with masscan
        or any(tool in args_str for tool in privileged_tools)
    )

    if not needs_root:
        return

    if os.environ.get("CYGOR_NO_SUDO") == "1":
        return

    # Check if tools have Linux capabilities set (no sudo needed)
    try:
        from cygor.privileges import get_privilege_status
        priv_status = get_privilege_status()
        installed = [t for t in priv_status.get("tools", []) if t["installed"]]
        if installed and all(t.get("has_caps") for t in installed):
            return  # Tools have caps, no sudo needed
    except Exception:
        pass

    print("[!] Elevated privileges required for this scan (raw socket access).")
    print("[*] Re-launching with sudo...")

    # Build sudo command. Use `env VAR=val` to pass workspace into the elevated env.
    sudo_cmd = ["sudo"]
    if workspace:
        # ensure the elevated process sees the workspace path as CYGOR_WORKSPACE
        sudo_cmd += ["env", f"CYGOR_WORKSPACE={workspace}"]
    sudo_cmd += [sys.executable, "-m", "cygor.cli", "scan"] + cmd_args

    try:
        os.execvp("sudo", sudo_cmd)
    except Exception as e:
        print(f"[!] Failed to elevate privileges: {e}", file=sys.stderr)
        sys.exit(1)


def _load_cfg() -> dict:
    if _CONFIG_FILE.exists():
        try:
            return json.loads(_CONFIG_FILE.read_text())
        except Exception:
            pass
    return {}

def _default_workspace() -> str | None:
    """Get the active workspace path (env vars, then `cygor workspace` config)."""
    from cygor.workspace import resolve_workspace
    ws = resolve_workspace()
    return str(ws) if ws else None

def _ensure_env_for_workspace():
    ws = _default_workspace()
    if ws:
        os.environ.setdefault("CYGOR_WORKSPACE", ws)
    return ws



def _exec_module_argv(module_name: str, prog: str, argv: list[str]) -> None:
    """Re-exec a module with a custom program name and argv."""
    # Try to let the module use a direct entrypoint if present
    try:
        mod = __import__(module_name, fromlist=['__name__'])
        if hasattr(mod, "main"):
            sys.argv = [prog] + list(argv)
            mod.main()  # type: ignore[attr-defined]
            return
    except Exception:
        pass

    sys.argv = [prog.split()[0], *list(argv)]
    try:
        del sys.modules[module_name]
    except KeyError:
        pass
    runpy.run_module(module_name, run_name="__main__", alter_sys=True)

# --- chown support (existing functionality kept) ---
import re
def _parse_chown_paths(argv: list[str]) -> tuple[list[str], list[str]]:
    """
    Extract --chown <paths...> from argv, returning (paths, remaining_argv).
    Also accepts CYGOR_CHOWN_PATHS=path1:path2:... in the environment.
    """
    paths: list[str] = []
    rest: list[str] = []
    it = iter(argv)
    for token in it:
        if token == "--chown":
            # collect subsequent non-option tokens
            for nexttok in it:
                if nexttok.startswith("-"):
                    rest.append(nexttok)
                    break
                paths.append(nexttok)
            # continue consuming the remaining tokens
            rest.extend(list(it))
            break
        else:
            rest.append(token)

    if not paths:
        env = os.environ.get("CYGOR_CHOWN_PATHS")
        if env:
            paths = [p for p in env.split(":") if p]

    return paths, rest

def _postrun_chown(paths: list[str]) -> None:
    if not paths:
        return
    try:
        import pwd, grp
        # If running under sudo, prefer to chown back to the original user
        sudo_uid = os.environ.get("SUDO_UID")
        sudo_gid = os.environ.get("SUDO_GID")
        if sudo_uid and sudo_gid:
            uid = int(sudo_uid)
            gid = int(sudo_gid)
        else:
            uid = os.getuid()
            gid = os.getgid()

        for p in paths:
            if not p:
                continue
            if os.path.exists(p):
                for root, dirs, files in os.walk(p):
                    for d in dirs:
                        try: os.chown(os.path.join(root, d), uid, gid)
                        except Exception: pass
                    for f in files:
                        try: os.chown(os.path.join(root, f), uid, gid)
                        except Exception: pass
                # also chown the top-level path
                try:
                    os.chown(p, uid, gid)
                except Exception:
                    pass
    except Exception as e:
        print(f"[!] chown failed: {e}", file=sys.stderr)



def _handle_proxy_command(args: list[str]) -> None:
    """
    Handle proxy configuration commands.

    Usage:
        cygor proxy status              Show current proxy status
        cygor proxy set                 Set proxy configuration
        cygor proxy clear               Clear proxy configuration
        cygor proxy test                Test proxy connection
    """
    import json
    from pathlib import Path

    config_path = Path.home() / ".cygor" / "proxy_config.json"

    def load_config() -> dict:
        if config_path.exists():
            try:
                return json.loads(config_path.read_text())
            except Exception:
                pass
        return {"enabled": False, "http_proxy": "", "https_proxy": "", "no_proxy": ""}

    def save_config(config: dict) -> None:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(config, indent=2))
        config_path.chmod(0o600)

    if not args:
        print(f"{Fore.CYAN}Proxy - HTTP/HTTPS Proxy Settings{Style.RESET_ALL}\n")
        print("Usage:")
        print("  cygor proxy status                       Show current proxy status")
        print("  cygor proxy set --http URL [--https URL] [--no-proxy HOSTS]")
        print("                                           Configure proxy settings")
        print("  cygor proxy enable                       Enable configured proxy")
        print("  cygor proxy disable                      Disable proxy (keep settings)")
        print("  cygor proxy clear                        Clear all proxy settings")
        print("  cygor proxy test                         Test proxy connection")
        return

    action = args[0].lower()

    if action == "status":
        try:
            from cygor.proxy_config import get_active_proxy_info
            info = get_active_proxy_info()
        except ImportError:
            info = {"active": False, "type": None}

        config = load_config()

        print(f"{Fore.CYAN}Proxy Status{Style.RESET_ALL}")
        print("-" * 40)

        if info.get("active"):
            proxy_type = info.get("type", "unknown")
            type_display = {
                "jumpbox": "Jumpbox/SOCKS Tunnel",
                "proxychains": "Proxychains (LD_PRELOAD)",
                "configured": "Configured Proxy",
                "environment": "Environment Variables"
            }.get(proxy_type, proxy_type)

            print(f"{Fore.GREEN}Active:{Style.RESET_ALL} Yes ({type_display})")

            if info.get("http_proxy"):
                print(f"  HTTP:  {info.get('http_proxy')}")
            if info.get("https_proxy"):
                print(f"  HTTPS: {info.get('https_proxy')}")
            if info.get("socks_url"):
                print(f"  SOCKS: {info.get('socks_url')}")
        else:
            print(f"{Fore.YELLOW}Active:{Style.RESET_ALL} No (direct connections)")

        print()
        print(f"{Fore.CYAN}Configured Settings:{Style.RESET_ALL}")
        print(f"  Enabled:    {config.get('enabled', False)}")
        print(f"  HTTP:       {config.get('http_proxy') or '(not set)'}")
        print(f"  HTTPS:      {config.get('https_proxy') or '(not set)'}")
        print(f"  No Proxy:   {config.get('no_proxy') or '(not set)'}")

    elif action == "set":
        config = load_config()
        i = 1
        while i < len(args):
            if args[i] in ("--http", "-h") and i + 1 < len(args):
                config["http_proxy"] = args[i + 1]
                i += 2
            elif args[i] in ("--https", "-s") and i + 1 < len(args):
                config["https_proxy"] = args[i + 1]
                i += 2
            elif args[i] in ("--no-proxy", "-n") and i + 1 < len(args):
                config["no_proxy"] = args[i + 1]
                i += 2
            else:
                i += 1

        if not config.get("http_proxy") and not config.get("https_proxy"):
            print(f"{Fore.YELLOW}[!] No proxy URL provided.{Style.RESET_ALL}")
            print("Usage: cygor proxy set --http http://proxy:8080 [--https http://proxy:8080]")
            return

        config["enabled"] = True
        save_config(config)
        print(f"{Fore.GREEN}[+] Proxy settings saved and enabled{Style.RESET_ALL}")
        if config.get("http_proxy"):
            print(f"    HTTP:  {config.get('http_proxy')}")
        if config.get("https_proxy"):
            print(f"    HTTPS: {config.get('https_proxy')}")

    elif action == "enable":
        config = load_config()
        if not config.get("http_proxy") and not config.get("https_proxy"):
            print(f"{Fore.YELLOW}[!] No proxy configured. Use 'cygor proxy set' first.{Style.RESET_ALL}")
            return
        config["enabled"] = True
        save_config(config)
        print(f"{Fore.GREEN}[+] Proxy enabled{Style.RESET_ALL}")

    elif action == "disable":
        config = load_config()
        config["enabled"] = False
        save_config(config)
        print(f"{Fore.YELLOW}[+] Proxy disabled (settings preserved){Style.RESET_ALL}")

    elif action == "clear":
        save_config({"enabled": False, "http_proxy": "", "https_proxy": "", "no_proxy": ""})
        print(f"{Fore.GREEN}[+] Proxy settings cleared{Style.RESET_ALL}")

    elif action == "test":
        print(f"{Fore.CYAN}[*] Testing proxy connection...{Style.RESET_ALL}")
        try:
            import requests as req_lib
            from cygor.proxy_config import get_requests_proxies
            proxies = get_requests_proxies()

            # Also check configured proxy
            config = load_config()
            if config.get("enabled"):
                if config.get("http_proxy"):
                    proxies["http"] = config["http_proxy"]
                if config.get("https_proxy"):
                    proxies["https"] = config["https_proxy"]

            resp = req_lib.get("https://ipinfo.io/json", proxies=proxies if proxies else None, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                geo = f"{data.get('city', '')}, {data.get('region', '')}, {data.get('country', '')}".strip(", ")
                using_proxy = " (via proxy)" if proxies else " (direct)"
                print(f"{Fore.GREEN}[+] Connection successful{using_proxy}{Style.RESET_ALL}")
                print(f"    External IP: {data.get('ip')}")
                if geo:
                    print(f"    Location:    {geo}")
            else:
                print(f"{Fore.RED}[!] HTTP {resp.status_code}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Test failed: {e}{Style.RESET_ALL}")

    else:
        print(f"{Fore.RED}[!] Unknown action: {action}{Style.RESET_ALL}")
        print("Use 'cygor proxy' for usage information.")


def main():
    argv = sys.argv[1:]

    # --- No command provided ---
    if not argv:
        _print_help()
        # Automatically run the one-time precheck on first-time use
        try:
            run_once_precheck()
        except Exception as e:
            print(f"[!] Precheck skipped: {e}", file=sys.stderr)
        sys.exit(0)

    # --- Manual precheck command ---
    if argv[0] == "precheck":
        print("[*] Running manual dependency check...")
        try:
            run_once_precheck(force=True)
            print("[✓] Dependency verification complete.")
        except Exception as e:
            print(f"[!] Precheck error: {e}", file=sys.stderr)
        sys.exit(0)

    # --- Proceed with normal commands ---
    chown_paths, rest = _parse_chown_paths(argv)
    if not rest:
        _print_help()
        sys.exit(0)

    cmd, cmd_args = rest[0], rest[1:]


    # --- precheck command (manual run)
    if cmd == "precheck":
        print("[*] Running manual dependency check...")
        run_once_precheck(force=True)
        print("[✓] Dependency verification complete.")
        return

    chown_paths, rest = _parse_chown_paths(argv)
    if not rest:
        _print_help()
        sys.exit(0)

    cmd, cmd_args = rest[0], rest[1:]

    # --- Help flags ---
    if cmd in ("-h", "--help", "help"):
        _print_help()
        sys.exit(0)

    # --- workspace ---
    if cmd == "workspace":
        _exec_module_argv("cygor.workspace", "cygor-workspace", cmd_args)
        return

    # --- proxy ---
    if cmd == "proxy":
        _handle_proxy_command(cmd_args)
        return

    # --- plugin ---
    if cmd == "plugin":
        from cygor.cli_plugin import main as plugin_main
        plugin_main(cmd_args)
        return

    # --- banner ---
    if cmd == "banner":
        _exec_module_argv("cygor.banner", "cygor-banner", cmd_args)
        return

    # --- scan ---
    if cmd == "scan":
        # Ensure we know the workspace and set CYGOR_WORKSPACE for the current process
        ws = _ensure_env_for_workspace()

        # If workspace exists and the user hasn't provided an explicit outdir, inject it.
        # Accept both `-o`/`--outdir` (common) and `--out-dir` (other modules).
        has_outdir_flag = any(flag in cmd_args for flag in ("-o", "--outdir", "--out-dir"))
        if ws and not has_outdir_flag:
            # put the workspace first so it's obvious and preserved when re-execing via sudo
            cmd_args = ["--outdir", ws] + cmd_args

        # Now, if we require raw sockets, re-exec with sudo — workspace is already in cmd_args,
        # and we additionally export CYGOR_WORKSPACE into the elevated process env.
        _ensure_root_for_scan(cmd_args, workspace=ws)

        _exec_module_argv("cygor.scan", "cygor-scan", cmd_args)

        # post-run chown defaults: only the resolved workspace (there is no
        # implicit ./results directory anymore).
        if not chown_paths and ws and os.path.isdir(ws):
            chown_paths.append(ws)

        _postrun_chown(chown_paths)
        return



    # --- parse ---
    if cmd == "parse":
        ws = _ensure_env_for_workspace()
        enhanced = any(flag in cmd_args for flag in ("--inputs", "--emit-json", "--emit-csv", "--nmap-dir"))
        if enhanced:
            if ws and not ("-o" in cmd_args or "--out-dir" in cmd_args):
                cmd_args = ["--out-dir", ws] + cmd_args
            _exec_module_argv("cygor.parse_ext", "cygor-parsex", cmd_args)
        else:
            if ws and not ("-o" in cmd_args or "--out-dir" in cmd_args):
                cmd_args = ["--out-dir", ws] + cmd_args
            _exec_module_argv("cygor.parse", "cygor-parse", cmd_args)

        if not chown_paths and ws and os.path.isdir(ws):
            chown_paths.append(ws)
        _postrun_chown(chown_paths)
        return

    # --- enrich ---
    if cmd == "enrich":
        ws = _ensure_env_for_workspace()
        if ws and not ("-o" in cmd_args or "--output" in cmd_args):
            # Auto-set output directory to workspace if not specified
            cmd_args = ["--output", os.path.join(ws, "enrichment-results.json")] + cmd_args
        _exec_module_argv("cygor.enrich", "cygor-enrich", cmd_args)
        return

    # --- enum ---
    if cmd == "enum":
        ws = _ensure_env_for_workspace()  # sets CYGOR_WORKSPACE if default workspace exists
        if ws:
            os.environ["CYGOR_WORKSPACE"] = ws  # ensure visibility for subprocesses
        _exec_module_argv("cygor.enumcli", "cygor-enum", cmd_args)
        _postrun_chown(chown_paths)
        return

    # --- credrecon ---
    if cmd == "credrecon":
        ws = _ensure_env_for_workspace()
        if ws:
            os.environ["CYGOR_WORKSPACE"] = ws
        _exec_module_argv("cygor.credrecon.scanner", "cygor-credrecon", cmd_args)
        _postrun_chown(chown_paths)
        return

    # --- web ---
    if cmd == "web":
        webctl = importlib.import_module("cygor.webctl")
        webctl.exec_argv(cmd_args)
        return

    # --- setup-privileges ---
    if cmd == "setup-privileges":
        from cygor.privileges import cli_main as priv_main
        priv_main(cmd_args)
        return

    # --- sync ---  (unified entry point for every refreshable data source)
    if cmd == "sync":
        _run_sync(cmd_args)
        # Fingerprint syncs build very large in-memory datasets (e.g. the
        # ~10M-entry Huginn-Muninn MAC-vendor table). By the time the summary
        # prints, every result is already written to the cache via context-
        # managed files, but Python's normal shutdown then spends seconds
        # freeing those millions of objects -- so the terminal looks hung after
        # a "completed" sync. No atexit handlers run on the CLI path, so skip
        # the slow teardown and exit immediately (same trick as service.py).
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)

    _print_help()
    sys.exit(2)


def _run_sync(cmd_args: list[str]) -> None:
    """
    Master sync command — refreshes every data source cygor reads from.

    Subcommands:
      cygor sync                       Show status of every sync source
      cygor sync fingerprints [args]   Sync fingerprint databases
                                         (Huginn / Satori / OUI / cloud IP ranges)
      cygor sync plugins [args]        Update installed community plugins
      cygor sync all [args]            Run all sources in sequence

    Each subcommand accepts its own flags — run with ``--help`` for detail:
      cygor sync fingerprints --help

    Examples:
      cygor sync                                # status across every source
      cygor sync fingerprints                   # all fingerprint sources
      cygor sync fingerprints --sources cloud   # just cloud IP ranges
      cygor sync all                            # everything, in sequence
    """
    # No subcommand → unified status across every source.
    if not cmd_args or cmd_args[0] in ("-h", "--help"):
        if not cmd_args:
            _show_sync_status()
            return
        # Help text
        print(f"\n{Fore.MAGENTA}Cygor Data Sync{Style.RESET_ALL}\n")
        print("Refresh every data source the cygor pipeline reads from.\n")
        print(f"{Fore.CYAN}Subcommands:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}cygor sync{Style.RESET_ALL}                       Show status of every sync source")
        print(f"  {Fore.YELLOW}cygor sync fingerprints [args]{Style.RESET_ALL}   Huginn / Satori / OUI / cloud IP ranges")
        print(f"  {Fore.YELLOW}cygor sync plugins [args]{Style.RESET_ALL}        Update installed community plugins")
        print(f"  {Fore.YELLOW}cygor sync all{Style.RESET_ALL}                   Run every source in sequence\n")
        print(f"{Fore.CYAN}Each subcommand accepts its own flags:{Style.RESET_ALL}")
        print("  cygor sync fingerprints --help\n")
        return

    sub = cmd_args[0]
    rest = cmd_args[1:]

    if sub == "fingerprints":
        _run_fingerprint_sync(rest)
        return
    if sub == "plugins":
        # Delegate to the existing plugin-update CLI inside cli_plugin.
        from cygor.cli_plugin import main as plugin_main
        # Translate: ``cygor sync plugins`` → ``cygor plugin update --all``
        # ``cygor sync plugins --slug X`` → ``cygor plugin update X``
        # Anything else → pass through to ``cygor plugin update <args>``.
        if not rest:
            plugin_main(["update", "--all"])
        else:
            plugin_main(["update"] + rest)
        return
    if sub == "all":
        print(f"{Fore.CYAN}[*] Running all sync sources in sequence…{Style.RESET_ALL}\n")
        print(f"{Fore.MAGENTA}── 1/2 fingerprints ──{Style.RESET_ALL}")
        try:
            _run_fingerprint_sync([])
        except SystemExit as e:
            if e.code:
                print(f"{Fore.YELLOW}[!] fingerprints sync exited with code {e.code} — continuing{Style.RESET_ALL}")
        print(f"\n{Fore.MAGENTA}── 2/2 plugins ──{Style.RESET_ALL}")
        try:
            from cygor.cli_plugin import main as plugin_main
            plugin_main(["update", "--all"])
        except SystemExit as e:
            if e.code:
                print(f"{Fore.YELLOW}[!] plugin sync exited with code {e.code}{Style.RESET_ALL}")
        print(f"\n{Fore.GREEN}[+] All sync sources processed.{Style.RESET_ALL}")
        return

    print(f"{Fore.RED}[!] Unknown sync subcommand: {sub!r}{Style.RESET_ALL}", file=sys.stderr)
    print(f"    Run 'cygor sync --help' to see available subcommands.")
    sys.exit(1)


def _show_sync_status() -> None:
    """Unified status view across every sync source — fingerprints, plugins."""
    print(f"\n{Fore.CYAN}Cygor Sync Sources{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'─'*70}{Style.RESET_ALL}\n")

    # --- Fingerprints ---
    print(f"{Fore.MAGENTA}● Fingerprints{Style.RESET_ALL}  ({Fore.YELLOW}cygor sync fingerprints{Style.RESET_ALL})")
    try:
        from cygor.fingerprinting.sync import JSONSyncEngine
        from cygor.fingerprinting.cache import get_cache_dir
        cache_dir = get_cache_dir()
        synced_count = 0
        total = 0
        for source in JSONSyncEngine.SYNC_ORDER:
            total += 1
            if (cache_dir / f"{source}.json").exists():
                synced_count += 1
        print(f"    {synced_count}/{total} sources synced under {cache_dir}\n")
    except Exception as e:
        print(f"    {Fore.RED}error reading fingerprint cache: {e}{Style.RESET_ALL}\n")

    # --- Plugins ---
    print(f"{Fore.MAGENTA}● Plugins{Style.RESET_ALL}  ({Fore.YELLOW}cygor sync plugins{Style.RESET_ALL})")
    try:
        from cygor.plugin_loader import discover_plugins
        plugins = discover_plugins()
        print(f"    {len(plugins)} community plugin(s) installed")
        for spec in plugins[:5]:
            print(f"      - {spec.slug:<20} {spec.version or '(no version)':>10}")
        if len(plugins) > 5:
            print(f"      … {len(plugins) - 5} more")
        print()
    except Exception as e:
        print(f"    {Fore.RED}error listing plugins: {e}{Style.RESET_ALL}\n")

    print(f"{Fore.CYAN}{'─'*70}{Style.RESET_ALL}")
    print(f"Run {Fore.YELLOW}cygor sync all{Style.RESET_ALL} to refresh everything in sequence.\n")


def _run_fingerprint_sync(cmd_args: list[str]) -> None:
    """
    Refresh the fingerprint source caches under ``~/.cache/cygor/fingerprints/``.

    Unified entry point that covers every fingerprint source the cygor
    pipeline consumes — Huginn-Muninn device + DHCP databases, Satori SSH
    /SMB/HTTP/UA/SIP/DHCP fingerprints, the IEEE OUI master, p0f TCP/IP
    signatures, and the cloud-provider IP-range files (AWS, GCP, etc.)
    used for cloud-attribution evidence.

    Subcommands:
      (none)                  Sync every source listed in SYNC_ORDER
      --sources <a> <b> …     Sync just these sources (use --list to see names)
      --status                Show what's cached and when
      --list                  Print every supported source + group aliases
      --force                 Re-download even if recently synced
      --azure-file PATH       Import Azure ServiceTags JSON (cloud_azure has no auto URL)

    Group aliases for --sources:
      cloud      → all cloud_* sources (AWS, GCP, Cloudflare, DO, Linode, Oracle)
      huginn     → all huginn_* sources
      satori     → all satori_* sources
    """
    import argparse
    import asyncio
    import json
    from pathlib import Path

    from cygor.fingerprinting.sync import (
        JSONSyncEngine,
        sync_fingerprints,
        _CLOUD_SOURCE_TO_PROVIDER,
    )
    from cygor.fingerprinting.cache import get_cache_dir

    parser = argparse.ArgumentParser(
        prog="cygor fingerprint-sync",
        description="Sync fingerprint sources used by cygor's identification pipeline.",
    )
    parser.add_argument(
        "--sources", nargs="+",
        help="Specific source names or group aliases (cloud / huginn / satori)",
    )
    parser.add_argument("--status", action="store_true", help="Show cache state and exit")
    parser.add_argument("--list", action="store_true", help="List supported sources")
    parser.add_argument("--force", action="store_true", help="Re-download even if recently synced")
    parser.add_argument(
        "--azure-file",
        help="Offline Azure import: path to a downloaded ServiceTags JSON (only used if portal scrape fails / air-gapped)",
    )
    args = parser.parse_args(cmd_args)

    all_sources = JSONSyncEngine.SYNC_ORDER
    cloud_sources = [s for s in all_sources if s.startswith("cloud_")]
    huginn_sources = [s for s in all_sources if s.startswith("huginn_")]
    satori_sources = [s for s in all_sources if s.startswith("satori_")]
    group_map = {"cloud": cloud_sources, "huginn": huginn_sources, "satori": satori_sources}

    # ── --list ──
    if args.list:
        print(f"\n{Fore.CYAN}Fingerprint sources{Style.RESET_ALL}\n")
        # Print groups first (most useful for the CLI user).
        for group, members in group_map.items():
            print(f"  {Fore.MAGENTA}{group:<22}{Style.RESET_ALL} group → {', '.join(members)}")
        print()
        for source in all_sources:
            display = JSONSyncEngine.SOURCE_NAMES.get(source, source)
            tag = ""
            if source in _CLOUD_SOURCE_TO_PROVIDER:
                tag = f" {Fore.YELLOW}(cloud){Style.RESET_ALL}"
            print(f"  {Fore.GREEN}{source:<28}{Style.RESET_ALL} {display}{tag}")
        print()
        print(f"{Fore.YELLOW}Tip:{Style.RESET_ALL} ``--azure-file <path>`` is the offline path. The auto Azure")
        print("     sync scrapes the Microsoft download portal for the current ServiceTags")
        print("     URL — use the manual flag only if the scrape fails (air-gapped install)")
        print("     or the portal is restructured.")
        return

    # ── --status ──
    if args.status:
        print(f"\n{Fore.CYAN}Fingerprint cache status{Style.RESET_ALL}\n")
        cache_dir = get_cache_dir()
        for source in all_sources:
            display = JSONSyncEngine.SOURCE_NAMES.get(source, source)
            # Cloud sources have a different filename pattern.
            if source.startswith("cloud_"):
                filename = f"{source}.json"
            else:
                filename = f"{source}.json"
            path = cache_dir / filename
            if not path.exists():
                print(f"  {Fore.RED}✗{Style.RESET_ALL} {source:<28} not synced  ({display})")
                continue
            try:
                size_kb = path.stat().st_size / 1024
                # Cloud cache files have a count + synced_at field.
                if source.startswith("cloud_"):
                    data = json.loads(path.read_text(encoding="utf-8"))
                    count = data.get("count", len(data.get("prefixes", [])))
                    synced = (data.get("synced_at") or "?")[:19]
                    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {source:<28} {count:>6} prefixes   {synced}")
                else:
                    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {source:<28} {size_kb:>7.0f} KB on disk")
            except Exception as e:
                print(f"  {Fore.YELLOW}!{Style.RESET_ALL} {source:<28} malformed cache: {e}")
        print()
        return

    # ── --azure-file <path> ──
    if args.azure_file:
        from cygor.fingerprinting.cloud_ipranges import save_provider_ranges
        print(f"{Fore.CYAN}[*] Importing Azure ServiceTags from {args.azure_file}{Style.RESET_ALL}")
        try:
            data = json.loads(Path(args.azure_file).read_text(encoding="utf-8"))
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to read file: {e}{Style.RESET_ALL}", file=sys.stderr)
            sys.exit(1)
        prefixes = []
        for vt in data.get("values", []):
            props = vt.get("properties", {}) or {}
            for cidr in props.get("addressPrefixes", []) or []:
                prefixes.append({
                    "cidr": cidr,
                    "service": props.get("systemService") or vt.get("name", ""),
                    "region": props.get("region") or "global",
                })
        if not prefixes:
            print(f"{Fore.RED}[!] No prefixes found — wrong file format?{Style.RESET_ALL}", file=sys.stderr)
            sys.exit(1)
        save_provider_ranges("Azure", prefixes)
        print(f"{Fore.GREEN}[+] Imported {len(prefixes)} Azure prefixes{Style.RESET_ALL}")
        return

    # ── Resolve --sources (with group aliases) ──
    requested: Optional[list[str]] = None
    if args.sources:
        requested = []
        for s in args.sources:
            if s in group_map:
                requested.extend(group_map[s])
            elif s in all_sources:
                requested.append(s)
            else:
                print(f"{Fore.RED}[!] Unknown source: {s!r}{Style.RESET_ALL}", file=sys.stderr)
                print(f"    Run 'cygor fingerprint-sync --list' to see available sources.")
                sys.exit(1)

    label = ", ".join(requested) if requested else "all sources"
    print(f"{Fore.CYAN}[*] Syncing {label}…{Style.RESET_ALL}")
    try:
        results = asyncio.run(sync_fingerprints(force=args.force, sources=requested))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Interrupted{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        print(f"{Fore.RED}[!] Sync failed: {e}{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)

    print()
    succeeded = {s: c for s, c in results.items() if c is not None and c >= 0}
    failed = [s for s, c in results.items() if c is None or c < 0]
    for source, count in succeeded.items():
        unit = "prefixes" if source.startswith("cloud_") else "records"
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {source:<28} {count:>6} {unit}")
    for source in failed:
        print(f"  {Fore.RED}✗{Style.RESET_ALL} {source:<28} failed")
    print()
    if failed:
        print(f"{Fore.YELLOW}[!] {len(failed)} source(s) failed — check network / logs{Style.RESET_ALL}")



if __name__ == "__main__":
    main()
