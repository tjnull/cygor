# cygor/cli.py
import os
import sys
import shutil
import pathlib
import importlib
import runpy
import json
import subprocess
from pathlib import Path
from .precheck import run_once_precheck

USAGE = """\
Usage:
  cygor <command> [args]

Commands:
  banner         Cygor tool banner (Warning it is large!)
  scan           Automated scanner to discover hosts and services. (Will require root/sudo privileges for scanning).
  parse          Analyze a NMAP scan file (nmap, gnmap, xml) and extract categorized hostlists by common service.
  enrich         Enrich IOCs with passive reconnaissance and threat intelligence from Shodan, VirusTotal, etc.
  enrich-config  Manage enrichment API keys (set/get/list/test/unset/info).
  enum           Loads enumeration modules that are located in the cygor modules directory.
  credrecon      Test default and weak credentials across multiple protocols (HTTP, SSH, FTP, databases, etc.)
  workspace      Manage workspaces (init/set-default/show).
  web            Control/launch the Cygor Web UI (start/stop/status) or run directly.

Environment:
  CYGOR_WORKSPACE     Override default workspace just for this run.
  CYGOR_RESULTS_DIR   Used by web and modules if set. (Auto-set from default workspace.)
"""

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
    # already root — nothing to do
    try:
        if os.geteuid() == 0:
            return
    except AttributeError:
        # Windows / weird environment — skip escalation
        return

    privileged_tools = {"masscan", "nmap", "naabu"}
    if not any(tool in " ".join(cmd_args) for tool in privileged_tools):
        return

    if os.environ.get("CYGOR_NO_SUDO") == "1":
        return

    print("[!] Elevated privileges required for this scan (raw socket access).")
    print("[*] Re-launching with sudo...")

    # Build sudo command. Use `env VAR=val` to pass workspace into the elevated env.
    sudo_cmd = ["sudo"]
    if workspace:
        # ensure the elevated process sees the workspace path as CYGOR_RESULTS_DIR
        sudo_cmd += ["env", f"CYGOR_RESULTS_DIR={workspace}"]
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
    ws = os.environ.get("CYGOR_WORKSPACE")
    if ws:
        return os.path.expanduser(ws)
    cfg = _load_cfg()
    return cfg.get("default_workspace")

def _ensure_env_for_workspace():
    ws = _default_workspace()
    if ws:
        os.environ.setdefault("CYGOR_RESULTS_DIR", ws)
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


def main():
    argv = sys.argv[1:]

    # --- No command provided ---
    if not argv:
        print(USAGE)
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
        print(USAGE)
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
        print(USAGE)
        sys.exit(0)

    cmd, cmd_args = rest[0], rest[1:]

    # --- workspace ---
    if cmd == "workspace":
        _exec_module_argv("cygor.workspace", "cygor-workspace", cmd_args)
        return

    # --- banner ---
    if cmd == "banner":
        _exec_module_argv("cygor.banner", "cygor-banner", cmd_args)
        return

    # --- scan ---
    if cmd == "scan":
        # Ensure we know the workspace and set CYGOR_RESULTS_DIR for the current process
        ws = _ensure_env_for_workspace()

        # If workspace exists and the user hasn't provided an explicit outdir, inject it.
        # Accept both `-o`/`--outdir` (common) and `--out-dir` (other modules).
        has_outdir_flag = any(flag in cmd_args for flag in ("-o", "--outdir", "--out-dir"))
        if ws and not has_outdir_flag:
            # put the workspace first so it's obvious and preserved when re-execing via sudo
            cmd_args = ["--outdir", ws] + cmd_args

        # Now, if we require raw sockets, re-exec with sudo — workspace is already in cmd_args,
        # and we additionally export CYGOR_RESULTS_DIR into the elevated process env.
        _ensure_root_for_scan(cmd_args, workspace=ws)

        _exec_module_argv("cygor.scan", "cygor-scan", cmd_args)

        # post-run chown defaults
        if not chown_paths:
            for default in ("results", "output",
                            "parsed-hostlists",
                            os.path.join("results", "parsed-hostlists")):
                if default and os.path.isdir(default):
                    chown_paths.append(default)
            if ws and os.path.isdir(ws):
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

        if not chown_paths:
            defaults = ["results", "output"]
            if ws:
                defaults.append(ws)
            for d in defaults:
                if os.path.isdir(d):
                    chown_paths.append(d)
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

    # --- enrich-config ---
    if cmd == "enrich-config":
        _exec_module_argv("cygor.enrich_config", "cygor-enrich-config", cmd_args)
        return

    # --- enum ---
    if cmd == "enum":
        ws = _ensure_env_for_workspace()  # sets CYGOR_RESULTS_DIR if default workspace exists
        if ws:
            os.environ["CYGOR_RESULTS_DIR"] = ws  # ensure visibility for subprocesses
        _exec_module_argv("cygor.enumcli", "cygor-enum", cmd_args)
        _postrun_chown(chown_paths)
        return

    # --- credrecon ---
    if cmd == "credrecon":
        ws = _ensure_env_for_workspace()
        if ws:
            os.environ["CYGOR_RESULTS_DIR"] = ws
        _exec_module_argv("cygor.credrecon.scanner", "cygor-credrecon", cmd_args)
        _postrun_chown(chown_paths)
        return

    # --- web ---
    if cmd == "web":
        webctl = importlib.import_module("cygor.webctl")
        webctl.exec_argv(cmd_args)
        return



    print(USAGE)
    sys.exit(2)


if __name__ == "__main__":
    main()
