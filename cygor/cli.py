# cygor/cli.py
import os
import sys
import shutil
import pathlib
import runpy

USAGE = """\
Usage:
  cygor <command> [args]

Commands:
  banner  Cygor tool banner (Warning it is large!)
  scan    Automated scanner to discover hosts and services. (Will require root/sudo privileges for scanning).
  parse   Analyze a NMAP scan file (nmap, gnmap, xml) and extract each host that is running a common service. Will create seperate hostlists for each service.
  enum    Loads enumeration modules that are located in the cygor modules directory. 
  web     Loads Cygor's Web UI and will allow you to interact with it by supplying data you have collected with Cygor.
"""

_NEEDS_ROOT = {"scan"}

# -----------------------------------------------------------------------------------------------
# Privilege elevation & post-run ownership fix
# -----------------------------------------------------------------------------------------------

def _reexec_with_sudo(argv: list[str]) -> None:
    """Re-exec self with sudo while preserving PATH."""
    env_path = os.environ.get("PATH", "")
    cmd = ["sudo", "env", f"PATH={env_path}"] + argv
    os.execvp(cmd[0], cmd)  # never returns


def _parse_chown_paths(argv: list[str]) -> tuple[list[str], list[str]]:
    """
    Extract --chown <paths...> from argv, returning (paths, remaining_argv).
    Also accepts CYGOR_CHOWN_PATHS=path1:path2:... in the environment.
    """
    paths, rest = [], []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--chown":
            i += 1
            while i < len(argv) and not argv[i].startswith("-"):
                paths.append(argv[i])
                i += 1
            continue
        rest.append(a)
        i += 1
    env_paths = os.environ.get("CYGOR_CHOWN_PATHS")
    if env_paths:
        paths += [p for p in env_paths.split(":") if p]
    # de-dup, preserve order
    seen, uniq = set(), []
    for p in paths:
        if p not in seen:
            uniq.append(p); seen.add(p)
    return uniq, rest


def _chown_recursive(root: str, uid: int, gid: int) -> None:
    try:
        if not os.path.exists(root):
            return
        for dirpath, _, filenames in os.walk(root):
            try:
                os.chown(dirpath, uid, gid)
            except Exception:
                pass
            for name in filenames:
                fpath = os.path.join(dirpath, name)
                try:
                    os.chown(fpath, uid, gid)
                except Exception:
                    pass
    except Exception:
        pass


def _postrun_chown(paths: list[str]) -> None:
    sudo_uid = os.environ.get("SUDO_UID")
    sudo_gid = os.environ.get("SUDO_GID")
    if not (sudo_uid and sudo_gid):
        return
    try:
        uid, gid = int(sudo_uid), int(sudo_gid)
    except Exception:
        return
    for p in paths:
        _chown_recursive(p, uid, gid)

# -----------------------------------------------------------------------------------------------
# Safe module execution helper (works whether or not module exposes exec_argv)
# -----------------------------------------------------------------------------------------------

def _exec_module_argv(module_name: str, prog: str, argv: list[str]) -> None:
    """
    Execute `module_name` as a script:
      1) Try module.exec_argv(argv) if present (our fast path)
      2) Else, re-run the module fresh as __main__ via runpy (preserves original argparse/help)
    """
    try:
        mod = __import__(module_name, fromlist=["*"])
        if hasattr(mod, "exec_argv"):
            mod.exec_argv(argv)  # our wrapper path
            return
    except Exception:
        # fall through to clean runpy execution
        pass

    # Clean re-exec like `python -m module_name`
    sys.argv = [prog] + list(argv)
    try:
        del sys.modules[module_name]
    except KeyError:
        pass
    runpy.run_module(module_name, run_name="__main__", alter_sys=True)

# -----------------------------------------------------------------------------------------------
# Hostlist merging/deduping (used ONLY when user supplies -o/--out-dir to legacy parser)
# -----------------------------------------------------------------------------------------------

# Known service tokens for bucketing
_SERVICE_TOKENS = {
    "http":    ("http", "web"),
    "https":   ("https", "ssl", "tls"),
    "smb":     ("smb", "cifs"),
    "nfs":     ("nfs",),
    "ldap":    ("ldap",),
    "ssh":     ("ssh",),
    "ftp":     ("ftp",),
    "mysql":   ("mysql",),
    "postgres":("postgres", "pgsql"),
    "mssql":   ("mssql", "sqlserver"),
    "redis":   ("redis",),
    "rpc":     ("rpc",),
    "winrm":   ("winrm",),
    "vnc":     ("vnc",),
    "dns":     ("dns",),
    "snmp":    ("snmp",),
    "smtp":    ("smtp",),
    "imap":    ("imap",),
    "pop3":    ("pop3",),
    "rdp":     ("rdp",),
    "rdp-gw":  ("rdp-gw", "rdpgw"),
}

# Directories we never scan into (raw results & our own destination)
_NEVER_SCAN_DIRS = {"nmap", "masscan", "naabu", "parsed-hostlists"}


def _infer_service_from_name_or_parent(path: pathlib.Path) -> str:
    """
    Infer a service bucket from the filename and its parent directory name.
    Parent directory wins if it is a known service; otherwise use filename tokens.
    """
    name = path.name.lower()
    parent = path.parent.name.lower()
    if parent in _SERVICE_TOKENS:
        return parent
    for svc, toks in _SERVICE_TOKENS.items():
        for t in toks:
            if t in name:
                return svc
    # http+https special case via hints in filenames
    if "http" in name and "https" in name:
        return "http+https"
    return "unknown"


def _looks_like_hostlist_line(s: str, relaxed: bool) -> bool:
    """
    Accepts:
      - host:port
      - http(s):// URL
      - (relaxed) IPv4 / IPv4 CIDR / bare hostname (common for SMB lists)
    """
    import re
    hostport_re = re.compile(r'^[A-Za-z0-9_.:-]+\:\d{1,5}\s*$')
    url_re      = re.compile(r'^(https?://)[A-Za-z0-9_.:-]+(?::\d{1,5})?(/.*)?$')
    if hostport_re.match(s) or url_re.match(s):
        return True
    if not relaxed:
        return False
    ipv4_re  = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}\s*$')
    cidr4_re = re.compile(r'^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\s*$')
    host_re  = re.compile(r'^[A-Za-z0-9.-]{1,253}$')
    return bool(ipv4_re.match(s) or cidr4_re.match(s) or host_re.match(s))


def _looks_like_hostlist_txt(path: pathlib.Path) -> bool:
    """
    *.txt whose non-empty lines are:
      - host:port OR http(s)://...
      - OR (relaxed): IPv4 / IPv4 CIDR / hostname when filename hints host list semantics.
    """
    if not path.is_file() or path.suffix.lower() != ".txt":
        return False
    name = path.name.lower()
    relaxed = any(k in name for k in ("hostlist", "hosts", "targets", "smb"))
    try:
        c = 0
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                s = line.strip()
                if not s:
                    continue
                if _looks_like_hostlist_line(s, relaxed=relaxed):
                    return True
                c += 1
                if c > 500:
                    break
    except Exception:
        return False
    return False


def _iter_hostlist_files_to_merge(out_dir: str):
    """
    Yield candidate files to merge:
      - Top-level *.txt files in out_dir
      - One level deep inside subfolders (except NEVER_SCAN_DIRS)
      - Never yields files from parsed-hostlists/
    """
    base = pathlib.Path(out_dir)
    if not base.exists():
        return
    # Top-level
    for child in sorted(base.iterdir()):
        if child.is_file() and child.suffix.lower() == ".txt" and _looks_like_hostlist_txt(child):
            yield child
    # One level inside subfolders (skip raw results & our own dest)
    for child in sorted(base.iterdir()):
        if not child.is_dir():
            continue
        if child.name.lower() in _NEVER_SCAN_DIRS:
            continue
        for f in sorted(child.iterdir()):
            if f.is_file() and f.suffix.lower() == ".txt" and _looks_like_hostlist_txt(f):
                yield f


def _merge_dedupe_into_parsed_hostlists(out_dir: str) -> None:
    """
    Merge & dedupe eligible hostlist-like files into:
        <out_dir>/parsed-hostlists/<service>/<service>-hostlist.txt
    Special case: http+https -> directory "http-https" and file "http-https-hostlist.txt".
    Remove the originals after merging. Never deletes from parsed-hostlists/.
    """
    try:
        base = pathlib.Path(out_dir)
        if not base.exists():
            return

        dest_root = base / "parsed-hostlists"
        dest_root.mkdir(parents=True, exist_ok=True)

        svc_seen: dict[str, set[str]] = {}
        merged_files: list[pathlib.Path] = []

        for src_file in _iter_hostlist_files_to_merge(out_dir):
            svc = _infer_service_from_name_or_parent(src_file)

            # Normalize http+https special case
            if svc == "http+https":
                svc_dir_name = "http-https"
                filename = "http-https-hostlist.txt"
            else:
                svc_dir_name = svc
                filename = f"{svc}-hostlist.txt"

            svc_dir = dest_root / svc_dir_name
            svc_dir.mkdir(parents=True, exist_ok=True)
            dst = svc_dir / filename

            # Preload existing targets for this service
            if svc not in svc_seen:
                svc_seen[svc] = set()
                if dst.exists():
                    try:
                        with dst.open("r", encoding="utf-8", errors="ignore") as fh:
                            for ln in fh:
                                ln = ln.rstrip("\n")
                                if ln:
                                    svc_seen[svc].add(ln)
                    except Exception:
                        pass

            relaxed = any(k in src_file.name.lower() for k in ("hostlist", "hosts", "targets", "smb"))

            wrote_any = False
            try:
                with src_file.open("r", encoding="utf-8", errors="ignore") as fh, \
                        dst.open("a", encoding="utf-8") as out:
                    for line in fh:
                        s = line.strip()
                        if not s:
                            continue
                        if not _looks_like_hostlist_line(s, relaxed=relaxed):
                            continue
                        if s in svc_seen[svc]:
                            continue
                        out.write(s + "\n")
                        svc_seen[svc].add(s)
                        wrote_any = True
            except Exception:
                # unreadable source file; skip deletion
                continue

            if wrote_any:
                merged_files.append(src_file)

        # Delete original files we successfully merged from (never from parsed-hostlists/)
        for f in merged_files:
            try:
                if "parsed-hostlists" in f.parts:
                    continue
                f.unlink(missing_ok=True)
            except Exception:
                pass
    except Exception:
        # Never fail CLI due to post-run merge
        pass

# -----------------------------------------------------------------------------------------------
# Main CLI dispatcher
# -----------------------------------------------------------------------------------------------

def main():
    argv = sys.argv[1:]
    if not argv:
        print(USAGE)
        sys.exit(0)

    chown_paths, rest = _parse_chown_paths(argv)
    if not rest:
        print(USAGE)
        sys.exit(0)

    cmd, cmd_args = rest[0], rest[1:]

    # --- banner ---
    if cmd == "banner":
        _exec_module_argv("cygor.banner", "cygor-banner", cmd_args)
        return

    # Elevate if needed (scan)
    if "--no-sudo" in cmd_args:
        cmd_args = [a for a in cmd_args if a != "--no-sudo"]
    elif cmd in _NEEDS_ROOT and os.geteuid() != 0:
        _reexec_with_sudo(["cygor", cmd, *cmd_args] + (["--chown"] + chown_paths if chown_paths else []))

    # --- scan ---
    if cmd == "scan":
        _exec_module_argv("cygor.scan", "cygor-scan", cmd_args)

        if not chown_paths:
            for default in ("results", "output",
                            "parsed-hostlists",
                            os.path.join("results", "parsed-hostlists")):
                if os.path.isdir(default):
                    chown_paths.append(default)
        _postrun_chown(chown_paths)
        return

    # --- parse ---
    if cmd == "parse":
        # Enhanced parser only when explicitly requested
        enhanced = any(flag in cmd_args for flag in ("--inputs", "--emit-json", "--emit-csv", "--nmap-dir"))
        if enhanced:
            _exec_module_argv("cygor.parse_ext", "cygor-parsex", cmd_args)
        else:
            # Legacy path: execute parse module, then optional merge/dedupe into parsed-hostlists
            _exec_module_argv("cygor.parse", "cygor-parse", cmd_args)

            # Only merge/dedupe when the user supplied -o/--out-dir
            user_specified_out = False
            out_dir = "results"
            try:
                if "-o" in cmd_args:
                    out_dir = cmd_args[cmd_args.index("-o") + 1]
                    user_specified_out = True
                elif "--out-dir" in cmd_args:
                    out_dir = cmd_args[cmd_args.index("--out-dir") + 1]
                    user_specified_out = True
            except Exception:
                pass

            if user_specified_out:
                _merge_dedupe_into_parsed_hostlists(out_dir)

        if not chown_paths:
            defaults = ["results", "output"]
            try:
                if "-o" in cmd_args:
                    od = cmd_args[cmd_args.index("-o") + 1]
                    ph = os.path.join(od, "parsed-hostlists")
                    if os.path.isdir(ph):
                        defaults.append(ph)
                elif "--out-dir" in cmd_args:
                    od = cmd_args[cmd_args.index("--out-dir") + 1]
                    ph = os.path.join(od, "parsed-hostlists")
                    if os.path.isdir(ph):
                        defaults.append(ph)
                else:
                    rph = os.path.join("results", "parsed-hostlists")
                    if os.path.isdir(rph):
                        defaults.append(rph)
            except Exception:
                pass

            for d in defaults:
                if os.path.isdir(d):
                    chown_paths.append(d)

        _postrun_chown(chown_paths)
        return

    # --- enum ---
    if cmd == "enum":
        _exec_module_argv("cygor.enumcli", "cygor-enum", cmd_args)
        _postrun_chown(chown_paths)
        return
    
    # --- web ---
    if cmd == "web":
        # Support: `cygor web start|stop|status` (+ options)
        # If called as `cygor web --port 9000`, treat as `start`.
        if (not cmd_args) or (cmd_args[0] in ("start", "stop", "status") or cmd_args[0].startswith("-")):
            _exec_module_argv("cygor.webctl", "cygor web", cmd_args)
        else:
            # Back-compat: allow direct pass-through to the web app
            _exec_module_argv("cygor.webapp.main", "cygor-web", cmd_args)
        return



    print(USAGE)
    sys.exit(2)


if __name__ == "__main__":
    main()
