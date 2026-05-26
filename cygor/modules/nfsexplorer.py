#!/usr/bin/env python3
"""
NFS Explorer - Cygor Enumeration Module
========================================

Enumerate NFS exports, permissions, and optionally list files.
Supports UID/GID spoofing for access testing.

Output format: cygor-result.json (universal schema)
"""
import sys
import uuid
import re
import argparse
import logging
import os
import json
import csv
from datetime import datetime
from pathlib import Path
from argparse import RawTextHelpFormatter
from colorama import Fore, Style, init as _color_init
from xml.etree.ElementTree import Element, SubElement, ElementTree
from pyNfsClient import (
    Portmap, Mount, NFSv3, NFS_PROGRAM, NFS_V3,
    ACCESS3_READ, ACCESS3_MODIFY, ACCESS3_EXECUTE, NFSSTAT3
)

# Import cygor module framework
from cygor.modules.schema import (
    CygorResult, ModuleInfo, SchemaDefinition, RunMetadata,
    AssetReferences, ColumnDefinition, ColumnType, ViewType, ModuleCategory
)
from cygor.modules.exporters import export_to_csv, export_to_xml, export_to_txt

# Import proxy configuration for jumpbox warning
try:
    from cygor.proxy_config import is_jumpbox_routing_active
except ImportError:
    def is_jumpbox_routing_active():
        return False

# IP rotation support
import socket as _socket_module
import threading as _threading_module
from contextlib import contextmanager
# IP rotation is enterprise-only; provide a no-op shim on dev.
def get_next_ip(*args, **kwargs):
    return None

_socket_patch_lock = _threading_module.Lock()


@contextmanager
def _bound_socket_context(source_ip):
    """Temporarily monkey-patch socket.socket to bind to source_ip.

    Uses a lock to prevent concurrent patches (safe even if targets
    were ever processed in parallel).
    """
    if not source_ip:
        yield
        return

    with _socket_patch_lock:
        _orig_init = _socket_module.socket.__init__

        def _patched_init(self, *args, **kwargs):
            _orig_init(self, *args, **kwargs)
            try:
                self.bind((source_ip, 0))
            except Exception:
                pass  # Best-effort binding

        _socket_module.socket.__init__ = _patched_init
        try:
            yield
        finally:
            _socket_module.socket.__init__ = _orig_init

# ---------------------------
# Color / formatting helpers
# ---------------------------
_color_init(autoreset=True, strip=False)

ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*m')

def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE.sub('', text)

def _fmt_aux(aux):
    if not aux:
        return "-"
    if isinstance(aux, (list, tuple)):
        return ",".join(str(x) for x in aux)
    return str(aux)

# ---- Permission parsing helper (export perm bits for UI) ----
def parse_perm_flags(text: str) -> dict:
    """
    Convert a permission string like 'READ WRITE EXECUTE' or
    'READ NO_WRITE NO_EXEC' into explicit booleans for UI.
    Returns: {'r': bool, 'w': bool, 'x': bool}
    """
    s = str(text or "").upper().replace("-", "_").replace(" ", "_")
    deny_r = ("NO_READ" in s) or ("DENY_READ" in s)
    deny_w = ("NO_WRITE" in s) or ("DENY_WRITE" in s) or ("NOWRITE" in s)
    deny_x = ("NO_EXEC" in s) or ("NO_EXECUTE" in s) or ("NOEXEC" in s) \
             or ("DENY_EXEC" in s) or ("DENY_EXECUTE" in s)

    has_r = ("READ" in s) and not deny_r
    has_w = ("WRITE" in s) and not deny_w
    has_x = (("EXEC" in s) or ("EXECUTE" in s)) and not deny_x
    return {"r": has_r, "w": has_w, "x": has_x}

# ----------------------------------------------------------------------
# CLI Help Menu (Cygor style)
# ----------------------------------------------------------------------
class ColorHelpFormatter(RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    def start_section(self, heading):
        heading = f"{Fore.CYAN}{heading}{Style.RESET_ALL}"
        super().start_section(heading)

    def _format_action_invocation(self, action):
        return f"{Fore.YELLOW}{super()._format_action_invocation(action)}{Style.RESET_ALL}"

_examples = f"""
   {Fore.MAGENTA}Examples:{Style.RESET_ALL}

    {Fore.YELLOW}# Basic NFS enumeration (shares only){Style.RESET_ALL}
    cygor enum nfsexplorer -t 10.10.10.5

    {Fore.YELLOW}# List files inside shares{Style.RESET_ALL}
    cygor enum nfsexplorer -t 192.168.1.100 --list-files

    {Fore.YELLOW}# Use fake UID/GID for access{Style.RESET_ALL}
    cygor enum nfsexplorer -t 192.168.1.150 --uid 1000 --gid 1000

    {Fore.YELLOW}# Limit to NFSv3 only{Style.RESET_ALL}
    cygor enum nfsexplorer -t 192.168.1.75 --version 3

    {Fore.YELLOW}# Check for no_root_squash{Style.RESET_ALL}
    cygor enum nfsexplorer -t 192.168.1.200 --check-root

    {Fore.YELLOW}# Save all formats (txt,csv,json,xml){Style.RESET_ALL}
    cygor enum nfsexplorer -t 10.10.10.5 --list-files --nfs-output-format all
"""

def parse_args(argv=None):
    banner = f"""
    {Fore.GREEN}{'='*60}
      CYGOR ENUM - NFS Explorer
    {Fore.GREEN}{'='*60}{Style.RESET_ALL}
    """

    parser = argparse.ArgumentParser(
        prog="cygor enum nfsexplorer",
        usage="cygor enum nfsexplorer [options]",
        description=banner + "\nEnumerate NFS exports, versions, and check for misconfigurations.\n",
        epilog=_examples,
        formatter_class=ColorHelpFormatter,
    )

    # Targets
    tgt = parser.add_argument_group("Targets")
    tgt.add_argument("-t", "--targets", type=str, help="IP address or comma-separated list")
    tgt.add_argument("-i", "--input-file", type=str, help="Input file with target IPs")

    # Output / Options
    out = parser.add_argument_group("Output / Options")
    out.add_argument(
        "-o", "--output-dir",
        type=str,
        default=None,
        help="Directory to save results (default: results/cygor-enumeration-modules/nfsexplorer/)"
    )
    out.add_argument(
    "--nfs-output-format",
    choices=["text", "csv", "json", "xml", "all"],
    default=None,  # <-- None means user did NOT explicitly request saving
    help="When provided, results are saved in this format (text, csv, json, xml, or all). ""If omitted, nothing is saved unless -o/--output-dir is set.")

    out.add_argument("--timeout", type=int, default=10, help="RPC timeout (seconds)")
    out.add_argument("-r", "--recurse", type=int, default=1, help="Directory recursion depth (0=list export root only)")
    out.add_argument("--info", action="store_true", help="Only show supported NFS versions/exports; skip listing contents")
    out.add_argument("--list-files", action="store_true", help="Also list files/directories inside each share")

    # Authentication / UID/GID
    auth = parser.add_argument_group("Authentication / UID/GID")
    auth.add_argument("--uid", type=int, default=0, help="Fake UID to use for NFS requests")
    auth.add_argument("--gid", type=int, default=0, help="Fake GID to use for NFS requests")
    auth.add_argument("--aux-gids", type=str, help="Comma-separated auxiliary GIDs")

    # Protocol Version
    ver = parser.add_argument_group("Protocol Version")
    ver.add_argument("--version", type=int, choices=[2, 3, 4], help="Force specific NFS protocol version")

    # Checks
    checks = parser.add_argument_group("Checks")
    checks.add_argument("--check-root", action="store_true", help="Attempt to detect no_root_squash misconfigurations")

    args = parser.parse_args(argv)

    if not args.targets and not args.input_file:
        parser.error("You must specify --targets or --input-file")

    return args

# ---------------------------
# Helpers for saving results
# ---------------------------
def _clean_value(v):
    # Preserve native types; only strip ANSI from strings
    if isinstance(v, str):
        return strip_ansi(v)
    return v

def _clean_row(row: dict) -> dict:
    return {k: _clean_value(v) for k, v in row.items()}

def save_results(host, results, outdir, basename, fmt_choice):
    os.makedirs(outdir, exist_ok=True)

    # map "text" -> ".txt" extension; "all" -> all four
    if fmt_choice == "all":
        formats = ["txt", "csv", "json", "xml"]
    elif fmt_choice == "text":
        formats = ["txt"]
    else:
        formats = [fmt_choice]

    for fmt in formats:
        outfile = os.path.join(outdir, f"{basename}.{fmt}")

        if fmt == "json":
            # Keep booleans as booleans
            clean_results = [_clean_row(r) for r in results]
            with open(outfile, "w") as f:
                json.dump(clean_results, f, indent=2)

        elif fmt == "csv":
            # CSV is text-based; stringify after cleaning
            fieldnames = list(results[0].keys())
            with open(outfile, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for r in results:
                    rr = _clean_row(r)
                    writer.writerow({k: (json.dumps(v) if isinstance(v, (dict, list)) else str(v)) for k, v in rr.items()})

        elif fmt == "xml":
            root = Element("nfsexplorer")
            for r in results:
                rr = _clean_row(r)
                entry = SubElement(root, "entry")
                for key, value in rr.items():
                    el = SubElement(entry, key)
                    el.text = str(value)
            ElementTree(root).write(outfile, encoding="utf-8", xml_declaration=True)

        else:  # txt
            with open(outfile, "w") as f:
                for r in results:
                    rr = _clean_row(r)
                    line = " ".join(str(v) for v in rr.values())
                    f.write(line + "\n")

        print(f"{Fore.GREEN}[+] Results written to {outfile}{Style.RESET_ALL}")


# ----------------------------------------------------------------------
# Save: cygor-result.json (new universal format)
# ----------------------------------------------------------------------
def save_cygor_result(
    all_results: list,
    output_dir: str,
    started_at: datetime,
    completed_at: datetime,
    target_count: int,
    list_files: bool = False,
    formats: str = "json,csv,xml,txt"
) -> list:
    """
    Save results in the new cygor-result.json format with embedded schema.

    Args:
        all_results: List of NFS share/file results
        output_dir: Output directory path
        started_at: Scan start time
        completed_at: Scan end time
        target_count: Number of targets scanned
        list_files: Whether file listing was enabled
        formats: Comma-separated list of formats to export

    Returns:
        List of saved file paths
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Clean results for JSON serialization
    results = []
    for r in all_results:
        clean_r = {k: _clean_value(v) for k, v in r.items() if k != "permissions_display"}
        results.append(clean_r)

    # Define schema columns based on whether listing files
    if list_files:
        columns = [
            ColumnDefinition(key="ip", label="IP Address", type=ColumnType.IP),
            ColumnDefinition(key="share", label="Share", type=ColumnType.STRING),
            ColumnDefinition(key="path", label="Path", type=ColumnType.STRING),
            ColumnDefinition(key="file", label="File/Dir", type=ColumnType.STRING),
            ColumnDefinition(key="type", label="Type", type=ColumnType.BADGE),
            ColumnDefinition(key="size", label="Size", type=ColumnType.STRING),
            ColumnDefinition(key="permissions", label="Permissions", type=ColumnType.BADGE),
        ]
    else:
        columns = [
            ColumnDefinition(key="ip", label="IP Address", type=ColumnType.IP),
            ColumnDefinition(key="share", label="Share", type=ColumnType.STRING),
            ColumnDefinition(key="name", label="Name", type=ColumnType.STRING),
            ColumnDefinition(key="type", label="Type", type=ColumnType.BADGE),
            ColumnDefinition(key="size", label="Size", type=ColumnType.STRING),
            ColumnDefinition(key="permissions", label="Permissions", type=ColumnType.BADGE),
        ]

    # Build module info
    module_info = ModuleInfo(
        name="NFS Explorer",
        slug="nfsexplorer",
        version="2.0.0",
        author="cygor",
        description="Enumerate NFS exports, permissions, and files",
        category=ModuleCategory.NETWORK_SHARES,
    )

    # Build schema
    schema = SchemaDefinition(
        view=ViewType.TABLE,
        columns=columns,
        group_by="ip",
    )

    # Parse formats
    formats_list = []
    if formats:
        fmt = formats.lower()
        if fmt == "all":
            formats_list = ["json", "csv", "xml", "txt"]
        elif fmt == "text":
            formats_list = ["txt"]
        else:
            formats_list = [fmt]
    else:
        formats_list = ["json"]

    # Build metadata
    success_count = len(set(r.get("ip", "") for r in results))
    metadata = RunMetadata(
        started_at=started_at,
        completed_at=completed_at,
        target_count=target_count,
        success_count=success_count,
        error_count=0,
        exported_formats=formats_list,
        workspace=os.environ.get("CYGOR_WORKSPACE") or os.environ.get("CYGOR_RESULTS_DIR"),
    )

    # Build CygorResult
    cygor_result = CygorResult(
        module=module_info,
        metadata=metadata,
        schema_def=schema,
        results=results,
        assets=AssetReferences(),
    )

    # Save files
    saved_files = []

    # Always save cygor-result.json (primary)
    json_path = out_dir / "cygor-result.json"
    cygor_result.save(json_path)
    saved_files.append(json_path)

    # Export other formats
    if "csv" in formats_list and results:
        csv_path = out_dir / "nfsexplorer-results.csv"
        export_to_csv(results, csv_path, columns)
        saved_files.append(csv_path)

    if "xml" in formats_list and results:
        xml_path = out_dir / "nfsexplorer-results.xml"
        export_to_xml(results, xml_path, "nfsexplorer")
        saved_files.append(xml_path)

    if ("txt" in formats_list or "text" in formats_list) and results:
        txt_path = out_dir / "nfsexplorer-results.txt"
        export_to_txt(results, txt_path, columns)
        saved_files.append(txt_path)

    return saved_files


# ----------------------------------------------------------------------
# NFS Client wrapper (pyNfsClient)
# ----------------------------------------------------------------------
class NFSClient:
    def __init__(self, host, args, source_ip=None):
        self.host = host
        self.timeout = args.timeout
        self.recurse = args.recurse
        self.args = args
        self.source_ip = source_ip
        self._start_time = datetime.now()  # Track scan start time

        aux_gids = []
        if args.aux_gids:
            try:
                aux_gids = [int(x) for x in args.aux_gids.split(",")]
            except ValueError:
                aux_gids = []

        self.requested_uid = args.uid
        self.requested_gid = args.gid
        self.requested_aux = aux_gids
        self.is_spoofing = (args.uid != 0) or (args.gid != 0) or (len(aux_gids) > 0)

        self.check_root = args.check_root
        self.logger = self._setup_logger()

        self.portmap = None
        self.mount = None
        self.nfs3 = None
        self.mnt_port = None

    def _setup_logger(self):
        logger = logging.getLogger("NFSClient")
        logger.setLevel(logging.DEBUG)
        if not logger.handlers:
            handler = logging.StreamHandler()
            handler.setFormatter(logging.Formatter('%(asctime)s - NFSClient - %(levelname)s - %(message)s'))
            logger.addHandler(handler)
        return logger

    def get_permissions(self, fhandle):
        try:
            res = self.nfs3.access(
                fhandle,
                ACCESS3_READ | ACCESS3_MODIFY | ACCESS3_EXECUTE,
                self.mount.auth
            )
            access = res.get("resok", {}).get("access", 0)
            return {
                "read": (access & ACCESS3_READ) != 0,
                "write": (access & ACCESS3_MODIFY) != 0,
                "exec": (access & ACCESS3_EXECUTE) != 0,
            }
        except Exception:
            return {"read": False, "write": False, "exec": False}

    def get_perm_strs(self, fhandle, colored=True):
        """
        Return a readable permission string. When denied, emit NO_* tokens so
        the string is unambiguous for logs and any parsers.
        """
        p = self.get_permissions(fhandle)  # {'read': bool, 'write': bool, 'exec': bool}

        def tok(label, allowed):
            if colored:
                if allowed:
                    return f"{Fore.GREEN}{label}{Style.RESET_ALL}"
                else:
                    return f"{Fore.RED}NO_{label}{Style.RESET_ALL}"
            else:
                return label if allowed else f"NO_{label}"

        return " ".join([
            tok("READ",    p["read"]),
            tok("WRITE",   p["write"]),
            tok("EXECUTE", p["exec"]),
        ])


    def print_table(self, rows):
        if not rows:
            return
        headers = ["Share Path", "File/Dir", "Type", "Size", "Permissions"]
        cols = list(zip(*rows)) if rows else []
        widths = []
        for i, header in enumerate(headers):
            col_len = max(len(strip_ansi(str(x))) for x in cols[i]) if cols else len(header)
            widths.append(max(len(header), col_len) + 3)
        header_line = "".join(h.ljust(widths[i]) for i, h in enumerate(headers))
        print(Fore.CYAN + header_line + Style.RESET_ALL)
        print("-" * sum(widths))
        for row in rows:
            line = "".join(str(col).ljust(widths[i]) for i, col in enumerate(row))
            print(line)

    def convert_size(self, size_bytes: int) -> str:
        try:
            size_bytes = int(size_bytes)
        except Exception:
            return "-"
        if size_bytes == 0:
            return "0B"
        units = ["B", "KB", "MB", "GB", "TB", "PB"]
        i = 0
        while size_bytes >= 1024 and i < len(units) - 1:
            size_bytes /= 1024.0
            i += 1
        return f"{size_bytes:.1f}{units[i]}"

    def create_conn_obj(self):
        try:
            with _bound_socket_context(self.source_ip):
                if self.source_ip:
                    self.logger.debug(f"Using source IP {self.source_ip} for NFS connection to {self.host}")
                self.portmap = Portmap(self.host, timeout=self.timeout)
                self.portmap.connect()
                self.mnt_port = self.portmap.getport(Mount.program, Mount.program_version)
                self.mount = Mount(
                    host=self.host,
                    port=self.mnt_port,
                    timeout=self.timeout,
                    auth={
                        "flavor": 1,
                        "machine_name": uuid.uuid4().hex.upper()[0:6],
                        "uid": self.requested_uid,
                        "gid": self.requested_gid,
                        "aux_gid": self.requested_aux,
                    },
                )
                self.mount.connect()
                nfs_port = self.portmap.getport(NFS_PROGRAM, NFS_V3)
                self.nfs3 = NFSv3(self.host, nfs_port, self.timeout, self.mount.auth)
                self.nfs3.connect()
            self.logger.info(f"{Fore.GREEN}Connected to NFS server at {self.host}{Style.RESET_ALL}")
            if self.is_spoofing:
                print(f"{Fore.YELLOW}[!] Using spoofed credentials: uid={self.requested_uid} gid={self.requested_gid} aux_gids={_fmt_aux(self.requested_aux)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[i] Using default credentials: uid={self.requested_uid} gid={self.requested_gid}{Style.RESET_ALL}")
            return True
        except Exception as e:
            self.logger.error(f"{Fore.RED}Error connecting: {e}{Style.RESET_ALL}")
            return False

    def enum_host_info(self):
        try:
            programs = self.portmap.dump()
            self.nfs_versions = {p["version"] for p in programs if p.get("program") == NFS_PROGRAM}
            return self.nfs_versions
        except Exception as e:
            self.logger.error(f"{Fore.RED}Failed to get host info: {e}{Style.RESET_ALL}")
            return []

    def print_host_info(self):
        if getattr(self, 'nfs_versions', None):
            self.logger.info(f"{Fore.CYAN}Target supports NFS versions: {', '.join(map(str, self.nfs_versions))}{Style.RESET_ALL}")
        else:
            self.logger.info(f"{Fore.RED}No NFS versions found{Style.RESET_ALL}")

    def check_root_escape(self, share, list_root=False, read_passwd=False):
        """
        Detect if no_root_squash/root escape is possible by checking if 
        the mounted share exposes the real host filesystem.
        """
        try:
            mount_info = self.mount.mnt(share, self.mount.auth)
            if mount_info["status"] != 0:
                return
            fhandle = mount_info["mountinfo"]["fhandle"]

            res = self.nfs3.readdirplus(fhandle, auth=self.mount.auth)
            if "resfail" in res:
                return

            entries = res["resok"]["reply"]["entries"]
            visible_entries = []
            stack = [entries]
            while stack:
                current = stack.pop()
                if isinstance(current, list):
                    stack.extend(current)
                elif isinstance(current, dict):
                    name = current.get("name")
                    if isinstance(name, bytes):
                        name = name.decode(errors="replace")
                    if name and name not in (".", ".."):
                        visible_entries.append(name)
                    nxt = current.get("nextentry")
                    if nxt:
                        stack.append(nxt)

            if visible_entries:
                print(
                    f"{Fore.RED}[!] Root-escape detected via share {share} "
                    f"— top-level entries visible: {', '.join(visible_entries[:10])}"
                    f"{' ...' if len(visible_entries) > 10 else ''}{Style.RESET_ALL}"
                )

                if list_root:
                    print(f"{Fore.CYAN}[i] Full root directory listing from {share}:{Style.RESET_ALL}")
                    for entry in visible_entries:
                        print(f"    {entry}")

                if read_passwd:
                    print(f"{Fore.YELLOW}[i] Attempting to read /etc/passwd...{Style.RESET_ALL}")
                    try:
                        etc_handle = None
                        for e in entries:
                            if e.get("name") == b"etc":
                                etc_handle = e["name_handle"]["handle"]["data"]
                                break
                        if etc_handle:
                            res2 = self.nfs3.readdirplus(etc_handle, auth=self.mount.auth)
                            files = res2["resok"]["reply"]["entries"]
                            for f in files:
                                fname = f.get("name")
                                if fname and fname.decode(errors="replace") == "passwd":
                                    passwd_handle = f["name_handle"]["handle"]["data"]
                                    read_res = self.nfs3.read(passwd_handle, 0, 2048, self.mount.auth)
                                    if "resok" in read_res:
                                        data = read_res["resok"]["data"].decode(errors="replace")
                                        print(f"{Fore.GREEN}[+] /etc/passwd contents:\n{data}{Style.RESET_ALL}")
                                    break
                    except Exception as e:
                        self.logger.debug(f"check_root_escape: failed reading /etc/passwd: {e}")

        except Exception as e:
            self.logger.debug(f"check_root_escape: readdirplus failed on candidate for {share}: {e}")

    # -------------------------------
    # Helpers
    # -------------------------------
    def _get_exports(self):
        exports = []
        raw_exports = self.mount.export()
        if hasattr(raw_exports, "ex_dir"):
            node = raw_exports
            while node:
                if node.ex_dir:
                    exports.append(node.ex_dir.decode() if isinstance(node.ex_dir, bytes) else node.ex_dir)
                node = getattr(node, "nextentry", None)
        elif isinstance(raw_exports, list):
            for entry in raw_exports:
                if hasattr(entry, "ex_dir"):
                    exports.append(entry.ex_dir.decode() if isinstance(entry.ex_dir, bytes) else entry.ex_dir)
                else:
                    exports.append(entry.decode() if isinstance(entry, bytes) else str(entry))
        return exports

    def _walk_entries(self, entry):
        """Flatten readdirplus structures (linked lists / lists of dicts)."""
        stack = []
        if isinstance(entry, list):
            stack.extend(entry)
        elif entry:
            stack.append(entry)
        while stack:
            current = stack.pop(0)
            yield current
            nxt = current.get("nextentry")
            if isinstance(nxt, dict):
                stack.append(nxt)
            elif isinstance(nxt, list) and nxt:
                stack.extend(nxt)

    def list_dir(self, fhandle, path, recurse=1):
        results = []
        try:
            res = self.nfs3.readdirplus(fhandle, auth=self.mount.auth)
            if "resfail" in res:
                raise Exception("Insufficient Permissions")
            entries = res["resok"]["reply"]["entries"]
        except Exception as e:
            self.logger.error(f"{Fore.RED}Failed to readdirplus {path}: {e}{Style.RESET_ALL}")
            return results

        for entry in self._walk_entries(entries):
            try:
                name = entry.get("name")
                if isinstance(name, bytes):
                    name = name.decode(errors="replace")
                if not name or name in (".", ".."):
                    continue

                item_path = f"{path}/{name}".replace("//", "/")
                size = "-"
                fhandle2 = None

                if entry.get("name_handle") and entry["name_handle"].get("present"):
                    try:
                        fhandle2 = entry["name_handle"]["handle"]["data"]
                    except Exception:
                        pass

                # attributes
                attrs = entry.get("name_attributes")
                is_dir = False
                if attrs and attrs.get("present"):
                    at = attrs["attributes"]
                    size = self.convert_size(at.get("size", 0))
                    is_dir = (at.get("type") == 2)

                # permissions (both text + booleans)
                perm_bools = {"read": False, "write": False, "exec": False}
                perm_text_colored = f"{Fore.YELLOW}UNKNOWN{Style.RESET_ALL}"
                perm_text_plain = "UNKNOWN"
                if fhandle2:
                    perm_bools = self.get_permissions(fhandle2)
                    perm_text_colored = self.get_perm_strs(fhandle2, colored=True)
                    perm_text_plain = self.get_perm_strs(fhandle2, colored=False)

                # if directory and recursion enabled, dive in
                if is_dir and recurse > 0 and fhandle2:
                    results.append({
                        "path": item_path + "/",
                        "filesize": "-",
                        "perms": perm_text_colored,
                        "perms_plain": perm_text_plain,
                        "perm_r": perm_bools["read"],
                        "perm_w": perm_bools["write"],
                        "perm_x": perm_bools["exec"],
                    })
                    results.extend(self.list_dir(fhandle2, item_path, recurse - 1))
                    continue

                # file (or non-recursed dir)
                results.append({
                    "path": item_path if not is_dir else item_path + "/",
                    "filesize": size if not is_dir else "-",
                    "perms": perm_text_colored,
                    "perms_plain": perm_text_plain,
                    "perm_r": perm_bools["read"],
                    "perm_w": perm_bools["write"],
                    "perm_x": perm_bools["exec"],
                })

            except Exception as e:
                self.logger.debug(f"Error processing entry in {path}: {e}")

        return results


    # -------------------------------
    # Share-only enumeration
    # -------------------------------
    def enum_shares_only(self):
        try:
            exports = self._get_exports()
            self.logger.info(f"{Fore.CYAN}Enumerating NFS Shares{Style.RESET_ALL}")
            all_results = []

            for share in exports:
                try:
                    mount_info = self.mount.mnt(share, self.mount.auth)
                    if mount_info["status"] != 0:
                        continue

                    fhandle = mount_info["mountinfo"]["fhandle"]
                    perms = self.get_permissions(fhandle)

                    print(f"\n{Fore.BLUE}Main Share:{Style.RESET_ALL} {Fore.YELLOW}{share}{Style.RESET_ALL}")
                    print(f"  Permissions: "
                          f"{'READ' if perms['read'] else 'NO_READ'} "
                          f"{'WRITE' if perms['write'] else 'NO_WRITE'} "
                          f"{'EXEC' if perms['exec'] else 'NO_EXEC'}")

                    # Top-level listing
                    res = self.nfs3.readdirplus(fhandle, auth=self.mount.auth)
                    entries = res["resok"]["reply"]["entries"] if "resok" in res else []
                    rows = []

                    for entry in self._walk_entries(entries):
                        name = entry.get("name")
                        if isinstance(name, bytes):
                            name = name.decode(errors="replace")
                        if not name or name in (".", ".."):
                            continue

                        attrs = entry.get("name_attributes", {})
                        size = "-"
                        ftype = "unknown"
                        if attrs and attrs.get("present"):
                            at = attrs["attributes"]
                            size = self.convert_size(at.get("size", 0))
                            ftype = "dir" if at.get("type") == 2 else "file"

                        # derive perms & bits directly from NFS, not from text
                        perm_bools = {"read": False, "write": False, "exec": False}
                        perm_text_plain = "UNKNOWN"
                        if entry.get("name_handle"):
                            fh2 = entry["name_handle"]["handle"]["data"]
                            perm_bools = self.get_permissions(fh2)
                            perm_text_plain = self.get_perm_strs(fh2, colored=False)

                        row = {
                            "ip": self.host,
                            "share": share,
                            "name": name,
                            "type": ftype,
                            "size": size,
                            "permissions": perm_text_plain,          # uncolored with NO_* where denied
                            "perm_r": perm_bools["read"],
                            "perm_w": perm_bools["write"],
                            "perm_x": perm_bools["exec"],
                        }
                        rows.append(row)
                        all_results.append(row)


                    if rows:
                        print("  Top-level entries:")
                        headers = ["Name", "Type", "Size", "Permissions"]
                        col_w = [max(len(strip_ansi(r[h.lower()])) for r in rows + [{h.lower(): h}]) + 3 for h in headers]
                        print("  " + " ".join(h.ljust(col_w[i]) for i, h in enumerate(headers)))
                        print("  " + "-" * (sum(col_w)))
                        for r in rows:
                            print(f"  {r['name'].ljust(col_w[0])}"
                                  f"{r['type'].ljust(col_w[1])}"
                                  f"{r['size'].ljust(col_w[2])}"
                                  f"{r['permissions']}")
                        print()

                    if self.check_root:
                        self.check_root_escape(share, list_root=False, read_passwd=False)

                except Exception as e:
                    self.logger.error(f"{Fore.RED}Error accessing share {share}: {e}{Style.RESET_ALL}")

            
            # Save if user provided an output dir OR explicitly set a format
            should_save = (self.args.output_dir is not None) or (self.args.nfs_output_format is not None)
            if should_save and all_results:
                outdir = self.args.output_dir if self.args.output_dir else os.path.join(
                    "results", "cygor-enumeration-modules", "nfsexplorer"
                )
                fmt = self.args.nfs_output_format if self.args.nfs_output_format else "json"

                # Save in new cygor-result.json format
                saved_files = save_cygor_result(
                    all_results=all_results,
                    output_dir=outdir,
                    started_at=getattr(self, '_start_time', datetime.now()),
                    completed_at=datetime.now(),
                    target_count=1,  # Single host
                    list_files=False,
                    formats=fmt,
                )
                for p in saved_files:
                    self.logger.info(f"Results saved to {p}")

            self.logger.info(f"{Fore.GREEN}Disconnect successful: {self.host}{Style.RESET_ALL}")

        except Exception as e:
            self.logger.error(f"{Fore.RED}Error during share-only enumeration: {e}{Style.RESET_ALL}")

    # -------------------------------
    # Shares + files enumeration
    # -------------------------------
    def enum_share_files(self, args):
        try:
            exports = self._get_exports()
            self.logger.info(f"{Fore.CYAN}Enumerating NFS Shares and Files{Style.RESET_ALL}")
            all_results = []

            for share in exports:
                try:
                    mount_info = self.mount.mnt(share, self.mount.auth)
                    if mount_info["status"] != 0:
                        continue

                    fhandle = mount_info["mountinfo"]["fhandle"]
                    perms = self.get_permissions(fhandle)

                    print(f"{Fore.BLUE}Main Share:{Style.RESET_ALL} {Fore.YELLOW}{share}{Style.RESET_ALL}")
                    print(f"    Permissions: "
                          f"{'READ' if perms['read'] else 'NO_READ'}, "
                          f"{'WRITE' if perms['write'] else 'NO_WRITE'}, "
                          f"{'EXEC' if perms['exec'] else 'NO_EXEC'}")

                    if self.args.check_root:
                        self.check_root_escape(share, list_root=True, read_passwd=False)

                    contents = self.list_dir(fhandle, share, self.recurse)
                    for item in contents:
                        full_path = item["path"]
                        if full_path.endswith("/"):
                            ftype = "directory"
                            filename = os.path.basename(full_path.rstrip("/"))
                        else:
                            ftype = "file"
                            filename = os.path.basename(full_path)

                        # use plain text + booleans carried out of list_dir
                        perm_text_plain = item.get("perms_plain", "UNKNOWN")
                        perm_text_display = item.get("perms", "UNKNOWN")
                        r = bool(item.get("perm_r", False))
                        w = bool(item.get("perm_w", False))
                        x = bool(item.get("perm_x", False))

                        row = {
                            "ip": self.host,
                            "share": share,
                            "path": os.path.dirname(full_path) if os.path.dirname(full_path) else share,
                            "file": filename,
                            "type": ftype,
                            "permissions": perm_text_plain,         # uncolored string with NO_*
                            "permissions_display": perm_text_display,  # colored for terminal table
                            "size": item["filesize"],
                            "perm_r": r,
                            "perm_w": w,
                            "perm_x": x,
                        }
                        all_results.append(row)


                    # Pretty print table per share
                    if contents:
                        headers = ["Share Path", "File/Dir", "Type", "Size", "Permissions"]
                        # compute widths based on this share's rows only
                        rows_this_share = [r for r in all_results if r["share"] == share]
                        share_w = max(len(strip_ansi(r["path"])) for r in rows_this_share + [{"path": headers[0]}]) + 3
                        file_w = max(len(strip_ansi(r["file"])) for r in rows_this_share + [{"file": headers[1]}]) + 3
                        type_w = max(len(r["type"]) for r in rows_this_share + [{"type": headers[2]}]) + 3
                        size_w = max(len(r["size"]) for r in rows_this_share + [{"size": headers[3]}]) + 3

                        header_line = (
                            headers[0].ljust(share_w)
                            + headers[1].ljust(file_w)
                            + headers[2].ljust(type_w)
                            + headers[3].ljust(size_w)
                            + headers[4]
                        )
                        print(Fore.CYAN + "\n" + header_line + Style.RESET_ALL)
                        print("-" * (share_w + file_w + type_w + size_w + len(headers[4]) + 5))

                        for row in rows_this_share:
                            print(
                                f"{row['path'].ljust(share_w)}"
                                f"{row['file'].ljust(file_w)}"
                                f"{row['type'].ljust(type_w)}"
                                f"{row['size'].ljust(size_w)}"
                                f"{row['permissions_display']}"
                            )
                        print()

                except Exception as e:
                    self.logger.error(f"{Fore.RED}Error accessing share {share}: {e}{Style.RESET_ALL}")

            # Save if user provided an output dir OR explicitly set a format
            should_save = (args.output_dir is not None) or (args.nfs_output_format is not None)
            if should_save and all_results:
                outdir = args.output_dir if args.output_dir else os.path.join(
                    "results", "cygor-enumeration-modules", "nfsexplorer"
                )
                fmt = args.nfs_output_format if args.nfs_output_format else "json"

                # Save in new cygor-result.json format
                saved_files = save_cygor_result(
                    all_results=all_results,
                    output_dir=outdir,
                    started_at=getattr(self, '_start_time', datetime.now()),
                    completed_at=datetime.now(),
                    target_count=1,  # Single host
                    list_files=True,
                    formats=fmt,
                )
                for p in saved_files:
                    self.logger.info(f"Results saved to {p}")

            self.logger.info(f"{Fore.GREEN}Disconnect successful: {self.host}{Style.RESET_ALL}")

        except Exception as e:
            self.logger.error(f"{Fore.RED}Error during share+file enumeration: {e}{Style.RESET_ALL}")

# ---------------------------
# Target collection
# ---------------------------
def _collect_targets(args):
    targets = []
    if args.targets:
        targets.extend([t.strip() for t in args.targets.split(",") if t.strip()])
    if args.input_file:
        with open(args.input_file) as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    targets.append(s)
    return list(dict.fromkeys(targets))

# ---------------------------
# Main
# ---------------------------
if __name__ == "__main__":
    args = parse_args()

    # Warn if jumpbox is active - NFS uses raw sockets and needs proxychains
    if is_jumpbox_routing_active():
        print(Fore.CYAN + "[i] Jumpbox active - NFS connections need proxychains wrapper" + Style.RESET_ALL)
        print(Fore.CYAN + "[i] Run: proxychains4 cygor module nfsexplorer ..." + Style.RESET_ALL)

    # ------------------------------------------------------------------
    # Workspace / Output Directory Resolution
    # ------------------------------------------------------------------
    # Priority:
    #   1) Explicit --output-dir from CLI
    #   2) Workspace ($CYGOR_WORKSPACE/$CYGOR_RESULTS_DIR or active workspace config)
    # There is no implicit ./results default; resolution errors out if no
    # workspace is configured. When -o/--output-dir is provided with no path
    # (empty string), a timestamped folder is created under the workspace.
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.output_dir and args.output_dir not in ("", None):
        out_dir = Path(args.output_dir)

    elif args.output_dir == "":
        from cygor.workspace import require_workspace
        out_dir = require_workspace() / "cygor-enumeration-modules" / "nfsexplorer" / ts

    else:
        from cygor.workspace import require_workspace
        out_dir = require_workspace() / "cygor-enumeration-modules" / "nfsexplorer"

    out_dir.mkdir(parents=True, exist_ok=True)
    args.output_dir = str(out_dir)
    print(Fore.CYAN + f"[*] Output directory: {out_dir}" + Style.RESET_ALL)
    
    #------------------------------------

    targets = _collect_targets(args)
    for host in targets:
        print(f"{Fore.MAGENTA}[*] Target: {host}{Style.RESET_ALL}")
        # Per-target IP rotation
        _rot = get_next_ip(target_ip=host, context="scan")
        _src_ip = _rot["address"] if _rot else None
        if _src_ip:
            print(f"{Fore.CYAN}[i] Source IP (rotation): {_src_ip}{Style.RESET_ALL}")
        cli = NFSClient(host, args, source_ip=_src_ip)
        if cli.create_conn_obj():
            cli.enum_host_info()
            cli.print_host_info()
            if args.list_files:
                cli.enum_share_files(args)
            else:
                cli.enum_shares_only()

