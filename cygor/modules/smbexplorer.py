#!/usr/bin/env python3
"""
SMB Explorer - Cygor Enumeration Module
========================================

Enumerate SMB shares, permissions, and optionally list files.
Supports NTLM and Kerberos authentication.

Output format: cygor-result.json (universal schema)
"""
import warnings

# Suppress pkg_resources deprecation warning globally before impacket imports
warnings.filterwarnings("ignore", category=UserWarning, message="pkg_resources is deprecated as an API")

import os
import logging
import argparse
import random
import ntpath
import re
import json
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from datetime import datetime
from time import time
from binascii import unhexlify

# impacket imports
import smbmap
from impacket.examples import logger as impacket_logger
from impacket import version, smbserver
from impacket.smbserver import SRVSServer, WKSTServer
from impacket.smbconnection import SMBConnection
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.types import Principal

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
# IP rotation is not available in this build; provide a no-op shim.
def get_next_ip(*args, **kwargs):
    return None

_socket_patch_lock = _threading_module.Lock()


@contextmanager
def _bound_socket_context(source_ip):
    """Temporarily monkey-patch socket.socket to bind to source_ip."""
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
                pass

        _socket_module.socket.__init__ = _patched_init
        try:
            yield
        finally:
            _socket_module.socket.__init__ = _orig_init

from colorama import Fore, Style, init as _color_init
from tabulate import tabulate

# Import cygor module framework
from cygor.modules.schema import (
    CygorResult, ModuleInfo, SchemaDefinition, RunMetadata,
    AssetReferences, ColumnDefinition, ColumnType, ViewType, ModuleCategory
)
from cygor.modules.exporters import export_to_csv, export_to_xml, export_to_txt

# ----------------------------------------------------------------------
# Init
# ----------------------------------------------------------------------
_color_init(autoreset=True, strip=False)
warnings.filterwarnings("ignore", category=UserWarning, module="pkg_resources")

# ----------------------------------------------------------------------
# Custom log formatter
# ----------------------------------------------------------------------
class CustomFormatter(logging.Formatter):
    FORMATS = {
        logging.DEBUG: Fore.BLUE + "[%(asctime)s] [DEBUG]" + Fore.RESET + " %(message)s",
        logging.INFO: Fore.GREEN + "[%(asctime)s] [INFO]" + Fore.RESET + " %(message)s",
        logging.WARNING: Fore.YELLOW + "[%(asctime)s] [WARNING]" + Fore.RESET + " %(message)s",
        logging.ERROR: Fore.RED + "[%(asctime)s] [ERROR]" + Fore.RESET + " %(message)s",
        logging.CRITICAL: Style.BRIGHT + Fore.RED + "[%(asctime)s] [CRITICAL]" + Style.RESET_ALL + " %(message)s",
    }
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt="%Y-%m-%d %H:%M:%S")
        return formatter.format(record)

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)

# ----------------------------------------------------------------------
# SMB share info
# ----------------------------------------------------------------------
share_info = {
    'ADMIN$': 'Remote Admin Share',
    'C$': 'Default System Drive',
    'IPC$': 'Remote IPC / Named Pipes',
    'SYSVOL': 'Domain Controller Share',
    'NETLOGON': 'Domain Controller Share',
    'PRINT$': 'Remote Administration of Printers',
    'FAX$': 'Shared Folder for Fax Transmissions',
}

# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def pathify(path):
    root = ntpath.join(path, '*')
    root = root.replace('/', '\\')
    root = root.replace('\\\\', '\\')
    return ntpath.normpath(root)

def clean_share_name(share_name):
    return re.sub(r'\x00|\s+$', '', share_name).strip()

ANSI_RE = re.compile(r'\x1b\[[0-9;]*m')
def _strip_ansi(val):
    return ANSI_RE.sub('', str(val))

def extract_share_name(share) -> str:
    """Extract the share name properly (UTF-16LE decoding)."""
    try:
        raw = share["shi1_netname"]
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-16le").rstrip("\x00")
        return clean_share_name(str(raw))
    except Exception:
        return "UNKNOWN"

# ----------------------------------------------------------------------
# Attribute decoding
# ----------------------------------------------------------------------
ATTR_FLAGS = {
    0x01: "READONLY", 0x02: "HIDDEN", 0x04: "SYSTEM", 0x08: "VOLUME",
    0x10: "DIRECTORY", 0x20: "ARCHIVE", 0x40: "DEVICE", 0x80: "NORMAL",
    0x100: "TEMPORARY", 0x200: "SPARSE", 0x400: "REPARSE", 0x800: "COMPRESSED",
    0x1000: "OFFLINE", 0x2000: "NOT_CONTENT_INDEXED", 0x4000: "ENCRYPTED",
}
def decode_attributes(attr_int):
    flags = [name for bit, name in ATTR_FLAGS.items() if attr_int & bit]
    return ",".join(flags) if flags else ""

# ----------------------------------------------------------------------
# File coloring (console only)
# ----------------------------------------------------------------------
EXT_COLOR_MAP = {
    ".txt": Fore.GREEN, ".log": Fore.GREEN, ".cfg": Fore.GREEN, ".conf": Fore.GREEN, ".ini": Fore.GREEN,
    ".doc": Fore.YELLOW, ".docx": Fore.YELLOW, ".xls": Fore.YELLOW, ".xlsx": Fore.YELLOW,
    ".ppt": Fore.YELLOW, ".pptx": Fore.YELLOW, ".pdf": Fore.YELLOW,
    ".exe": Fore.RED, ".dll": Fore.RED, ".bat": Fore.RED, ".cmd": Fore.RED, ".ps1": Fore.RED,
    ".vbs": Fore.RED, ".js": Fore.RED, ".sh": Fore.RED,
    ".zip": Fore.CYAN, ".rar": Fore.CYAN, ".7z": Fore.CYAN, ".gz": Fore.CYAN, ".tar": Fore.CYAN,
    ".png": Fore.MAGENTA, ".jpg": Fore.MAGENTA, ".jpeg": Fore.MAGENTA, ".gif": Fore.MAGENTA,
    ".bmp": Fore.MAGENTA, ".mp4": Fore.MAGENTA, ".avi": Fore.MAGENTA, ".mov": Fore.MAGENTA,
}
def colorize_name(name, is_dir=False):
    if is_dir:
        return Fore.YELLOW + name + Style.RESET_ALL
    ext = os.path.splitext(name)[1].lower()
    if ext in EXT_COLOR_MAP:
        return EXT_COLOR_MAP[ext] + name + Style.RESET_ALL
    return name

# ----------------------------------------------------------------------
# File listing helper
# ----------------------------------------------------------------------
def list_files_in_share(smb, share_name, max_files=50):
    entries = []
    try:
        for f in smb.listPath(share_name, '\\*'):
            fname = f.get_longname()
            if fname in [".", ".."]:
                continue
            is_dir = f.is_directory()
            size = f.get_filesize()
            mtime = datetime.fromtimestamp(f.get_mtime_epoch()).strftime("%Y-%m-%d %H:%M") if f.get_mtime_epoch() else ""
            attrs = decode_attributes(f.get_attributes())
            entries.append({
                "name": fname + ("/" if is_dir else ""),
                "size": "(dir)" if is_dir else f"{size:.1f} B",
                "mtime": mtime,
                "attributes": attrs,
                "is_dir": is_dir,
                "type": "Directory" if is_dir else ("Special" if share_name == "IPC$" else "File")
            })
            if len(entries) >= max_files:
                break
    except Exception as e:
        logger.debug(f"Error listing {share_name}: {e}")
    return entries

# ----------------------------------------------------------------------
# SMB enumeration worker
# ----------------------------------------------------------------------
def smb_enumerate(ip, username, password, domain, ntlm_hash, use_kerberos,
                  result_data, list_files=False, max_files=50, file_results=None,
                  kerberos_keytab=None, kerberos_aeskey=None, kerberos_principal=None, kerberos_ccache=None,
                  source_ip=None):
    smb_versions = ["SMBv3", "SMBv2", "SMBv1"]
    for smb_version in smb_versions:
        try:
            logger.info(f"Connecting to {ip} with {smb_version}...")
            if source_ip:
                logger.debug(f"Using source IP {source_ip} for SMB connection to {ip}")
            with _bound_socket_context(source_ip):
                smb = SMBConnection(ip, ip)

            user = username  # Don't prepend domain for Kerberos
            if use_kerberos:
                # Priority order: keytab > aeskey > ccache > KRB5CCNAME env
                try:
                    domain_upper = domain.upper() if domain else ''

                    if kerberos_keytab:
                        # Use keytab file authentication
                        keytab_path = os.path.abspath(os.path.expanduser(kerberos_keytab))
                        if not os.path.exists(keytab_path):
                            raise KerberosError(f"Keytab file not found: {keytab_path}")

                        logger.info(f"Using Kerberos keytab: {keytab_path}")

                        # Set environment variable for keytab
                        os.environ['KRB5_KTNAME'] = keytab_path

                        # Determine principal
                        if kerberos_principal:
                            principal = kerberos_principal
                        elif domain:
                            principal = f"{username}@{domain_upper}"
                        else:
                            raise KerberosError("Domain or principal required for keytab authentication")

                        logger.info(f"Authenticating as principal: {principal}")

                        # Use kerberosLogin with keytab
                        # impacket will read the keytab from KRB5_KTNAME
                        smb.kerberosLogin(username, '', domain_upper, '', '', useCache=False)

                    elif kerberos_aeskey:
                        # Use AES key for pass-the-key attack
                        logger.info("Using Kerberos AES key (pass-the-key)")

                        # Validate hex key
                        try:
                            aes_key = unhexlify(kerberos_aeskey)
                            if len(aes_key) not in (16, 32):  # AES-128 or AES-256
                                raise ValueError(f"AES key must be 128 or 256 bits (got {len(aes_key)*8} bits)")
                        except Exception as e:
                            raise KerberosError(f"Invalid AES key format: {e}")

                        if not domain:
                            raise KerberosError("Domain required for AES key authentication")

                        logger.info(f"Using {'AES-256' if len(aes_key) == 32 else 'AES-128'} key for user {username}@{domain_upper}")

                        # Use kerberosLogin with AES key
                        smb.kerberosLogin(username, '', domain_upper, '', '', aesKey=kerberos_aeskey)

                    else:
                        # Use ccache file
                        ccache_path = kerberos_ccache or os.getenv('KRB5CCNAME')
                        if not ccache_path:
                            raise KerberosError("No Kerberos credentials provided. Use --kerberos-keytab, --kerberos-aeskey, --kerberos-ccache, or set KRB5CCNAME")

                        # Handle KRB5CCNAME format (FILE:/path/to/ccache)
                        if ccache_path.startswith('FILE:'):
                            ccache_path = ccache_path[5:]

                        ccache_path = os.path.abspath(os.path.expanduser(ccache_path))
                        if not os.path.exists(ccache_path):
                            raise KerberosError(f"Ccache file not found: {ccache_path}")

                        logger.info(f"Using Kerberos ccache: {ccache_path}")

                        # Set the environment variable so impacket can find it
                        os.environ['KRB5CCNAME'] = ccache_path

                        # Use kerberosLogin with cache
                        smb.kerberosLogin(username, '', domain_upper, '', '', useCache=True)

                except KerberosError as e:
                    logger.error(f"Kerberos authentication failed: {e}")
                    raise
                except Exception as e:
                    logger.error(f"Kerberos authentication error: {e}")
                    raise KerberosError(f"Kerberos authentication failed: {e}")

            else:
                # NTLM or password authentication
                user = f"{domain}\\{username}" if domain else username

                if ntlm_hash:
                    try:
                        lm_hash, nt_hash = ntlm_hash.split(':', 1)
                        smb.login(user, '', lmhash=lm_hash, nthash=nt_hash)
                    except Exception:
                        smb.login(user, password)
                else:
                    smb.login(user, password)

            shares = smb.listShares()
            if not shares:
                result_data.append([ip, "No shares found", "Error", smb_version, "N/A", ""])
            else:
                for share in shares:
                    share_name_cleaned = extract_share_name(share)
                    result_info = share_info.get(share_name_cleaned, "")
                    permission = check_permissions(smb, share_name_cleaned)
                    result_data.append([ip, share_name_cleaned, "Success", smb_version, permission, result_info])

                    if list_files and file_results is not None and "No Access" not in permission:
                        files = list_files_in_share(smb, share_name_cleaned, max_files=max_files)
                        for f in files:
                            file_results.append({"ip": ip, "share": share_name_cleaned, **f})
            return
        except Exception as e:
            logger.warning(f"Failed to connect to {ip} using {smb_version}: {e}")
    result_data.append([ip, "Error", "Connection Failed", "N/A", "N/A", ""])

# ----------------------------------------------------------------------
# Permission checks
# ----------------------------------------------------------------------
def check_permissions(smb, share_name):
    try:
        smb.listPath(share_name, pathify('/'))
    except Exception as e:
        if "STATUS_ACCESS_DENIED" in str(e):
            return Fore.RED + "No Access" + Style.RESET_ALL
        return Fore.RED + "Share not accessible" + Style.RESET_ALL
    permissions = []
    try:
        smb.listPath(share_name, pathify('/'))
        permissions.append(Fore.YELLOW + "Read Only" + Style.RESET_ALL)
    except Exception:
        permissions.append(Fore.RED + "No Read" + Style.RESET_ALL)
    try:
        randm_dir = f"temp-dir-{random.randint(1,100000)}"
        smb.createDirectory(share_name, randm_dir)
        permissions.append(Fore.GREEN + "Read Write" + Style.RESET_ALL)
        try: smb.deleteDirectory(share_name, randm_dir)
        except Exception: pass
    except Exception:
        permissions.append(Fore.RED + "No Write" + Style.RESET_ALL)
    if any("No Access" in p for p in permissions):
        return Fore.RED + "No Access" + Style.RESET_ALL
    return ", ".join(permissions)

# ----------------------------------------------------------------------
# Save: shares table
# ----------------------------------------------------------------------
def save_share_results(result_data, output_dir, basename="smb_results", formats="txt,csv,json,xml"):
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    # Normalize headers for JSON
    headers = ["ip", "share", "status", "smb_version", "permissions", "information"]
    # Strip ANSI values
    rows = [[_strip_ansi(c) for c in r] for r in result_data[1:]]
    formats_list = [f.strip().lower() for f in formats.split(',') if f.strip()]
    if "all" in formats_list: formats_list = ["txt","csv","json","xml"]
    saved = []
    if "txt" in formats_list:
        p = Path(output_dir) / f"{basename}.txt"
        with open(p, "w", encoding="utf-8") as f:
            f.write(tabulate([result_data[0]] + rows, headers="firstrow", tablefmt="pretty"))
        saved.append(p)
    if "csv" in formats_list:
        p = Path(output_dir) / f"{basename}.csv"
        with open(p, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(result_data[0])
            writer.writerows(rows)
        saved.append(p)
    if "json" in formats_list:
        p = Path(output_dir) / f"{basename}.json"
        with open(p, "w", encoding="utf-8") as f:
            json.dump([dict(zip(headers, r)) for r in rows], f, indent=4)
        saved.append(p)
    if "xml" in formats_list:
        p = Path(output_dir) / f"{basename}.xml"
        root = ET.Element("results")
        for r in rows:
            entry = ET.SubElement(root, "share")
            for h, v in zip(headers, r):
                child = ET.SubElement(entry, h)
                child.text = str(v)
        ET.ElementTree(root).write(p, encoding="utf-8", xml_declaration=True)
        saved.append(p)
    return saved

# ----------------------------------------------------------------------
# Save: all files
# ----------------------------------------------------------------------
def save_file_results(file_results, output_dir, basename="smb_files", formats="txt,csv,json,xml"):
    if not file_results: return []
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    headers = ["ip", "share", "name", "size", "modified", "attributes", "type"]
    rows = [[f["ip"], f["share"], _strip_ansi(f["name"]), f["size"], f["mtime"], f["attributes"], f["type"]] for f in file_results]
    formats_list = [f.strip().lower() for f in formats.split(',') if f.strip()]
    if "all" in formats_list: formats_list = ["txt","csv","json","xml"]
    saved = []
    if "txt" in formats_list:
        p = Path(output_dir) / f"{basename}.txt"
        with open(p, "w", encoding="utf-8") as f:
            f.write(tabulate([headers] + rows, headers="firstrow", tablefmt="pretty"))
        saved.append(p)
    if "csv" in formats_list:
        p = Path(output_dir) / f"{basename}.csv"
        with open(p, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(rows)
        saved.append(p)
    if "json" in formats_list:
        p = Path(output_dir) / f"{basename}.json"
        with open(p, "w", encoding="utf-8") as f:
            json.dump([dict(zip(headers, r)) for r in rows], f, indent=4)
        saved.append(p)
    if "xml" in formats_list:
        p = Path(output_dir) / f"{basename}.xml"
        root = ET.Element("files")
        for r in rows:
            entry = ET.SubElement(root, "file")
            for h, v in zip(headers, r):
                child = ET.SubElement(entry, h)
                child.text = str(v)
        ET.ElementTree(root).write(p, encoding="utf-8", xml_declaration=True)
        saved.append(p)
    return saved


# ----------------------------------------------------------------------
# Save: cygor-result.json (new universal format)
# ----------------------------------------------------------------------
def save_cygor_result(
    result_data: list,
    file_results: list,
    output_dir: str,
    started_at: datetime,
    completed_at: datetime,
    target_count: int,
    formats: str = "json,csv,xml,txt"
) -> list:
    """
    Save results in the new cygor-result.json format with embedded schema.

    Args:
        result_data: List of share results (rows from result_data[1:])
        file_results: List of file results (if --list-files was used)
        output_dir: Output directory path
        started_at: Scan start time
        completed_at: Scan end time
        target_count: Number of targets scanned
        formats: Comma-separated list of formats to export

    Returns:
        List of saved file paths
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build results list from share data
    results = []
    headers = ["ip", "share", "status", "smb_version", "permissions", "information"]

    # Skip header row (result_data[0])
    for row in result_data[1:] if len(result_data) > 1 else []:
        result_dict = {}
        for i, h in enumerate(headers):
            if i < len(row):
                result_dict[h] = _strip_ansi(str(row[i])) if row[i] is not None else ""
            else:
                result_dict[h] = ""
        results.append(result_dict)

    # Define schema columns
    columns = [
        ColumnDefinition(key="ip", label="IP Address", type=ColumnType.IP),
        ColumnDefinition(key="share", label="Share Name", type=ColumnType.STRING),
        ColumnDefinition(key="status", label="Status", type=ColumnType.BADGE),
        ColumnDefinition(key="smb_version", label="SMB Version", type=ColumnType.STRING),
        ColumnDefinition(key="permissions", label="Permissions", type=ColumnType.BADGE),
        ColumnDefinition(key="information", label="Information", type=ColumnType.STRING),
    ]

    # Build module info
    module_info = ModuleInfo(
        name="SMB Explorer",
        slug="smbexplorer",
        version="2.0.0",
        author="cygor",
        description="Enumerate SMB shares, permissions, and files",
        category=ModuleCategory.NETWORK_SHARES,
    )

    # Build schema
    schema = SchemaDefinition(
        view=ViewType.TABLE,
        columns=columns,
        group_by="ip",
    )

    # Parse formats
    formats_list = [f.strip().lower() for f in formats.split(',') if f.strip()]
    if "all" in formats_list:
        formats_list = ["json", "csv", "xml", "txt"]

    # Build metadata
    metadata = RunMetadata(
        started_at=started_at,
        completed_at=completed_at,
        target_count=target_count,
        success_count=len([r for r in results if r.get("status") == "Success"]),
        error_count=len([r for r in results if r.get("status") != "Success"]),
        exported_formats=formats_list,
        workspace=os.environ.get("CYGOR_WORKSPACE") or os.environ.get("CYGOR_RESULTS_DIR"),
    )

    # Build assets (file listing data if available)
    assets = AssetReferences()
    if file_results:
        # Save file results as secondary JSON
        files_path = out_dir / "smb_files.json"
        clean_files = []
        for f in file_results:
            clean_files.append({
                "ip": f["ip"],
                "share": f["share"],
                "name": _strip_ansi(f["name"]),
                "size": f["size"],
                "modified": f["mtime"],
                "attributes": f["attributes"],
                "type": f["type"],
                "is_dir": f["is_dir"],
            })
        with open(files_path, "w", encoding="utf-8") as fp:
            json.dump(clean_files, fp, indent=2)
        assets.files.append("smb_files.json")

    # Build CygorResult
    cygor_result = CygorResult(
        module=module_info,
        metadata=metadata,
        schema_def=schema,
        results=results,
        assets=assets,
    )

    # Save files
    saved_files = []

    # Always save cygor-result.json (primary)
    json_path = out_dir / "cygor-result.json"
    cygor_result.save(json_path)
    saved_files.append(json_path)

    # Export other formats
    if "csv" in formats_list and results:
        csv_path = out_dir / "smbexplorer-results.csv"
        export_to_csv(results, csv_path, columns)
        saved_files.append(csv_path)

    if "xml" in formats_list and results:
        xml_path = out_dir / "smbexplorer-results.xml"
        export_to_xml(results, xml_path, "smbexplorer")
        saved_files.append(xml_path)

    if "txt" in formats_list and results:
        txt_path = out_dir / "smbexplorer-results.txt"
        export_to_txt(results, txt_path, columns)
        saved_files.append(txt_path)

    return saved_files

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def smbexplorer(input_file, output_dir=None, target=None, smb_output_format="txt,csv,json,xml",
                list_files=False, max_files=50, **module_command):
    start_time = time()

    # Warn if jumpbox is active - SMB uses raw sockets and needs proxychains
    if is_jumpbox_routing_active():
        print(f"{Fore.CYAN}[i] Jumpbox active - SMB connections need proxychains wrapper{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] Run: proxychains4 cygor module smbexplorer ...{Style.RESET_ALL}")

    username = module_command.get('username', 'guest')
    password = module_command.get('password', '')
    domain = module_command.get('domain', '')
    ntlm_hash = module_command.get('ntlm-hash') or module_command.get('ntlm_hash') or module_command.get('hash')
    use_kerberos = module_command.get('use_kerberos', False)

    # New Kerberos options
    kerberos_keytab = module_command.get('kerberos_keytab') or module_command.get('kerberos-keytab')
    kerberos_aeskey = module_command.get('kerberos_aeskey') or module_command.get('kerberos-aeskey')
    kerberos_principal = module_command.get('kerberos_principal') or module_command.get('kerberos-principal')
    kerberos_ccache = module_command.get('kerberos_ccache') or module_command.get('kerberos-ccache')

    # Resolve output directory with workspace awareness (no implicit ./results).

    # 1) CLI explicit path (highest priority)
    if output_dir and output_dir not in ("", None):
        out_dir = Path(output_dir)

    # 2) User passed -o with no argument: timestamped folder inside the workspace
    elif output_dir == "":
        from cygor.workspace import require_workspace
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_dir = require_workspace() / "cygor-enumeration-modules" / "smbexplorer" / ts

    # 3) Workspace (env var or active workspace config)
    else:
        from cygor.workspace import require_workspace
        out_dir = require_workspace() / "cygor-enumeration-modules" / "smbexplorer"

    out_dir.mkdir(parents=True, exist_ok=True)
    output_dir = str(out_dir)
    print(Fore.CYAN + f"[*] Output directory: {out_dir}" + Style.RESET_ALL)



    ips = []
    if target:
        ips = [target] if "," not in target else [t.strip() for t in target.split(",")]
    elif input_file:
        with open(input_file, 'r', encoding="utf-8") as f:
            ips = [l.strip() for l in f.read().splitlines() if l.strip()]

    result_data = [["IP Address", "Share", "Status", "SMB Version", "Permissions", "Information"]]
    file_results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for ip in ips:
            # Per-target IP rotation
            _rot = get_next_ip(target_ip=ip.strip(), context="scan")
            _src_ip = _rot["address"] if _rot else None
            futures.append(executor.submit(
                smb_enumerate, ip.strip(), username, password, domain, ntlm_hash,
                use_kerberos, result_data, list_files, max_files, file_results,
                kerberos_keytab, kerberos_aeskey, kerberos_principal, kerberos_ccache,
                _src_ip,
            ))
        for fut in as_completed(futures):
            fut.result()

    print(tabulate(result_data, headers="firstrow", tablefmt="pretty"))

    # Record timestamps
    started_at = datetime.fromtimestamp(start_time)
    completed_at = datetime.now()

    saved_paths = []
    if output_dir:
        # Save in new cygor-result.json format (primary)
        saved_paths += save_cygor_result(
            result_data=result_data,
            file_results=file_results,
            output_dir=output_dir,
            started_at=started_at,
            completed_at=completed_at,
            target_count=len(ips),
            formats=smb_output_format,
        )

    if list_files and file_results:
        print("\nAccessible files:\n")
        grouped = defaultdict(lambda: defaultdict(list))
        for f in file_results:
            grouped[f["ip"]][f["share"]].append(f)

        for ip, shares in grouped.items():
            share_names = sorted(shares.keys(), key=lambda s: (s == "IPC$", s))
            for share in share_names:
                files = shares[share]
                print(f"[{ip}] Share: {share}")

                dirs = [f for f in files if f["is_dir"]]
                regular = [f for f in files if not f["is_dir"] and share != "IPC$"]
                specials = [f for f in files if share == "IPC$" and not f["is_dir"]]

                if regular:
                    print("\n  Files\n  -----")
                    print(tabulate(
                        [[colorize_name(f["name"]), f["size"], f["mtime"], f["attributes"]] for f in regular],
                        headers=["Name", "Size", "Modified", "Attributes"],
                        tablefmt="plain"
                    ))

                if dirs:
                    print("\n  Directories\n  -----------")
                    print(tabulate(
                        [[colorize_name(f["name"], is_dir=True), f["size"], f["mtime"], f["attributes"]] for f in dirs],
                        headers=["Name", "Size", "Modified", "Attributes"],
                        tablefmt="plain"
                    ))

                if specials:
                    print("\n  Specials / Pipes\n  ----------------")
                    print(tabulate(
                        [[colorize_name(f["name"]), f["size"], f["mtime"], f["attributes"]] for f in specials],
                        headers=["Name", "Size", "Modified", "Attributes"],
                        tablefmt="plain"
                    ))
                print()

        # Note: File results are now saved as part of cygor-result.json assets (smb_files.json)

    if saved_paths:
        print()
        for p in saved_paths:
            logger.info(f"Results saved to {p}")

    elapsed = time() - start_time
    # Each row in result_data after the header is one host+share or one
    # error row. Count actual successes separately from failures so the
    # summary doesn't claim "3 shares found" when all 3 are connection errors.
    data_rows = result_data[1:] if result_data else []
    shares_count = sum(1 for r in data_rows if len(r) >= 3 and r[2] == "Success")
    failed_count = sum(1 for r in data_rows
                       if len(r) >= 3 and r[2] in ("Connection Failed", "Error"))

    if file_results:
        files_count = sum(1 for f in file_results if not f["is_dir"] and f["type"] == "File")
        dirs_count = sum(1 for f in file_results if f["is_dir"])
        specials_count = sum(1 for f in file_results if f["type"] == "Special")
        suffix = f" ({failed_count} host(s) failed)" if failed_count else ""
        logger.info(
            f"SMB enumeration completed in {elapsed:.1f}s: "
            f"{shares_count} shares, {files_count} files, {dirs_count} directories, "
            f"{specials_count} specials.{suffix}"
        )
    elif shares_count == 0 and failed_count:
        logger.info(
            f"SMB enumeration completed in {elapsed:.1f}s: "
            f"no shares accessible ({failed_count} host(s) failed to connect or authenticate)."
        )
    else:
        suffix = f" ({failed_count} host(s) failed)" if failed_count else ""
        logger.info(
            f"SMB enumeration completed in {elapsed:.1f}s: "
            f"{shares_count} shares found.{suffix} "
            f"Use --list-files to enumerate files, directories, and specials."
        )

# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
class ColorHelpFormatter(argparse.RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    def start_section(self, heading):
        heading = f"{Fore.CYAN}{heading}{Style.RESET_ALL}"
        super().start_section(heading)
    def _format_action_invocation(self, action):
        return f"{Fore.YELLOW}{super()._format_action_invocation(action)}{Style.RESET_ALL}"

_examples = f"""
{Fore.MAGENTA}Examples:{Style.RESET_ALL}

{Fore.CYAN}Basic Authentication:{Style.RESET_ALL}

{Fore.YELLOW}# Run SMB Explorer with guest login{Style.RESET_ALL}
cygor enum smbexplorer -t 10.10.10.5

{Fore.YELLOW}# Authenticate with username and password{Style.RESET_ALL}
cygor enum smbexplorer -t 192.168.1.100 -u administrator -p Passw0rd!

{Fore.YELLOW}# Use NTLM hash for login (pass-the-hash){Style.RESET_ALL}
cygor enum smbexplorer -t 192.168.1.50 -u administrator -d CORP -H aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99

{Fore.CYAN}Kerberos Authentication:{Style.RESET_ALL}

{Fore.YELLOW}# Use Kerberos with ccache file (from kinit or Rubeus){Style.RESET_ALL}
cygor enum smbexplorer -t dc01.corp.local -u user01 -d CORP -k --kerberos-ccache /tmp/krb5cc_user01

{Fore.YELLOW}# Use Kerberos with keytab file (common for service accounts){Style.RESET_ALL}
cygor enum smbexplorer -t dc01.corp.local -u svc_scanner -d CORP -k --kerberos-keytab /opt/keytabs/svc_scanner.keytab

{Fore.YELLOW}# Use Kerberos with AES key (pass-the-key attack){Style.RESET_ALL}
cygor enum smbexplorer -t dc01.corp.local -u user01 -d CORP -k --kerberos-aeskey 5f4dcc3b5aa765d61d8327deb882cf99

{Fore.YELLOW}# Specify custom Kerberos principal{Style.RESET_ALL}
cygor enum smbexplorer -t dc01.corp.local -d CORP -k --kerberos-ccache /tmp/ccache --kerberos-principal user@CORP.LOCAL

{Fore.CYAN}Output Options:{Style.RESET_ALL}

{Fore.YELLOW}# Save results to JSON only{Style.RESET_ALL}
cygor enum smbexplorer -t 10.10.10.5 -o results/smb --smb-output-format json

{Fore.YELLOW}# List up to 20 files from each share{Style.RESET_ALL}
cygor enum smbexplorer -t 10.10.10.5 --list-files --max-files 20

{Fore.CYAN}Notes:{Style.RESET_ALL}
- For Kerberos authentication, ensure the target is resolvable (use FQDN or add to /etc/hosts)
- Keytab files are most commonly used for service account authentication
- AES keys can be extracted from memory dumps or obtained during attacks
- Ccache files can be created with 'kinit' on Linux or exported from Windows with tools like Rubeus
- All Kerberos options work on both Windows and Linux
"""

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="cygor enum smbexplorer",
        usage="cygor enum smbexplorer [options]",
        description="Enumerate SMB shares, permissions, and optionally list files.",
        epilog=_examples, formatter_class=ColorHelpFormatter
    )
    a = p.add_argument_group("Authentication")
    a.add_argument("-u", "--username", type=str, default="guest", help="Username (default: guest)")
    a.add_argument("-p", "--password", type=str, default="", help="Password")
    a.add_argument("-d", "--domain", type=str, default="", help="Domain name")
    a.add_argument("-H", "--hashes", type=str, help="NTLM hash (LMHASH:NTHASH)")

    k = p.add_argument_group("Kerberos Authentication")
    k.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication")
    k.add_argument("--kerberos-keytab", type=str, help="Path to Kerberos keytab file (most common for service accounts)")
    k.add_argument("--kerberos-aeskey", type=str, help="AES key (128/256-bit hex) for pass-the-key attack")
    k.add_argument("--kerberos-principal", type=str, help="Kerberos principal (e.g., user@DOMAIN.COM). If not specified, uses username@DOMAIN")
    k.add_argument("--kerberos-ccache", type=str, help="Path to Kerberos ccache file (overrides KRB5CCNAME env variable)")

    t = p.add_argument_group("Targets")
    # `--target` is the project-wide convention (see cygor/modules/base.py);
    # `--targets` is the historic alias and stays accepted.
    t.add_argument("-t", "--target", "--targets", dest="targets", type=str,
                   help="Target IP address or comma-separated list")
    t.add_argument("-i", "-f", "--file", "--input-file", dest="input_file", type=str,
                   help="File with target IPs (one per line)")

    o = p.add_argument_group("Output/Options")
    o.add_argument("-o", "--output-dir", nargs="?", const="", type=str,
                   help="Directory to save results (if -o is passed without a path, "
                        "a timestamped folder is created under "
                        "<workspace>/cygor-enumeration-modules/smbexplorer/)")
    # Accept the standard `--format` plus the legacy `--smb-output-format`.
    o.add_argument("--format", "--smb-output-format",
                   dest="format", type=str, default="txt,csv,json,xml",
                   help="Output formats: txt,csv,json,xml or all")
    o.add_argument("--list-files", action="store_true", help="List accessible files in each share")
    o.add_argument("--max-files", type=int, default=50, help="Max files to list per share when using --list-files")

    return p.parse_args(argv)

# ----------------------------------------------------------------------
# Entry
# ----------------------------------------------------------------------
if __name__ == "__main__":
    args = parse_args()
    smbexplorer(
        input_file=args.input_file,
        output_dir=args.output_dir,
        target=args.targets,
        smb_output_format=args.format,
        list_files=args.list_files,
        max_files=args.max_files,
        username=args.username,
        password=args.password,
        domain=args.domain,
        ntlm_hash=args.hashes,
        use_kerberos=args.kerberos,
        kerberos_keytab=args.kerberos_keytab,
        kerberos_aeskey=args.kerberos_aeskey,
        kerberos_principal=args.kerberos_principal,
        kerberos_ccache=args.kerberos_ccache,
    )
