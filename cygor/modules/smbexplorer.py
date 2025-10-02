#!/usr/bin/env python3
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

# impacket imports
import smbmap
from impacket.examples import logger as impacket_logger
from impacket import version, smbserver
from impacket.smbserver import SRVSServer, WKSTServer
from impacket.smbconnection import SMBConnection
from impacket.krb5.ccache import CCache
from impacket.krb5.kerberosv5 import KerberosError
from impacket.krb5.types import Principal

from colorama import Fore, Style, init as _color_init
from tabulate import tabulate

# ----------------------------------------------------------------------
# Init
# ----------------------------------------------------------------------
_color_init(autoreset=True)
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
                  result_data, list_files=False, max_files=50, file_results=None):
    smb_versions = ["SMBv3", "SMBv2", "SMBv1"]
    for smb_version in smb_versions:
        try:
            logger.info(f"Connecting to {ip} with {smb_version}...")
            smb = SMBConnection(ip, ip)

            user = f"{domain}\\{username}" if domain else username
            if use_kerberos:
                ccache_path = os.getenv('KRB5CCNAME')
                if not ccache_path:
                    raise KerberosError("KRB5CCNAME not set")
                ccache = CCache.loadFile(ccache_path)
                tgt = ccache.getCredential(Principal(f'krbtgt/{domain.upper()}@{domain.upper()}', ccache.principal.realm))
                if tgt is None:
                    raise KerberosError("No TGT found in ccache")
                smb.kerberosLogin(user, '', '', tgt, domain=domain)
            elif ntlm_hash:
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
# Main
# ----------------------------------------------------------------------
def smbexplorer(input_file, output_dir=None, target=None, smb_output_format="txt,csv,json,xml",
                list_files=False, max_files=50, **module_command):
    start_time = time()
    username = module_command.get('username', 'guest')
    password = module_command.get('password', '')
    domain = module_command.get('domain', '')
    ntlm_hash = module_command.get('ntlm-hash') or module_command.get('ntlm_hash') or module_command.get('hash')
    use_kerberos = module_command.get('use_kerberos', False)

    if output_dir == "":
        output_dir = f"results/cygor-enumeration-modules/smbexplorer/"

    ips = []
    if target:
        ips = [target] if "," not in target else [t.strip() for t in target.split(",")]
    elif input_file:
        with open(input_file, 'r', encoding="utf-8") as f:
            ips = [l.strip() for l in f.read().splitlines() if l.strip()]

    result_data = [["IP Address", "Share", "Status", "SMB Version", "Permissions", "Information"]]
    file_results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(
            smb_enumerate, ip.strip(), username, password, domain, ntlm_hash,
            use_kerberos, result_data, list_files, max_files, file_results
        ) for ip in ips]
        for fut in as_completed(futures):
            fut.result()

    print(tabulate(result_data, headers="firstrow", tablefmt="pretty"))

    saved_paths = []
    if output_dir:
        saved_paths += save_share_results(result_data, output_dir, basename="smb_results", formats=smb_output_format)

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

        if output_dir:
            saved_paths += save_file_results(file_results, output_dir, basename="smb_files", formats=smb_output_format)

    if saved_paths:
        print()
        for p in saved_paths:
            logger.info(f"Results saved to {p}")

    elapsed = time() - start_time
    shares_count = len(result_data) - 1

    if file_results:
        files_count = sum(1 for f in file_results if not f["is_dir"] and f["type"] == "File")
        dirs_count = sum(1 for f in file_results if f["is_dir"])
        specials_count = sum(1 for f in file_results if f["type"] == "Special")
        logger.info(
            f"SMB enumeration completed in {elapsed:.1f}s: "
            f"{shares_count} shares, {files_count} files, {dirs_count} directories, {specials_count} specials."
        )
    else:
        logger.info(
            f"SMB enumeration completed in {elapsed:.1f}s: "
            f"{shares_count} shares found. Use --list-files to enumerate files, directories, and specials."
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

{Fore.YELLOW}# Run SMB Explorer with guest login{Style.RESET_ALL}
cygor enum smbexplorer -t 10.10.10.5

{Fore.YELLOW}# Authenticate with username and password{Style.RESET_ALL}
cygor enum smbexplorer -t 192.168.1.100 -u administrator -p Passw0rd!

{Fore.YELLOW}# Use NTLM hash for login{Style.RESET_ALL}
cygor enum smbexplorer -t 192.168.1.50 -H aad3...:5f4d...

{Fore.YELLOW}# Save results to JSON only{Style.RESET_ALL}
cygor enum smbexplorer -t 10.10.10.5 -o results/smb --smb-output-format json

{Fore.YELLOW}# List up to 20 files from each share{Style.RESET_ALL}
cygor enum smbexplorer -t 10.10.10.5 --list-files --max-files 20
"""

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="cygor enum smbexplorer",
        usage="cygor enum smbexplorer [options]",
        description="Enumerate SMB shares, permissions, and optionally list files.",
        epilog=_examples, formatter_class=ColorHelpFormatter
    )
    a = p.add_argument_group("Authentication")
    a.add_argument("-u", "--username", type=str, default="guest")
    a.add_argument("-p", "--password", type=str, default="")
    a.add_argument("-d", "--domain", type=str, default="")
    a.add_argument("-H", "--hashes", type=str, help="NTLM hash (LMHASH:NTHASH)")
    a.add_argument("-k", "--kerberos", action="store_true", help="Use Kerberos authentication from ccache")

    t = p.add_argument_group("Targets")
    t.add_argument("-t", "--targets", type=str, help="Target IP address or comma-separated list")
    t.add_argument("-i", "--input-file", type=str, help="File with target IPs (one per line)")

    o = p.add_argument_group("Output/Options")
    o.add_argument("-o", "--output-dir", nargs="?", const="", type=str,
                   help="Directory to save results (if -o used with no path, a timestamped folder will be created under results/cygor-enumeration-modules/smbexplorer/)")
    o.add_argument("--smb-output-format", type=str, default="txt,csv,json,xml",
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
        smb_output_format=args.smb_output_format,
        list_files=args.list_files,
        max_files=args.max_files,
        username=args.username,
        password=args.password,
        domain=args.domain,
        ntlm_hash=args.hashes,
        use_kerberos=args.kerberos,
    )
