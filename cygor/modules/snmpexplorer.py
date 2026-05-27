#!/usr/bin/env python3
"""
SNMP Explorer - Cygor Enumeration Module
========================================

Enumerate SNMP v1/v2c devices. Find a working community string (configured set,
falling back to an onesixtyone brute of common strings), then pull the system
group AND walk the high-value MIB subtrees -- user accounts, running processes,
installed software, listening TCP ports, and network interfaces. Everything is
parsed into structured rows rather than raw tool output ("parse-don't-dump")
so results land in the cygor inventory (DB + web UI), searchable and
correlatable by host.

Wraps net-snmp (snmpget/snmpwalk) and, when present, onesixtyone for fast
community brute-forcing. snmpwalk/onesixtyone are optional: the module degrades
to system-group-only (and configured-community-only) when they're absent.

Output format: cygor-result.json (universal schema)
"""
import os
import sys
import shutil
import argparse
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from colorama import Fore, Style, init as _color_init

from cygor.modules.schema import (
    CygorResult, ModuleInfo, SchemaDefinition, RunMetadata,
    AssetReferences, ColumnDefinition, ColumnType, ViewType, ModuleCategory,
)
from cygor.modules.exporters import export_to_csv, export_to_xml, export_to_txt

_color_init(autoreset=True, strip=False)

# Standard SNMPv2-MIB system group, numeric OIDs so no MIB files are needed.
SYS_OIDS = [
    ("sysDescr",    "1.3.6.1.2.1.1.1.0"),
    ("sysUpTime",   "1.3.6.1.2.1.1.3.0"),
    ("sysContact",  "1.3.6.1.2.1.1.4.0"),
    ("sysName",     "1.3.6.1.2.1.1.5.0"),
    ("sysLocation", "1.3.6.1.2.1.1.6.0"),
]
PROBE_OID = "1.3.6.1.2.1.1.1.0"  # sysDescr -- used to detect a live community

DEFAULT_COMMUNITIES = ["public", "private"]

# Brute-force fallback set (used via onesixtyone when the configured communities
# fail). Common read strings seen across vendors/appliances.
COMMON_COMMUNITIES = [
    "public", "private", "community", "manager", "admin", "read", "write",
    "monitor", "cisco", "default", "snmp", "snmpd", "security", "readonly",
    "readwrite", "all", "guest", "root", "ilmi", "system",
]

# High-value MIB subtrees to walk once a community works (numeric OIDs, no MIB
# files needed). This is the classic SNMP "loot": accounts, processes, installed
# software, listening ports, and interfaces.
WALK_OIDS = {
    "users":      "1.3.6.1.4.1.77.1.2.25",   # Windows LanMgr user accounts
    "processes":  "1.3.6.1.2.1.25.4.2.1.2",  # hrSWRunName (running processes)
    "software":   "1.3.6.1.2.1.25.6.3.1.2",  # hrSWInstalledName (installed software)
    "tcp_ports":  "1.3.6.1.2.1.6.13.1.3",    # tcpConnLocalPort (local TCP ports)
    "interfaces": "1.3.6.1.2.1.2.2.1.2",     # ifDescr (network interfaces)
}


def _read_targets(targets_arg, input_file):
    """Build a target host list from a comma string and/or a one-per-line file."""
    hosts = []
    if input_file:
        p = Path(input_file)
        if not p.is_file():
            print(f"{Fore.RED}[!] Input file not found: {input_file}{Style.RESET_ALL}", file=sys.stderr)
        else:
            for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    # tolerate "ip", "ip:port", "ip<whitespace>..."
                    hosts.append(line.replace(",", " ").split()[0].split(":")[0])
    if targets_arg:
        for t in targets_arg.split(","):
            t = t.strip()
            if t:
                hosts.append(t)
    seen, out = set(), []
    for h in hosts:
        if h and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _snmpget(host, community, oid, timeout):
    """Run `snmpget` for a single OID. Returns the value string, or None."""
    try:
        proc = subprocess.run(
            ["snmpget", "-v2c", "-c", community, "-t", str(timeout), "-r", "0",
             "-Oqv", host, oid],
            capture_output=True, text=True, timeout=timeout + 3,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None
    if proc.returncode != 0:
        return None
    val = (proc.stdout or "").strip().strip('"').strip()
    # net-snmp prints these for missing/unreachable instead of failing hard
    if not val or "No Such" in val or "Timeout" in val or "No Response" in val:
        return None
    return val


def _snmpwalk(host, community, oid, timeout, cap=300):
    """Walk an OID subtree, returning the list of values (deduped of empties)."""
    if not shutil.which("snmpwalk"):
        return []
    try:
        proc = subprocess.run(
            ["snmpwalk", "-v2c", "-c", community, "-t", str(timeout), "-r", "0",
             "-Oqv", host, oid],
            capture_output=True, text=True, timeout=timeout * 4 + 15,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []
    if proc.returncode != 0:
        return []
    out = []
    for line in (proc.stdout or "").splitlines():
        v = line.strip().strip('"').strip()
        if v and "No Such" not in v and "No more" not in v and "End of MIB" not in v:
            out.append(v)
        if len(out) >= cap:
            break
    return out


def _onesixtyone(host, communities, timeout):
    """Fast UDP community brute via onesixtyone. Returns valid communities."""
    if not shutil.which("onesixtyone"):
        return []
    import re
    import tempfile
    cfile = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as tf:
            tf.write("\n".join(communities))
            cfile = tf.name
        proc = subprocess.run(
            ["onesixtyone", "-c", cfile, "-w", "100", host],
            capture_output=True, text=True, timeout=timeout * 2 + 20,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return []
    finally:
        if cfile:
            try:
                os.unlink(cfile)
            except OSError:
                pass
    # output lines look like: "192.168.1.1 [public] Hardware: ..."
    seen, valid = set(), []
    for line in (proc.stdout or "").splitlines():
        m = re.search(r"\[([^\]]+)\]", line)
        if m and m.group(1) not in seen:
            seen.add(m.group(1))
            valid.append(m.group(1))
    return valid


def _enumerate_host(host, communities, timeout):
    """Detect a working community for *host*, pull the system group, and walk the
    high-value MIB subtrees (users/processes/software/ports/interfaces).

    Returns a structured row dict, or None if SNMP didn't answer.
    """
    community = None
    for c in communities:
        if _snmpget(host, c, PROBE_OID, timeout) is not None:
            community = c
            break
    # Fallback: brute the common set with onesixtyone, then confirm with snmpget.
    if not community:
        for c in _onesixtyone(host, COMMON_COMMUNITIES, timeout):
            if _snmpget(host, c, PROBE_OID, timeout) is not None:
                community = c
                break
    if not community:
        return None

    row = {"ip": host, "community": community, "snmp": "v2c"}
    for label, oid in SYS_OIDS:
        row[label] = _snmpget(host, community, oid, timeout) or ""

    # Deep walk (skips cleanly if snmpwalk is absent -> empty lists).
    users = _snmpwalk(host, community, WALK_OIDS["users"], timeout, cap=100)
    procs = _snmpwalk(host, community, WALK_OIDS["processes"], timeout, cap=300)
    soft = _snmpwalk(host, community, WALK_OIDS["software"], timeout, cap=300)
    ports = _snmpwalk(host, community, WALK_OIDS["tcp_ports"], timeout, cap=400)
    ifaces = _snmpwalk(host, community, WALK_OIDS["interfaces"], timeout, cap=50)

    ports_u = sorted({p for p in ports if p.isdigit()}, key=lambda x: int(x))
    row["users"] = ", ".join(users[:40])
    row["user_count"] = str(len(users))
    row["processes"] = ", ".join(procs[:60])
    row["process_count"] = str(len(procs))
    row["software"] = ", ".join(soft[:60])
    row["software_count"] = str(len(soft))
    row["tcp_ports"] = ", ".join(ports_u[:60])
    row["interfaces"] = ", ".join(ifaces[:20])
    return row


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="cygor enum snmpexplorer",
        usage="cygor enum snmpexplorer (-t IPs | -f FILE) [options]",
        description="Enumerate SNMP v1/v2c: find a valid community and read device system info.",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    tgt = parser.add_argument_group("Targets")
    # `--target` is the project-wide convention (cygor/modules/base.py);
    # `--targets` is the historic alias and stays accepted.
    tgt.add_argument("-t", "--target", "--targets", dest="targets", type=str,
                     help="IP/host or comma-separated list")
    tgt.add_argument("-f", "-i", "--file", "--input-file", dest="input_file", type=str,
                     help="File of targets, one per line")

    out = parser.add_argument_group("Options")
    # Bare `-o` -> workspace default, matches base.py.
    out.add_argument("-o", "--output-dir", nargs="?", const="", default=None,
                     help="Output directory (default: <workspace>/cygor-enumeration-modules/snmpexplorer/)")
    out.add_argument("-c", "--communities", default=",".join(DEFAULT_COMMUNITIES),
                     help="Community strings to try, comma-separated (default: public,private)")
    out.add_argument("--timeout", type=int, default=2, help="Per-probe timeout in seconds (default: 2)")
    out.add_argument("--threads", type=int, default=10, help="Concurrent hosts (default: 10)")
    # `--format` is the project-wide convention; `--output-format` is the
    # historic alias.
    out.add_argument("--format", "--output-format",
                     dest="format",
                     choices=["json", "csv", "xml", "txt", "all"],
                     default="json", help="Also export this format (default: json)")

    args = parser.parse_args(argv)
    if not args.targets and not args.input_file:
        parser.error("specify targets with -t/--target or -f/--input-file")
    return args


# Web UI registration: discovery reads this module-level dict to name the module
# on /modules and render its Run-Module form. Field names map snake_case ->
# --kebab-case CLI flags.
module_info = {
    "name": "SNMP Explorer",
    "slug": "snmpexplorer",
    "description": "Enumerate SNMP v1/v2c community strings and device system info",
    "author": "cygor",
    "version": "1.0.0",
    "module_type": "enumeration",
    "view": "table",
    "table": {"columns": [
        {"key": "ip", "label": "IP Address", "type": "ip"},
        {"key": "community", "label": "Community", "type": "badge"},
        {"key": "sysName", "label": "System Name", "type": "string"},
        {"key": "sysDescr", "label": "Description", "type": "string"},
        {"key": "users", "label": "Users", "type": "string"},
        {"key": "tcp_ports", "label": "TCP Ports", "type": "string"},
        {"key": "process_count", "label": "Procs", "type": "badge"},
        {"key": "software_count", "label": "Software", "type": "badge"},
        {"key": "sysUpTime", "label": "Uptime", "type": "string"},
    ]},
    "options": [
        {
            "name": "communities", "label": "Communities", "type": "text",
            "default": "public,private",
            "help": "Comma-separated community strings to try.",
        },
        {
            "name": "timeout", "label": "Timeout (s)", "type": "number",
            "default": "2", "min": 1, "max": 30,
            "help": "Per-probe timeout in seconds.",
        },
        {
            "name": "threads", "label": "Threads", "type": "number",
            "default": "10", "min": 1, "max": 100,
            "help": "Concurrent hosts.",
        },
    ],
}


def main(argv=None):
    args = parse_args(argv)

    # Declare + check the external tool dependency; skip cleanly if missing.
    if not shutil.which("snmpget"):
        print(f"{Fore.RED}[!] snmpget not found in PATH. Install net-snmp "
              f"(Debian/Kali: apt install snmp).{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(2)

    hosts = _read_targets(args.targets, args.input_file)
    if not hosts:
        print(f"{Fore.RED}[!] No valid targets supplied.{Style.RESET_ALL}", file=sys.stderr)
        sys.exit(1)

    communities = [c.strip() for c in args.communities.split(",") if c.strip()] or DEFAULT_COMMUNITIES

    # Output dir resolution (matches the convention used by the other modules):
    #   - explicit non-empty --output-dir wins;
    #   - bare `-o` (const="") -> workspace default + a timestamped subdir
    #     so consecutive runs don't trample each other;
    #   - omitted altogether -> workspace default (no timestamp), legacy behaviour.
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if args.output_dir not in (None, ""):
        out_dir = Path(args.output_dir)
    elif args.output_dir == "":
        from cygor.workspace import require_workspace
        out_dir = require_workspace() / "cygor-enumeration-modules" / "snmpexplorer" / ts
    else:
        from cygor.workspace import require_workspace
        out_dir = require_workspace() / "cygor-enumeration-modules" / "snmpexplorer"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"{Fore.CYAN}[*] SNMP enumeration: {len(hosts)} host(s), "
          f"communities={communities}, timeout={args.timeout}s{Style.RESET_ALL}")

    started_at = datetime.now(timezone.utc)
    results = []
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as ex:
        futures = {ex.submit(_enumerate_host, h, communities, args.timeout): h for h in hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                row = fut.result()
            except Exception as e:
                print(f"{Fore.YELLOW}[!] {host}: {e}{Style.RESET_ALL}")
                continue
            if row:
                results.append(row)
                descr = (row.get("sysDescr") or "")[:50]
                loot = []
                for k, lbl in (("user_count", "users"), ("process_count", "procs"),
                               ("software_count", "sw")):
                    if row.get(k) and row[k] != "0":
                        loot.append(f"{row[k]} {lbl}")
                if row.get("tcp_ports"):
                    loot.append(f"{len(row['tcp_ports'].split(','))} tcp-ports")
                extra = f"  [{', '.join(loot)}]" if loot else ""
                print(f"{Fore.GREEN}[+] {host} community '{row['community']}' "
                      f"{row.get('sysName', '')}  {descr}{extra}{Style.RESET_ALL}")
    completed_at = datetime.now(timezone.utc)

    columns = [
        ColumnDefinition(key="ip", label="IP Address", type=ColumnType.IP),
        ColumnDefinition(key="community", label="Community", type=ColumnType.BADGE),
        ColumnDefinition(key="sysName", label="System Name", type=ColumnType.STRING),
        ColumnDefinition(key="sysDescr", label="Description", type=ColumnType.STRING),
        ColumnDefinition(key="users", label="Users", type=ColumnType.STRING),
        ColumnDefinition(key="tcp_ports", label="TCP Ports", type=ColumnType.STRING),
        ColumnDefinition(key="process_count", label="Procs", type=ColumnType.BADGE),
        ColumnDefinition(key="software_count", label="Software", type=ColumnType.BADGE),
        ColumnDefinition(key="sysUpTime", label="Uptime", type=ColumnType.STRING),
    ]
    module_info = ModuleInfo(
        name="SNMP Explorer",
        slug="snmpexplorer",
        version="1.0.0",
        author="cygor",
        description="Enumerate SNMP v1/v2c community strings and device system info",
        category=ModuleCategory.ENUMERATION,
    )
    schema = SchemaDefinition(view=ViewType.TABLE, columns=columns, group_by="ip")

    fmt = args.format.lower()
    formats_list = ["json", "csv", "xml", "txt"] if fmt == "all" else [fmt]
    metadata = RunMetadata(
        started_at=started_at,
        completed_at=completed_at,
        target_count=len(hosts),
        success_count=len(results),
        error_count=0,
        exported_formats=formats_list,
        command_line="cygor enum snmpexplorer",
        workspace=os.environ.get("CYGOR_WORKSPACE") or os.environ.get("CYGOR_RESULTS_DIR"),
    )
    cygor_result = CygorResult(
        module=module_info,
        metadata=metadata,
        schema_def=schema,
        results=results,
        assets=AssetReferences(),
    )

    json_path = out_dir / "cygor-result.json"
    cygor_result.save(json_path)
    # Always honour the requested formats, even when `results` is empty:
    # an empty CSV/XML/TXT is a valid record-of-run that a user can grep
    # to confirm the scan really happened (the previous "skip if empty"
    # behaviour made `--format all` look broken on no-result runs).
    if "csv" in formats_list:
        export_to_csv(results, out_dir / "snmpexplorer-results.csv", columns)
    if "xml" in formats_list:
        export_to_xml(results, out_dir / "snmpexplorer-results.xml")
    if "txt" in formats_list:
        export_to_txt(results, out_dir / "snmpexplorer-results.txt", columns)

    print(f"{Fore.GREEN}[+] SNMP: {len(results)}/{len(hosts)} host(s) responded. "
          f"Results saved to {json_path}{Style.RESET_ALL}")


if __name__ == "__main__":
    main()
