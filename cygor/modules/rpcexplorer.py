#!/usr/bin/env python3
"""
RPC Explorer - Cygor Enumeration Module
=======================================

Enumerate Windows/Samba hosts over MSRPC (via SMB named pipes) using a null
session by default: server/OS info, domain name + SID, domain users and groups,
and the password policy. Supply credentials to enumerate as an authenticated
user. Complements smbexplorer (which focuses on shares/files) with the
SAMR/LSARPC object enumeration that drives AD recon.

Results are parsed into typed rows ("parse-don't-dump") so they land in the
cygor inventory (DB + web UI), searchable and correlatable by host.

Wraps Samba's rpcclient and declares it as a dependency (skips cleanly if
absent). Targets are typically the SMB host bucket (445 open).

Output format: cygor-result.json (universal schema)
"""
import re
import shutil
import sys
from typing import Any, Dict, List, Optional

from colorama import Fore, Style

from cygor.modules.base import CygorModule, wrap_external

# One round-trip pulls server info, domain/SID, users, groups, and pw policy.
_RPC_COMMANDS = "srvinfo;lsaquery;enumdomusers;enumdomgroups;getdompwinfo"
_FAIL_MARKERS = ("NT_STATUS_LOGON_FAILURE", "NT_STATUS_ACCESS_DENIED",
                 "NT_STATUS_CONNECTION_REFUSED", "Cannot connect", "NT_STATUS_IO_TIMEOUT",
                 "NT_STATUS_HOST_UNREACHABLE")

# RID ranges for the RID-cycling fallback (matches enum4linux-ng's defaults).
DEFAULT_RID_RANGES = "500-550,1000-1050"
_MAX_RIDS = 4000  # safety cap on how many RIDs we'll look up in one pass


def _rpcclient(host: str, user: str, password: str, timeout: int) -> Optional[str]:
    if user:
        auth = ["-U", f"{user}%{password}"]
    else:
        auth = ["-U", "", "-N"]
    cmd = ["rpcclient", *auth, "-c", _RPC_COMMANDS, host]
    try:
        proc = wrap_external(cmd, timeout=timeout + 15)
    except Exception:
        return None
    return (proc.stdout or "") + "\n" + (proc.stderr or "")


def _parse_rpcclient(out: str) -> Dict[str, Any]:
    row: Dict[str, Any] = {"os": "", "domain": "", "domain_sid": "",
                           "users": "", "groups": "", "info": "",
                           "pw_min_length": "", "pw_complexity": ""}
    m = re.search(r"os version\s*:\s*(\S+)", out, re.IGNORECASE)
    if m:
        row["os"] = m.group(1)
    m = re.search(r"Domain Name\s*:\s*(\S+)", out, re.IGNORECASE)
    if m:
        row["domain"] = m.group(1)
    m = re.search(r"Domain Sid\s*:\s*(S-\S+)", out, re.IGNORECASE)
    if m:
        row["domain_sid"] = m.group(1)
    users = re.findall(r"user:\[([^\]]+)\]", out)
    groups = re.findall(r"group:\[([^\]]+)\]", out)
    if users:
        row["users"] = str(len(users))
    if groups:
        row["groups"] = str(len(groups))
    # Password policy from getdompwinfo: min length + the password_properties
    # bitmask (bit 0 = DOMAIN_PASSWORD_COMPLEX).
    m = re.search(r"min_password_length\s*:\s*(\d+)", out, re.IGNORECASE)
    if m:
        row["pw_min_length"] = m.group(1)
    m = re.search(r"password_properties\s*:\s*(0x[0-9a-fA-F]+)", out, re.IGNORECASE)
    if m:
        try:
            row["pw_complexity"] = "yes" if (int(m.group(1), 16) & 0x1) else "no"
        except ValueError:
            pass
    return row


def _polenum(host: str, user: str, password: str, timeout: int) -> Dict[str, Any]:
    """Full domain password policy via polenum (lockout threshold / max age /
    history) -- the bits getdompwinfo doesn't return. Empty dict if unavailable."""
    if not shutil.which("polenum"):
        return {}
    cmd = ["polenum", "--username", user or "", "--password", password or "", host]
    try:
        proc = wrap_external(cmd, timeout=timeout + 15)
    except Exception:
        return {}
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")

    def g(label):
        m = re.search(rf"{re.escape(label)}\s*:\s*(.+)", out)
        return m.group(1).strip() if m else ""

    pol: Dict[str, Any] = {}
    for key, label in (("min_length", "Minimum password length"),
                       ("lockout", "Account Lockout Threshold"),
                       ("max_age", "Maximum password age"),
                       ("history", "Password history length")):
        v = g(label)
        if v:
            pol[key] = v
    m = re.search(r"Domain Password Complex\s*:\s*(\d)", out)
    if m:
        pol["complexity"] = "yes" if m.group(1) == "1" else "no"
    return pol


def _parse_rid_ranges(spec: str) -> List[int]:
    """'500-550,1000-1050' -> [500..550, 1000..1050] (capped)."""
    rids: List[int] = []
    for part in (spec or "").split(","):
        part = part.strip()
        if "-" in part:
            a, _, b = part.partition("-")
            if a.strip().isdigit() and b.strip().isdigit():
                rids.extend(range(int(a), int(b) + 1))
        elif part.isdigit():
            rids.append(int(part))
    if not rids:
        rids = list(range(500, 551)) + list(range(1000, 1051))
    return rids[:_MAX_RIDS]


def _rid_cycle(host: str, user: str, password: str, domain_sid: str,
               rids: List[int], timeout: int) -> List[str]:
    """Resolve domain SID + RID -> account name via rpcclient lookupsids, in a
    single connection. Returns user (SID type 1) account names. This finds
    accounts when SAMR enumdomusers is restricted but lookupsids isn't."""
    if not domain_sid or not rids:
        return []
    cmds = ";".join(f"lookupsids {domain_sid}-{r}" for r in rids)
    auth = ["-U", f"{user}%{password}"] if user else ["-U", "", "-N"]
    try:
        proc = wrap_external(["rpcclient", *auth, "-c", cmds, host], timeout=timeout + 25)
    except Exception:
        return []
    names, seen = [], set()
    for line in (proc.stdout or "").splitlines():
        if "*unknown*" in line:
            continue
        # "S-1-5-21-..-1000 CORP\\jsmith (1)"  -- trailing (1) == SID_NAME_USER
        m = re.search(r"S-[\d-]+\s+(\S+\\[^\s(]+)\s+\((\d+)\)", line)
        if m and m.group(2) == "1":
            name = m.group(1).split("\\")[-1]
            if name not in seen:
                seen.add(name)
                names.append(name)
    return names


def _summarize_policy(row: Dict[str, Any]) -> str:
    parts = []
    if row.get("pw_min_length"):
        parts.append(f"minlen={row['pw_min_length']}")
    if row.get("pw_complexity"):
        parts.append(f"complex={row['pw_complexity']}")
    if row.get("pw_lockout"):
        parts.append(f"lockout={row['pw_lockout']}")
    if row.get("pw_max_age"):
        parts.append(f"maxage={row['pw_max_age']}")
    return ", ".join(parts)


class RPCExplorer(CygorModule):
    name = "RPC Explorer"
    slug = "rpcexplorer"
    version = "1.0.0"
    author = "cygor"
    description = "Enumerate MSRPC via null/auth session: server info, domain SID, users, groups, pw policy"
    category = "enumeration"
    view = "table"
    columns = [
        {"key": "ip", "label": "IP Address", "type": "ip"},
        {"key": "null_session", "label": "Null Session", "type": "badge"},
        {"key": "os", "label": "OS", "type": "string"},
        {"key": "domain", "label": "Domain", "type": "string"},
        {"key": "users", "label": "Users", "type": "string"},
        {"key": "groups", "label": "Groups", "type": "string"},
        {"key": "pw_policy", "label": "Password Policy", "type": "string"},
        {"key": "info", "label": "Info", "type": "string"},
    ]

    def setup_argparser(self, parser):
        parser.add_argument("-u", "--username", default=None,
                            help="Username for an authenticated session (default: null session)")
        parser.add_argument("-p", "--password", default="",
                            help="Password for the authenticated session")
        parser.add_argument("--timeout", type=int, default=10,
                            help="Per-host timeout in seconds (default: 10)")
        parser.add_argument("--rid-cycle", action="store_true",
                            help="Force RID cycling (default: auto when SAMR user enum is blocked)")
        parser.add_argument("--rid-ranges", default=DEFAULT_RID_RANGES,
                            help=f"RID ranges for cycling (default: {DEFAULT_RID_RANGES})")

    def run(self, targets: List[str], **kwargs) -> None:
        if not shutil.which("rpcclient"):
            print(f"{Fore.RED}[!] rpcclient not found in PATH. Install samba-client/"
                  f"samba-common-bin (Debian/Kali: apt install smbclient).{Style.RESET_ALL}",
                  file=sys.stderr)
            sys.exit(2)

        username = kwargs.get("username")
        password = kwargs.get("password") or ""
        timeout = kwargs.get("timeout") or 10
        authed = bool(username)
        force_rid = bool(kwargs.get("rid_cycle"))
        rids = _parse_rid_ranges(kwargs.get("rid_ranges") or DEFAULT_RID_RANGES)

        for raw in targets:
            host = raw.strip().split()[0].split(":")[0] if raw.strip() else ""
            if not host:
                continue
            out = _rpcclient(host, username or "", password, timeout)
            row = {"ip": host, "null_session": "no", "os": "", "domain": "",
                   "domain_sid": "", "users": "", "groups": "", "info": "",
                   "pw_min_length": "", "pw_complexity": "", "pw_lockout": "",
                   "pw_max_age": "", "pw_policy": ""}
            if out is None:
                row["info"] = "rpcclient error"
                self.add_result(row)
                continue
            parsed = _parse_rpcclient(out)
            got_data = any(parsed[k] for k in ("os", "domain", "users", "groups", "pw_min_length"))
            if got_data:
                row.update(parsed)
                row["null_session"] = "n/a (auth)" if authed else "yes"
                # Full policy (lockout/max age) via polenum, supplementing getdompwinfo.
                pol = _polenum(host, username or "", password, timeout)
                if pol.get("min_length") and not row["pw_min_length"]:
                    row["pw_min_length"] = pol["min_length"]
                if pol.get("complexity") and not row["pw_complexity"]:
                    row["pw_complexity"] = pol["complexity"]
                row["pw_lockout"] = pol.get("lockout", "")
                row["pw_max_age"] = pol.get("max_age", "")
                row["pw_policy"] = _summarize_policy(row)
                # RID cycle when SAMR user enum returned nothing (or when forced).
                if (force_rid or not row["users"] or row["users"] == "0") and row["domain_sid"]:
                    names = _rid_cycle(host, username or "", password, row["domain_sid"], rids, timeout)
                    if names:
                        row["users"] = str(len(names))
                        row["info"] = ("RID-cycled: " + ", ".join(names[:15]))[:200]
            else:
                fail = next((m for m in _FAIL_MARKERS if m in out), "")
                row["info"] = fail or "no data"
            self.add_result(row)
            print(f"[+] {host} session={row['null_session']} domain='{row['domain'] or '?'}' "
                  f"users={row['users'] or '0'} groups={row['groups'] or '0'}"
                  + (f" pw[{row['pw_policy']}]" if row['pw_policy'] else ""))


# Web UI registration (see dbprobe for the rationale).
module_info = {
    "name": RPCExplorer.name,
    "slug": RPCExplorer.slug,
    "description": RPCExplorer.description,
    "author": RPCExplorer.author,
    "version": RPCExplorer.version,
    "module_type": "enumeration",
    "view": RPCExplorer.view,
    "table": {"columns": RPCExplorer.columns},
    "options": [
        {"name": "username", "label": "Username", "type": "text", "default": "",
         "help": "Optional. Blank = null session (-U '' -N)."},
        {"name": "password", "label": "Password", "type": "password", "default": "",
         "help": "Password for an authenticated session."},
        {"name": "timeout", "label": "Timeout (s)", "type": "number",
         "default": "10", "min": 1, "max": 120, "help": "Per-host timeout in seconds."},
        {"name": "rid_cycle", "label": "Force RID cycling", "type": "checkbox", "default": False,
         "help": "Resolve SID+RID -> usernames even if SAMR user enum works (auto when it's blocked)."},
        {"name": "rid_ranges", "label": "RID ranges", "type": "text", "default": DEFAULT_RID_RANGES,
         "help": "RID ranges to cycle, e.g. 500-550,1000-1050."},
    ],
}


def main(argv=None):
    RPCExplorer().cli(argv)


if __name__ == "__main__":
    main()
