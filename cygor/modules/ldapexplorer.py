#!/usr/bin/env python3
"""
LDAP Explorer - Cygor Enumeration Module
========================================

Enumerate LDAP / Active Directory servers found by cygor's scan. Two paths:

  - No credentials: read the rootDSE with ldapsearch (naming contexts, domain,
    DC hostname, functional level, SASL mechanisms) and test whether anonymous
    bind and anonymous *search* are allowed -- the latter is a real finding.
  - With credentials: run ldapdomaindump to pull users/groups/computers as JSON
    and report the counts (full dumps land on disk for follow-up).

Results are parsed into typed rows ("parse-don't-dump") so they land in the
cygor inventory (DB + web UI), searchable and correlatable by host.

Wraps best-of-breed tools rather than reimplementing LDAP:
  - ldapsearch      rootDSE + anonymous bind/search probes (no creds)
  - ldapdomaindump  authenticated AD object dump to JSON (with creds)

Output format: cygor-result.json (universal schema)
"""
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from colorama import Fore, Style

from cygor.modules.base import CygorModule, wrap_external

# domainControllerFunctionality / domainFunctionality -> AD release.
FUNC_LEVELS = {
    "0": "2000", "1": "2003 interim", "2": "2003", "3": "2008",
    "4": "2008 R2", "5": "2012", "6": "2012 R2", "7": "2016+",
}


def _ldif_parse(text: str) -> Dict[str, List[str]]:
    """Parse simple (unwrapped) LDIF into key -> [values]."""
    out: Dict[str, List[str]] = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, _, val = line.partition(":")
        val = val.lstrip(":").strip()  # tolerate "key:: base64" loosely
        out.setdefault(key.strip(), []).append(val)
    return out


def _dn_to_domain(dn: str) -> str:
    """DC=corp,DC=local -> corp.local."""
    parts = [p.split("=", 1)[1] for p in dn.split(",") if p.strip().upper().startswith("DC=")]
    return ".".join(parts)


def _ldapsearch(server: str, base: str, scope: str, timeout: int,
                filt: str = "(objectClass=*)", attrs: Optional[List[str]] = None,
                sizelimit: Optional[int] = None) -> tuple:
    cmd = ["ldapsearch", "-x", "-LLL", "-o", "ldif-wrap=no",
           "-o", f"nettimeout={timeout}", "-l", str(timeout),
           "-H", f"ldap://{server}", "-s", scope, "-b", base]
    if sizelimit:
        cmd += ["-z", str(sizelimit)]
    cmd += [filt]
    cmd += attrs or []
    try:
        proc = wrap_external(cmd, timeout=timeout + 10)
    except Exception:
        return 1, ""
    return proc.returncode, (proc.stdout or "")


def _ldapdomaindump_counts(server: str, user: str, password: str, out_dir: Path,
                           timeout: int) -> Dict[str, str]:
    if not shutil.which("ldapdomaindump"):
        return {"info": "ldapdomaindump not installed"}
    dump_dir = out_dir / "ldapdomaindump" / server.replace(":", "_")
    dump_dir.mkdir(parents=True, exist_ok=True)
    try:
        wrap_external(
            ["ldapdomaindump", "-u", user, "-p", password, "-o", str(dump_dir),
             "--no-html", "--no-grep", server],
            timeout=timeout + 120,
        )
    except Exception as e:
        return {"info": f"dump error: {str(e)[:50]}"}

    def _count(name: str) -> str:
        f = dump_dir / name
        if not f.is_file():
            return ""
        try:
            data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
            return str(len(data)) if isinstance(data, list) else ""
        except Exception:
            return ""

    return {
        "users": _count("domain_users.json"),
        "groups": _count("domain_groups.json"),
        "computers": _count("domain_computers.json"),
        "info": f"dumped -> {dump_dir}",
    }


class LDAPExplorer(CygorModule):
    name = "LDAP Explorer"
    slug = "ldapexplorer"
    version = "1.0.0"
    author = "cygor"
    description = "Enumerate LDAP/AD: rootDSE, anonymous bind/search, and authenticated dump (ldapsearch + ldapdomaindump)"
    category = "enumeration"
    view = "table"
    columns = [
        {"key": "ip", "label": "LDAP Server", "type": "ip"},
        {"key": "domain", "label": "Domain", "type": "string"},
        {"key": "dc_hostname", "label": "DC Hostname", "type": "string"},
        {"key": "func_level", "label": "Func Level", "type": "badge"},
        {"key": "anon_bind", "label": "Anon Bind", "type": "badge"},
        {"key": "anon_search", "label": "Anon Search", "type": "badge"},
        {"key": "users", "label": "Users", "type": "string"},
        {"key": "groups", "label": "Groups", "type": "string"},
        {"key": "computers", "label": "Computers", "type": "string"},
        {"key": "info", "label": "Info", "type": "string"},
    ]

    def setup_argparser(self, parser):
        parser.add_argument("-u", "--username", default=None,
                            help="Username for authenticated dump, e.g. 'CORP\\\\user' (enables ldapdomaindump)")
        parser.add_argument("-p", "--password", default=None,
                            help="Password for authenticated dump")
        parser.add_argument("--timeout", type=int, default=8,
                            help="Per-query timeout in seconds (default: 8)")

    def run(self, targets: List[str], **kwargs) -> None:
        if not shutil.which("ldapsearch"):
            print(f"{Fore.RED}[!] ldapsearch not found in PATH. Install ldap-utils "
                  f"(Debian/Kali: apt install ldap-utils).{Style.RESET_ALL}", file=sys.stderr)
            sys.exit(2)

        username = kwargs.get("username")
        password = kwargs.get("password")
        timeout = kwargs.get("timeout") or 8

        for raw in targets:
            server = raw.strip().split()[0].split(":")[0] if raw.strip() else ""
            if not server:
                continue

            row = {"ip": server, "domain": "", "dc_hostname": "", "func_level": "",
                   "anon_bind": "no", "anon_search": "no",
                   "users": "", "groups": "", "computers": "", "info": ""}

            rc, out = _ldapsearch(
                server, "", "base", timeout,
                attrs=["namingContexts", "defaultNamingContext", "dnsHostName",
                       "domainControllerFunctionality", "domainFunctionality",
                       "supportedSASLMechanisms"],
            )
            attrs = _ldif_parse(out)
            naming = attrs.get("defaultNamingContext", []) or attrs.get("namingContexts", [])
            if rc == 0 and naming:
                row["anon_bind"] = "yes"
                row["domain"] = _dn_to_domain(naming[0])
                row["dc_hostname"] = (attrs.get("dnsHostName") or [""])[0]
                fl = (attrs.get("domainControllerFunctionality")
                      or attrs.get("domainFunctionality") or [""])[0]
                row["func_level"] = FUNC_LEVELS.get(fl, fl)

                # Anonymous *search* against the domain naming context.
                src, sout = _ldapsearch(server, naming[0], "sub", timeout,
                                        attrs=["dn"], sizelimit=1)
                if "dn:" in sout or "sizelimit exceeded" in sout.lower():
                    row["anon_search"] = "yes"
            else:
                row["info"] = "no anonymous rootDSE"

            # Authenticated dump path.
            if username and password:
                row.update(_ldapdomaindump_counts(server, username, password,
                                                  self.output_dir, timeout))

            self.add_result(row)
            print(f"[+] {server} domain='{row['domain'] or '?'}' "
                  f"anon_bind={row['anon_bind']} anon_search={row['anon_search']} "
                  f"func={row['func_level'] or '?'}")


# Web UI registration (see dbprobe for the rationale).
module_info = {
    "name": LDAPExplorer.name,
    "slug": LDAPExplorer.slug,
    "description": LDAPExplorer.description,
    "author": LDAPExplorer.author,
    "version": LDAPExplorer.version,
    "module_type": "enumeration",
    "view": LDAPExplorer.view,
    "table": {"columns": LDAPExplorer.columns},
    "options": [
        {
            "name": "username", "label": "Username", "type": "text", "default": "",
            "help": "Optional, e.g. CORP\\\\user. Enables the authenticated ldapdomaindump.",
        },
        {
            "name": "password", "label": "Password", "type": "password", "default": "",
            "help": "Password for the authenticated dump.",
        },
        {
            "name": "timeout", "label": "Timeout (s)", "type": "number",
            "default": "8", "min": 1, "max": 120,
            "help": "Per-query timeout in seconds.",
        },
    ],
}


def main(argv=None):
    LDAPExplorer().cli(argv)


if __name__ == "__main__":
    main()
