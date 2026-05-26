#!/usr/bin/env python3
"""
DNS Explorer - Cygor Enumeration Module
=======================================

Enumerate DNS servers found by cygor's scan: version disclosure, open-resolver
(recursion) detection, and -- when a domain is supplied -- AXFR zone transfer
plus broader record enumeration via dnsrecon. Results are parsed into typed rows
("parse-don't-dump") so they land in the cygor inventory (DB + web UI),
searchable and correlatable by host.

Wraps best-of-breed tools rather than reimplementing them:
  - dig       version.bind (CHAOS), recursion probe, AXFR zone transfer
  - dnsrecon  standard + AXFR record enumeration as JSON (-j), parsed for counts

Per-server checks (version, recursion) need no domain. AXFR and dnsrecon run
only when ``--domain`` is given (a zone transfer has no meaning without a zone).

Output format: cygor-result.json (universal schema)
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from colorama import Fore, Style

from cygor.modules.base import CygorModule, wrap_external

# A benign public name the target resolver is not authoritative for -- if it
# returns an answer, the server is recursing for arbitrary clients.
RECURSION_PROBE = "example.com"


def _dig(server: str, name: str, rtype: str, timeout: int, extra: Optional[List[str]] = None) -> str:
    cmd = ["dig", f"@{server}", name, rtype, "+time=" + str(timeout), "+tries=1"]
    cmd += extra or []
    try:
        proc = wrap_external(cmd, timeout=timeout + 5)
    except Exception:
        return ""
    return proc.stdout or ""


def _version_bind(server: str, timeout: int) -> str:
    out = _dig(server, "version.bind", "CHAOS", timeout, extra=["TXT", "+short"])
    return out.strip().strip('"') if out.strip() else ""


def _recursion_open(server: str, timeout: int) -> str:
    out = _dig(server, RECURSION_PROBE, "A", timeout, extra=["+short"])
    for line in out.splitlines():
        line = line.strip()
        # an A record (dotted quad) for a name we don't host => recursive
        if line and line[0].isdigit() and line.count(".") == 3:
            return "open"
    return "closed"


def _axfr(server: str, domain: str, timeout: int) -> Dict[str, Any]:
    out = _dig(server, domain, "AXFR", timeout, extra=["+noall", "+answer"])
    lines = [l for l in out.splitlines() if l.strip() and not l.startswith(";")]
    if any("SOA" in l for l in lines) and len(lines) > 1:
        return {"axfr": "SUCCESS", "records": str(len(lines))}
    if "Transfer failed" in out or "communications error" in out or "connection refused" in out.lower():
        return {"axfr": "refused", "records": "0"}
    if not out.strip():
        return {"axfr": "refused", "records": "0"}
    return {"axfr": "refused", "records": str(len(lines))}


def _dnsrecon_count(server: str, domain: str, timeout: int) -> Optional[int]:
    if not shutil.which("dnsrecon"):
        return None
    tmp = Path(tempfile.mkdtemp()) / "dnsrecon.json"
    try:
        wrap_external(
            ["dnsrecon", "-n", server, "-d", domain, "-t", "std,axfr",
             "-j", str(tmp)],
            timeout=timeout + 60,
        )
    except Exception:
        return None
    if not tmp.is_file():
        return None
    try:
        data = json.loads(tmp.read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return None
    # dnsrecon writes a list; the first item is a scan_info header.
    if isinstance(data, list):
        return max(0, len([d for d in data if isinstance(d, dict) and d.get("type")]))
    return None


class DNSExplorer(CygorModule):
    name = "DNS Explorer"
    slug = "dnsexplorer"
    version = "1.0.0"
    author = "cygor"
    description = "Enumerate DNS servers: version, open-resolver, AXFR zone transfer (dig + dnsrecon)"
    category = "enumeration"
    view = "table"
    columns = [
        {"key": "ip", "label": "DNS Server", "type": "ip"},
        {"key": "version", "label": "version.bind", "type": "string"},
        {"key": "recursion", "label": "Recursion", "type": "badge"},
        {"key": "axfr", "label": "AXFR", "type": "badge"},
        {"key": "records", "label": "Records", "type": "string"},
        {"key": "info", "label": "Info", "type": "string"},
    ]

    def setup_argparser(self, parser):
        parser.add_argument("-d", "--domain", default=None,
                            help="Domain/zone to attempt AXFR + dnsrecon enumeration against")
        parser.add_argument("--timeout", type=int, default=5,
                            help="Per-query timeout in seconds (default: 5)")

    def run(self, targets: List[str], **kwargs) -> None:
        if not shutil.which("dig"):
            print(f"{Fore.RED}[!] dig not found in PATH. Install dnsutils/bind-tools "
                  f"(Debian/Kali: apt install dnsutils).{Style.RESET_ALL}", file=sys.stderr)
            sys.exit(2)

        domain = kwargs.get("domain")
        timeout = kwargs.get("timeout") or 5

        for raw in targets:
            server = raw.strip().split()[0].split(":")[0] if raw.strip() else ""
            if not server:
                continue
            version = _version_bind(server, timeout)
            recursion = _recursion_open(server, timeout)
            row = {"ip": server, "version": version, "recursion": recursion,
                   "axfr": "not-tested", "records": "", "info": ""}
            if domain:
                row.update(_axfr(server, domain, timeout))
                n = _dnsrecon_count(server, domain, timeout)
                if n is not None:
                    row["records"] = str(n)
                row["info"] = f"domain={domain}"
            self.add_result(row)
            print(f"[+] {server} version='{version or '?'}' recursion={recursion} "
                  f"axfr={row['axfr']}")


# Web UI registration (see dbprobe for the rationale).
module_info = {
    "name": DNSExplorer.name,
    "slug": DNSExplorer.slug,
    "description": DNSExplorer.description,
    "author": DNSExplorer.author,
    "version": DNSExplorer.version,
    "module_type": "enumeration",
    "view": DNSExplorer.view,
    "table": {"columns": DNSExplorer.columns},
    "options": [
        {
            "name": "domain", "label": "Domain / zone", "type": "text", "default": "",
            "help": "Optional. Enables AXFR zone transfer + dnsrecon enumeration of this zone.",
        },
        {
            "name": "timeout", "label": "Timeout (s)", "type": "number",
            "default": "5", "min": 1, "max": 60,
            "help": "Per-query timeout in seconds.",
        },
    ],
}


def main(argv=None):
    DNSExplorer().cli(argv)


if __name__ == "__main__":
    main()
