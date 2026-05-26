#!/usr/bin/env python3
"""
FTP Explorer - Cygor Enumeration Module
=======================================

Enumerate FTP servers found by cygor's scan: banner, anonymous-login check,
root-directory listing count, advertised FEATures, and (optionally) an anonymous
write test. Parsed into typed rows ("parse-don't-dump") so results land in the
cygor inventory (DB + web UI), searchable and correlatable by host.

Uses the Python standard-library ftplib -- no external tool dependency. The
write test (mkdir/rmdir of a temp dir) is gated behind --check-writable and off
by default.

Output format: cygor-result.json (universal schema)
"""
from ftplib import FTP, all_errors
from typing import Any, Dict, List, Optional

from cygor.modules.base import CygorModule

DEFAULT_PORT = 21
_WRITE_TEST_DIR = "cygor_write_test"


def _ftp_probe(host: str, port: int, timeout: float, check_writable: bool) -> Optional[Dict[str, Any]]:
    """Probe one FTP endpoint. Returns a row dict, or None if unreachable."""
    ftp = FTP()
    try:
        ftp.connect(host, port, timeout=timeout)
    except all_errors:
        return None

    welcome = (ftp.getwelcome() or "").replace("\r", " ").replace("\n", " ").strip()
    anon, listing, writable, feats = "no", "", "not-tested", ""

    try:
        ftp.login("anonymous", "anonymous@example.com")
        anon = "yes"
    except all_errors:
        anon = "no"

    if anon == "yes":
        try:
            listing = str(len(ftp.nlst()))
        except all_errors:
            listing = "0"
        if check_writable:
            try:
                ftp.mkd(_WRITE_TEST_DIR)
                writable = "yes"
                try:
                    ftp.rmd(_WRITE_TEST_DIR)
                except all_errors:
                    pass
            except all_errors:
                writable = "no"

    try:
        feat_resp = ftp.sendcmd("FEAT")
        feats = " ".join(l.strip() for l in feat_resp.splitlines()[1:-1] if l.strip())
    except all_errors:
        feats = ""

    try:
        ftp.quit()
    except all_errors:
        try:
            ftp.close()
        except all_errors:
            pass

    return {"banner": welcome[:120], "anon_login": anon, "listing": listing,
            "writable": writable, "info": feats[:80]}


class FTPExplorer(CygorModule):
    name = "FTP Explorer"
    slug = "ftpexplorer"
    version = "1.0.0"
    author = "cygor"
    description = "Enumerate FTP: banner, anonymous login, directory listing, FEAT, anonymous write"
    category = "enumeration"
    view = "table"
    columns = [
        {"key": "ip", "label": "IP Address", "type": "ip"},
        {"key": "port", "label": "Port", "type": "string"},
        {"key": "banner", "label": "Banner", "type": "string"},
        {"key": "anon_login", "label": "Anon Login", "type": "badge"},
        {"key": "listing", "label": "Entries", "type": "string"},
        {"key": "writable", "label": "Writable", "type": "badge"},
        {"key": "info", "label": "FEAT", "type": "string"},
    ]

    def setup_argparser(self, parser):
        parser.add_argument("--port", type=int, default=DEFAULT_PORT,
                            help=f"FTP port (default: {DEFAULT_PORT})")
        parser.add_argument("--timeout", type=float, default=5.0,
                            help="Per-probe timeout in seconds (default: 5)")
        parser.add_argument("--check-writable", action="store_true",
                            help="Test anonymous write access (creates+removes a temp dir)")

    def run(self, targets: List[str], **kwargs) -> None:
        port = kwargs.get("port") or DEFAULT_PORT
        timeout = kwargs.get("timeout") or 5.0
        check_writable = bool(kwargs.get("check_writable"))

        for raw in targets:
            host = raw.strip().split()[0].split(":")[0] if raw.strip() else ""
            if not host:
                continue
            try:
                row = _ftp_probe(host, port, timeout, check_writable)
            except Exception:
                self.increment_errors()
                continue
            if row is None:
                continue
            row = {"ip": host, "port": str(port), **row}
            self.add_result(row)
            print(f"[+] {host}:{port} anon={row['anon_login']} "
                  f"entries={row['listing']} writable={row['writable']}")


# Web UI registration (see dbprobe for the rationale).
module_info = {
    "name": FTPExplorer.name,
    "slug": FTPExplorer.slug,
    "description": FTPExplorer.description,
    "author": FTPExplorer.author,
    "version": FTPExplorer.version,
    "module_type": "enumeration",
    "view": FTPExplorer.view,
    "table": {"columns": FTPExplorer.columns},
    "options": [
        {"name": "port", "label": "Port", "type": "number", "default": "21",
         "min": 1, "max": 65535, "help": "FTP control port."},
        {"name": "timeout", "label": "Timeout (s)", "type": "number",
         "default": "5", "min": 1, "max": 60, "help": "Per-probe timeout in seconds."},
        {"name": "check_writable", "label": "Test anon write", "type": "checkbox",
         "default": False, "help": "Create+remove a temp dir to test anonymous write."},
    ],
}


def main(argv=None):
    FTPExplorer().cli(argv)


if __name__ == "__main__":
    main()
