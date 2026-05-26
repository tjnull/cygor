#!/usr/bin/env python3
"""
SMTP Explorer - Cygor Enumeration Module
========================================

Enumerate SMTP servers found by cygor's scan: banner, EHLO capabilities
(STARTTLS, AUTH mechanisms), VRFY user-enumeration support, and an optional
open-relay check. Parsed into typed rows ("parse-don't-dump") so results land in
the cygor inventory (DB + web UI), searchable and correlatable by host.

Pure-socket SMTP -- no external tool dependency. The open-relay test only issues
MAIL FROM / RCPT TO (never DATA), so no message is ever relayed; it is still
gated behind --check-relay and off by default.

Output format: cygor-result.json (universal schema)
"""
import socket
from typing import Any, Dict, List, Optional

from cygor.modules.base import CygorModule

DEFAULT_PORTS = [25, 587]


def _recv_response(sock: socket.socket) -> str:
    """Read a full (possibly multiline) SMTP response and return it as text."""
    data = b""
    while True:
        try:
            chunk = sock.recv(1024)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
        text = data.decode("utf-8", "ignore")
        lines = [l for l in text.split("\r\n") if l]
        # Final line of an SMTP reply is "NNN <text>" (space, not '-', after code)
        if lines and len(lines[-1]) >= 4 and lines[-1][:3].isdigit() and lines[-1][3] == " ":
            return text
    return data.decode("utf-8", "ignore")


def _cmd(sock: socket.socket, line: str) -> str:
    sock.sendall((line + "\r\n").encode())
    return _recv_response(sock)


def _smtp_probe(host: str, port: int, timeout: float, check_relay: bool) -> Optional[Dict[str, Any]]:
    """Probe one SMTP endpoint. Returns a row dict, or None if not SMTP/closed."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            banner_txt = _recv_response(s)
            if not banner_txt[:3].isdigit() or not banner_txt.startswith("220"):
                return None  # not an SMTP greeting
            banner = banner_txt.split("\r\n")[0][4:].strip()

            ehlo = _cmd(s, "EHLO cygor.local")
            caps = [l[4:].strip() for l in ehlo.split("\r\n") if len(l) >= 4 and l[:3].isdigit()]
            caps_low = " ".join(caps).lower()
            starttls = "yes" if "starttls" in caps_low else "no"
            auth = next((c[5:].strip() for c in caps if c.upper().startswith("AUTH ")), "")

            vr = _cmd(s, "VRFY root")
            vrfy = "yes" if vr[:3] in ("250", "251", "252") else "no"

            open_relay = "not-tested"
            if check_relay:
                _cmd(s, "MAIL FROM:<probe@cygor.test>")
                rcpt = _cmd(s, "RCPT TO:<relay-test@example.com>")
                open_relay = "OPEN" if rcpt[:3] == "250" else "no"
                _cmd(s, "RSET")
            try:
                _cmd(s, "QUIT")
            except OSError:
                pass
            return {"banner": banner[:120], "starttls": starttls, "auth": auth[:60],
                    "vrfy": vrfy, "open_relay": open_relay, "info": ""}
    except OSError:
        return None


class SMTPExplorer(CygorModule):
    name = "SMTP Explorer"
    slug = "smtpexplorer"
    version = "1.0.0"
    author = "cygor"
    description = "Enumerate SMTP: banner, STARTTLS, AUTH mechanisms, VRFY user-enum, open relay"
    category = "enumeration"
    view = "table"
    columns = [
        {"key": "ip", "label": "IP Address", "type": "ip"},
        {"key": "port", "label": "Port", "type": "string"},
        {"key": "banner", "label": "Banner", "type": "string"},
        {"key": "starttls", "label": "STARTTLS", "type": "badge"},
        {"key": "auth", "label": "AUTH", "type": "string"},
        {"key": "vrfy", "label": "VRFY", "type": "badge"},
        {"key": "open_relay", "label": "Open Relay", "type": "badge"},
        {"key": "info", "label": "Info", "type": "string"},
    ]

    def setup_argparser(self, parser):
        parser.add_argument("--port", type=int, default=None,
                            help="Probe only this port (default: 25 and 587)")
        parser.add_argument("--timeout", type=float, default=5.0,
                            help="Per-probe timeout in seconds (default: 5)")
        parser.add_argument("--check-relay", action="store_true",
                            help="Test for open relay (MAIL/RCPT only, no message sent)")

    def run(self, targets: List[str], **kwargs) -> None:
        timeout = kwargs.get("timeout") or 5.0
        check_relay = bool(kwargs.get("check_relay"))
        port = kwargs.get("port")
        ports = [port] if port else DEFAULT_PORTS

        for raw in targets:
            host = raw.strip().split()[0].split(":")[0] if raw.strip() else ""
            if not host:
                continue
            for p in ports:
                try:
                    row = _smtp_probe(host, p, timeout, check_relay)
                except Exception as e:
                    self.increment_errors()
                    continue
                if row is None:
                    continue
                row = {"ip": host, "port": str(p), **row}
                self.add_result(row)
                flag = "OPEN-RELAY" if row["open_relay"] == "OPEN" else f"vrfy={row['vrfy']}"
                print(f"[+] {host}:{p} {flag} starttls={row['starttls']}")


# Web UI registration (see dbprobe for the rationale).
module_info = {
    "name": SMTPExplorer.name,
    "slug": SMTPExplorer.slug,
    "description": SMTPExplorer.description,
    "author": SMTPExplorer.author,
    "version": SMTPExplorer.version,
    "module_type": "enumeration",
    "view": SMTPExplorer.view,
    "table": {"columns": SMTPExplorer.columns},
    "options": [
        {"name": "port", "label": "Port", "type": "number", "default": "",
         "help": "Probe only this port. Blank = try 25 and 587."},
        {"name": "timeout", "label": "Timeout (s)", "type": "number",
         "default": "5", "min": 1, "max": 60, "help": "Per-probe timeout in seconds."},
        {"name": "check_relay", "label": "Test open relay", "type": "checkbox",
         "default": False, "help": "Issue MAIL/RCPT only (no message is sent)."},
    ],
}


def main(argv=None):
    SMTPExplorer().cli(argv)


if __name__ == "__main__":
    main()
