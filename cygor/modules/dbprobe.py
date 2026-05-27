#!/usr/bin/env python3
"""
Database Probe - Cygor Enumeration Module
=========================================

Probe common databases for *unauthenticated access* and version disclosure:
Redis, MySQL/MariaDB, PostgreSQL, MongoDB, Elasticsearch, and CouchDB.

The single highest-value field is ``auth_required`` -- an open database (no
auth) is the finding that turns up constantly in real engagements. Results are
parsed into typed rows ("parse-don't-dump") so they land in the cygor inventory
(DB + web UI), searchable and correlatable by host.

Each service is checked with the lightest reliable method:
  - redis          raw RESP ``INFO`` (NOAUTH/DENIED => auth; else version+role)
  - mysql/mariadb  server handshake greeting (version disclosure)
  - postgres       wrap ``psql`` trust-auth probe (unauth => version)
  - mongodb        wire-protocol OP_MSG ``buildInfo`` + ``listDatabases``
  - elasticsearch  HTTP GET ``/`` and ``/_cat/indices`` (open => data exposed)
  - couchdb        HTTP GET ``/`` and ``/_all_dbs`` (open => data exposed)

Run via auto-dispatch with ``--service <name>`` against a parsed bucket, or
manually with ``-t``/``-f`` to probe every supported service on each host.

Output format: cygor-result.json (universal schema)
"""
import socket
import ssl
import struct
import sys
from typing import Any, Dict, List, Optional

from cygor.modules.base import CygorModule, wrap_external, merge_prior_results

# service -> default port. Auto-dispatch passes --service so we probe only the
# port that cygor's parser already found open on these hosts.
DB_PORTS = {
    "redis": 6379,
    "mysql": 3306,
    "postgres": 5432,
    "mongodb": 27017,
    "elasticsearch": 9200,
    "couchdb": 5984,
}


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


# ----------------------------------------------------------------------
# Per-service probes. Each returns a row dict (without ip/service/port,
# which the caller fills in) or None if the port is closed/unreachable.
# ----------------------------------------------------------------------
def _probe_redis(host: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"*1\r\n$4\r\nINFO\r\n")
            data = s.recv(4096)
    except OSError:
        return None
    text = data.decode("utf-8", "ignore")
    if "NOAUTH" in text or "WRONGPASS" in text:
        return {"reachable": "yes", "auth_required": "yes", "version": "", "info": "auth required"}
    if "DENIED" in text and "protected mode" in text:
        return {"reachable": "yes", "auth_required": "yes", "version": "",
                "info": "protected mode (bound localhost)"}
    version, role = "", ""
    for line in text.splitlines():
        if line.startswith("redis_version:"):
            version = line.split(":", 1)[1].strip()
        elif line.startswith("role:"):
            role = line.split(":", 1)[1].strip()
    if version or "# Server" in text:
        return {"reachable": "yes", "auth_required": "no", "version": version,
                "info": f"role={role}" if role else "UNAUTH read"}
    return {"reachable": "yes", "auth_required": "unknown", "version": "", "info": "no INFO reply"}


def _probe_mysql(host: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(256)
    except OSError:
        return None
    if not data or len(data) < 6:
        return {"reachable": "yes", "auth_required": "unknown", "version": "", "info": "no handshake"}
    # 4-byte packet header, then 1-byte protocol version, then NUL-terminated
    # server version string.
    payload = data[4:]
    if payload and payload[0] == 0xFF:  # ERR packet (e.g. host not allowed)
        msg = payload[3:].decode("utf-8", "ignore").strip()
        return {"reachable": "yes", "auth_required": "yes", "version": "", "info": msg[:60]}
    end = payload.find(b"\x00", 1)
    version = payload[1:end].decode("utf-8", "ignore") if end > 1 else ""
    return {"reachable": "yes", "auth_required": "yes", "version": version,
            "info": "version disclosed"}


def _probe_postgres(host: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    import shutil
    if not _tcp_open(host, port, timeout):
        return None
    if not shutil.which("psql"):
        return {"reachable": "yes", "auth_required": "unknown", "version": "",
                "info": "psql not installed"}
    env = {"PGPASSWORD": "", "PGCONNECT_TIMEOUT": str(max(1, int(timeout)))}
    try:
        proc = wrap_external(
            ["psql", "-h", host, "-p", str(port), "-U", "postgres", "-w",
             "-tA", "-c", "SELECT version();", "--no-psqlrc"],
            timeout=int(timeout) + 5, env=env,
        )
    except Exception:
        return {"reachable": "yes", "auth_required": "unknown", "version": "", "info": "probe error"}
    out = (proc.stdout or "") + (proc.stderr or "")
    if proc.returncode == 0 and "PostgreSQL" in (proc.stdout or ""):
        ver = (proc.stdout or "").strip().split(",")[0].replace("PostgreSQL", "").strip()
        return {"reachable": "yes", "auth_required": "no", "version": ver, "info": "UNAUTH (trust auth)"}
    if "no password supplied" in out or "password authentication" in out or "authentication failed" in out:
        return {"reachable": "yes", "auth_required": "yes", "version": "", "info": "auth required"}
    if "does not exist" in out:  # reached pg, role/db missing -> still reachable
        return {"reachable": "yes", "auth_required": "yes", "version": "", "info": out.strip()[:60]}
    return {"reachable": "yes", "auth_required": "unknown", "version": "", "info": out.strip()[:60]}


def _bson_cmd(name: str, db: str) -> bytes:
    """Encode a minimal BSON command document: {<name>: 1, "$db": <db>}."""
    def cstr(s: str) -> bytes:
        return s.encode("utf-8") + b"\x00"
    body = b"\x10" + cstr(name) + struct.pack("<i", 1)            # int32 name:1
    body += b"\x02" + cstr("$db") + struct.pack("<i", len(db) + 1) + cstr(db)  # string $db
    doc = body + b"\x00"
    return struct.pack("<i", len(doc) + 4) + doc


def _mongo_op_msg(host: str, port: int, timeout: float, name: str) -> Optional[bytes]:
    """Send an OP_MSG command and return the raw reply bytes (or None)."""
    doc = _bson_cmd(name, "admin")
    section = b"\x00" + doc                       # kind 0 body section
    body = struct.pack("<I", 0) + section          # flagBits=0 + section
    request_id = 1
    header = struct.pack("<iiii", 16 + len(body), request_id, 0, 2013)  # 2013 = OP_MSG
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(header + body)
            chunks, total = [], 0
            while total < 16:  # at least the header
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
                total += len(b)
            return b"".join(chunks)
    except OSError:
        return None


def _bson_find_str(data: bytes, key: str) -> str:
    """Best-effort: find a BSON string element by key in a reply blob."""
    marker = b"\x02" + key.encode() + b"\x00"
    i = data.find(marker)
    if i < 0:
        return ""
    p = i + len(marker)
    if p + 4 > len(data):
        return ""
    length = struct.unpack("<i", data[p:p + 4])[0]
    return data[p + 4:p + 4 + length - 1].decode("utf-8", "ignore")


def _probe_mongodb(host: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    if not _tcp_open(host, port, timeout):
        return None
    build = _mongo_op_msg(host, port, timeout, "buildInfo")
    if build is None:
        return {"reachable": "yes", "auth_required": "unknown", "version": "", "info": "no reply"}
    version = _bson_find_str(build, "version")
    dbs = _mongo_op_msg(host, port, timeout, "listDatabases")
    blob = dbs or b""
    if b"databases" in blob:
        return {"reachable": "yes", "auth_required": "no", "version": version, "info": "UNAUTH listDatabases"}
    if b"requires authentication" in blob or b"Unauthorized" in blob or b"not authorized" in blob:
        return {"reachable": "yes", "auth_required": "yes", "version": version, "info": "auth required"}
    return {"reachable": "yes", "auth_required": "unknown", "version": version,
            "info": "reachable" if version else ""}


def _http_get(host: str, port: int, path: str, timeout: float):
    """GET path over http then https; return (status, text) or (None, '')."""
    import requests
    requests.packages.urllib3.disable_warnings()
    for scheme in ("http", "https"):
        try:
            r = requests.get(f"{scheme}://{host}:{port}{path}", timeout=timeout, verify=False)
            return r.status_code, r.text
        except requests.exceptions.RequestException:
            continue
    return None, ""


def _probe_elasticsearch(host: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    if not _tcp_open(host, port, timeout):
        return None
    status, text = _http_get(host, port, "/", timeout)
    if status is None:
        return {"reachable": "yes", "auth_required": "unknown", "version": "", "info": "no HTTP reply"}
    if status == 401:
        return {"reachable": "yes", "auth_required": "yes", "version": "", "info": "auth required"}
    version = ""
    try:
        import json as _json
        version = (_json.loads(text).get("version") or {}).get("number", "")
    except Exception:
        pass
    cat, _ = _http_get(host, port, "/_cat/indices", timeout)
    info = "UNAUTH (indices listable)" if cat == 200 else "UNAUTH"
    return {"reachable": "yes", "auth_required": "no", "version": version, "info": info}


def _probe_couchdb(host: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    if not _tcp_open(host, port, timeout):
        return None
    status, text = _http_get(host, port, "/", timeout)
    if status is None:
        return {"reachable": "yes", "auth_required": "unknown", "version": "", "info": "no HTTP reply"}
    version = ""
    try:
        import json as _json
        version = _json.loads(text).get("version", "")
    except Exception:
        pass
    dbs, dbs_text = _http_get(host, port, "/_all_dbs", timeout)
    if dbs == 401:
        return {"reachable": "yes", "auth_required": "yes", "version": version, "info": "auth required"}
    if dbs == 200 and dbs_text.strip().startswith("["):
        return {"reachable": "yes", "auth_required": "no", "version": version, "info": "UNAUTH (_all_dbs)"}
    return {"reachable": "yes", "auth_required": "unknown", "version": version, "info": "reachable"}


PROBES = {
    "redis": _probe_redis,
    "mysql": _probe_mysql,
    "postgres": _probe_postgres,
    "mongodb": _probe_mongodb,
    "elasticsearch": _probe_elasticsearch,
    "couchdb": _probe_couchdb,
}


class DBProbe(CygorModule):
    name = "Database Probe"
    slug = "dbprobe"
    version = "1.0.0"
    author = "cygor"
    description = "Probe Redis/MySQL/PostgreSQL/MongoDB/Elasticsearch/CouchDB for unauth access and version"
    category = "enumeration"
    view = "table"
    columns = [
        {"key": "ip", "label": "IP Address", "type": "ip"},
        {"key": "service", "label": "Service", "type": "badge"},
        {"key": "port", "label": "Port", "type": "string"},
        {"key": "reachable", "label": "Reachable", "type": "badge"},
        {"key": "auth_required", "label": "Auth Required", "type": "badge"},
        {"key": "version", "label": "Version", "type": "string"},
        {"key": "info", "label": "Info", "type": "string"},
    ]

    def setup_argparser(self, parser):
        parser.add_argument("--service", choices=sorted(DB_PORTS), default=None,
                            help="Probe only this database service (default: all). "
                                 "Auto-dispatch sets this per parsed bucket.")
        parser.add_argument("--port", type=int, default=None,
                            help="Override the default port for --service")
        parser.add_argument("--timeout", type=float, default=4.0,
                            help="Per-probe timeout in seconds (default: 4)")

    def save(self, formats=None):
        # Merge with any existing dbprobe results so auto-dispatch (which runs
        # this module once per DB bucket) accumulates into one file instead of
        # each --service run overwriting the last. Re-running a service refreshes
        # only that service's rows.
        json_path = self.output_dir / "cygor-result.json"
        self._results = merge_prior_results(
            json_path, self._results, "service",
            getattr(self, "_refreshed_services", set()),
        )
        return super().save(formats)

    def run(self, targets: List[str], **kwargs) -> None:
        service = kwargs.get("service")
        timeout = kwargs.get("timeout") or 4.0
        port_override = kwargs.get("port")
        # `--port N` without `--service S` is ambiguous: which of the 7
        # protocols would inherit the overridden port? Reject early so we
        # don't silently fall back to the default ports and confuse the user.
        if port_override and not service:
            print(f"[!] --port requires --service (which database is on port "
                  f"{port_override}?)", file=sys.stderr)
            return

        services = [service] if service else list(DB_PORTS)
        self._refreshed_services = set(services)

        # Import the IPv6-safe host parser from the module base. The
        # previous '.split(":")[0]' idiom mangled bare IPv6 hosts.
        from cygor.modules.base import parse_host_token

        for host in targets:
            host = parse_host_token(host)
            if not host:
                continue
            for svc in services:
                # Apply the port override only when the user pinned a single
                # service via --service. (We already rejected the
                # port-without-service case above, so port_override here
                # implies service is set.)
                port = port_override if port_override else DB_PORTS[svc]
                try:
                    row = PROBES[svc](host, port, timeout)
                except Exception as e:
                    self.increment_errors()
                    row = {"reachable": "unknown", "auth_required": "unknown",
                           "version": "", "info": f"error: {str(e)[:50]}"}
                if row is None:
                    continue  # port closed -- don't clutter results
                row = {"ip": host, "service": svc, "port": str(port), **row}
                self.add_result(row)
                flag = "OPEN/UNAUTH" if row.get("auth_required") == "no" else row.get("auth_required", "")
                print(f"[+] {host}:{port} {svc} -> {flag} {row.get('version','')}".rstrip())


# Web UI registration: discovery reads this module-level dict (it does not
# instantiate the class), so mirror the class metadata here and declare the
# Run-Module form fields. Field names map snake_case -> --kebab-case CLI flags.
module_info = {
    "name": DBProbe.name,
    "slug": DBProbe.slug,
    "description": DBProbe.description,
    "author": DBProbe.author,
    "version": DBProbe.version,
    "module_type": "enumeration",
    "view": DBProbe.view,
    "table": {"columns": DBProbe.columns},
    "options": [
        {
            "name": "service", "label": "Database service", "type": "select",
            "default": "",
            "choices": [
                {"value": "", "label": "All databases"},
                {"value": "redis", "label": "Redis"},
                {"value": "mysql", "label": "MySQL / MariaDB"},
                {"value": "postgres", "label": "PostgreSQL"},
                {"value": "mongodb", "label": "MongoDB"},
                {"value": "elasticsearch", "label": "Elasticsearch"},
                {"value": "couchdb", "label": "CouchDB"},
            ],
            "help": "Probe a single service, or all of them on each target.",
        },
        {
            "name": "timeout", "label": "Timeout (s)", "type": "number",
            "default": "4", "min": 1, "max": 60,
            "help": "Per-probe timeout in seconds.",
        },
    ],
}


def main(argv=None):
    DBProbe().cli(argv)


if __name__ == "__main__":
    main()
