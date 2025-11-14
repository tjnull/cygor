from contextlib import asynccontextmanager
from datetime import datetime, timezone
import os, argparse, asyncio, pkgutil, shutil, json, re, gzip, uvicorn, sys, psycopg, subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from fastapi import FastAPI, Request, Depends, Query, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from psycopg.rows import dict_row
from sqlalchemy import select, func, exists
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from collections import namedtuple
from importlib.resources import files  

from . import db
from .db import get_session, reset_db
from datetime import datetime, timezone, timedelta
from .models import Host, Port, Script, OSGuess
from ..module_loader import discover_modules, resolve_legacy_context
from .ingest import ingest_directory
from .config import settings
from .tasks import task_manager, TaskStatus
from .credrecon_tasks import credrecon_manager


templates = None  # will be initialized in lifespan
DISCOVERED_MODULES = []  # filled during startup
SYNC_HISTORY = []  # List of sync events: {timestamp, ingested_files, hosts_added, ports_added, ...}

# -------- Service normalization --------
SERVICE_NAME_MAP = {
    "domain": "dns", "kerberos-sec": "kerberos", "ldapssl": "ldaps",
    "microsoft-ds": "smb", "netbios-ssn": "smb", "ms-wbt-server": "rdp",
    "epmap": "dcom", "http-alt": "http", "ssl/http": "https",
    "https-alt": "https", "http-proxy": "proxy", "ajp13": "ajp",
    "ajp12": "ajp", "ms-sql-s": "mssql", "ms-sql-m": "mssql",
    "mysqlx": "mysql", "postgresql": "postgres", "oracle-tns": "oracle",
    "redis": "redis", "smtp-submission": "smtp", "submission": "smtp",
    "pop3s": "pop3", "imaps": "imap", "vnc": "vnc",
    "pcanywheredata": "pcanywhere", "rpcbind": "rpc", "ipp": "cups",
    "upnp": "upnp", "mdns": "mdns", "snmptrap": "snmp", "snmp": "snmp",
}

def normalize_service(name: str | None) -> str:
    if not name:
        return "unknown"
    return SERVICE_NAME_MAP.get(name.lower(), name.lower())

# -------- OS Guess Helpers --------
def _bucket_family(guess: "OSGuess") -> str:
    txt = " ".join([
        (guess.name or ""), (guess.family or ""),
        (guess.vendor or ""), (guess.type or "")
    ]).lower()

    if "windows" in txt or "microsoft" in txt: return "Windows"
    if "linux" in txt: return "Linux"
    if "android" in txt: return "Android"
    if "mac os" in txt or "macos" in txt or "apple" in txt or "os x" in txt: return "macOS"
    if any(x in txt for x in ["freebsd","openbsd","netbsd","solaris","unix"]): return "BSD/Unix"
    if any(x in txt for x in ["router","switch","ubiquiti","cisco","juniper","embedded","network device"]): return "Network Device"
    if any(x in txt for x in ["vmware","oracle vm","virtualbox","hyper-v","qemu","xen"]): return "Virtualization/Hypervisor"
    if any(x in txt for x in ["ios","ipad","iphone"]): return "iOS"
    if any(x in txt for x in ["printer","copier","hp","xerox","ricoh"]): return "Printer/Peripheral"
    if any(x in txt for x in ["specialized","appliance","control system","crestron","scada"]): return "Specialized Device"
    return "Other"

def _top_guess(host: "Host"):
    if not host.os_guesses: return None
    return sorted(host.os_guesses, key=lambda g: (-int(g.accuracy or 0), len(g.name or "")))[0]

TopItem = namedtuple("TopItem", ["host", "guess"])

def _count_hosts_in_nmap_xml(path: Path) -> int:
    """Return number of <host> elements in an nmap XML file. Returns 0 on failure."""
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        # direct host tags
        hosts = list(root.iter('host'))
        if hosts:
            return len(hosts)
        # fallback for namespaces: count tags that end with 'host'
        hosts = [el for el in root.iter() if isinstance(el.tag, str) and el.tag.endswith('host')]
        return len(hosts)
    except Exception:
        return 0

def _count_hosts_in_nmap_text(path: Path) -> int:
    """Try to extract host summary from an nmap textual file (best-effort)."""
    try:
        txt = path.read_text(errors="ignore")
        # Try the "Nmap done" summary with "(X hosts up)" first
        m2 = re.search(r"\((\d+)\s+hosts?\s+up\)", txt)
        if m2:
            return int(m2.group(1))
        # Try "Nmap done: 100 IP addresses (90 hosts up) scanned in ..."""
        m = re.search(r"Nmap done: .*?(\d+)\s+IP addresses", txt)
        if m:
            # fallback if hosts up not present, return the IP count (best-effort)
            return int(m.group(1))
        # As last resort, count lines that start with "Host:" (some text outputs)
        count_hosts = len(re.findall(r"(?m)^Host:\s", txt))
        if count_hosts:
            return count_hosts
    except Exception:
        pass
    return 0

def _parse_nmap_xml_times(path: Path):
    """
    Read an Nmap XML file and return (start_iso, end_iso, host_count).

    - start_iso and end_iso are ISO8601 UTC strings or None
    - host_count is integer (from runstats/hosts up= or host count fallback)

    Handles compressed .gz, missing namespaces, and raw comment timestamps.
    """
    start_iso = None
    end_iso = None
    host_count = 1

    try:
        # ---- Load raw text (supports gzip) ----
        raw_text = ""
        try:
            if path.suffix.lower().endswith(".gz"):
                with gzip.open(path, "rt", errors="ignore") as fh:
                    raw_text = fh.read()
            else:
                raw_text = path.read_text(errors="ignore")
        except Exception:
            try:
                raw_text = path.read_bytes().decode("utf-8", errors="ignore")
            except Exception:
                raw_text = ""

        # ---- Parse XML ----
        tree = None
        try:
            tree = ET.parse(path)
        except Exception:
            try:
                tree = ET.ElementTree(ET.fromstring(raw_text))
            except Exception:
                tree = None

        root = tree.getroot() if tree is not None else None

        def _find_tag_suffix(root_el, suffix):
            if root_el is None:
                return None
            if isinstance(root_el.tag, str) and root_el.tag.endswith(suffix):
                return root_el
            for el in root_el.iter():
                if isinstance(el.tag, str) and el.tag.endswith(suffix):
                    return el
            return None

        # ---- Extract elements ----
        nmaprun_el = root if root is not None and root.tag.endswith("nmaprun") else _find_tag_suffix(root, "nmaprun")
        finished_el = _find_tag_suffix(root, "finished")
        hosts_el = _find_tag_suffix(root, "hosts")

        # ---- Parse start ----
        if nmaprun_el is not None:
            start_attr = nmaprun_el.attrib.get("start")
            startstr_attr = nmaprun_el.attrib.get("startstr")

            if start_attr:
                try:
                    start_dt = datetime.fromtimestamp(int(start_attr), tz=timezone.utc)
                    start_iso = start_dt.isoformat()
                except Exception:
                    start_iso = None

            if start_iso is None and startstr_attr:
                try:
                    start_dt = datetime.strptime(startstr_attr.strip(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                    start_iso = start_dt.isoformat()
                except Exception:
                    try:
                        start_dt = datetime.fromisoformat(startstr_attr)
                        if start_dt.tzinfo is None:
                            start_dt = start_dt.replace(tzinfo=timezone.utc)
                        start_iso = start_dt.isoformat()
                    except Exception:
                        start_iso = None

        # ---- Parse end ----
        if finished_el is not None:
            finished_time = finished_el.attrib.get("time")
            finished_timestr = finished_el.attrib.get("timestr")

            if finished_time:
                try:
                    if str(finished_time).isdigit():
                        end_dt = datetime.fromtimestamp(int(finished_time), tz=timezone.utc)
                    else:
                        end_dt = datetime.fromisoformat(finished_time)
                        if end_dt.tzinfo is None:
                            end_dt = end_dt.replace(tzinfo=timezone.utc)
                    end_iso = end_dt.isoformat()
                except Exception:
                    end_iso = None

            if end_iso is None and finished_timestr:
                try:
                    end_dt = datetime.strptime(finished_timestr.strip(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                    end_iso = end_dt.isoformat()
                except Exception:
                    try:
                        end_dt = datetime.fromisoformat(finished_timestr)
                        if end_dt.tzinfo is None:
                            end_dt = end_dt.replace(tzinfo=timezone.utc)
                        end_iso = end_dt.isoformat()
                    except Exception:
                        end_iso = None

        # ---- Host count ----
        if hosts_el is not None:
            up = hosts_el.attrib.get("up")
            if up:
                try:
                    host_count = max(1, int(up))
                except Exception:
                    pass
        if host_count == 1 and root is not None:
            try:
                hosts = [el for el in root.iter() if isinstance(el.tag, str) and el.tag.endswith("host")]
                if hosts:
                    host_count = len(hosts)
            except Exception:
                pass

        # ---- Fallback: try comment line like "scan initiated ..." ----
        if start_iso is None and raw_text:
            m = re.search(
                r"scan initiated\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+as:",
                raw_text,
                re.I,
            )
            if m:
                ts = m.group(1).strip()
                try:
                    dt = datetime.strptime(ts, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                    start_iso = dt.isoformat()
                except Exception:
                    try:
                        dt = datetime.fromisoformat(ts)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        start_iso = dt.isoformat()
                    except Exception:
                        pass

        # ---- Final fallbacks ----
        if start_iso is None and end_iso is not None:
            # assume scan took 1 minute if only end known
            dt_end = datetime.fromisoformat(end_iso)
            start_iso = (dt_end - timedelta(seconds=60)).isoformat()

        if end_iso is None and start_iso is not None:
            dt_start = datetime.fromisoformat(start_iso)
            end_iso = (dt_start + timedelta(seconds=60)).isoformat()

        return start_iso, end_iso, host_count

    except Exception:
        return None, None, 1
    
def extract_host_key(label_or_path: str) -> str | None:
    """Extract an IP or base name from a scan label/path."""
    if not label_or_path:
        return None
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', label_or_path)
    if m:
        return m.group(1)
    base = os.path.basename(label_or_path)
    base = re.sub(r'\.(xml|nmap|gnmap|txt|gz)$', '', base, flags=re.I)
    return base or None

def gather_scan_times(results_dir: str):
    """
    Walk RESULTS_DIR/nmap and collect scan start/end times.
    Returns a list of dicts:
      [{"label":"<filename>","path":"<relpath>","start":"<ISO>","end":"<ISO or null>","host_count":<int>}]
    Sorted by parsed start time (earliest first). Uses mtime fallback only when parsing fails.
    """
    scans = []
    base = Path(results_dir) / "nmap"
    if not base.exists():
        return scans

    for f in sorted(base.rglob("*")):
        if not f.is_file():
            continue

        parsed_start = None
        parsed_end = None
        host_count = 1

        try:
            if f.suffix.lower() == ".xml" or f.suffix.lower().endswith(".gz"):
                parsed_start, parsed_end, host_count = _parse_nmap_xml_times(f)
            else:
                # try text formats (.nmap, .gnmap, .txt)
                txt = None
                try:
                    txt = f.read_text(errors="ignore")
                except Exception:
                    try:
                        txt = f.open('rb').read().decode('utf-8', errors='ignore')
                    except Exception:
                        txt = ''
                if txt:
                    # look for started line in textual header
                    m = re.search(r"^#?\s*Nmap scan initiated\s*:\s*(.+)$", txt, re.M | re.I)
                    if not m:
                        # try common textual header variants
                        m = re.search(r"^#?\s*Nmap .* scan initiated\s*(.+)$", txt, re.M | re.I)
                    if m:
                        ts = m.group(1).strip()
                        try:
                            dt = datetime.fromisoformat(ts)
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            parsed_start = dt.isoformat()
                        except Exception:
                            try:
                                dt = datetime.strptime(ts, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                                parsed_start = dt.isoformat()
                            except Exception:
                                parsed_start = None

                    # if textual contains a "Nmap done" line with hosts up, try to extract finished times
                    m2 = re.search(r"Nmap done at (.+); .* scanned in", txt)
                    if m2:
                        ts2 = m2.group(1).strip()
                        try:
                            dt2 = datetime.fromisoformat(ts2)
                            if dt2.tzinfo is None:
                                dt2 = dt2.replace(tzinfo=timezone.utc)
                            parsed_end = dt2.isoformat()
                        except Exception:
                            try:
                                dt2 = datetime.strptime(ts2, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                                parsed_end = dt2.isoformat()
                            except Exception:
                                parsed_end = None

                    # try to detect host count
                    m3 = re.search(r"\((\d+)\s+hosts?\s+up\)", txt)
                    if m3:
                        try:
                            host_count = int(m3.group(1))
                        except Exception:
                            host_count = host_count

        except Exception:
            parsed_start = None
            parsed_end = None
            host_count = host_count

        # fallback: use file mtime as start if nothing parsed
        if parsed_start is None:
            parsed_start = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat()

        scans.append({
            "label": f.name,
            "path": str(f.relative_to(base.parent)),
            "start": parsed_start,
            "end": parsed_end,
            "host_count": host_count,
        })

    # sort the collected scans by start time (safely parse ISO -> datetime)
    def _parse_iso_to_dt(iso_str):
        if not iso_str:
            return datetime.fromtimestamp(0, tz=timezone.utc)
        try:
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            try:
                # try trimming trailing Z or fractions
                s = iso_str.replace('Z', '')
                s = re.sub(r'(\.\d{3})\d+', r'\1', s)
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                return datetime.fromtimestamp(0, tz=timezone.utc)

    scans.sort(key=lambda s: _parse_iso_to_dt(s.get("start")))

    return scans

def gather_ondemand_scan_times(results_dir: str):
    """
    Walk RESULTS_DIR/ondemand-scans and collect scan start/end times.
    Returns a list of dicts similar to gather_scan_times but from the ondemand-scans subdirectory.
    """
    scans = []
    base = Path(results_dir) / "ondemand-scans"
    if not base.exists():
        return scans

    # Iterate through timestamped directories
    for scan_dir in sorted(base.iterdir()):
        if not scan_dir.is_dir():
            continue

        # Look for nmap results within this scan directory
        nmap_dir = scan_dir / "nmap"
        if not nmap_dir.exists():
            continue

        for f in sorted(nmap_dir.rglob("*")):
            if not f.is_file():
                continue

            parsed_start = None
            parsed_end = None
            host_count = 1

            try:
                if f.suffix.lower() == ".xml" or f.suffix.lower().endswith(".gz"):
                    parsed_start, parsed_end, host_count = _parse_nmap_xml_times(f)
                else:
                    # try text formats (.nmap, .gnmap, .txt)
                    txt = None
                    try:
                        txt = f.read_text(errors="ignore")
                    except Exception:
                        try:
                            txt = f.open('rb').read().decode('utf-8', errors='ignore')
                        except Exception:
                            txt = ''
                    if txt:
                        # look for started line in textual header
                        m = re.search(r"^#?\s*Nmap scan initiated\s*:\s*(.+)$", txt, re.M | re.I)
                        if not m:
                            # try common textual header variants
                            m = re.search(r"^#?\s*Nmap .* scan initiated\s*(.+)$", txt, re.M | re.I)
                        if m:
                            ts = m.group(1).strip()
                            try:
                                dt = datetime.fromisoformat(ts)
                                if dt.tzinfo is None:
                                    dt = dt.replace(tzinfo=timezone.utc)
                                parsed_start = dt.isoformat()
                            except Exception:
                                try:
                                    dt = datetime.strptime(ts, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                                    parsed_start = dt.isoformat()
                                except Exception:
                                    parsed_start = None

                        # if textual contains a "Nmap done" line with hosts up, try to extract finished times
                        m2 = re.search(r"Nmap done at (.+); .* scanned in", txt)
                        if m2:
                            ts2 = m2.group(1).strip()
                            try:
                                dt2 = datetime.fromisoformat(ts2)
                                if dt2.tzinfo is None:
                                    dt2 = dt2.replace(tzinfo=timezone.utc)
                                parsed_end = dt2.isoformat()
                            except Exception:
                                try:
                                    dt2 = datetime.strptime(ts2, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                                    parsed_end = dt2.isoformat()
                                except Exception:
                                    parsed_end = None

                        # try to detect host count
                        m3 = re.search(r"\((\d+)\s+hosts?\s+up\)", txt)
                        if m3:
                            try:
                                host_count = int(m3.group(1))
                            except Exception:
                                host_count = host_count

            except Exception:
                parsed_start = None
                parsed_end = None
                host_count = host_count

            # fallback: use file mtime as start if nothing parsed
            if parsed_start is None:
                parsed_start = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat()

            scans.append({
                "label": f"{scan_dir.name} - {f.name}",
                "path": str(f.relative_to(base.parent)),
                "start": parsed_start,
                "end": parsed_end,
                "host_count": host_count,
                "scan_dir": scan_dir.name,  # Include the timestamp directory name
            })

    # sort the collected scans by start time (safely parse ISO -> datetime)
    def _parse_iso_to_dt(iso_str):
        if not iso_str:
            return datetime.fromtimestamp(0, tz=timezone.utc)
        try:
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            try:
                # try trimming trailing Z or fractions
                s = iso_str.replace('Z', '')
                s = re.sub(r'(\.\d{3})\d+', r'\1', s)
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except Exception:
                return datetime.fromtimestamp(0, tz=timezone.utc)

    scans.sort(key=lambda s: _parse_iso_to_dt(s.get("start")))

    return scans

# --- Temporary workaround for asyncpg+SQLAlchemy Python 3.13 bug ---
def _ignore_event_loop_closed(loop, context):
    msg = context.get("message", "")
    exc = context.get("exception")
    if isinstance(exc, RuntimeError) and "Event loop is closed" in str(exc):
        return  # swallow harmless cleanup noise
    if "Event loop is closed" in msg:
        return
    loop.default_exception_handler(context)

# Patch all asyncio loops created after import
asyncio.get_event_loop().set_exception_handler(_ignore_event_loop_closed)



# ---------------- Lifespan ----------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global templates
    base_dir = Path(__file__).resolve().parent
    templates_dir = base_dir / "templates"
    static_dir = base_dir / "static"

    # Static
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    else:
        print(f"[!] Static directory not found: {static_dir}")

    templates = Jinja2Templates(directory=str(templates_dir))

    # -------------------------
    # Database Initialization
    # -------------------------
    try:
        db_url = os.environ.get("CYGOR_DB_URL") or db.get_default_database_url()

        # Force new engine tied to FastAPI's running loop
        db.init_engine(db_url, debug=(os.environ.get("CYGOR_VERBOSE", "0") > "1"))

        # Run migrations / create schema within this loop
        await db.init_db()
        print("[✓] Database initialized and schema verified.")
    except Exception as e:
        print(f"[!] Database initialization error: {e}")

    # Lockon screenshots mount
    lockon_dir = Path(settings.RESULTS_DIR) / "cygor-enumeration-modules" / "lockon" / "screenshots"
    if lockon_dir.exists():
        app.mount("/modules/lockon/screenshots", StaticFiles(directory=str(lockon_dir)), name="lockon_screenshots")
        print(f"[*] Mounting Lockon screenshots from: {lockon_dir}")
    else:
        print(f"[!] Lockon screenshots directory not found: {lockon_dir}")

    # -------------------------
    # Module Discovery
    # -------------------------
    global DISCOVERED_MODULES
    try:
        # print("[DEBUG] Module loader: using default modules path from module_loader")
        DISCOVERED_MODULES = discover_modules()
        _register_module_routes(app, templates_dir, settings.RESULTS_DIR)

        print(f"[✓] Registered {len(DISCOVERED_MODULES)} dynamic module routes: {[m.slug for m in DISCOVERED_MODULES]}")
    except Exception as e:
        print(f"[!] Error during module discovery: {e}")

    # -------------------------
    # Restore Historical Tasks
    # -------------------------
    try:
        await task_manager.restore_historical_tasks(settings.RESULTS_DIR)
        task_count = len(task_manager.tasks)
        if task_count > 0:
            print(f"[✓] Restored {task_count} historical task(s) from ondemand-scans directory")
    except Exception as e:
        print(f"[!] Error restoring historical tasks: {e}")
    
    # -------------------------
    # Ingestion (DO IT NOW, before yield)
    # -------------------------
    load_dir = os.environ.get("CYGOR_LOAD_DIR")
    verbose = int(os.environ.get("CYGOR_VERBOSE", "0"))

    if load_dir:
        print(f"[*] Preloading results from {load_dir} ...")
        try:
            async with db.SessionLocal() as session:
                count = await ingest_directory(Path(load_dir), session, dedupe=True, verbose=verbose)
                await session.commit()
            print(f"[✓] Ingested {count} result file(s) from {load_dir}")
        except Exception as e:
            print(f"[!] Ingestion error: {e}")


    # -------------------------
    # Yield to FastAPI
    # -------------------------
    try:
        yield
    finally:
        # -------------------------
        # Clean shutdown (safe for Python 3.13)
        # -------------------------
        if getattr(db, "engine", None):
            print("[*] Disposing database engine...")
            try:
                loop = asyncio.get_running_loop()
                if loop.is_closed():
                    print("[!] Event loop already closed — skipping engine dispose.")
                else:
                    await db.engine.dispose()
                    print("[✓] Database engine disposed cleanly.")
            except (RuntimeError, Exception) as e:
                if "Event loop is closed" in str(e) or "attached to a different loop" in str(e):
                    print("[!] Ignored psycopg loop-closed cleanup noise.")
                else:
                    print(f"[!] Unhandled dispose error: {e}")

        # -------------------------
        # PostgreSQL Cleanup (psycopg_async)
        # -------------------------
        try:
            await cleanup_postgresql()
        except Exception as e:
            print(f"[!] PostgreSQL cleanup failed: {e}")


async def cleanup_postgresql():
    """
    Fully cleanup PostgreSQL database and role after Cygor Web shutdown.

    Behavior:
      - Only runs if --cleanup-db or CYGOR_CLEANUP_DB=1 is set.
      - Prompts user for confirmation unless --yes or CYGOR_YES=1.
      - Can escalate to sudo (-u postgres) for privileged cleanup.
    """
    db_url = os.environ.get("CYGOR_DB_URL") or ""
    if not db_url.startswith("postgresql"):
        return  # Skip non-Postgres backends

    # respect --cleanup-db flag or env var
    if os.environ.get("CYGOR_CLEANUP_DB") != "1":
        print("[*] Skipping PostgreSQL cleanup (use --cleanup-db to enable).")
        return

    if os.environ.get("CYGOR_PERSIST_DB") == "1":
        print("[*] Persistent database mode enabled — skipping cleanup.")
        return

    pg_db   = os.getenv("PGDATABASE", "cygor")
    pg_user = os.getenv("PGUSER", "cygor_user")

    conn_user = os.getenv("PGADMIN_USER", os.getenv("PGUSER", "cygor"))
    conn_pass = os.getenv("PGADMIN_PASS", os.getenv("PGPASSWORD", "cygorpass"))
    pg_host   = os.getenv("PGHOST", "localhost")
    pg_port   = int(os.getenv("PGPORT", "5432"))

    # -------------------------
    # Ask for confirmation
    # -------------------------
    if os.getenv("CYGOR_YES") != "1":
        try:
            answer = input(f"[?] Do you want to delete PostgreSQL database '{pg_db}' "
                           f"and user '{pg_user}' on shutdown? [y/N]: ").strip().lower()
            if answer not in ("y", "yes"):
                print("[*] Cleanup aborted by user — keeping PostgreSQL data.")
                return
        except EOFError:
            print("[*] Non-interactive environment; skipping cleanup.")
            return

    print(f"[*] Cleaning up PostgreSQL database '{pg_db}' and user '{pg_user}'...")

    db_dropped = False
    role_dropped = False
    need_sudo_cleanup = False

    # -------------------------
    # Step 1: psycopg best-effort cleanup
    # -------------------------
    try:
        conninfo = f"postgresql://{conn_user}:{conn_pass}@{pg_host}:{pg_port}/postgres"
        async with await psycopg.AsyncConnection.connect(conninfo, autocommit=True) as conn:
            async with conn.cursor(row_factory=dict_row) as cur:
                await cur.execute("SELECT rolsuper FROM pg_roles WHERE rolname = current_user;")
                row = await cur.fetchone()
                is_superuser = bool(row and row["rolsuper"])

                if is_superuser:
                    print("[*] Running as superuser — performing full cleanup.")
                    await cur.execute("""
                        SELECT pg_terminate_backend(pid)
                        FROM pg_stat_activity
                        WHERE datname = %s AND pid <> pg_backend_pid();
                    """, (pg_db,))
                    await cur.execute(f"DROP DATABASE IF EXISTS {pg_db};")
                    db_dropped = True
                    await cur.execute(f"DROP ROLE IF EXISTS {pg_user};")
                    role_dropped = True
                    print("[✓] PostgreSQL cleanup completed via superuser.")
                else:
                    print("[*] Current user is not a superuser — limited cleanup mode.")
                    try:
                        await cur.execute(f"DROP DATABASE IF EXISTS {pg_db};")
                        db_dropped = True
                        print(f"[✓] Dropped database '{pg_db}'.")
                    except Exception as e:
                        print(f"[!] Cannot drop database: {e}")
                        need_sudo_cleanup = True

                    try:
                        await cur.execute(f"DROP ROLE IF EXISTS {pg_user};")
                        role_dropped = True
                        print(f"[✓] Dropped role '{pg_user}'.")
                    except Exception as e:
                        print(f"[!] Cannot drop role: {e}")
                        need_sudo_cleanup = True

    except Exception as e:
        print(f"[!] psycopg cleanup path error: {e}")
        need_sudo_cleanup = True

    # -------------------------
    # Step 2: sudo fallback
    # -------------------------
    if (not db_dropped or not role_dropped) and shutil.which("sudo"):
        print("[*] Attempting privileged cleanup via sudo (postgres user)...")

        def run_sudo_sql(sql: str):
            return subprocess.run(
                ["sudo", "-u", "postgres", "psql", "-tAc", sql],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )

        try:
            run_sudo_sql(f"SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                         f"WHERE datname='{pg_db}' AND pid <> pg_backend_pid();")
            run_sudo_sql(f"DROP DATABASE IF EXISTS {pg_db};")
            db_dropped = True

            run_sudo_sql(f"REASSIGN OWNED BY {pg_user} TO postgres;")
            run_sudo_sql(f"DROP OWNED BY {pg_user};")
            run_sudo_sql(f"DROP ROLE IF EXISTS {pg_user};")
            role_dropped = True

            print("[✓] PostgreSQL cleanup completed via sudo.")
        except Exception as e:
            print(f"[!] Sudo cleanup failed: {e}")

    # -------------------------
    # Final summary
    # -------------------------
    if db_dropped and role_dropped:
        print(f"[✓] PostgreSQL database '{pg_db}' and role '{pg_user}' fully removed.")
    elif db_dropped and not role_dropped:
        print(f"[i] Database '{pg_db}' removed, but role '{pg_user}' kept (no privileges).")
    elif not db_dropped and role_dropped:
        print(f"[i] Role '{pg_user}' removed, but database '{pg_db}' kept (locked/in use).")
    else:
        print(f"[!] Cleanup incomplete — manual removal may be required.")




# ---------------- FastAPI App ----------------
app = FastAPI(lifespan=lifespan)

@app.middleware("http")
async def add_modules_to_request(request: Request, call_next):
    request.state.modules = DISCOVERED_MODULES
    return await call_next(request)

def register_static_page(app: FastAPI, slug: str, title: str, template: str):
    """
    Dynamically register a simple static page route.
    Example:
        register_static_page(app, "about", "About Cygor", "page_about.html")
        -> available at /pages/about
    """
    @app.get(f"/pages/{slug}", response_class=HTMLResponse)
    async def static_page(request: Request):
        return templates.TemplateResponse(
            template,
            {"request": request, "title": title},
        )

    print(f"[+] Registered static page: /pages/{slug}")



# ---- Safe dynamic route registration ----
def _register_module_routes(app: FastAPI, templates_dir: Path, results_dir: Path):
    """
    Dynamically register /modules/<slug> routes for all discovered modules.
    Automatically selects the best template based on the context returned
    by each module (rows, items, chart, etc.).
    """
    import inspect
    from cygor.module_loader import resolve_legacy_context
    from jinja2 import TemplateNotFound

    global DISCOVERED_MODULES

    for spec in DISCOVERED_MODULES:
        route_path = f"/modules/{spec.slug}"

        async def handler(request: Request, spec=spec):
            context = {}
            try:
                # --- Collect context from module ---
                if spec.get_context:
                    result = spec.get_context(request, None)
                    if inspect.iscoroutine(result):
                        result = await result
                    if isinstance(result, dict):
                        context.update(result)
                else:
                    # legacy compatibility
                    context.update(resolve_legacy_context(spec.slug, results_dir))

                # --- Determine best template automatically ---
                has_rows = "rows" in context
                has_items = "items" in context
                has_chart = "chart" in context

                # Prefer explicit module_<slug>.html if present
                template_file = f"module_{spec.slug}.html"
                if not (templates_dir / template_file).exists():
                    if has_items:
                        template_file = "modules_gallery.html"
                    elif has_chart:
                        template_file = "modules_chart.html"
                    else:
                        template_file = "modules_common.html"

                # Add optional summary helpers
                if has_rows and not context["rows"]:
                    context["message"] = "No rows to display yet."
                if has_items and not context["items"]:
                    context["message"] = "No items to display yet."

                # --- Render the final template ---
                # Make a lightweight copy without the live module object
                safe_spec = {k: v for k, v in spec.__dict__.items() if k != "module"}

                return templates.TemplateResponse(
                    template_file,
                    {
                        "request": request,
                        "module": safe_spec,
                        "ctx": context,
                        **context,
                    },
                )


            except TemplateNotFound as e:
                print(f"[!] Missing template for {spec.slug}: {e.name}")
                return HTMLResponse(
                    f"<h3>Template not found for module '{spec.slug}'</h3>", status_code=500
                )

            except Exception as e:
                print(f"[!] Error rendering module {spec.slug}: {e}")
                return HTMLResponse(
                    f"<h3>Error rendering module '{spec.slug}'</h3><pre>{e}</pre>",
                    status_code=500,
                )

        app.add_api_route(
            route_path,
            handler,
            name=f"module_{spec.slug}",
            include_in_schema=False,
        )

        print(f"[+] Registered dynamic module route: {route_path}")

    # ----------------------------------------------------------------
    # Index route for all modules
    # ----------------------------------------------------------------
    @app.get("/modules", response_class=HTMLResponse)
    async def modules_index(request: Request):
        """Render overview of all discovered modules."""
        return templates.TemplateResponse(
            "modules_index.html",
            {"request": request, "modules": DISCOVERED_MODULES},
        )


# -------- ROUTES --------
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: AsyncSession = Depends(get_session)):
    # ==========================================================
    # Accurate tile counts  — exclude script-only hosts
    # ==========================================================
    from sqlalchemy import exists

    # Hosts that have at least one Port OR OSGuess (real Nmap/Masscan data)
    base_host_filter = exists().where(Port.host_id == Host.id) | exists().where(OSGuess.host_id == Host.id)

    # Total/scanned = real scanned hosts only
    hosts_total = await session.scalar(
        select(func.count(func.distinct(Host.id))).where(base_host_filter)
    )
    hosts_scanned = hosts_total
    hosts_enum = 0  # keep 0 if you dropped the enumerated tile

    # Donut math (2-slice version)
    not_scanned = 0
    scanned_only = hosts_scanned

    # ==========================================================
    # Fetch filtered hosts for OS & Service summaries
    # ==========================================================
    hosts = (
        await session.execute(
            select(Host)
            .where(base_host_filter)
            .options(
                selectinload(Host.ports),
                selectinload(Host.scripts),
                selectinload(Host.os_guesses),
            )
        )
    ).scalars().unique().all()

    # ==========================================================
    # OS Discovery  — accurate, deduplicated by host_id
    # ==========================================================
    buckets = {
        k: 0
        for k in [
            "Windows", "Linux", "macOS", "BSD/Unix", "Android", "iOS",
            "Network Device", "Virtualization/Hypervisor", "Printer/Peripheral",
            "Specialized Device", "Other", "Unknown",
        ]
    }

    # 1. Gather all OS guesses (for filtered hosts) and deduplicate by host_id
    os_rows = (
        await session.execute(
            select(OSGuess)
            .where(OSGuess.host_id.in_([h.id for h in hosts]))
            .options(selectinload(OSGuess.host))
        )
    ).scalars().all()

    best_guess_per_host = {}
    for g in os_rows:
        hid = g.host_id
        if hid not in best_guess_per_host or (g.accuracy or 0) > (best_guess_per_host[hid].accuracy or 0):
            best_guess_per_host[hid] = g

    # 2. Tally by OS family
    top_items = []
    for guess in best_guess_per_host.values():
        fam = _bucket_family(guess)
        buckets[fam] = buckets.get(fam, 0) + 1
        if len(top_items) < 10:
            top_items.append(TopItem(host=guess.host, guess=guess))

    # 3. Include hosts that have ports but no OS guesses as "Unknown"
    guessed_host_ids = {g.host_id for g in best_guess_per_host.values()}

    unknown_hosts = (
        await session.execute(
            select(Host)
            .where(
                (exists().where(Port.host_id == Host.id))
                & (~exists().where(OSGuess.host_id == Host.id))
            )
            .where(base_host_filter)
        )
    ).scalars().unique().all()

    buckets["Unknown"] = len(unknown_hosts)


    # ==========================================================
    # Services summary  — unique host count per normalized service
    # ==========================================================
    ports = (
        await session.execute(select(Port).options(selectinload(Port.host)))
    ).scalars().unique().all()
    service_counts = {}
    for p in ports:
        svc = normalize_service(p.service)
        service_counts.setdefault(svc, set()).add(p.host.address)
    service_summary = {
        svc: len(hosts_set) for svc, hosts_set in service_counts.items()
    }
    service_summary = dict(sorted(service_summary.items(), key=lambda x: -x[1]))

    # ==========================================================
    # Scan timeline
    # ==========================================================
    try:
        scan_times = gather_scan_times(settings.RESULTS_DIR)
    except Exception:
        scan_times = []

    ip_to_id = {h.address: h.id for h in hosts}
    for entry in scan_times:
        key = extract_host_key(entry.get("label") or entry.get("path"))
        entry["host_id"] = ip_to_id.get(key)

    # ==========================================================
    # Render
    # ==========================================================
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "hosts_total": hosts_total or 0,
            "hosts_scanned": hosts_scanned or 0,
            "hosts_enum": hosts_enum,
            "not_scanned": not_scanned,
            "scanned_only": scanned_only,
            "os_summary": {"counts": buckets, "top_items": top_items},
            "scan_times": scan_times,
            "service_summary": service_summary,
        },
    )


@app.get("/hosts", response_class=HTMLResponse)
async def hosts_view(
    request: Request,
    os: str = Query(None, description="Filter by OS family"),
    ip: str = Query(None, description="Filter by IP address"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE, description="Items per page"),
    session: AsyncSession = Depends(get_session)
):
    # Always fetch all hosts + related data for filtering
    all_hosts = (await session.execute(
        select(Host).options(
            selectinload(Host.ports),
            selectinload(Host.scripts),
            selectinload(Host.os_guesses)
        )
    )).scalars().unique().all()

    top_map = {h.id: _top_guess(h) for h in all_hosts}

    # Priority 1: IP filter (redirect if only one match)
    if ip:
        filtered_hosts = [h for h in all_hosts if h.address == ip]
        if not filtered_hosts:
            # fallback: partial substring match (192.168.1.x)
            filtered_hosts = [h for h in all_hosts if ip in h.address]

        if len(filtered_hosts) == 1:
            #  Redirect directly to /hosts/<id>
            return RedirectResponse(
                url=f"/hosts/{filtered_hosts[0].id}",
                status_code=303
            )

        hosts = filtered_hosts

    # Priority 2: OS family filter
    elif os:
        os_lower = os.lower()
        filtered_hosts = []
        for h in all_hosts:
            tg = top_map[h.id]
            if not tg:
                if os_lower == "unknown":
                    filtered_hosts.append(h)
            else:
                if _bucket_family(tg).lower() == os_lower:
                    filtered_hosts.append(h)
        hosts = filtered_hosts

    # Default: show all hosts
    else:
        hosts = all_hosts

    # Apply pagination
    total_hosts = len(hosts)
    total_pages = (total_hosts + per_page - 1) // per_page if total_hosts > 0 else 1
    page = min(page, total_pages)  # clamp to valid range
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_hosts = hosts[start_idx:end_idx]

    return templates.TemplateResponse(
        "hosts.html",
        {
            "request": request,
            "hosts": paginated_hosts,
            "top_os_map": top_map,
            "filter_os": os,
            "filter_ip": ip,
            "page": page,
            "per_page": per_page,
            "total_hosts": total_hosts,
            "total_pages": total_pages,
        }
    )



@app.get("/hosts/{host_id}", response_class=HTMLResponse)
async def host_detail(
    request: Request,
    host_id: int,
    session: AsyncSession = Depends(get_session)
):
    host = (await session.execute(
        select(Host)
        .options(
            selectinload(Host.ports),
            selectinload(Host.scripts),
            selectinload(Host.os_guesses)
        )
        .where(Host.id == host_id)
    )).scalars().first()

    if not host:
        return HTMLResponse(f"<h1>Host {host_id} not found</h1>", status_code=404)

    top_guess = _top_guess(host)

    # Try to locate raw scan files
    nmap_output = xml_output = gnmap_output = None
    base = Path(settings.RESULTS_DIR) / "nmap"
    if base.exists():
        for sub in base.rglob(f"{host.address}*"):
            if sub.suffix == ".nmap":
                nmap_output = sub.read_text(errors="ignore")
            elif sub.suffix == ".xml":
                xml_output = sub.read_text(errors="ignore")
            elif sub.suffix == ".gnmap":
                gnmap_output = sub.read_text(errors="ignore")

    return templates.TemplateResponse("host_detail.html", {
        "request": request,
        "h": host,
        "os_guesses": host.os_guesses,
        "top_guess": top_guess,
        "nmap_output": nmap_output,
        "xml_output": xml_output,
        "gnmap_output": gnmap_output,
    })



# Services overview page
@app.get("/services", response_class=HTMLResponse)
async def services_view(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    ports = (await session.execute(
        select(Port).options(selectinload(Port.host))
    )).scalars().unique().all()

    service_counts = {}
    for p in ports:
        svc = normalize_service(p.service)
        service_counts.setdefault(svc, set()).add(p.host.address)

    service_summary = {svc: len(hosts) for svc, hosts in service_counts.items()}
    total_hosts = len({p.host.address for p in ports})

    return templates.TemplateResponse(
        "services.html",
        {
            "request": request,
            "ports": ports,
            "service_summary": service_summary,
            "total_hosts": total_hosts
        }
    )


# --------------------------------------------------------
# Service detail page: /services/{service_name}
# --------------------------------------------------------
@app.get("/services/{service_name}", response_class=HTMLResponse)
async def service_detail(
    request: Request,
    service_name: str,
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE, description="Items per page"),
    session: AsyncSession = Depends(get_session)
):
    # Load all ports with host so we can normalize in Python
    result = await session.execute(
        select(Port)
        .options(selectinload(Port.host))
        .order_by(Port.port)
    )
    all_ports = result.scalars().all()

    # Keep rows whose *normalized* service matches the URL segment
    matching_ports = [p for p in all_ports if normalize_service(p.service) == service_name]

    # Unique host count for the summary card
    unique_host_ids = {p.host.id for p in matching_ports if p.host}
    host_count = len(unique_host_ids)

    # Total hosts (for the percentage bar)
    total_hosts_result = await session.execute(select(func.count(Host.id)))
    total_hosts = total_hosts_result.scalar_one_or_none() or 0

    # Apply pagination
    total_items = len(matching_ports)
    total_pages = (total_items + per_page - 1) // per_page if total_items > 0 else 1
    page = min(page, total_pages)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    host_services = matching_ports[start_idx:end_idx]

    return templates.TemplateResponse(
        "service_detail.html",
        {
            "request": request,
            "service": service_name,
            "host_services": host_services,
            "host_count": host_count,
            "total_hosts": total_hosts,
            "page": page,
            "per_page": per_page,
            "total_items": total_items,
            "total_pages": total_pages,
        },
    )




@app.get("/modules/lockon", response_class=HTMLResponse)
async def enum_lockon(request: Request):
    base = Path(settings.RESULTS_DIR) / "cygor-enumeration-modules" / "lockon"
    urls_file = base / "tested-urls.txt"
    shots_dir = base / "screenshots"

    items = []
    has_shots = shots_dir.exists()

    def find_screenshot_file(addr: str, port: str) -> str | None:
        for scheme in ("http", "https"):
            fname = f"{scheme}_{addr}_{port}.png"
            if (shots_dir / fname).exists():
                return fname
        return None

    json_file = base / "lockon-results.json"
    if json_file.exists():
        import json
        try:
            data = json.loads(json_file.read_text(encoding="utf-8", errors="ignore"))
            from urllib.parse import urlparse
            for entry in data:
                url = entry.get("url")
                if not url: continue
                parsed = urlparse(url)
                host = parsed.hostname or ""
                port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
                sf = entry.get("screenshot_file")
                screenshot_url = f"/modules/lockon/screenshots/{sf}" if sf and (shots_dir / sf).exists() else None
                items.append({
                    "url": url,
                    "status_code": entry.get("status_code"),
                    "screenshot_file": sf,
                    "screenshot_failed": entry.get("screenshot_failed", False),
                    "screenshot_url": screenshot_url,
                })
        except Exception as e:
            print(f"[!] Failed to parse lockon-results.json: {e}")
    elif urls_file.exists():
        from urllib.parse import urlparse
        for u in urls_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            u = u.strip()
            if not u: continue
            parsed = urlparse(u)
            host = parsed.hostname or ""
            port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
            sf = find_screenshot_file(host, port)
            screenshot_url = f"/modules/lockon/screenshots/{sf}" if sf else None
            items.append({
                "url": u,
                "status_code": None,
                "screenshot_file": sf,
                "screenshot_failed": False,
                "screenshot_url": screenshot_url,
            })

    return templates.TemplateResponse("module_lockon.html", {
        "request": request,
        "items": items,
        "has_shots": has_shots,
        "has_urls": bool(items),
    })

@app.get("/modules/smbexplorer", response_class=HTMLResponse)
async def enum_smbexplorer(request: Request, session: AsyncSession = Depends(get_session)):
    import json
    base = Path(settings.RESULTS_DIR) / "cygor-enumeration-modules" / "smbexplorer"
    rows, file_rows = [], []

    if base.exists():
        for f in base.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                if "smb_results" in f.name:
                    rows.extend(data)
                elif "smb_files" in f.name:
                    file_rows.extend(data)
            except Exception:
                continue

    seen = set()
    deduped_rows = []
    for r in rows:
        key = (r.get("IP Address") or r.get("ip"), r.get("Share") or r.get("share"))
        if key not in seen:
            seen.add(key)
            deduped_rows.append({
                "ip": r.get("IP Address") or r.get("ip"),
                "share": r.get("Share") or r.get("share"),
                "status": r.get("Status") or r.get("status"),
                "smb_version": r.get("SMB Version") or r.get("smb_version"),
                "permissions": r.get("Permissions") or r.get("permissions"),
                "information": r.get("Information") or r.get("information"),
            })

    norm_file_rows = []
    for f in file_rows:
        norm_file_rows.append({
            "ip": f.get("IP") or f.get("ip"),
            "share": f.get("Share") or f.get("share"),
            "name": f.get("Name") or f.get("name"),
            "size": f.get("Size") or f.get("size"),
            "mtime": f.get("Modified") or f.get("mtime"),
            "attributes": f.get("Attributes") or f.get("attributes"),
            "type": f.get("Type") or f.get("type"),
        })

    ports = (await session.execute(
        select(Port).options(selectinload(Port.host)).where(Port.port == 445)
    )).scalars().all()
    hosts_with_445 = len({p.host.address for p in ports})

    return templates.TemplateResponse("module_smbexplorer.html", {
        "request": request,
        "rows": deduped_rows,
        "file_rows": norm_file_rows,
        "hosts_with_445": hosts_with_445,
    })

@app.get("/modules/nfsexplorer", response_class=HTMLResponse)
async def enum_nfsexplorer(request: Request):
    import json
    base = Path(settings.RESULTS_DIR) / "cygor-enumeration-modules" / "nfsexplorer"
    rows = []
    if base.exists():
        for f in base.glob("*.json"):
            try:
                rows.extend(json.loads(f.read_text()))
            except Exception:
                continue

    hosts_with_nfs = len({r.get("ip") for r in rows if r.get("ip")})
    return templates.TemplateResponse("module_nfsexplorer.html", {
        "request": request,
        "rows": rows,
        "hosts_with_nfs": hosts_with_nfs
    })

@app.get("/search", response_class=HTMLResponse)
async def search(
    request: Request,
    q: str = Query("", description="Search query"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE, description="Items per page"),
    session: AsyncSession = Depends(get_session)
):
    q = (q or "").strip()
    all_hosts = all_ports = all_scripts = []

    if q:
        # Eager load ports + scripts for hosts (so template can access safely)
        host_result = await session.execute(
            select(Host)
            .where((Host.address.contains(q)) | (Host.hostname.contains(q)))
            .options(selectinload(Host.ports), selectinload(Host.scripts))
        )
        all_hosts = host_result.scalars().unique().all()

        # Eager load host for ports (fixes MissingGreenlet)
        port_result = await session.execute(
            select(Port)
            .where((Port.service.contains(q)) | (Port.banner.contains(q)))
            .options(selectinload(Port.host))
        )
        all_ports = port_result.scalars().unique().all()

        # Eager load host + port for scripts if needed in template
        script_result = await session.execute(
            select(Script)
            .where(Script.output.contains(q))
            .options(selectinload(Script.host), selectinload(Script.port))
        )
        all_scripts = script_result.scalars().unique().all()

    # Pagination helper
    def paginate(items, page_num, page_size):
        total = len(items)
        total_pgs = (total + page_size - 1) // page_size if total > 0 else 1
        p = min(page_num, total_pgs)
        start = (p - 1) * page_size
        end = start + page_size
        return items[start:end], total, total_pgs

    hosts, hosts_total, hosts_pages = paginate(all_hosts, page, per_page)
    ports, ports_total, ports_pages = paginate(all_ports, page, per_page)
    scripts, scripts_total, scripts_pages = paginate(all_scripts, page, per_page)

    return templates.TemplateResponse("search.html", {
        "request": request,
        "query": q,
        "hosts": hosts,
        "ports": ports,
        "scripts": scripts,
        "page": page,
        "per_page": per_page,
        "hosts_total": hosts_total,
        "ports_total": ports_total,
        "scripts_total": scripts_total,
        "hosts_pages": hosts_pages,
        "ports_pages": ports_pages,
        "scripts_pages": scripts_pages,
    })
# -------- Task Management Pages --------
@app.get("/tasks", response_class=HTMLResponse)
async def tasks_page(request: Request):
    """Tasks dashboard page."""
    return templates.TemplateResponse("tasks.html", {"request": request})

@app.get("/tasks/scan/new", response_class=HTMLResponse)
async def new_scan_page(request: Request):
    """New scan form page."""
    return templates.TemplateResponse("scan_new.html", {"request": request})

@app.get("/sync-status", response_class=HTMLResponse)
async def sync_status_page(request: Request):
    """Sync status and history page."""
    # Get current database stats
    async with db.SessionLocal() as session:
        from sqlalchemy import func, select
        total_hosts = await session.scalar(select(func.count(Host.id))) or 0
        total_ports = await session.scalar(select(func.count(Port.id))) or 0

    results_dir = os.environ.get("CYGOR_LOAD_DIR") or settings.RESULTS_DIR

    return templates.TemplateResponse("sync_status.html", {
        "request": request,
        "total_hosts": total_hosts,
        "total_ports": total_ports,
        "results_dir": results_dir
    })

@app.get("/api/sync-history")
async def get_sync_history():
    """Get sync history."""
    return JSONResponse({
        "status": "success",
        "history": SYNC_HISTORY
    })

def scan_available_hostlists() -> dict:
    """Scan workspace for available parsed hostlists and discovery results."""
    available_hostlists = {}
    parsed_dir = Path(settings.RESULTS_DIR) / "parsed-hostlists"

    if parsed_dir.exists():
        # Common service directories to check
        service_dirs = {
            "http": "HTTP Hosts",
            "https": "HTTPS Hosts",
            "http-https": "All Web Services",
            "smb": "SMB Hosts",
            "nfs": "NFS Hosts",
            "ftp": "FTP Hosts",
            "ssh": "SSH Hosts",
            "rdp": "RDP Hosts",
            "vnc": "VNC Hosts",
            "telnet": "Telnet Hosts",
            "winrm": "WinRM Hosts",
            "dns": "DNS Servers",
            "proxmox": "Proxmox Hosts",
            "mysql": "MySQL Databases",
            "postgres": "PostgreSQL Databases",
            "mssql": "MSSQL Databases",
            "mongodb": "MongoDB Databases",
            "redis": "Redis Servers",
        }

        for service_dir, label in service_dirs.items():
            hostlist_file = parsed_dir / service_dir / f"{service_dir}-hostlist.txt"
            if hostlist_file.exists():
                # Store relative path from RESULTS_DIR
                rel_path = f"parsed-hostlists/{service_dir}/{service_dir}-hostlist.txt"
                available_hostlists[service_dir] = {
                    "label": label,
                    "path": rel_path,
                    "count": len(hostlist_file.read_text().strip().split('\n')) if hostlist_file.stat().st_size > 0 else 0
                }

    # Also check for discovery results
    discovery_dir = Path(settings.RESULTS_DIR) / "discovery"
    if discovery_dir.exists():
        discovery_files = {
            "all-discovered-hosts.txt": "All Discovered Hosts",
            "masscan-discovered.txt": "Masscan Results",
            "naabu-discovered.txt": "Naabu Results"
        }
        for filename, label in discovery_files.items():
            filepath = discovery_dir / filename
            if filepath.exists():
                rel_path = f"discovery/{filename}"
                available_hostlists[f"discovery_{filename}"] = {
                    "label": label,
                    "path": rel_path,
                    "count": len(filepath.read_text().strip().split('\n')) if filepath.stat().st_size > 0 else 0
                }

    return available_hostlists

@app.get("/tasks/module/new", response_class=HTMLResponse)
async def new_module_page(request: Request):
    """Run module form page."""
    available_hostlists = scan_available_hostlists()
    return templates.TemplateResponse("module_run.html", {
        "request": request,
        "available_hostlists": available_hostlists
    })

@app.get("/api/hostlists")
async def get_available_hostlists():
    """API endpoint to get available hostlists (for dynamic reloading)."""
    return JSONResponse(scan_available_hostlists())

@app.get("/api/module-configs")
async def get_module_configs():
    """API endpoint to get module configuration options."""
    # Module configuration with all available options
    module_configs = {
        "lockon": {
            "name": "Lockon - Web Screenshots",
            "description": "Captures screenshots of HTTP/HTTPS services using Playwright browser automation",
            "options": [
                {
                    "name": "scheme",
                    "label": "URL Scheme",
                    "type": "select",
                    "choices": [
                        {"value": "both", "label": "Both HTTP & HTTPS (default)"},
                        {"value": "http", "label": "HTTP only"},
                        {"value": "https", "label": "HTTPS only"}
                    ],
                    "default": "both",
                    "help": "Scheme(s) to test for bare host entries"
                },
                {
                    "name": "workers",
                    "label": "Worker Threads",
                    "type": "number",
                    "default": "32",
                    "min": 1,
                    "max": 256,
                    "help": "Number of concurrent worker threads (default: min(32, cpu_count * 4))"
                },
                {
                    "name": "scan_workers",
                    "label": "HTTP Scan Workers",
                    "type": "number",
                    "min": 1,
                    "max": 256,
                    "help": "Separate worker count for HTTP scanning (defaults to --workers value)"
                },
                {
                    "name": "shot_workers",
                    "label": "Screenshot Workers",
                    "type": "number",
                    "min": 1,
                    "max": 256,
                    "help": "Separate worker count for screenshots (defaults to --workers value)"
                },
                {
                    "name": "http_timeout",
                    "label": "HTTP Timeout (seconds)",
                    "type": "number",
                    "default": "5.0",
                    "step": 0.1,
                    "min": 0.1,
                    "help": "HTTP connect/read timeout in seconds"
                },
                {
                    "name": "nav_timeout",
                    "label": "Navigation Timeout (ms)",
                    "type": "number",
                    "default": "45000",
                    "min": 1000,
                    "help": "Playwright page.goto timeout in milliseconds"
                },
                {
                    "name": "viewport",
                    "label": "Viewport Size",
                    "type": "text",
                    "default": "1366x768",
                    "pattern": "\\d+x\\d+",
                    "help": "Browser viewport size (WIDTHxHEIGHT)"
                },
                {
                    "name": "extra_wait",
                    "label": "Extra Wait Time (ms)",
                    "type": "number",
                    "default": "2000",
                    "min": 0,
                    "help": "Wait time after page load before screenshot in milliseconds"
                },
                {
                    "name": "status_filter",
                    "label": "HTTP Status Filter",
                    "type": "text",
                    "default": "200,301,302,307,308",
                    "help": "Comma-separated list of HTTP status codes to capture (0 = all)"
                },
                {
                    "name": "output_format",
                    "label": "Output Format",
                    "type": "select",
                    "choices": [
                        {"value": "json", "label": "JSON (default)"},
                        {"value": "xml", "label": "XML"},
                        {"value": "csv", "label": "CSV"},
                        {"value": "txt", "label": "Text"},
                        {"value": "all", "label": "All formats"}
                    ],
                    "default": "json",
                    "help": "Output file format"
                }
            ]
        },
        "smbexplorer": {
            "name": "SMB Explorer",
            "description": "Enumerates SMB shares, permissions, and accessible files on Windows/Samba hosts",
            "options": [
                {
                    "name": "username",
                    "label": "Username",
                    "type": "text",
                    "default": "guest",
                    "help": "Authentication username (default: guest)"
                },
                {
                    "name": "password",
                    "label": "Password",
                    "type": "password",
                    "help": "Authentication password"
                },
                {
                    "name": "domain",
                    "label": "Domain",
                    "type": "text",
                    "help": "Domain name for authentication"
                },
                {
                    "name": "ntlm_hash",
                    "label": "NTLM Hash",
                    "type": "text",
                    "help": "NTLM hash for pass-the-hash (LMHASH:NTHASH format)"
                },
                {
                    "name": "use_kerberos",
                    "label": "Use Kerberos",
                    "type": "checkbox",
                    "default": False,
                    "help": "Enable Kerberos authentication (requires one of the Kerberos options below)"
                },
                {
                    "name": "kerberos_keytab",
                    "label": "Kerberos Keytab File",
                    "type": "text",
                    "help": "Path to Kerberos keytab file (most common for service accounts)"
                },
                {
                    "name": "kerberos_aeskey",
                    "label": "Kerberos AES Key",
                    "type": "text",
                    "help": "AES key (128/256-bit hex) for pass-the-key attack"
                },
                {
                    "name": "kerberos_principal",
                    "label": "Kerberos Principal",
                    "type": "text",
                    "help": "Kerberos principal (e.g., user@DOMAIN.COM). If not specified, uses username@DOMAIN"
                },
                {
                    "name": "kerberos_ccache",
                    "label": "Kerberos Ccache File",
                    "type": "text",
                    "help": "Path to Kerberos ccache file (overrides KRB5CCNAME environment variable)"
                },
                {
                    "name": "list_files",
                    "label": "List Files",
                    "type": "checkbox",
                    "default": False,
                    "help": "List accessible files in each share"
                },
                {
                    "name": "max_files",
                    "label": "Max Files Per Share",
                    "type": "number",
                    "default": "50",
                    "min": 1,
                    "help": "Maximum number of files to list per share"
                },
                {
                    "name": "smb_output_format",
                    "label": "Output Format",
                    "type": "select",
                    "choices": [
                        {"value": "txt,csv,json,xml", "label": "Multiple formats (default)"},
                        {"value": "txt", "label": "Text"},
                        {"value": "csv", "label": "CSV"},
                        {"value": "json", "label": "JSON"},
                        {"value": "xml", "label": "XML"},
                        {"value": "all", "label": "All formats"}
                    ],
                    "default": "txt,csv,json,xml",
                    "help": "Output file format(s)"
                }
            ]
        },
        "nfsexplorer": {
            "name": "NFS Explorer",
            "description": "Interacts with NFS exports to analyze access levels and test UID/GID mappings",
            "options": [
                {
                    "name": "uid",
                    "label": "User ID (UID)",
                    "type": "number",
                    "default": "0",
                    "min": 0,
                    "help": "Fake UID to use for NFS requests (default: 0/root)"
                },
                {
                    "name": "gid",
                    "label": "Group ID (GID)",
                    "type": "number",
                    "default": "0",
                    "min": 0,
                    "help": "Fake GID to use for NFS requests (default: 0/root)"
                },
                {
                    "name": "aux_gids",
                    "label": "Auxiliary GIDs",
                    "type": "text",
                    "help": "Comma-separated auxiliary GIDs (e.g., 100,1000)"
                },
                {
                    "name": "timeout",
                    "label": "RPC Timeout (seconds)",
                    "type": "number",
                    "default": "10",
                    "min": 1,
                    "help": "RPC timeout in seconds"
                },
                {
                    "name": "recurse",
                    "label": "Recursion Depth",
                    "type": "number",
                    "default": "1",
                    "min": 0,
                    "max": 10,
                    "help": "Directory recursion depth (default: 1)"
                },
                {
                    "name": "list_files",
                    "label": "List Files",
                    "type": "checkbox",
                    "default": False,
                    "help": "List files/directories inside each share"
                },
                {
                    "name": "info",
                    "label": "Info Only",
                    "type": "checkbox",
                    "default": False,
                    "help": "Only show supported NFS versions/exports"
                },
                {
                    "name": "check_root",
                    "label": "Check no_root_squash",
                    "type": "checkbox",
                    "default": False,
                    "help": "Attempt to detect no_root_squash misconfigurations"
                },
                {
                    "name": "version",
                    "label": "NFS Version",
                    "type": "select",
                    "choices": [
                        {"value": "", "label": "Auto-detect (default)"},
                        {"value": "2", "label": "NFSv2"},
                        {"value": "3", "label": "NFSv3"},
                        {"value": "4", "label": "NFSv4"}
                    ],
                    "help": "Force specific NFS protocol version"
                },
                {
                    "name": "nfs_output_format",
                    "label": "Output Format",
                    "type": "select",
                    "choices": [
                        {"value": "text,csv,json,xml", "label": "Multiple formats (default)"},
                        {"value": "text", "label": "Text"},
                        {"value": "csv", "label": "CSV"},
                        {"value": "json", "label": "JSON"},
                        {"value": "xml", "label": "XML"},
                        {"value": "all", "label": "All formats"}
                    ],
                    "default": "text,csv,json,xml",
                    "help": "Output file format(s)"
                }
            ]
        }
    }

    return JSONResponse(module_configs)

@app.get("/tasks/{task_id}", response_class=HTMLResponse)
async def task_detail_page(request: Request, task_id: str):
    """Task detail page with live output."""
    return templates.TemplateResponse("task_detail.html", {"request": request, "task_id": task_id})

# -------- Credential Scanner (On-Demand Scanner) --------
@app.get("/credrecon", response_class=HTMLResponse)
async def credrecon_dashboard(request: Request):
    """Credential reconnaissance dashboard."""
    return templates.TemplateResponse("credrecon_dashboard.html", {"request": request})

@app.get("/credrecon/new", response_class=HTMLResponse)
async def credrecon_new_scan(request: Request):
    """Credential reconnaissance new scan page."""
    return templates.TemplateResponse("credrecon.html", {"request": request})

@app.get("/credrecon/scans/{scan_id}", response_class=HTMLResponse)
async def credrecon_scan_detail(request: Request, scan_id: str):
    """Credential reconnaissance scan details page."""
    return templates.TemplateResponse("credrecon_scan_detail.html", {
        "request": request,
        "scan_id": scan_id
    })

@app.get("/credrecon/results", response_class=HTMLResponse)
async def credrecon_results_page(request: Request):
    """Credential reconnaissance results page."""
    from cygor import credrecon
    # Search in both old and new directory structures (for backward compatibility)
    results_dirs = [
        Path("credrecon") / "credrecon-tasks",  # New structure
        Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks",  # New structure with RESULTS_DIR
        Path("credrecon-tasks"),  # Old structure (backward compatibility)
        Path(settings.RESULTS_DIR) / "credrecon-tasks",  # Old structure with RESULTS_DIR (backward compatibility)
        Path(settings.RESULTS_DIR) / "credrecon",  # Legacy structure
        Path("credrecon"),  # Legacy structure
    ]

    # Load all credential scanner results
    # Track loaded files by absolute path to avoid duplicates
    loaded_files = set()
    all_results = []
    for results_dir in results_dirs:
        if results_dir.exists():
            for json_file in sorted(results_dir.rglob("credrecon_results.json")):
                # Use absolute path to avoid loading the same file twice
                abs_path = json_file.resolve()
                if abs_path in loaded_files:
                    continue
                loaded_files.add(abs_path)
                
                try:
                    data = json.loads(json_file.read_text())
                    if isinstance(data, list):
                        all_results.extend(data)
                except Exception as e:
                    print(f"Error loading {json_file}: {e}", file=sys.stderr)

    # Deduplicate results based on unique combination of fields
    # Create a set of unique result identifiers
    seen_results = set()
    unique_results = []
    for result in all_results:
        # Create a unique key from result fields
        target = result.get("ip") or result.get("target", "")
        port = result.get("port", 0)
        protocol = result.get("protocol", "")
        username = result.get("username", "")
        password = result.get("password", "")
        status = result.get("status", "")
        timestamp = result.get("timestamp", "")
        
        # Create unique identifier
        result_key = (target, port, protocol, username, password, status, timestamp)
        
        if result_key not in seen_results:
            seen_results.add(result_key)
            unique_results.append(result)

    # Separate successful from failed
    successful = [r for r in unique_results if r.get("status") == "success"]
    failed = [r for r in unique_results if r.get("status") == "failed"]
    errors = [r for r in unique_results if r.get("status") == "error"]

    return templates.TemplateResponse("credrecon_results.html", {
        "request": request,
        "successful": successful,
        "failed": failed,
        "errors": errors,
        "total": len(unique_results)
    })

# -------- Task Management API --------
class ScanRequest(BaseModel):
    targets: List[str]
    interface: Optional[str] = None
    discover: Optional[List[str]] = ["masscan"]
    scan_type: str = "top-ports"
    ports: Optional[str] = None
    nmap_options: Optional[str] = None
    output_dir: Optional[str] = None
    exclusions: Optional[List[str]] = None
    is_ondemand: bool = True  # Default to True for web UI scans

class ModuleRequest(BaseModel):
    module_name: str
    targets_file: str
    output_dir: Optional[str] = None
    uploaded_content: Optional[str] = None  # For file uploads from web UI
    module_options: Optional[Dict[str, Any]] = {}  # Module-specific options as key-value pairs

@app.post("/api/scans")
async def create_scan(req: ScanRequest):
    """Create a new scan task."""
    if not req.targets:
        raise HTTPException(status_code=400, detail="No targets provided")

    output_dir = req.output_dir or str(settings.RESULTS_DIR)

    task_id = await task_manager.create_scan_task(
        targets=req.targets,
        interface=req.interface,
        discover=req.discover,
        scan_type=req.scan_type,
        ports=req.ports,
        nmap_options=req.nmap_options,
        output_dir=output_dir,
        exclusions=req.exclusions,
        is_ondemand=req.is_ondemand
    )

    return JSONResponse({"task_id": task_id, "status": "created"})

@app.post("/api/modules")
async def create_module_task(req: ModuleRequest):
    """Create a new enumeration module task."""
    if not req.targets_file:
        raise HTTPException(status_code=400, detail="No targets file provided")

    targets_file_path = req.targets_file

    # Handle uploaded file content
    if req.uploaded_content:
        # Create a temporary file for uploaded content
        import tempfile
        temp_dir = Path(tempfile.gettempdir()) / "cygor-uploads"
        temp_dir.mkdir(parents=True, exist_ok=True)

        temp_file = temp_dir / f"module-targets-{uuid.uuid4()}.txt"
        temp_file.write_text(req.uploaded_content)
        targets_file_path = str(temp_file)
    else:
        # Resolve path relative to RESULTS_DIR if it's a relative path
        file_path = Path(targets_file_path)
        if not file_path.is_absolute():
            # Try resolving relative to RESULTS_DIR first
            resolved_path = Path(settings.RESULTS_DIR) / targets_file_path
            if resolved_path.exists():
                targets_file_path = str(resolved_path)
            elif not file_path.exists():
                raise HTTPException(status_code=400, detail=f"Targets file not found: {targets_file_path}")
        else:
            # Validate absolute path
            if not file_path.exists():
                raise HTTPException(status_code=400, detail=f"Targets file not found: {targets_file_path}")

    output_dir = req.output_dir or str(settings.RESULTS_DIR)

    task_id = await task_manager.create_module_task(
        module_name=req.module_name,
        targets_file=targets_file_path,
        output_dir=output_dir,
        module_options=req.module_options or {}
    )

    return JSONResponse({"task_id": task_id, "status": "created"})

@app.post("/api/credrecon")
async def create_credrecon_task(request: Request, db_session: AsyncSession = Depends(get_session)):
    """Create a new credential scanner task."""
    try:
        data = await request.json()

        targets = data.get("targets", [])
        protocol = data.get("protocol", "auto")
        threads = data.get("threads", 10)
        max_attempts = data.get("max_attempts", 3)
        timeout = data.get("timeout", 5)
        rate_limit = data.get("rate_limit", 0.1)
        creds_file = data.get("creds_file", "")
        uploaded_targets = data.get("uploaded_targets", "")
        uploaded_usernames = data.get("uploaded_usernames", "")
        uploaded_passwords = data.get("uploaded_passwords", "")

        if not targets and not uploaded_targets:
            raise HTTPException(status_code=400, detail="No targets provided")

        # Generate scan ID first (needed for directory name)
        import uuid
        scan_id = str(uuid.uuid4())

        # Create output directory: credrecon/credrecon-tasks/credrecon-taskid-timestamp
        from datetime import datetime
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        # Use short scan ID (first 8 chars) for directory name
        short_scan_id = scan_id[:8]
        # Create credrecon directory if it doesn't exist
        credrecon_base = Path("credrecon")
        credrecon_base.mkdir(exist_ok=True)
        output_dir = credrecon_base / "credrecon-tasks" / f"credrecon-{short_scan_id}-{timestamp}"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save targets file in the output directory instead of /tmp
        if uploaded_targets:
            targets_content = uploaded_targets
        else:
            targets_content = "\n".join(targets)

        targets_file = output_dir / "targets.txt"
        with open(targets_file, 'w') as f:
            f.write(targets_content)

        # Build command
        cmd = ["cygor", "credrecon", "-i", str(targets_file)]

        if protocol and protocol != "auto":
            cmd.extend(["--protocol", protocol])

        if threads:
            cmd.extend(["--threads", str(threads)])

        if max_attempts:
            cmd.extend(["--max-attempts", str(max_attempts)])

        if timeout:
            cmd.extend(["--timeout", str(timeout)])

        if rate_limit:
            cmd.extend(["--rate-limit", str(rate_limit)])

        if creds_file:
            cmd.extend(["--creds-file", creds_file])

        # Handle username/password file uploads - save in output directory
        if uploaded_usernames and uploaded_passwords:
            usernames_file = output_dir / "usernames.txt"
            with open(usernames_file, 'w') as f:
                f.write(uploaded_usernames)

            passwords_file = output_dir / "passwords.txt"
            with open(passwords_file, 'w') as f:
                f.write(uploaded_passwords)

            cmd.extend(["--usernames-file", str(usernames_file)])
            cmd.extend(["--passwords-file", str(passwords_file)])

        # Add output directory and scan-id to command
        cmd.extend(["-o", str(output_dir)])
        cmd.extend(["--scan-id", scan_id])

        # Create scan record in database
        from cygor.webapp.models import CredReconScan

        try:
            db_scan = CredReconScan(
                scan_id=scan_id,
                created_at=datetime.utcnow().isoformat(),
                status="pending",
                command=" ".join(cmd),
                num_targets=len(targets_content.splitlines())
                # Note: output_dir column doesn't exist in database, so we don't set it here
                # The output directory path is stored in the command string and can be reconstructed from created_at timestamp
            )
            db_session.add(db_scan)
            await db_session.commit()
        except Exception as e:
            print(f"Error creating scan record in database: {e}", file=sys.stderr)

        # Create credential scanner task using dedicated manager
        await credrecon_manager.create_scan(
            command=cmd,
            num_targets=len(targets_content.splitlines()),
            scan_id=scan_id
        )

        return JSONResponse({"scan_id": scan_id, "status": "created", "redirect": f"/credrecon/scans/{scan_id}"})
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error creating credrecon task: {str(e)}")

@app.get("/api/credrecon/stats")
async def get_credrecon_stats(session: AsyncSession = Depends(get_session)):
    """Get credential scanner statistics for dashboard."""
    # Search in both old and new directory structures (for backward compatibility)
    results_dirs = [
        Path("credrecon") / "credrecon-tasks",  # New structure
        Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks",  # New structure with RESULTS_DIR
        Path("credrecon-tasks"),  # Old structure (backward compatibility)
        Path(settings.RESULTS_DIR) / "credrecon-tasks",  # Old structure with RESULTS_DIR (backward compatibility)
        Path(settings.RESULTS_DIR) / "credrecon",  # Legacy structure
        Path("credrecon"),  # Legacy structure
    ]

    # Load all credential scanner results from disk (completed scans)
    # Track loaded files by absolute path to avoid duplicates
    loaded_files = set()
    all_results = []
    for results_dir in results_dirs:
        if results_dir.exists():
            for json_file in sorted(results_dir.rglob("credrecon_results.json")):
                # Use absolute path to avoid loading the same file twice
                abs_path = json_file.resolve()
                if abs_path in loaded_files:
                    continue
                loaded_files.add(abs_path)
                
                try:
                    data = json.loads(json_file.read_text())
                    if isinstance(data, list):
                        all_results.extend(data)
                except Exception as e:
                    print(f"Error loading {json_file}: {e}", file=sys.stderr)
    
    # Deduplicate results based on unique combination of fields
    seen_results = set()
    unique_results = []
    for result in all_results:
        # Create a unique key from result fields
        target = result.get("ip") or result.get("target", "")
        port = result.get("port", 0)
        protocol = result.get("protocol", "")
        username = result.get("username", "")
        password = result.get("password", "")
        status = result.get("status", "")
        timestamp = result.get("timestamp", "")
        
        # Create unique identifier
        result_key = (target, port, protocol, username, password, status, timestamp)
        
        if result_key not in seen_results:
            seen_results.add(result_key)
            unique_results.append(result)
    
    # Use unique_results instead of all_results
    all_results = unique_results

    # Calculate stats
    successful = [r for r in all_results if r.get("status") == "success"]
    failed = [r for r in all_results if r.get("status") == "failed"]
    errors = [r for r in all_results if r.get("status") == "error"]

    # Get recent scans (last 20 results for dashboard, prioritize successful)
    recent = sorted(successful, key=lambda x: x.get("timestamp", ""), reverse=True)[:20]

    # Get ALL scan tasks from credrecon_manager (including completed ones that might not be in DB yet)
    all_task_scans = await credrecon_manager.get_all_scans()
    active_scan_info = []

    # Only include pending/running scans (current active tasks)
    active_scans = [s for s in all_task_scans if s.status.value in ['pending', 'running']]
    
    # Also include recently completed scans from task manager (in case DB hasn't been updated yet)
    # This ensures completed scans show up immediately
    recently_completed = [s for s in all_task_scans if s.status.value in ['completed', 'failed']]

    # Sort: running first, then pending
    def scan_sort_key(scan):
        status_priority = {'running': 0, 'pending': 1}
        return (status_priority.get(scan.status.value, 99), -scan.created_at.timestamp())

    for scan in sorted(active_scans, key=scan_sort_key):
        active_scan_info.append({
            "scan_id": scan.scan_id,
            "status": scan.status.value,
            "num_targets": scan.num_targets,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "command": " ".join(scan.command),
        })

    # Get historical scans (completed/failed) from database
    # Also merge in recently completed scans from task manager to ensure we don't miss any
    from sqlalchemy import select
    from cygor.webapp.models import CredReconScan

    historical_scan_info = []
    db_scan_ids = set()  # Track which scan IDs we've already added from DB
    
    try:
        # Get completed/failed scans from database, ordered by most recent
        # Explicitly select only columns that exist in the database (excluding output_dir)
        statement = (
            select(
                CredReconScan.id,
                CredReconScan.scan_id,
                CredReconScan.created_at,
                CredReconScan.started_at,
                CredReconScan.completed_at,
                CredReconScan.status,
                CredReconScan.command,
                CredReconScan.num_targets
            )
            .where(CredReconScan.status.in_(['completed', 'failed']))
            .order_by(CredReconScan.created_at.desc())
            .limit(50)  # Increased limit to get more historical scans
        )
        result = await session.execute(statement)
        db_scans = result.all()

        for scan in db_scans:
            db_scan_ids.add(scan.scan_id)
            # Note: created_at, started_at, completed_at are already strings (ISO format) in the database
            historical_scan_info.append({
                "scan_id": scan.scan_id,
                "status": scan.status,
                "num_targets": scan.num_targets,
                "created_at": scan.created_at if scan.created_at else None,
                "started_at": scan.started_at if scan.started_at else None,
                "completed_at": scan.completed_at if scan.completed_at else None,
                "command": scan.command,
            })
    except Exception as e:
        print(f"Error fetching historical scans from database: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
    
    # Add recently completed scans from task manager that aren't in database yet
    # This ensures scans show up immediately after completion
    for scan in recently_completed:
        if scan.scan_id not in db_scan_ids:
            historical_scan_info.append({
                "scan_id": scan.scan_id,
                "status": scan.status.value,
                "num_targets": scan.num_targets,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "command": " ".join(scan.command),
            })
            db_scan_ids.add(scan.scan_id)  # Mark as added
    
    # Discover scans from JSON files on disk that aren't in database or task manager
    # This handles cases where scans were run but database records weren't created/updated
    discovered_dirs = set()
    all_known_scan_ids = db_scan_ids.copy()
    
    # Get all scan IDs from task manager too
    for scan in all_task_scans:
        all_known_scan_ids.add(scan.scan_id)
    
    for results_dir in results_dirs:
        if results_dir.exists():
            for json_file in sorted(results_dir.rglob("credrecon_results.json")):
                try:
                    # Try to extract scan_id from directory name
                    # Format: credrecon/credrecon-tasks/credrecon-{short_scan_id}-{timestamp}/credrecon_results.json
                    # Or: credrecon-tasks/credrecon-{short_scan_id}-{timestamp}/credrecon_results.json (old format)
                    parent_dir = json_file.parent.name
                    if parent_dir.startswith("credrecon-") and len(parent_dir) > 10:
                        # Extract the short scan ID (first 8 chars after "credrecon-")
                        parts = parent_dir.split("-")
                        if len(parts) >= 2:
                            short_id = parts[1]  # e.g., "e3ef5374"
                            
                            # Try to find full scan_id by checking if any known scan_id starts with short_id
                            file_scan_id = None
                            for known_scan_id in all_known_scan_ids:
                                if known_scan_id.startswith(short_id):
                                    file_scan_id = known_scan_id
                                    break
                            
                            # If not found, search database for scan_ids starting with short_id
                            if not file_scan_id:
                                try:
                                    # Query database for scan_ids that start with short_id
                                    search_statement = (
                                        select(CredReconScan.scan_id)
                                        .where(CredReconScan.scan_id.like(f"{short_id}%"))
                                        .limit(1)
                                    )
                                    search_result = await session.execute(search_statement)
                                    found_scan = search_result.scalar_one_or_none()
                                    if found_scan:
                                        file_scan_id = found_scan
                                        all_known_scan_ids.add(found_scan)
                                except Exception as e:
                                    print(f"Error searching for scan_id starting with {short_id}: {e}", file=sys.stderr)
                            
                            # Only add if we haven't seen this directory before
                            if parent_dir not in discovered_dirs:
                                # Check if this scan_id is already in our historical scans
                                scan_id_to_check = file_scan_id if file_scan_id else f"discovered-{short_id}"
                                
                                # Only add if not already in historical_scan_info
                                already_added = any(s.get('scan_id') == scan_id_to_check for s in historical_scan_info)
                                
                                if not already_added:
                                    discovered_dirs.add(parent_dir)
                                    
                                    # Check file modification time to estimate when scan was created
                                    file_mtime = json_file.stat().st_mtime
                                    from datetime import datetime
                                    file_time = datetime.fromtimestamp(file_mtime)
                                    
                                    # Try to load JSON to get result count
                                    try:
                                        json_data = json.loads(json_file.read_text())
                                        num_results = len(json_data) if isinstance(json_data, list) else 0
                                    except:
                                        num_results = 0
                                    
                                    # Create scan info from file discovery
                                    # Use the found scan_id or create a reference using the directory name
                                    scan_id_to_use = file_scan_id if file_scan_id else f"historic-{short_id}"
                                    
                                    historical_scan_info.append({
                                        "scan_id": scan_id_to_use,
                                        "status": "completed",  # Assume completed if results file exists
                                        "num_targets": num_results,  # Use result count as proxy
                                        "created_at": file_time.isoformat(),
                                        "started_at": file_time.isoformat(),
                                        "completed_at": file_time.isoformat(),
                                        "command": f"cygor credrecon -o {parent_dir}",
                                    })
                                    db_scan_ids.add(scan_id_to_use)  # Mark as added
                except Exception as e:
                    print(f"Error discovering scan from {json_file}: {e}", file=sys.stderr)
                    continue
    
    # Debug logging
    # print(f"DEBUG: Returning {len(historical_scan_info)} historical scans", file=sys.stderr)
    if historical_scan_info:
        scan_ids = [s['scan_id'][:8] if s.get('scan_id') else 'N/A' for s in historical_scan_info[:5]]
        # print(f"DEBUG: Historical scan IDs (first 5): {scan_ids}", file=sys.stderr)

    return JSONResponse({
        "successful": len(successful),
        "failed": len(failed),
        "errors": len(errors),
        "total": len(all_results),
        "recent": recent,
        "active_scans": active_scan_info,
        "historical_scans": historical_scan_info
    })

@app.get("/api/credrecon/scans")
async def list_credrecon_scans():
    """List all credential scanner scans."""
    scans = await credrecon_manager.get_all_scans()
    return JSONResponse([scan.to_dict() for scan in scans])

@app.get("/api/credrecon/scans/{scan_id}")
async def get_credrecon_scan(scan_id: str):
    """Get details of a specific credential scanner scan."""
    # Handle historic scans (from disk discovery)
    if scan_id.startswith("historic-"):
        short_id = scan_id.replace("historic-", "")
        
        # Find the directory matching this short_id
        discovered_json_file = None
        discovered_dir = None
        
        for results_dir in [
            Path("credrecon") / "credrecon-tasks",  # New structure
            Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks",  # New structure with RESULTS_DIR
            Path("credrecon-tasks"),  # Old structure (backward compatibility)
            Path(settings.RESULTS_DIR) / "credrecon-tasks",  # Old structure with RESULTS_DIR (backward compatibility)
            Path("credrecon"),  # Legacy structure
            Path(settings.RESULTS_DIR) / "credrecon",  # Legacy structure
        ]:
            if results_dir.exists():
                for json_file in results_dir.rglob("credrecon_results.json"):
                    parent_dir = json_file.parent.name
                    if parent_dir.startswith("credrecon-") and short_id in parent_dir:
                        discovered_json_file = json_file
                        discovered_dir = parent_dir
                        break
                if discovered_json_file:
                    break
        
        if discovered_json_file:
            # Create scan dict from discovered scan
            file_mtime = discovered_json_file.stat().st_mtime
            from datetime import datetime
            file_time = datetime.fromtimestamp(file_mtime)
            
            # Try to load JSON to get result count
            try:
                json_data = json.loads(discovered_json_file.read_text())
                num_results = len(json_data) if isinstance(json_data, list) else 0
            except:
                num_results = 0
            
            scan_dict = {
                "scan_id": scan_id,
                "status": "completed",
                "num_targets": num_results,
                "created_at": file_time.isoformat(),
                "started_at": file_time.isoformat(),
                "completed_at": file_time.isoformat(),
                "command": [f"cygor", "credrecon", "-o", discovered_dir],
            }
            return JSONResponse(scan_dict)
        else:
            raise HTTPException(status_code=404, detail="Historic scan not found on disk")
    
    # Regular scan from task manager
    try:
        scan = await credrecon_manager.get_scan(scan_id)
        if scan:
            return JSONResponse(scan.to_dict())
    except:
        pass
    
    raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/api/credrecon/scans/{scan_id}/output")
async def get_credrecon_scan_output(scan_id: str):
    """Get the output of a specific credential scanner scan."""
    # Handle historic scans (from disk discovery) - try to load output from files
    if scan_id.startswith("historic-"):
        short_id = scan_id.replace("historic-", "")
        
        # Find the directory matching this short_id
        historic_dir = None
        for results_dir in [
            Path("credrecon") / "credrecon-tasks",  # New structure
            Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks",  # New structure with RESULTS_DIR
            Path("credrecon-tasks"),  # Old structure (backward compatibility)
            Path(settings.RESULTS_DIR) / "credrecon-tasks",  # Old structure with RESULTS_DIR (backward compatibility)
            Path("credrecon"),  # Legacy structure
            Path(settings.RESULTS_DIR) / "credrecon",  # Legacy structure
        ]:
            if results_dir.exists():
                for json_file in results_dir.rglob("credrecon_results.json"):
                    parent_dir = json_file.parent.name
                    if parent_dir.startswith("credrecon-") and short_id in parent_dir:
                        historic_dir = json_file.parent
                        break
                if historic_dir:
                    break
        
        if historic_dir:
            # Try to find output files (stdout, stderr, or log files)
            output_text = ""
            error_text = ""
            
            # Look for common output file names
            output_files = [
                historic_dir / "output.txt",
                historic_dir / "stdout.txt",
                historic_dir / "log.txt",
                historic_dir / "credrecon.log",
            ]
            
            for output_file in output_files:
                if output_file.exists():
                    try:
                        output_text = output_file.read_text()
                        break
                    except:
                        pass
            
            # Look for error files
            error_files = [
                historic_dir / "errors.txt",
                historic_dir / "stderr.txt",
            ]
            
            for error_file in error_files:
                if error_file.exists():
                    try:
                        error_text = error_file.read_text()
                        break
                    except:
                        pass
            
            # If no output files found, create a summary from the JSON results
            if not output_text:
                json_file = historic_dir / "credrecon_results.json"
                if json_file.exists():
                    try:
                        import json
                        results = json.loads(json_file.read_text())
                        if isinstance(results, list):
                            output_text = f"Historic scan results loaded from disk.\n"
                            output_text += f"Total results: {len(results)}\n"
                            output_text += f"Successful: {len([r for r in results if r.get('status') == 'success'])}\n"
                            output_text += f"Failed: {len([r for r in results if r.get('status') == 'failed'])}\n"
                            output_text += f"Errors: {len([r for r in results if r.get('status') == 'error'])}\n"
                            
                            # Add detailed results summary
                            output_text += f"\n--- Detailed Results ---\n"
                            for i, result in enumerate(results[:20], 1):  # Show first 20 results
                                target = result.get('ip') or result.get('target', 'N/A')
                                port = result.get('port', 'N/A')
                                protocol = result.get('protocol', 'N/A')
                                username = result.get('username', 'N/A')
                                status = result.get('status', 'N/A')
                                reason = result.get('details') or result.get('reason', 'N/A')
                                output_text += f"{i}. {target}:{port} ({protocol}) - {username} - {status} - {reason}\n"
                            if len(results) > 20:
                                output_text += f"\n... and {len(results) - 20} more results (see Results tab for full details)\n"
                    except Exception as e:
                        output_text = f"Historic scan discovered from disk. Results are available in the Results tab.\nError loading details: {str(e)}"
                else:
                    output_text = "Historic scan discovered from disk. Results are available in the Results tab."
            
            # Convert strings to arrays of lines (as expected by the frontend)
            output_lines = output_text.split('\n') if output_text else []
            error_lines = error_text.split('\n') if error_text else []
            
            # Remove empty last line if present
            if output_lines and output_lines[-1] == '':
                output_lines = output_lines[:-1]
            if error_lines and error_lines[-1] == '':
                error_lines = error_lines[:-1]
            
            return JSONResponse({
                "output": output_lines,
                "errors": error_lines
            })
        else:
            return JSONResponse({
                "output": ["Historic scan discovered from disk. Results are available in the Results tab."],
                "errors": []
            })
    
    # Regular scan from task manager
    output = await credrecon_manager.get_scan_output(scan_id)
    if "error" in output:
        raise HTTPException(status_code=404, detail=output["error"])
    return JSONResponse(output)

@app.get("/api/credrecon/scans/{scan_id}/results")
async def get_credrecon_scan_results(scan_id: str, session: AsyncSession = Depends(get_session)):
    """Get parsed credential test results from database or local JSON file."""
    from sqlalchemy import select
    from cygor.webapp.models import CredReconScan, CredReconResult

    try:
        # First, try to get scan from task manager (in case it's not in DB yet)
        scan_from_manager = None
        try:
            scan_from_manager = await credrecon_manager.get_scan(scan_id)
        except:
            pass  # Scan not in task manager, will check database
        
        # Get the scan from database - explicitly select columns that exist (excluding output_dir)
        statement = (
            select(
                CredReconScan.id,
                CredReconScan.scan_id,
                CredReconScan.created_at,
                CredReconScan.started_at,
                CredReconScan.completed_at,
                CredReconScan.status,
                CredReconScan.command,
                CredReconScan.num_targets
            )
            .where(CredReconScan.scan_id == scan_id)
        )
        result = await session.execute(statement)
        scan_row = result.first()

        # If not in database, try to create a mock scan_row from task manager data or discovered scan
        if not scan_row:
            if scan_from_manager:
                # Create a simple object that mimics scan_row structure
                class MockScanRow:
                    def __init__(self, scan):
                        self.id = None  # No DB ID since not in DB
                        self.scan_id = scan.scan_id
                        self.created_at = scan.created_at.isoformat() if scan.created_at else None
                        self.started_at = scan.started_at.isoformat() if scan.started_at else None
                        self.completed_at = scan.completed_at.isoformat() if scan.completed_at else None
                        self.status = scan.status.value
                        self.command = " ".join(scan.command) if scan.command else ""
                        self.num_targets = scan.num_targets
                
                scan_row = MockScanRow(scan_from_manager)
            elif scan_id.startswith("historic-"):
                # Handle historic scans (from disk discovery)
                # Format: historic-{short_id}
                short_id = scan_id.replace("historic-", "")
                
                # Find the directory matching this short_id
                discovered_json_file = None
                discovered_dir = None
                
                for results_dir in [
                    Path("credrecon-tasks"),
                    Path(settings.RESULTS_DIR) / "credrecon-tasks",
                    Path("credrecon"),
                    Path(settings.RESULTS_DIR) / "credrecon",
                ]:
                    if results_dir.exists():
                        for json_file in results_dir.rglob("credrecon_results.json"):
                            parent_dir = json_file.parent.name
                            if parent_dir.startswith("credrecon-") and short_id in parent_dir:
                                discovered_json_file = json_file
                                discovered_dir = parent_dir
                                break
                        if discovered_json_file:
                            break
                
                if discovered_json_file:
                    # Create a mock scan_row from discovered scan
                    file_mtime = discovered_json_file.stat().st_mtime
                    from datetime import datetime
                    file_time = datetime.fromtimestamp(file_mtime)
                    
                    class DiscoveredScanRow:
                        def __init__(self, scan_id, dir_name, file_time):
                            self.id = None
                            self.scan_id = scan_id
                            self.created_at = file_time.isoformat()
                            self.started_at = file_time.isoformat()
                            self.completed_at = file_time.isoformat()
                            self.status = "completed"
                            self.command = f"cygor credrecon -o {dir_name}"
                            self.num_targets = 0
                    
                    scan_row = DiscoveredScanRow(scan_id, discovered_dir, file_time)
                else:
                    raise HTTPException(status_code=404, detail="Historic scan not found on disk")
            else:
                raise HTTPException(status_code=404, detail="Scan not found")

        # Get all results for this scan from database (only if scan has a DB ID)
        db_results = []
        if scan_row.id is not None:
            try:
                statement = select(CredReconResult).where(CredReconResult.scan_id == scan_row.id)
                result = await session.execute(statement)
                db_results = result.scalars().all()
            except Exception as e:
                print(f"Error fetching results from database: {e}", file=sys.stderr)
                db_results = []

        # If no database results, try reading from JSON file
        results = []
        if db_results:
            results = db_results
        else:
            # Try to find JSON file by reconstructing output directory from created_at timestamp
            # Output dir format: credrecon/YYYY-MM-DD_HH-MM-SS/credrecon_results.json
            import json
            from datetime import datetime
            
            json_file = None
            
            # Method 1: Try to reconstruct path from scan_id and created_at timestamp
            # New format: credrecon/credrecon-tasks/credrecon-taskid-timestamp/credrecon_results.json
            # Old format: credrecon-tasks/credrecon-taskid-timestamp/credrecon_results.json (backward compatibility)
            if scan_id:
                try:
                    # Handle historic scans specially
                    if scan_id.startswith("historic-"):
                        short_scan_id = scan_id.replace("historic-", "")
                    else:
                        short_scan_id = scan_id[:8]
                    
                    # Try new format first - search for directories containing the scan_id
                    base_dirs = [
                        Path("credrecon") / "credrecon-tasks",  # New structure
                        Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks",  # New structure with RESULTS_DIR
                        Path("credrecon-tasks"),  # Old structure (backward compatibility)
                        Path(settings.RESULTS_DIR) / "credrecon-tasks",  # Old structure with RESULTS_DIR (backward compatibility)
                    ]
                    
                    for base_dir in base_dirs:
                        if base_dir.exists():
                            # Search for directories that contain the short scan_id
                            for task_dir in base_dir.iterdir():
                                if task_dir.is_dir() and short_scan_id in task_dir.name:
                                    potential_json = task_dir / "credrecon_results.json"
                                    if potential_json.exists():
                                        json_file = potential_json
                                        break
                            if json_file:
                                break
                    
                    # If still not found and we have created_at, try with timestamp
                    if not json_file and scan_row.created_at:
                        try:
                            created_dt = datetime.fromisoformat(scan_row.created_at.replace('Z', '+00:00'))
                            timestamp = created_dt.strftime("%Y%m%d_%H%M%S")
                            new_format_paths = [
                                Path("credrecon") / "credrecon-tasks" / f"credrecon-{short_scan_id}-{timestamp}" / "credrecon_results.json",  # New structure
                                Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks" / f"credrecon-{short_scan_id}-{timestamp}" / "credrecon_results.json",  # New structure with RESULTS_DIR
                                Path("credrecon-tasks") / f"credrecon-{short_scan_id}-{timestamp}" / "credrecon_results.json",  # Old structure (backward compatibility)
                                Path(settings.RESULTS_DIR) / "credrecon-tasks" / f"credrecon-{short_scan_id}-{timestamp}" / "credrecon_results.json",  # Old structure with RESULTS_DIR (backward compatibility)
                            ]
                            for potential_path in new_format_paths:
                                if potential_path.exists():
                                    json_file = potential_path
                                    break
                        except Exception as e:
                            print(f"Error reconstructing timestamp path: {e}", file=sys.stderr)
                except Exception as e:
                    print(f"Error reconstructing new format path: {e}", file=sys.stderr)
            
            # Method 1b: Try old format paths (for backward compatibility)
            if not json_file and scan_row.created_at:
                try:
                    # Parse the created_at timestamp
                    created_dt = datetime.fromisoformat(scan_row.created_at.replace('Z', '+00:00'))
                    timestamp1 = created_dt.strftime("%Y-%m-%d_%H-%M-%S")  # Old API format
                    timestamp2 = created_dt.strftime("%Y%m%d_%H%M%S")  # resolve_output_dir format
                    
                    # Try various old path combinations
                    potential_paths = [
                        Path("credrecon") / timestamp1 / "credrecon_results.json",  # Relative, old API format
                        Path(settings.RESULTS_DIR) / "credrecon" / timestamp1 / "credrecon_results.json",  # RESULTS_DIR, old API format
                        Path("credrecon") / timestamp1 / timestamp2 / "credrecon_results.json",  # Nested with resolve_output_dir
                        Path(settings.RESULTS_DIR) / "credrecon" / timestamp1 / timestamp2 / "credrecon_results.json",  # RESULTS_DIR nested
                        Path("credrecon") / timestamp2 / "credrecon_results.json",  # Direct resolve_output_dir format
                        Path(settings.RESULTS_DIR) / "credrecon" / timestamp2 / "credrecon_results.json",  # RESULTS_DIR, resolve format
                    ]
                    
                    for potential_path in potential_paths:
                        if potential_path.exists():
                            json_file = potential_path
                            break
                except Exception as e:
                    print(f"Error parsing timestamp: {e}", file=sys.stderr)
            
            # Method 2: Search for JSON files in credrecon directories and match by timestamp or scan_id
            if not json_file:
                # Try multiple base directories (both old and new structure, for backward compatibility)
                base_dirs = [
                    Path("credrecon") / "credrecon-tasks",  # New structure
                    Path(settings.RESULTS_DIR) / "credrecon" / "credrecon-tasks",  # New structure with RESULTS_DIR
                    Path("credrecon-tasks"),  # Old structure (backward compatibility)
                    Path(settings.RESULTS_DIR) / "credrecon-tasks",  # Old structure with RESULTS_DIR (backward compatibility)
                    Path(settings.RESULTS_DIR) / "credrecon",  # Legacy structure
                    Path("credrecon"),  # Legacy structure
                    Path(settings.RESULTS_DIR),  # Fallback
                ]
                
                for base_dir in base_dirs:
                    if not base_dir.exists():
                        continue
                    
                    # Search all credrecon_results.json files
                    for json_path in base_dir.rglob("credrecon_results.json"):
                        try:
                            # First, check if the directory name contains the scan_id
                            parent_dir = json_path.parent.name
                            if scan_id and scan_id[:8] in parent_dir:
                                json_file = json_path
                                break
                            
                            # Otherwise, check if file was created around the same time as the scan
                            file_mtime = datetime.fromtimestamp(json_path.stat().st_mtime)
                            if scan_row.created_at:
                                try:
                                    scan_time = datetime.fromisoformat(scan_row.created_at.replace('Z', '+00:00'))
                                    # If file was created within 10 minutes of scan creation, it's likely the right one
                                    time_diff = abs((file_mtime - scan_time.replace(tzinfo=None)).total_seconds())
                                    if time_diff < 600:  # 10 minutes (more generous)
                                        json_file = json_path
                                        break
                                except:
                                    pass
                        except Exception:
                            continue
                    
                    if json_file:
                        break
            
            # Read JSON file if found
            if json_file and json_file.exists():
                try:
                    file_results = json.loads(json_file.read_text())
                    if not isinstance(file_results, list):
                        file_results = []
                    
                    # Convert file results to match database format
                    class FileResult:
                        def __init__(self, data):
                            self.target = data.get('ip', data.get('target', ''))
                            self.port = data.get('port', 0)
                            self.protocol = data.get('protocol', '')
                            self.service = data.get('service')
                            self.username = data.get('username', '')
                            self.password = data.get('password')
                            self.status = data.get('status', '')
                            self.reason = data.get('details', data.get('reason'))
                            self.tested_at = data.get('timestamp')
                    
                    results = [FileResult(r) for r in file_results]
                except Exception as e:
                    print(f"Error reading JSON results from {json_file}: {e}", file=sys.stderr)
                    results = []
            else:
                results = []

        # Group results by status
        successful = [r for r in results if r.status == "success"]
        failed = [r for r in results if r.status == "failed"]
        errors = [r for r in results if r.status == "error"]
        skipped = [r for r in results if r.status == "skipped"]

        # Convert to dicts
        return JSONResponse({
            "scan_id": scan_id,
            "total": len(results),
            "successful": len(successful),
            "failed": len(failed),
            "errors": len(errors),
            "skipped": len(skipped),
            "results": {
                "successful": [
                    {
                        "target": r.target,
                        "port": r.port,
                        "protocol": r.protocol,
                        "service": r.service,
                        "username": r.username,
                        "password": r.password,
                        "reason": r.reason,
                        "tested_at": r.tested_at
                    }
                    for r in successful
                ],
                "failed": [
                    {
                        "target": r.target,
                        "port": r.port,
                        "protocol": r.protocol,
                        "service": r.service,
                        "username": r.username,
                        "password": r.password,
                        "reason": r.reason,
                        "tested_at": r.tested_at
                    }
                    for r in failed
                ],
                "errors": [
                    {
                        "target": r.target,
                        "port": r.port,
                        "protocol": r.protocol,
                        "service": r.service,
                        "username": r.username,
                        "password": r.password,
                        "reason": r.reason,
                        "tested_at": r.tested_at
                    }
                    for r in errors
                ],
                "skipped": [
                    {
                        "target": r.target,
                        "port": r.port,
                        "protocol": r.protocol,
                        "service": r.service,
                        "username": r.username,
                        "password": r.password,
                        "reason": r.reason,
                        "tested_at": r.tested_at
                    }
                    for r in skipped
                ]
            }
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error fetching results: {str(e)}")

@app.delete("/api/credrecon/scans/{scan_id}")
async def cancel_credrecon_scan(scan_id: str):
    """Cancel a running credential scanner scan."""
    success = await credrecon_manager.cancel_scan(scan_id)
    if not success:
        raise HTTPException(status_code=404, detail="Scan not found or cannot be cancelled")
    return JSONResponse({"status": "cancelled"})

@app.get("/api/tasks")
async def list_tasks():
    """List all tasks."""
    tasks = await task_manager.list_tasks()
    return JSONResponse(tasks)

@app.get("/api/ondemand-scans")
async def list_ondemand_scans():
    """List on-demand scan history from results/ondemand-scans directory."""
    try:
        ondemand_scans = gather_ondemand_scan_times(settings.RESULTS_DIR)
        return JSONResponse(ondemand_scans)
    except Exception as e:
        return JSONResponse({"error": str(e), "scans": []}, status_code=500)

@app.get("/api/tasks/{task_id}")
async def get_task_status(task_id: str):
    """Get status of a specific task."""
    task = await task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return JSONResponse(task.to_dict())

@app.get("/api/tasks/{task_id}/output")
async def get_task_output(task_id: str):
    """Get output of a specific task."""
    task = await task_manager.get_task(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    return JSONResponse({
        "task_id": task_id,
        "status": task.status.value,
        "output": task.output_lines,
        "errors": task.error_lines,
    })

@app.post("/api/tasks/{task_id}/cancel")
async def cancel_task(task_id: str):
    """Cancel a running task."""
    success = await task_manager.cancel_task(task_id)
    if not success:
        raise HTTPException(status_code=400, detail="Cannot cancel task (not running or not found)")
    return JSONResponse({"status": "cancelled"})

@app.delete("/api/tasks/{task_id}")
async def delete_task(task_id: str):
    """Delete a task."""
    success = await task_manager.delete_task(task_id)
    if not success:
        raise HTTPException(status_code=400, detail="Cannot delete task (running or not found)")
    return JSONResponse({"status": "deleted"})

class SyncRequest(BaseModel):
    scan_dir: Optional[str] = None  # Optional specific directory to sync (e.g., ondemand-scans/2025-01-06_12-34-56)

@app.post("/api/sync-database")
async def sync_database(req: Optional[SyncRequest] = None):
    """
    Sync database by ingesting scan results.

    If scan_dir is provided, only syncs that specific directory (fast, for on-demand scans).
    Otherwise, syncs the entire results directory (slower, for full refresh).
    """
    base_dir = os.environ.get("CYGOR_LOAD_DIR") or settings.RESULTS_DIR

    # Determine which directory to sync
    if req and req.scan_dir:
        # Sync only the specific scan directory (relative to base_dir)
        load_dir = Path(base_dir) / req.scan_dir
        if not load_dir.exists():
            return JSONResponse({
                "status": "error",
                "error": f"Scan directory not found: {load_dir}"
            }, status_code=404)
        print(f"[*] Fast sync: ingesting only {req.scan_dir}")
    else:
        # Full sync of entire results directory
        load_dir = Path(base_dir)
        print(f"[*] Full database sync started from: {load_dir}")

    try:
        # Count hosts and ports before sync
        async with db.SessionLocal() as session:
            from sqlalchemy import func, select
            hosts_before = await session.scalar(select(func.count(Host.id))) or 0
            ports_before = await session.scalar(select(func.count(Port.id))) or 0

        print(f"[i] Database state before sync: {hosts_before} hosts, {ports_before} ports")

        # Run ingestion with verbose output
        async with db.SessionLocal() as session:
            count = await ingest_directory(load_dir, session, dedupe=True, verbose=1)
            await session.commit()

        print(f"[✓] Ingested {count} file(s)")

        # Count hosts and ports after sync
        async with db.SessionLocal() as session:
            hosts_after = await session.scalar(select(func.count(Host.id))) or 0
            ports_after = await session.scalar(select(func.count(Port.id))) or 0

        hosts_added = hosts_after - hosts_before
        ports_added = ports_after - ports_before

        print(f"[✓] Database state after sync: {hosts_after} hosts (+{hosts_added}), {ports_after} ports (+{ports_added})")

        # Create sync result object
        sync_result = {
            "status": "success",
            "ingested_files": count,
            "directory": str(load_dir),
            "hosts_before": hosts_before,
            "hosts_after": hosts_after,
            "hosts_added": hosts_added,
            "ports_before": ports_before,
            "ports_after": ports_after,
            "ports_added": ports_added,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

        # Add to sync history (keep last 50 syncs)
        SYNC_HISTORY.insert(0, sync_result)
        if len(SYNC_HISTORY) > 50:
            SYNC_HISTORY.pop()

        return JSONResponse(sync_result)
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        print(f"[!] Sync error: {error_details}")
        return JSONResponse({
            "status": "error",
            "error": str(e),
            "details": error_details
        }, status_code=500)

# -------- Entrypoint --------
def exec_argv(argv):
    import uvicorn
    parser = argparse.ArgumentParser(description="Run the Cygor Web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reset-db", action="store_true")
    parser.add_argument("--load-dir", type=str, help="Results directory or database file to load")
    parser.add_argument("--cleanup-db",action="store_true",help="Drop the PostgreSQL database and user after shutdown (default: keep data)")
    parser.add_argument("-v", "--verbose", action="count", default=0,help="Increase verbosity (-v shows more, -vv shows debug details)")
    parser.add_argument("-y", "--yes",action="store_true",help="Automatic yes to cleanup prompts (for non-interactive or CI mode)")
    args = parser.parse_args(argv)

    # Resolve results dir early (for banner + env)
    load_path = Path(args.load_dir or settings.RESULTS_DIR).expanduser().resolve()
    if not load_path.exists():
        print(f"[!] Specified results directory does not exist: {load_path}")
        return

    # Persist into env so the FastAPI lifespan can read them
    settings.RESULTS_DIR = str(load_path)
    os.environ["CYGOR_LOAD_DIR"] = settings.RESULTS_DIR
    os.environ["CYGOR_RESULTS_DIR"] = settings.RESULTS_DIR  # For credrecon and other modules
    os.environ["CYGOR_VERBOSE"] = str(args.verbose)
    if args.reset_db:
        os.environ["CYGOR_RESET_DB"] = "1"

    # Decide which DB we’ll use, but DO NOT create/connect here.
    database_url = db.get_default_database_url()
    if args.cleanup_db:
        print("[!] Database cleanup ENABLED — database and role will be deleted on exit.")
    else:
        print("[*] Database cleanup disabled — data will persist after shutdown.")
    # export CLI options to env
    os.environ["CYGOR_CLEANUP_DB"] = "1" if args.cleanup_db else "0"
    os.environ["CYGOR_YES"] = "1" if args.yes else "0"
    os.environ["CYGOR_DB_URL"] = database_url  # lifespan() will init the engine with this
    

    # Friendly banner
    print("[*] Initializing Cygor Web UI...")
    print(f"[*] Results directory: {load_path}")
    print(f"[*] Using database: {database_url}")

    # Run uvicorn — engine/schema are handled inside FastAPI lifespan on THIS loop.
    uvicorn.run(
        "cygor.webapp.main:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="debug" if args.verbose > 1 else "info",
        access_log=args.verbose > 1,  # Only show access logs in debug mode
    )


if __name__ == "__main__":
    import sys
    exec_argv(sys.argv[1:])