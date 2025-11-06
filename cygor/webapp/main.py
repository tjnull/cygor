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
from typing import List, Optional
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


templates = None  # will be initialized in lifespan
DISCOVERED_MODULES = []  # filled during startup

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
        print("[DEBUG] Module loader: using default modules path from module_loader")
        DISCOVERED_MODULES = discover_modules()
        _register_module_routes(app, templates_dir, settings.RESULTS_DIR)

        print(f"[✓] Registered {len(DISCOVERED_MODULES)} dynamic module routes: {[m.slug for m in DISCOVERED_MODULES]}")
    except Exception as e:
        print(f"[!] Error during module discovery: {e}")
    
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

@app.get("/tasks/{task_id}", response_class=HTMLResponse)
async def task_detail_page(request: Request, task_id: str):
    """Task detail page with live output."""
    return templates.TemplateResponse("task_detail.html", {"request": request, "task_id": task_id})

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
        output_dir=output_dir
    )

    return JSONResponse({"task_id": task_id, "status": "created"})

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

        return JSONResponse({
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
        })
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
    )


if __name__ == "__main__":
    import sys
    exec_argv(sys.argv[1:])