from contextlib import asynccontextmanager
from datetime import datetime, timezone
import os, argparse, asyncio, pkgutil, shutil, json, re
import xml.etree.ElementTree as ET
from pathlib import Path
from fastapi import FastAPI, Request, Depends, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, exists
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from collections import namedtuple
from importlib.resources import files  

from . import db
from .db import get_session, reset_db
from .models import Host, Port, Script, OSGuess
from .ingest import ingest_directory
from .config import settings

templates = None  # will be initialized in lifespan


# --------- Module Discovery ---------
MODULES_DIR = Path(__file__).resolve().parent.parent / "modules"

def discover_modules() -> list[str]:
    if MODULES_DIR.exists():
        return sorted(
            name
            for _, name, ispkg in pkgutil.iter_modules([str(MODULES_DIR)])
            if not ispkg and not name.startswith("_")
        )
    return []

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
    Read an nmap XML file and return (start_iso, end_iso, host_count).
    - start_iso and end_iso are ISO8601 strings in UTC (or None)
    - host_count is integer (from runstats/hosts up attribute or <host> count fallback)
    This function is defensive against namespaces and slightly different XML layouts,
    and will fall back to searching the raw file text for a 'scan initiated' comment.
    """
    try:
        # read raw text (gzip-safe)
        raw_text = None
        try:
            if path.suffix.lower().endswith('.gz'):
                with gzip.open(path, 'rt', errors='ignore') as fh:
                    raw_text = fh.read()
            else:
                raw_text = path.read_text(errors='ignore')
        except Exception:
            # fallback to binary read
            try:
                raw_text = path.read_bytes().decode('utf-8', errors='ignore')
            except Exception:
                raw_text = ''

        # Parse XML tree (ElementTree) if possible
        tree = None
        try:
            # ET can parse from a file-like or path string
            tree = ET.parse(path)
        except Exception:
            # If the file is gzipped or ET.parse failed, try parsing from raw_text
            try:
                tree = ET.ElementTree(ET.fromstring(raw_text))
            except Exception:
                tree = None

        root = tree.getroot() if tree is not None else None

        # helper: find element ignoring namespace by suffix match
        def _find_tag_suffix(root_el, suffix):
            if root_el is None:
                return None
            # check root itself
            if isinstance(root_el.tag, str) and root_el.tag.endswith(suffix):
                return root_el
            # walk tree
            for el in root_el.iter():
                if isinstance(el.tag, str) and el.tag.endswith(suffix):
                    return el
            return None

        # nmaprun: either root or a child; be resilient
        nmaprun_el = _find_tag_suffix(root, 'nmaprun') if root is not None else None

        # runstats/finished: find finished element
        finished_el = _find_tag_suffix(root, 'finished') if root is not None else None

        # hosts element under runstats or elsewhere
        hosts_el = _find_tag_suffix(root, 'hosts') if root is not None else None

        # Attempt to read attributes
        start_iso = None
        end_iso = None
        host_count = 1

        # 1) start attribute (epoch) on nmaprun
        if nmaprun_el is not None:
            start_attr = nmaprun_el.attrib.get('start')
            startstr_attr = nmaprun_el.attrib.get('startstr')
        else:
            start_attr = None
            startstr_attr = None

        # prefer epoch 'start' attribute
        if start_attr:
            try:
                start_dt = datetime.fromtimestamp(int(start_attr), tz=timezone.utc)
                start_iso = start_dt.isoformat()
            except Exception:
                start_iso = None

        # try startstr if epoch not available
        if start_iso is None and startstr_attr:
            try:
                # common format: "Wed Oct 15 00:26:26 2025"
                start_dt = datetime.strptime(startstr_attr, "%a %b %d %H:%M:%S %Y")
                # treat as UTC to keep consistent (nmap start epoch is authoritative when present)
                start_dt = start_dt.replace(tzinfo=timezone.utc)
                start_iso = start_dt.isoformat()
            except Exception:
                # try iso format parse
                try:
                    start_dt = datetime.fromisoformat(startstr_attr)
                    if start_dt.tzinfo is None:
                        start_dt = start_dt.replace(tzinfo=timezone.utc)
                    start_iso = start_dt.isoformat()
                except Exception:
                    start_iso = None

        # 2) finished time from runstats/finished
        if finished_el is not None:
            finished_time = finished_el.attrib.get('time')
            finished_timestr = finished_el.attrib.get('timestr') or finished_el.attrib.get('timestr')  # conservative
            if finished_time:
                try:
                    if str(finished_time).isdigit():
                        end_dt = datetime.fromtimestamp(int(finished_time), tz=timezone.utc)
                    else:
                        # try ISO-like parse
                        end_dt = datetime.fromisoformat(finished_time)
                        if end_dt.tzinfo is None:
                            end_dt = end_dt.replace(tzinfo=timezone.utc)
                    end_iso = end_dt.isoformat()
                except Exception:
                    end_iso = None
            if end_iso is None and finished_timestr:
                try:
                    end_dt = datetime.strptime(finished_timestr, "%a %b %d %H:%M:%S %Y")
                    end_dt = end_dt.replace(tzinfo=timezone.utc)
                    end_iso = end_dt.isoformat()
                except Exception:
                    try:
                        end_dt = datetime.fromisoformat(finished_timestr)
                        if end_dt.tzinfo is None:
                            end_dt = end_dt.replace(tzinfo=timezone.utc)
                        end_iso = end_dt.isoformat()
                    except Exception:
                        end_iso = None

        # 3) host_count: prefer runstats/hosts @up, else count <host> elements
        if hosts_el is not None and 'up' in hosts_el.attrib:
            try:
                hc = int(hosts_el.attrib.get('up') or 0)
                if hc > 0:
                    host_count = hc
            except Exception:
                host_count = host_count

        # fallback: count host elements if runstats didn't provide up
        if host_count == 1:
            try:
                # look for any <host> occurrences (namespace-tolerant)
                if tree is not None:
                    host_nodes = [el for el in root.iter() if isinstance(el.tag, str) and el.tag.endswith('host')]
                    if host_nodes:
                        host_count = max(1, len(host_nodes))
            except Exception:
                host_count = host_count

        # 4) If we still don't have a start time, attempt to extract from the raw comment line:
        #    e.g. "<!-- Nmap 7.95 scan initiated Wed Oct 15 00:26:26 2025 as: /usr/lib/nmap/nmap ... -->"
        if start_iso is None and raw_text:
            try:
                # case-insensitive search for 'scan initiated ... as:'
                m = re.search(r"scan initiated\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+as:", raw_text, re.I)
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
                            start_iso = None
            except Exception:
                pass

        return start_iso, end_iso, host_count
    except Exception:
        # fail closed: return None for times but default host_count=1
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



# ---------------- Lifespan ----------------
async def lifespan(app: FastAPI):
    global templates
    templates_dir = files("cygor.webapp") / "templates"
    static_dir = files("cygor.webapp") / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")
    else:
        print(f"[!] Static directory not found: {static_dir}")


    templates = Jinja2Templates(directory=str(templates_dir))
    

    await db.init_db()
    load_dir = os.environ.get("CYGOR_LOAD_DIR")

    # Mount Lockon screenshots *after* RESULTS_DIR is known
    lockon_dir = Path(settings.RESULTS_DIR) / "cygor-enumeration-modules" / "lockon" / "screenshots"
    if lockon_dir.exists():
        app.mount(
            "/enum/lockon/screenshots",
            StaticFiles(directory=str(lockon_dir)),
            name="lockon_screenshots"
        )
        print(f"[*] Mounting Lockon screenshots from: {lockon_dir}")
    else:
        print(f"[!] Lockon screenshots directory not found: {lockon_dir}")

    if load_dir:
        print(f"[*] Background preload from {load_dir} ...")
        async def _bg():
            async with db.SessionLocal() as session:
                await ingest_directory(Path(load_dir), session, dedupe=True)
            print("[✓] Background preload complete.")
        asyncio.create_task(_bg())

    yield



app = FastAPI(lifespan=lifespan)
# Mount static assets




@app.middleware("http")
async def add_modules_to_request(request: Request, call_next):
    request.state.modules = discover_modules()
    return await call_next(request)

# -------- ROUTES --------
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: AsyncSession = Depends(get_session)):
    # ----- Accurate tile counts (deduplicated by address) -----
    try:
        hosts_total = await session.scalar(
            select(func.count(func.distinct(Host.address))).select_from(Host)
        )
    except Exception:
        # fallback to row-count if anything goes wrong
        hosts_total = await session.scalar(select(func.count(Host.id)))

    try:
        hosts_scanned = await session.scalar(
            select(func.count(func.distinct(Host.address)))
            .select_from(Host)
            .where(
                exists().where(Port.host_id == Host.id)
                | exists().where(Script.host_id == Host.id)
                | exists().where(OSGuess.host_id == Host.id)
            )
        )
    except Exception:
        # fallback to previous behavior
        scanned_ids_q = (
            select(Host.id)
            .where(
                exists().where(Port.host_id == Host.id)
                | exists().where(Script.host_id == Host.id)
                | exists().where(OSGuess.host_id == Host.id)
            )
        )
        hosts_scanned = await session.scalar(select(func.count()).select_from(scanned_ids_q.subquery()))

    # If you removed "Enumerated", comment the line below & adjust donut in index.html
    hosts_enum = 0  # <- set 0 if you dropped the enumerated tile

    # clamps & defaulting
    hosts_total = (hosts_total or 0)
    hosts_scanned = min((hosts_scanned or 0), hosts_total)
    hosts_enum = min(hosts_enum or 0, hosts_scanned)

    # Donut parts (choose 2-slice or 3-slice depending on whether you keep enumerated)
    not_scanned = max(hosts_total - hosts_scanned, 0)
    scanned_only = max(hosts_scanned - hosts_enum, 0)  # only used if you still display enumerated

    # ----- Build OS + Services summaries (ALWAYS provide these) -----
    hosts = (
        await session.execute(
            select(Host).options(
                selectinload(Host.ports),
                selectinload(Host.scripts),
                selectinload(Host.os_guesses),
            )
        )
    ).scalars().unique().all()

    # OS buckets
    buckets = {
        k: 0
        for k in [
            "Windows", "Linux", "macOS", "BSD/Unix", "Android", "iOS",
            "Network Device", "Virtualization/Hypervisor", "Printer/Peripheral",
            "Specialized Device", "Other", "Unknown",
        ]
    }

    top_items = []
    for h in hosts:
        tg = _top_guess(h)  # your helper already in main.py
        if tg:
            buckets[_bucket_family(tg)] += 1  # your helper already in main.py
            top_items.append(TopItem(host=h, guess=tg))
        else:
            buckets["Unknown"] += 1

    # Services summary = unique host count per normalized service
    ports = (await session.execute(select(Port).options(selectinload(Port.host)))).scalars().unique().all()
    service_counts = {}
    for p in ports:
        svc = normalize_service(p.service)  # your helper already in main.py
        service_counts.setdefault(svc, set()).add(p.host.address)
    service_summary = {svc: len(hosts_set) for svc, hosts_set in service_counts.items()}
    service_summary = dict(sorted(service_summary.items(), key=lambda x: -x[1]))

    # ----- Scan timeline data -----
    try:
        scan_times = gather_scan_times(settings.RESULTS_DIR)
    except Exception:
        scan_times = []

    # Build IP → ID lookup so the JS can link dots to /hosts/<id>
    ip_to_id = {h.address: h.id for h in hosts}

    for entry in scan_times:
        key = extract_host_key(entry.get("label") or entry.get("path"))
        if key in ip_to_id:
            entry["host_id"] = ip_to_id[key]
        else:
            entry["host_id"] = None


    # ----- Render -----
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "hosts_total": hosts_total,
            "hosts_scanned": hosts_scanned,
            "hosts_enum": hosts_enum,       # keep if you still show that tile; else remove in template
            "not_scanned": not_scanned,
            "scanned_only": scanned_only,   # only used if you still show enumerated/3-slice donut
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
    session: AsyncSession = Depends(get_session)
):
    # Always fetch all hosts + related data
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

    return templates.TemplateResponse(
        "hosts.html",
        {
            "request": request,
            "hosts": hosts,
            "top_os_map": top_map,
            "filter_os": os,
            "filter_ip": ip,
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


# Service detail page (click-through from services.html)
@app.get("/services/{service}", response_class=HTMLResponse)
async def service_detail(
    request: Request,
    service: str,
    session: AsyncSession = Depends(get_session)
):
    ports = (await session.execute(
        select(Port).options(selectinload(Port.host))
    )).scalars().unique().all()

    normalized_service = normalize_service(service)
    host_services = []
    for p in ports:
        if normalize_service(p.service) == normalized_service:
            host_services.append({"host": p.host, "ports": [p]})

    total_hosts = len({p.host.address for p in ports})

    return templates.TemplateResponse(
        "service_detail.html",
        {
            "request": request,
            "service": service,
            "host_services": host_services,
            "total_hosts": total_hosts
        }
    )


@app.get("/enum/lockon", response_class=HTMLResponse)
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
                screenshot_url = f"/enum/lockon/screenshots/{sf}" if sf and (shots_dir / sf).exists() else None
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
            screenshot_url = f"/enum/lockon/screenshots/{sf}" if sf else None
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

@app.get("/enum/smbexplorer", response_class=HTMLResponse)
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

@app.get("/enum/nfsexplorer", response_class=HTMLResponse)
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
async def search(request: Request, q: str = Query("", description="Search query"), session: AsyncSession = Depends(get_session)):
    q = (q or "").strip()
    hosts = ports = scripts = []
    if q:
        hosts = (await session.execute(select(Host).where((Host.address.contains(q)) | (Host.hostname.contains(q))))).scalars().all()
        ports = (await session.execute(select(Port).where((Port.service.contains(q)) | (Port.banner.contains(q))))).scalars().all()
        scripts = (await session.execute(select(Script).where(Script.output.contains(q)))).scalars().all()
    return templates.TemplateResponse("search.html", {"request": request, "query": q, "hosts": hosts, "ports": ports, "scripts": scripts})

# -------- Entrypoint --------
def exec_argv(argv):
    parser = argparse.ArgumentParser(description="Run the Cygor Web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reset-db", action="store_true")
    parser.add_argument("--load-dir", type=str, help="Results directory or database file to load")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity (-v shows more, -vv shows debug details)")
    args = parser.parse_args(argv)

    load_path = Path(args.load_dir or settings.RESULTS_DIR).expanduser().resolve()
    if not load_path.exists():
        print(f"[!] Specified results directory does not exist: {load_path}")
        return

    db_path = load_path / "cygor.db"
    settings.RESULTS_DIR = str(load_path)
    os.environ["CYGOR_LOAD_DIR"] = settings.RESULTS_DIR

    print(f"[*] Initializing Cygor Web UI...")
    print(f"[*] Results directory: {load_path}")
    print(f"[*] Database file:     {db_path}")

    # init DB engine + schema
    db.init_engine(str(db_path), debug=(args.verbose > 1))
    asyncio.run(db.init_db())   # <-- ensure schema exists

    if args.reset_db:
        print("[*] Resetting database...")
        asyncio.run(db.reset_db())
        print("[✓] Database reset complete.")
        return

    async def _initial_ingest(verbose: int):
        async with db.SessionLocal() as session:
            count = await ingest_directory(load_path, session, dedupe=True, verbose=verbose)
            await session.commit()  # <-- make sure data is written
            return count

    count = asyncio.run(_initial_ingest(args.verbose))
    if args.verbose:
        print(f"[✓] Finished ingesting {count} file(s) from {load_path}")
    else:
        print(f"[✓] Ingested {count} result file(s) from {load_path}")

    # Print banner last
    print("------------------------------------------------------------")
    print(f"Cygor Web UI is running at: http://{args.host}:{args.port}")
    print("Press CTRL+C to stop")
    print("------------------------------------------------------------")

    import uvicorn
    uvicorn.run(
        "cygor.webapp.main:app",
        host=args.host,
        port=args.port,
        reload=False,
        log_level="debug" if args.verbose > 1 else "info"
    )



if __name__ == "__main__":
    import sys
    exec_argv(sys.argv[1:])
