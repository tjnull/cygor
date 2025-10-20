from contextlib import asynccontextmanager
from datetime import datetime, timezone
import os, argparse, asyncio, pkgutil, shutil, json, re, gzip, uvicorn
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
from ..module_loader import discover_modules, resolve_legacy_context
from .ingest import ingest_directory
from .config import settings

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
    # Background Ingestion
    # -------------------------
    load_dir = os.environ.get("CYGOR_LOAD_DIR")
    verbose = int(os.environ.get("CYGOR_VERBOSE", "0"))
    if load_dir:
        print(f"[*] Background preload from {load_dir} scheduled...")

        async def _preload():
            await asyncio.sleep(1.0)
            try:
                async with db.SessionLocal() as session:
                    count = await ingest_directory(Path(load_dir), session, dedupe=True, verbose=verbose)
                    await session.commit()
                print(f"[✓] Finished ingesting {count} file(s) from {load_dir}")
            except Exception as e:
                print(f"[!] Background preload error: {e}")

        @app.on_event("startup")
        async def _kickoff_preload():
            asyncio.create_task(_preload())

    # -------------------------
    # Yield to FastAPI
    # -------------------------
    try:
        yield
    finally:
        # -------------------------
        #  Clean shutdown
        # -------------------------
        try:
            if db.engine:
                print("[*] Disposing database engine...")
                await db.engine.dispose()
                print("[✓] Database engine disposed cleanly.")
        except Exception as e:
            print(f"[!] Error during engine disposal: {e}")




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
    import uvicorn
    parser = argparse.ArgumentParser(description="Run the Cygor Web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reset-db", action="store_true")
    parser.add_argument("--load-dir", type=str, help="Results directory or database file to load")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity (-v shows more, -vv shows debug details)")
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