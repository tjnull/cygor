from contextlib import asynccontextmanager
import os, argparse, asyncio, pathlib, pkgutil
from pathlib import Path
from fastapi import FastAPI, Request, UploadFile, Depends, Query
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from collections import namedtuple
from .config import settings
from .db import init_db, get_session, reset_db, SessionLocal
from .models import Host, Port, Script, OSGuess
from .ingest import ingest_file, ingest_directory


RESULTS_SCREENSHOTS = Path(settings.RESULTS_DIR) / "web" / "screenshots"
NMAP_RESULTS_DIR = Path(settings.RESULTS_DIR) / "nmap"
templates = Jinja2Templates(directory="cygor/webapp/templates")

# --------- Enumeration module discovery (file-system based) ---------
MODULES_DIR = Path(__file__).resolve().parent.parent / "modules"

def discover_modules() -> list[str]:
    """Return a sorted list of module names found under cygor/modules."""
    if MODULES_DIR.exists():
        return sorted(
            name
            for _, name, ispkg in pkgutil.iter_modules([str(MODULES_DIR)])
            if not ispkg and not name.startswith("_")
        )
    return []


# -------------------------
# Service name normalization
# -------------------------
SERVICE_NAME_MAP = {
    "domain": "dns",
    "kerberos-sec": "kerberos",
    "ldapssl": "ldaps",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "ms-wbt-server": "rdp",
    "epmap": "dcom",

    # Web
    "http-alt": "http",
    "ssl/http": "https",
    "https-alt": "https",
    "http-proxy": "proxy",
    "ajp13": "ajp",
    "ajp12": "ajp",

    # Databases
    "ms-sql-s": "mssql",
    "ms-sql-m": "mssql",
    "mysqlx": "mysql",
    "postgresql": "postgres",
    "oracle-tns": "oracle",
    "redis": "redis",

    # Mail
    "smtp-submission": "smtp",
    "submission": "smtp",
    "pop3s": "pop3",
    "imaps": "imap",

    # Remote management
    "vnc": "vnc",
    "pcanywheredata": "pcanywhere",
    "rpcbind": "rpc",

    # Misc
    "ipp": "cups",
    "upnp": "upnp",
    "mdns": "mdns",
    "snmptrap": "snmp",
    "snmp": "snmp",
}

def normalize_service(name: str | None) -> str:
    if not name:
        return "unknown"
    return SERVICE_NAME_MAP.get(name.lower(), name.lower())

# -------------------------
# OS Guess Helpers
# -------------------------
def _bucket_family(guess: "OSGuess") -> str:
    txt = " ".join([
        (guess.name or ""),
        (guess.family or ""),
        (guess.vendor or ""),
        (guess.type or "")
    ]).lower()

    if "windows" in txt or "microsoft" in txt:
        return "Windows"
    if "linux" in txt:
        return "Linux"
    if "android" in txt:
        return "Android"
    if "mac os" in txt or "macos" in txt or "apple" in txt or "os x" in txt:
        return "macOS"
    if any(x in txt for x in ["freebsd", "openbsd", "netbsd", "solaris", "unix"]):
        return "BSD/Unix"
    if any(x in txt for x in ["router", "switch", "ubiquiti", "cisco", "juniper", "embedded", "network device"]):
        return "Network Device"
    if any(x in txt for x in ["vmware", "oracle vm", "virtualbox", "hyper-v", "qemu", "xen"]):
        return "Virtualization/Hypervisor"
    if any(x in txt for x in ["ios", "ipad", "iphone"]):
        return "iOS"
    if any(x in txt for x in ["printer", "copier", "hp laserjet", "xerox", "ricoh"]):
        return "Printer/Peripheral"
    if any(x in txt for x in ["specialized", "appliance", "control system", "crestron", "scada"]):
        return "Specialized Device"
    return "Other"

def _top_guess(host: "Host"):
    if not host.os_guesses:
        return None
    return sorted(host.os_guesses, key=lambda g: (-int(g.accuracy or 0), len(g.name or "")))[0]

# Namedtuple for top OS guesses
TopItem = namedtuple("TopItem", ["host", "guess"])

# -------------------------
# App Lifespan
# -------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    load_dir = os.environ.get("CYGOR_LOAD_DIR")
    if load_dir:
        print(f"[*] Background preload from {load_dir} ...")
        async def _bg():
            async with SessionLocal() as session:
                await ingest_directory(Path(load_dir), session, dedupe=True)
            print("[✓] Background preload complete.")
        asyncio.create_task(_bg())
    yield

app = FastAPI(lifespan=lifespan)

# Make modules available on every request (auto-detect new files)
@app.middleware("http")
async def add_modules_to_request(request: Request, call_next):
    # Scan on every request so new modules are picked up without restarts
    request.state.modules = discover_modules()
    response = await call_next(request)
    return response


# Mount Lockon screenshots explicitly
lockon_shots = Path(settings.RESULTS_DIR) / "cygor-enumeration-modules" / "lockon" / "screenshots"
if lockon_shots.exists():
    print(f"[*] Mounting Lockon screenshots from: {lockon_shots}")
    app.mount("/enum/lockon/screenshots", StaticFiles(directory=str(lockon_shots)), name="lockon_screens")
else:
    print(f"[!] Lockon screenshots directory not found: {lockon_shots}")



if RESULTS_SCREENSHOTS.exists():
    app.mount("/screenshots", StaticFiles(directory=str(RESULTS_SCREENSHOTS)), name="screenshots")

# ---------- Lockon helpers ----------
def _find_lockon_paths():
    base = Path(settings.RESULTS_DIR)
    candidates = [
        base / "cygor-enumeration-modules" / "lockon",
        base / "web",  # legacy fallback
    ]
    chosen = None
    for c in candidates:
        if c.exists():
            chosen = c
            break
    if not chosen:
        return None, None, None
    urls_file = chosen / "tested-urls.txt"
    shots_dir = chosen / "screenshots"
    return chosen, urls_file if urls_file.exists() else None, shots_dir if shots_dir.exists() else None

def _screenshot_name_for_url(url: str) -> str:
    # Mirror Lockon's naming convention
    return url.replace("://", "_").replace("/", "_") + ".png"

# ---------- Routes: Enumeration ----------
@app.get("/enum", response_class=HTMLResponse)
async def enum_index(request: Request):
    # simple landing page for enumeration (optional)
    return templates.TemplateResponse("enum_index.html", {
        "request": request
    })

@app.get("/enum/lockon", response_class=HTMLResponse)
async def enum_lockon(request: Request):
    _, urls_file, shots_dir = _find_lockon_paths()

    items = []
    has_shots = shots_dir is not None

    # Prefer JSON results (they contain status_code + metadata)
    json_file = urls_file.with_name("lockon-results.json") if urls_file else None
    if json_file and json_file.exists():
        import json
        try:
            data = json.loads(json_file.read_text(encoding="utf-8", errors="ignore"))
            for entry in data:
                url = entry.get("url")
                if not url:
                    continue
                code = entry.get("status_code")
                screenshot_file = entry.get("screenshot_file")
                failed = entry.get("screenshot_failed", False)

                items.append({
                    "url": url,
                    "status_code": code,
                    "screenshot_file": screenshot_file,
                    "screenshot_failed": failed,
                })
        except Exception as e:
            print(f"[!] Failed to parse lockon-results.json: {e}")

    # Fallback to tested-urls.txt if JSON missing
    elif urls_file and urls_file.exists():
        content = urls_file.read_text(encoding="utf-8", errors="ignore")
        urls = [ln.strip() for ln in content.splitlines() if ln.strip()]
        for u in urls:
            shot_name = _screenshot_name_for_url(u)
            items.append({
                "url": u,
                "status_code": None,
                "screenshot_file": shot_name if has_shots else None,
                "screenshot_failed": False,
            })

    return templates.TemplateResponse("module_lockon.html", {
        "request": request,
        "items": items,
        "has_shots": has_shots,
        "has_urls": bool(items),
    })


@app.get("/enum/smbexplorer", response_class=HTMLResponse)
async def enum_smbexplorer(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    import json

    base = Path(settings.RESULTS_DIR) / "cygor-enumeration-modules" / "smbexplorer"
    rows, file_rows = [], []

    if base.exists():
        for f in base.glob("*.json"):
            try:
                data = json.loads(f.read_text())
                if "smb_results" in f.name:   # distinguish results vs files
                    rows.extend(data)
                elif "smb_files" in f.name:
                    file_rows.extend(data)
            except Exception:
                continue

    # Deduplicate share rows by (ip, share)
    seen = set()
    deduped_rows = []
    for r in rows:
        key = (r.get("IP Address") or r.get("ip"), r.get("Share") or r.get("share"))
        if key not in seen:
            seen.add(key)
            # Normalize keys for Jinja (snake_case)
            deduped_rows.append({
                "ip": r.get("IP Address") or r.get("ip"),
                "share": r.get("Share") or r.get("share"),
                "status": r.get("Status") or r.get("status"),
                "smb_version": r.get("SMB Version") or r.get("smb_version"),
                "permissions": r.get("Permissions") or r.get("permissions"),
                "information": r.get("Information") or r.get("information"),
            })

    # Normalize file rows
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

    # Count hosts with port 445 open (from DB)
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
                data = json.loads(f.read_text())
                rows.extend(data)
            except Exception:
                continue

    # Count unique hosts with NFS entries
    hosts_with_nfs = len({r.get("ip") for r in rows if r.get("ip")})

    return templates.TemplateResponse("module_nfsexplorer.html", {
        "request": request,
        "rows": rows,
        "hosts_with_nfs": hosts_with_nfs
    })


# -------------------------
# Routes
# -------------------------
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: AsyncSession = Depends(get_session)):
    hosts = (await session.execute(
        select(Host).options(selectinload(Host.ports),
                             selectinload(Host.scripts),
                             selectinload(Host.os_guesses))
    )).scalars().unique().all()

    buckets = {
        "Windows": 0, "Linux": 0, "macOS": 0, "BSD/Unix": 0,
        "Android": 0, "iOS": 0, "Network Device": 0,
        "Virtualization/Hypervisor": 0, "Printer/Peripheral": 0,
        "Specialized Device": 0, "Other": 0, "Unknown": 0
    }

    top_items = []
    for h in hosts:
        tg = _top_guess(h)
        if tg:
            buckets[_bucket_family(tg)] += 1
            top_items.append(TopItem(host=h, guess=tg))  # 🔹 use namedtuple
        else:
            buckets["Unknown"] += 1

    top_items = sorted(top_items, key=lambda x: -int(x.guess.accuracy or 0))[:10]

    # ---- build service summary ----
    ports = (await session.execute(
        select(Port).options(selectinload(Port.host))
    )).scalars().unique().all()
    service_counts = {}
    for p in ports:
        svc = normalize_service(p.service)
        service_counts.setdefault(svc, set()).add(p.host.address)

    service_summary = {svc: len(hosts) for svc, hosts in service_counts.items()}
    sorted_services = dict(sorted(service_summary.items(), key=lambda x: -x[1]))

    return templates.TemplateResponse("index.html", {
        "request": request,
        "hosts_total": len(hosts),
        "hosts_scanned": len([h for h in hosts if h.ports]),
        "hosts_enum": len([h for h in hosts if h.scripts]),
        "os_summary": {
            "counts": buckets,
            "top_items": top_items
        },
        "service_summary": sorted_services
    })

@app.get("/hosts", response_class=HTMLResponse)
async def hosts_view(request: Request, os: str | None = None, session: AsyncSession = Depends(get_session)):
    hosts = (await session.execute(
        select(Host).options(
            selectinload(Host.ports),
            selectinload(Host.scripts),
            selectinload(Host.os_guesses)
        )
    )).scalars().unique().all()

    top_map = {h.id: _top_guess(h) for h in hosts}

    if os:
        hosts = [h for h in hosts if _top_guess(h) and _bucket_family(_top_guess(h)) == os]

    return templates.TemplateResponse("hosts.html", {
        "request": request,
        "hosts": hosts,
        "top_os_map": top_map,
        "filter_os": os
    })

@app.get("/hosts/{host_id}", response_class=HTMLResponse)
async def host_detail(host_id: int, request: Request, session: AsyncSession = Depends(get_session)):
    h = await session.get(
        Host,
        host_id,
        options=[selectinload(Host.ports),
                 selectinload(Host.scripts),
                 selectinload(Host.os_guesses)]
    )
    if not h:
        return RedirectResponse("/hosts", status_code=302)
    await session.refresh(h)

    # Screenshots
    screenshots = []
    for p in h.ports:
        for scheme in ("http", "https"):
            fname = f"{scheme}_{h.address.replace(':','_')}_{p.port}.png"
            if RESULTS_SCREENSHOTS.joinpath(fname).exists():
                screenshots.append(fname)

    # Outputs
    nmap_output = xml_output = gnmap_output = None
    search_dir = Path(settings.RESULTS_DIR)

    for f in search_dir.rglob("*"):
        if f.is_file():
            if f.name == f"{h.address}.nmap" and not nmap_output:
                nmap_output = f.read_text(errors="ignore")
            elif f.name == f"{h.address}.xml" and not xml_output:
                xml_output = f.read_text(errors="ignore")
            elif f.name == f"{h.address}.gnmap" and not gnmap_output:
                gnmap_output = f.read_text(errors="ignore")

    if not (nmap_output and xml_output and gnmap_output):
        for f in search_dir.rglob("*"):
            if f.is_file():
                if f.suffix.lower() == ".nmap" and not nmap_output:
                    text = f.read_text(errors="ignore")
                    if h.address in text:
                        nmap_output = text
                elif f.suffix.lower() == ".xml" and not xml_output:
                    text = f.read_text(errors="ignore")
                    if h.address in text:
                        xml_output = text
                elif f.suffix.lower() == ".gnmap" and not gnmap_output:
                    text = f.read_text(errors="ignore")
                    if h.address in text:
                        gnmap_output = text

    return templates.TemplateResponse("host_detail.html", {
        "request": request,
        "h": h,
        "screenshots": screenshots,
        "os_guesses": sorted(h.os_guesses, key=lambda g: -int(g.accuracy or 0)),
        "nmap_output": nmap_output,
        "xml_output": xml_output,
        "gnmap_output": gnmap_output
    })

@app.get("/services", response_class=HTMLResponse)
async def services_view(request: Request, session: AsyncSession = Depends(get_session)):
    ports = (await session.execute(
        select(Port).options(selectinload(Port.host), selectinload(Port.scripts))
    )).scalars().unique().all()

    service_counts = {}
    for p in ports:
        svc = normalize_service(p.service)
        service_counts.setdefault(svc, set()).add(p.host.address)

    service_summary = {svc: len(hosts) for svc, hosts in service_counts.items()}
    total_hosts = len({p.host.address for p in ports})

    return templates.TemplateResponse("services.html", {
        "request": request,
        "ports": ports,
        "service_summary": service_summary,
        "total_hosts": total_hosts
    })

@app.get("/services/{service_name}", response_class=HTMLResponse)
async def service_detail(service_name: str, request: Request, session: AsyncSession = Depends(get_session)):
    raw_key = service_name.lower()
    display_name = normalize_service(raw_key)

    ports = (await session.execute(
        select(Port)
        .options(selectinload(Port.host))
    )).scalars().unique().all()

    host_services = []
    seen_hosts = set()
    for p in ports:
        svc_norm = normalize_service(p.service)
        if svc_norm == display_name:
            if p.host.id not in seen_hosts:
                host_services.append({
                    "host": p.host,
                    "ports": [p]
                })
                seen_hosts.add(p.host.id)
            else:
                for entry in host_services:
                    if entry["host"].id == p.host.id:
                        entry["ports"].append(p)
                        break

    total_hosts = len({p.host.address for p in ports})

    if not host_services:
        return HTMLResponse(
            f"<div style='padding:2rem; text-align:center; color:#bbb;'>"
            f"No hosts found running <strong>{display_name}</strong>"
            f"</div>",
            status_code=404
        )

    return templates.TemplateResponse("service_detail.html", {
        "request": request,
        "service": display_name,
        "host_services": host_services,
        "total_hosts": total_hosts
    })

@app.get("/search", response_class=HTMLResponse)
async def search(request: Request, q: str = Query("", description="Search query"),
                 session: AsyncSession = Depends(get_session)):
    q = (q or "").strip()
    hosts = ports = scripts = []
    if q:
        hosts = (await session.execute(
            select(Host).where((Host.address.contains(q)) | (Host.hostname.contains(q)))
        )).scalars().all()
        ports = (await session.execute(
            select(Port).where((Port.service.contains(q)) | (Port.banner.contains(q)))
        )).scalars().all()
        scripts = (await session.execute(
            select(Script).where(Script.output.contains(q))
        )).scalars().all()

    return templates.TemplateResponse("search.html", {
        "request": request, "query": q, "hosts": hosts, "ports": ports, "scripts": scripts
    })

def exec_argv(argv):
    parser = argparse.ArgumentParser(description="Run the Cygor Web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--reset-db", action="store_true",
                        help="Drop and recreate the database, then exit")
    parser.add_argument("--load-dir", type=str,
                        help="Path to results directory to preload (background)")
    args = parser.parse_args(argv)

    if args.reset_db:
       print("[*] Resetting database...")
       asyncio.run(reset_db())
       print("[✓] Database reset complete.")
       return

    if args.load_dir:
        load_path = Path(args.load_dir)
        if not load_path.exists() or not any(load_path.rglob("*.xml")):
            print(f"[!] Load directory '{load_path}' does not exist or contains no XML files — skipping ingestion.")
        else:
            os.environ["CYGOR_LOAD_DIR"] = str(load_path)



    import uvicorn
    uvicorn.run("cygor.webapp.main:app", host=args.host, port=args.port, reload=False)
