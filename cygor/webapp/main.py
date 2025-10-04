from contextlib import asynccontextmanager
import os, argparse, asyncio, pkgutil, shutil
from pathlib import Path
from fastapi import FastAPI, Request, Depends, Query
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
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
    hosts = (await session.execute(
        select(Host).options(
            selectinload(Host.ports),
            selectinload(Host.scripts),
            selectinload(Host.os_guesses)
        )
    )).scalars().unique().all()

    buckets = {k:0 for k in [
        "Windows","Linux","macOS","BSD/Unix","Android","iOS",
        "Network Device","Virtualization/Hypervisor","Printer/Peripheral",
        "Specialized Device","Other","Unknown"
    ]}

    top_items = []
    for h in hosts:
        tg = _top_guess(h)
        if tg:
            buckets[_bucket_family(tg)] += 1
            top_items.append(TopItem(host=h, guess=tg))
        else:
            buckets["Unknown"] += 1

    ports = (await session.execute(select(Port).options(selectinload(Port.host)))).scalars().unique().all()
    service_counts = {}
    for p in ports:
        svc = normalize_service(p.service)
        service_counts.setdefault(svc, set()).add(p.host.address)
    service_summary = {svc: len(hosts) for svc, hosts in service_counts.items()}

    hosts_total = len(hosts)
    hosts_scanned = sum(1 for h in hosts if h.ports)
    hosts_enum = sum(1 for h in hosts if h.scripts)
    hosts_unscanned = hosts_total - hosts_scanned

    return templates.TemplateResponse("index.html", {
        "request": request,
        "hosts_total": hosts_total,
        "hosts_scanned": hosts_scanned,
        "hosts_enum": hosts_enum,
        "hosts_unscanned": hosts_unscanned,
        "os_summary": {"counts": buckets, "top_items": top_items},
        "service_summary": dict(sorted(service_summary.items(), key=lambda x: -x[1]))
    })

@app.get("/hosts", response_class=HTMLResponse)
async def hosts_view(
    request: Request,
    os: str = Query(None, description="Filter by OS family"),
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

    # Apply filter only if ?os= is passed
    if os:
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
    else:
        hosts = all_hosts

    return templates.TemplateResponse(
        "hosts.html",
        {
            "request": request,
            "hosts": hosts,
            "top_os_map": top_map,
            "filter_os": os
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


