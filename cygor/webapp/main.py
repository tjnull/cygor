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

from . import db
from .db import get_session, reset_db
from .models import Host, Port, Script, OSGuess
from .ingest import ingest_directory
from .config import settings

# -------- Templates --------
templates = Jinja2Templates(directory="cygor/webapp/templates")

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

# -------- Lifespan --------
# -------- Lifespan --------
@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_db()
    print("[✓] Database schema ensured.")

    base = Path(settings.RESULTS_DIR)
    lockon_shots = base / "cygor-enumeration-modules" / "lockon" / "screenshots"
    if lockon_shots.exists():
        print(f"[*] Mounting Lockon screenshots from: {lockon_shots}")
        app.mount("/enum/lockon/screenshots", StaticFiles(directory=str(lockon_shots)), name="lockon_screens")
    else:
        print(f"[!] Lockon screenshots directory not found: {lockon_shots}")

    results_shots = base / "web" / "screenshots"
    if results_shots.exists():
        app.mount("/screenshots", StaticFiles(directory=str(results_shots)), name="screenshots")

    # removed background preload (no double ingestion)
    yield


app = FastAPI(lifespan=lifespan)

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
async def hosts_view(request: Request, session: AsyncSession = Depends(get_session)):
    hosts = (await session.execute(
        select(Host).options(
            selectinload(Host.ports),
            selectinload(Host.scripts),
            selectinload(Host.os_guesses)
        )
    )).scalars().unique().all()
    top_map = {h.id: _top_guess(h) for h in hosts}
    return templates.TemplateResponse("hosts.html", {"request": request, "hosts": hosts, "top_os_map": top_map})

@app.get("/services", response_class=HTMLResponse)
async def services_view(request: Request, session: AsyncSession = Depends(get_session)):
    ports = (await session.execute(
        select(Port).options(selectinload(Port.host))
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
                sf = find_screenshot_file(host, port)
                screenshot_url = f"/enum/lockon/screenshots/{sf}" if sf else None
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
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity (-v shows more, -vv shows debug details)")
    args = parser.parse_args(argv)

    if args.load_dir:
        load_path = Path(args.load_dir).expanduser().resolve()
        if not load_path.exists():
            print(f"[!] Specified results directory does not exist: {load_path}")
            return
        if load_path.is_file():
            if load_path.suffix != ".db":
                print(f"[!] Invalid database file: {load_path}")
                return
            db_path = load_path
            load_path = load_path.parent
        else:
            db_path = load_path / "cygor.db"
            if not db_path.exists():
                print(f"[*] No database found in {load_path}, creating {db_path} ...")

        settings.RESULTS_DIR = str(load_path)
        os.environ["CYGOR_LOAD_DIR"] = settings.RESULTS_DIR
    else:
        load_path = Path(settings.RESULTS_DIR).expanduser().resolve()
        if not load_path.exists() or not load_path.is_dir():
            print(f"[!] Default results directory not found: {load_path}")
            return
        db_path = load_path / "cygor.db"

    print(f"[*] Using results directory: {settings.RESULTS_DIR}")
    print(f"[*] Using database at {db_path}")

    db.init_engine(str(db_path), debug=False)
    asyncio.run(db.init_db())

    if args.reset_db:
        print("[*] Resetting database...")
        asyncio.run(db.reset_db())
        print("[✓] Database reset complete.")
        return

    async def _initial_ingest():
        async with db.SessionLocal() as session:
            count = await ingest_directory(load_path, session, dedupe=True, verbose=args.verbose)
            return count

    count = asyncio.run(_initial_ingest())
    if count == 0:
        if db_path.exists():
            db_path.unlink(missing_ok=True)
            print(f"[!] No results ingested, removed empty database {db_path}")
        if load_path.exists() and load_path.is_dir() and not any(load_path.iterdir()):
            try:
                shutil.rmtree(load_path)
                print(f"[!] Removed empty results directory {load_path}")
            except Exception as e:
                print(f"[!] Failed to remove empty directory {load_path}: {e}")
        print("[!] Aborting web startup — no results available.")
        return
    else:
        print(f"[✓] Finished ingesting {count} files from {load_path}")


    import uvicorn
    uvicorn.run("cygor.webapp.main:app", host=args.host, port=args.port, reload=False)

if __name__ == "__main__":
    import sys
    exec_argv(sys.argv[1:])
