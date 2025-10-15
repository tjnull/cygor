from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from .models import Host
from libnmap.parser import NmapParser
import xml.etree.ElementTree as ET
import json

from . import db
from .db import (
    get_or_create_host,
    get_or_create_port,
    get_or_create_script,
    get_or_create_osguess,
)

# ---------------------------------------------------
# Logging Helper
# ---------------------------------------------------
def log(msg: str, level: int = 1, verbose: int = 0):
    """
    level=0 -> always (errors)
    level=1 -> summary
    level=2 -> detailed (only with -v / -vv)
    """
    if level == 0 or verbose >= level:
        print(msg)


# ---------------------------------------------------
# Directory Walker
# ---------------------------------------------------
async def ingest_directory(path, session, dedupe=True, verbose=0):
    """
    Walk a directory and ingest all supported files.
    """
    log(f"[*] Ingesting files from {path}", level=1, verbose=verbose)

    ingested_count = 0
    failed_files = []

    for file in path.rglob("*"):
        if not file.is_file():
            continue

        try:
            if file.suffix.lower() in [".xml", ".json"]:
                log(f"[*] Processing file: {file}", level=2, verbose=verbose)
                await ingest_file(file, session, dedupe=dedupe, verbose=verbose)
                ingested_count += 1
            else:
                log(f"[i] Skipping unsupported file format: {file}", level=2, verbose=verbose)
        except Exception as e:
            log(f"[!] Failed to ingest {file}: {e}", level=0, verbose=verbose)
            failed_files.append(file)

    log(f"[✓] Finished ingesting {ingested_count} files from {path}", level=1, verbose=verbose)

    if failed_files:
        log(f"[!] {len(failed_files)} files failed ingestion. See errors above.", level=0, verbose=verbose)

    return ingested_count


# ---------------------------------------------------
# Generic JSON Fallback
# ---------------------------------------------------
def flatten_entry(entry: dict) -> str:
    parts = []
    for k, v in entry.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v)
        parts.append(f"{k}={v}")
    return ", ".join(parts)


async def ingest_generic_json(file: Path, session: AsyncSession, data, module_hint: str, verbose: int = 0):
    log(f"[i] Generic JSON ingestion for {file}", level=2, verbose=verbose)
    module_name = module_hint or file.stem.split("_")[0] or "generic_json"

    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        entries = (
            data.get("results")
            or data.get("shares")
            or data.get("files")
            or [data]
        )
    else:
        log(f"[i] Unsupported JSON shape in {file}", level=2, verbose=verbose)
        return

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        ip = entry.get("ip") or entry.get("target") or entry.get("host")
        db_host = await get_or_create_host(session, ip or module_name)

        output = flatten_entry(entry)
        await get_or_create_script(session, db_host, None, module_name, output)

    await session.commit()
    log(f"[+] Ingested {module_name} JSON: {file.name}", level=1, verbose=verbose)


# ---------------------------------------------------
# Ingestion Core
# ---------------------------------------------------
async def ingest_file(file: Path, session: AsyncSession, dedupe: bool = True, verbose: int = 0):
    log(f"[*] Processing file: {file}", level=2, verbose=verbose)
    if not file.exists():
        log(f"[!] File not found: {file}", level=0, verbose=verbose)
        return

    # ---------------------------------------------------
    # Handle Nmap XML
    # ---------------------------------------------------
    if file.suffix.lower() == ".xml":
        log(f"[i] XML detected, parsing {file}", level=2, verbose=verbose)
        try:
            root = ET.parse(file).getroot()
        except Exception as e:
            log(f"[!] Failed to read XML {file}: {e}", level=0, verbose=verbose)
            return

        if root.tag != "nmaprun":
            log(f"[i] Skipping non-Nmap XML file: {file} (root={root.tag})", level=2, verbose=verbose)
            return

        try:
            nmap_report = NmapParser.parse_fromfile(str(file))
        except Exception as e:
            log(f"[!] Failed to parse {file} with NmapParser: {e}", level=0, verbose=verbose)
            return

        for host in nmap_report.hosts:
            if not host.is_up():
                continue

            hostname = host.hostnames[0] if getattr(host, "hostnames", None) else None
            db_host = await get_or_create_host(session, host.address, hostname=hostname)

            # --- OS Guesses (top match only) ---
            try:
                if getattr(host, "os", None) and getattr(host.os, "osmatches", []):
                    top_guess = sorted(
                        host.os.osmatches,
                        key=lambda g: int(getattr(g, "accuracy", 0)),
                        reverse=True,
                    )[0]

                    guess_name = getattr(top_guess, "name", None)
                    accuracy = getattr(top_guess, "accuracy", 0)
                    osclass = top_guess.osclasses[0] if top_guess.osclasses else None
                    family = getattr(osclass, "osfamily", None) if osclass else None
                    vendor = getattr(osclass, "vendor", None) if osclass else None
                    type_ = getattr(osclass, "type", None) if osclass else None

                    await get_or_create_osguess(
                        session,
                        db_host,
                        name=guess_name,
                        accuracy=int(accuracy or 0),
                        family=family,
                        vendor=vendor,
                        type=type_,
                    )
            except Exception as e:
                log(f"[!] Failed to ingest OS guesses for {host.address}: {e}", level=0, verbose=verbose)

            # --- Ports & Scripts ---
            for service in host.services:
                if service.state != "open":
                    continue

                db_port = await get_or_create_port(
                    session,
                    db_host,
                    service.port,
                    service=getattr(service, "service", None) or None,
                    protocol=getattr(service, "protocol", None) or None,
                    banner=getattr(service, "banner", None) or None,
                )

                scripts = getattr(service, "scripts_results", {})
                items = scripts.items() if hasattr(scripts, "items") else [
                    (s.get("id"), s.get("output", "")) for s in scripts or []
                ]
                for sid, out in items:
                    if not sid:
                        continue
                    await get_or_create_script(session, db_host, db_port, sid, out or "")

        await session.commit()
        log(f"[+] Ingested {file.name}", level=1, verbose=verbose)
        return

    # ---------------------------------------------------
    # Handle JSON Modules
    # ---------------------------------------------------
    if file.suffix.lower() == ".json":
        module_hint = (file.parent.name or "").lower()
        fname = file.name.lower()

        log(f"[i] JSON detected, module hint: {module_hint}, filename: {fname}", level=2, verbose=verbose)

        try:
            raw = file.read_text(errors="ignore")
            if not raw.strip():
                log(f"[i] Empty JSON file: {file}", level=2, verbose=verbose)
                return
            data = json.loads(raw)
        except Exception as e:
            log(f"[!] Failed to parse JSON {file}: {e}", level=0, verbose=verbose)
            return

        # ---------- LOCKON ----------
        if module_hint == "lockon" or (
            isinstance(data, list) and any(isinstance(x, dict) and "url" in x for x in data)
        ) or (isinstance(data, dict) and "results" in data):
            from urllib.parse import urlparse
            entries = data if isinstance(data, list) else data.get("results", [])
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                url = entry.get("url")
                if not url:
                    continue
                try:
                    host = (urlparse(url).hostname) or url
                except Exception:
                    host = url

                res = await session.execute(select(Host).where(Host.address == host))
                db_host = res.scalar_one_or_none()
                if not db_host:
                    log(f"[i] Skipping Lockon result for {host} (not in Nmap/Masscan data)", level=2, verbose=verbose)
                    continue

                parts = [f"URL: {url}"]
                status_code = entry.get("status_code") or entry.get("status")
                if status_code is not None:
                    parts.append(f"Status: {status_code}")

                screenshot_file = entry.get("screenshot_file")
                if screenshot_file:
                    parts.append(f"Screenshot: {screenshot_file}")

                failed = entry.get("screenshot_failed", True)
                parts.append(f"Failed: {bool(failed)}")

                await get_or_create_script(
                    session,
                    db_host,
                    None,
                    "lockon",
                    ", ".join(parts),
                    status_code=status_code,
                    screenshot_file=screenshot_file,
                    screenshot_failed=entry.get("screenshot_failed", True),
                    url=url,
                )

            await session.commit()
            log(f"[+] Ingested lockon JSON: {file.name}", level=1, verbose=verbose)
            return

        # ---------- SMBEXPLORER ----------
        elif module_hint == "smbexplorer" or fname.startswith("smb_"):
            entries = []
            if isinstance(data, list):
                entries = data
            elif isinstance(data, dict):
                entries = data.get("shares") or data.get("files") or data.get("results") or []

            for entry in entries:
                if not isinstance(entry, dict):
                    continue

                ip = entry.get("ip") or data.get("ip") or entry.get("server")
                if not ip:
                    continue

                res = await session.execute(select(Host).where(Host.address == ip))
                db_host = res.scalar_one_or_none()
                if not db_host:
                    log(f"[i] Skipping SMBExplorer result for {ip} (not in Nmap/Masscan data)", level=2, verbose=verbose)
                    continue

                share = entry.get("share") or entry.get("name") or entry.get("path")
                perms = entry.get("permissions")
                info = entry.get("info") or entry.get("comment")

                parts = []
                if share: parts.append(f"Share: {share}")
                if perms: parts.append(f"Permissions: {perms}")
                if info:  parts.append(f"Info: {info}")

                await get_or_create_script(session, db_host, None, "smbexplorer", ", ".join(parts))

            await session.commit()
            log(f"[+] Ingested smbexplorer JSON: {file.name}", level=1, verbose=verbose)
            return

        # ---------- NFSEXPLORER ----------
        elif module_hint == "nfsexplorer" or fname.startswith("nfsexplorer_"):
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                ip = entry.get("ip")
                if not ip:
                    continue

                res = await session.execute(select(Host).where(Host.address == ip))
                db_host = res.scalar_one_or_none()
                if not db_host:
                    log(f"[i] Skipping NFSExplorer result for {ip} (not in Nmap/Masscan data)", level=2, verbose=verbose)
                    continue

                share = entry.get("share")
                name = entry.get("name")
                perms = entry.get("permissions")

                parts = []
                if share: parts.append(f"Share: {share}")
                if name:  parts.append(f"Name: {name}")
                if perms: parts.append(f"Permissions: {perms}")

                await get_or_create_script(session, db_host, None, "nfsexplorer", ", ".join(parts))

            await session.commit()
            log(f"[+] Ingested nfsexplorer JSON: {file.name}", level=1, verbose=verbose)
            return

        # ---------- GENERIC JSON FALLBACK ----------
        else:
            await ingest_generic_json(file, session, data, module_hint, verbose=verbose)
            return


# ---------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------
if __name__ == "__main__":
    import argparse, asyncio

    parser = argparse.ArgumentParser(description="Manually ingest a results directory")
    parser.add_argument("directory", type=str, help="Path to results directory")
    parser.add_argument("--db", type=str, default="results/cygor.db",
                        help="SQLite database path (default: results/cygor.db)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity (-v shows more, -vv shows debug details)")
    args = parser.parse_args()

    db_path = Path(args.db).expanduser().resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_url = f"sqlite+aiosqlite:///{db_path}"

    print(f"[*] Using database {db_path}")
    db.init_engine(db_url, debug=True)

    async def _main():
        async with db.SessionLocal() as session:
            await db.init_db()
            await ingest_directory(Path(args.directory), session, dedupe=True, verbose=args.verbose)

    asyncio.run(_main())
