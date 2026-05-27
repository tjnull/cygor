from pathlib import Path
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from .models import Host, Port
from libnmap.parser import NmapParser
import xml.etree.ElementTree as ET
import json
import os
from urllib.parse import urlparse
from datetime import datetime, timezone
from collections import defaultdict
from typing import List, Dict, Any

from . import db

# ---------------------------------------------------
# Fingerprint Summary Collector
# ---------------------------------------------------
class FingerprintCollector:
    """Collects fingerprint results during ingestion for summary display."""

    def __init__(self):
        self.results: List[Dict[str, Any]] = []
        self.os_counts: Dict[str, int] = defaultdict(int)
        self.type_counts: Dict[str, int] = defaultdict(int)
        self.vendor_counts: Dict[str, int] = defaultdict(int)
        self.confidence_buckets = {"high": 0, "medium": 0, "low": 0, "none": 0}

    def add(self, fp_result):
        """Add a fingerprint result to the collector."""
        self.results.append({
            "ip": fp_result.ip_address,
            "os": fp_result.os_full or fp_result.os_name or fp_result.os_family or "Unknown",
            "type": fp_result.device_type or "Unknown",
            "vendor": fp_result.manufacturer or "Unknown",
            "confidence": fp_result.confidence,
        })

        # Track OS families
        os_family = fp_result.os_family or "Unknown"
        self.os_counts[os_family] += 1

        # Track device types
        device_type = fp_result.device_type or "Unknown"
        self.type_counts[device_type] += 1

        # Track vendors
        vendor = fp_result.manufacturer or "Unknown"
        self.vendor_counts[vendor] += 1

        # Track confidence buckets
        conf = fp_result.confidence
        if conf >= 0.8:
            self.confidence_buckets["high"] += 1
        elif conf >= 0.5:
            self.confidence_buckets["medium"] += 1
        elif conf > 0:
            self.confidence_buckets["low"] += 1
        else:
            self.confidence_buckets["none"] += 1

    def print_summary(self, verbose: int = 0):
        """Print a summary of all fingerprint results."""
        if not self.results:
            return
        # Suppress the chatty multi-section breakdown unless the caller
        # explicitly asked for verbose output. Auto-sync after a task and
        # other background ingests pass verbose=0 and don't want this in
        # the server terminal.
        if verbose < 1:
            return

        total = len(self.results)
        print(f"\n[*] Fingerprint Summary ({total} hosts)")
        print("=" * 60)

        # OS breakdown
        if self.os_counts:
            print("\n  OS Families:")
            for os_name, count in sorted(self.os_counts.items(), key=lambda x: -x[1]):
                pct = (count / total) * 100
                print(f"    {os_name:<20} {count:>3} ({pct:>5.1f}%)")

        # Device type breakdown
        if self.type_counts:
            print("\n  Device Types:")
            for dev_type, count in sorted(self.type_counts.items(), key=lambda x: -x[1]):
                pct = (count / total) * 100
                print(f"    {dev_type:<20} {count:>3} ({pct:>5.1f}%)")

        # Vendor breakdown (top 5 only if many)
        if self.vendor_counts:
            print("\n  Vendors:")
            vendors = sorted(self.vendor_counts.items(), key=lambda x: -x[1])
            shown = vendors[:5] if len(vendors) > 5 else vendors
            for vendor, count in shown:
                pct = (count / total) * 100
                # Truncate long vendor names
                vendor_display = vendor[:25] + "..." if len(vendor) > 28 else vendor
                print(f"    {vendor_display:<28} {count:>3} ({pct:>5.1f}%)")
            if len(vendors) > 5:
                others = sum(c for _, c in vendors[5:])
                print(f"    {'(others)':<28} {others:>3}")

        # Confidence breakdown
        print("\n  Confidence:")
        print(f"    High (≥80%):    {self.confidence_buckets['high']:>3}")
        print(f"    Medium (50-79%):{self.confidence_buckets['medium']:>3}")
        print(f"    Low (<50%):     {self.confidence_buckets['low']:>3}")
        print(f"    None (0%):      {self.confidence_buckets['none']:>3}")

        print("=" * 60)


# Global fingerprint collector (reset per ingestion session)
_fingerprint_collector: FingerprintCollector = None

def get_fingerprint_collector() -> FingerprintCollector:
    """Get or create the global fingerprint collector."""
    global _fingerprint_collector
    if _fingerprint_collector is None:
        _fingerprint_collector = FingerprintCollector()
    return _fingerprint_collector

def reset_fingerprint_collector():
    """Reset the fingerprint collector for a new ingestion session."""
    global _fingerprint_collector
    _fingerprint_collector = FingerprintCollector()
from .db import (
    get_or_create_host,
    get_or_create_port,
    get_or_create_script,
    get_or_create_osguess,
    get_or_create_device_info,
    IngestionCache,
    build_ingestion_cache,
    cached_get_or_create_host,
    cached_get_or_create_port,
    cached_get_or_create_script,
    cached_get_or_create_osguess,
    cached_get_or_create_device_info,
)

# ---------------------------------------------------
# File Mtime Tracker (skip unchanged files)
# ---------------------------------------------------
# Stores {file_path_str: mtime_ns} from last successful ingestion.
# Persisted in a JSON sidecar file next to the load directory.
_MTIME_CACHE_FILENAME = ".cygor-ingest-mtimes.json"

def _load_mtime_cache(load_dir: Path) -> dict:
    """Load the mtime cache from disk. Returns {path_str: mtime_ns}."""
    cache_file = load_dir / _MTIME_CACHE_FILENAME
    if cache_file.exists():
        try:
            return json.loads(cache_file.read_text())
        except Exception:
            pass
    return {}

def _save_mtime_cache(load_dir: Path, cache: dict):
    """Persist the mtime cache to disk."""
    cache_file = load_dir / _MTIME_CACHE_FILENAME
    try:
        cache_file.write_text(json.dumps(cache))
    except Exception:
        pass

# ---------------------------------------------------
# Database URL Auto-Detector
# ---------------------------------------------------
def get_default_database_url(fallback_sqlite: str = "results/cygor.db") -> str:
    """
    Determine which database backend to use.
    Priority:
      1. CYGOR_DB_URL (exported by webctl)
      2. PostgreSQL (if pg_isready is reachable)
      3. Fallback to local SQLite file
    """
    env_url = os.getenv("CYGOR_DB_URL")
    if env_url:
        return env_url

    try:
        import subprocess
        subprocess.run(["pg_isready", "-q"], check=True)
        return "postgresql+psycopg_async://cygor:cygorpass@localhost/cygor"
    except Exception:
        pass

    return f"sqlite+aiosqlite:///{fallback_sqlite}"


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
# Directory Walker (Safe Ingestion)
# ---------------------------------------------------
async def ingest_directory(path, session, dedupe=True, verbose=0):
    """
    Walk a directory and ingest only supported scan/module files.
    Skips directories, empty files, and unsupported formats.
    """
    import time
    t0 = time.monotonic()

    # Reset fingerprint collector for this ingestion session
    reset_fingerprint_collector()

    log(f"[*] Ingesting files from {path}", level=1, verbose=verbose)

    # --- Bulk pre-load existing records into memory ---
    # This replaces thousands of individual SELECT queries with 5 bulk queries
    log("[*] Pre-loading existing records into cache...", level=1, verbose=verbose)
    cache = await build_ingestion_cache(session)
    cache_time = time.monotonic() - t0
    log(f"[*] Cache loaded in {cache_time:.1f}s: {len(cache.hosts)} hosts, "
        f"{len(cache.ports)} ports, {len(cache.scripts)} scripts", level=1, verbose=verbose)

    # Create a shared FingerprintLookup for the entire ingestion session
    try:
        from cygor.fingerprinting.lookup import FingerprintLookup
        fp_lookup = FingerprintLookup()
    except ImportError:
        fp_lookup = None

    supported_exts = {".xml", ".json", ".jsonl"}
    ingested_count = 0
    failed_files = []

    # --- Load mtime cache for change detection ---
    load_path = Path(path)
    mtime_cache = _load_mtime_cache(load_path)
    # If the database is empty but the mtime cache has entries, the DB was
    # reset/recreated.  Invalidate the cache so all files get re-ingested.
    if mtime_cache and len(cache.hosts) == 0:
        log("[!] Database is empty but mtime cache exists — forcing full re-ingestion", level=1, verbose=verbose)
        mtime_cache = {}
    # If hosts exist but no DeviceInfo has been fully fingerprinted (no
    # validation_status set), the enhanced fingerprint pipeline was skipped.
    # Clear the mtime cache to force re-processing so fingerprinting runs.
    elif mtime_cache and cache.hosts:
        if not cache.device_info:
            log("[!] Hosts exist but no DeviceInfo records — forcing re-ingestion for fingerprinting", level=1, verbose=verbose)
            mtime_cache = {}
        else:
            has_full_fp = any(
                di.validation_status is not None or di.sources is not None
                for di in cache.device_info.values()
            )
            if not has_full_fp:
                log("[!] No fully fingerprinted hosts found — forcing re-ingestion for fingerprinting", level=1, verbose=verbose)
                mtime_cache = {}
    new_mtime_cache = {}

    # Collect all files first to avoid re-scanning directory during iteration
    all_files = []
    files_to_ingest = []
    skipped_unchanged = 0
    for file in load_path.rglob("*"):
        if not file.is_file():
            continue
        # Skip enrichment outputs -- they're ingested via the enrichment
        # route, not the generic scan-result ingestor. Accept both the new
        # 'enrich/' subdir (current) and the legacy 'enrichment/' name so
        # existing workspaces don't double-ingest after the rename.
        if "enrich" in file.parts or "enrichment" in file.parts:
            continue
        if (file.name.startswith("enrichment-") or
            file.name.startswith("enrich-") or
            "enrichment" in file.name.lower() or
            "enrich" in file.name.lower()):
            continue
        if file.name.startswith(".") or file.name == ".cygor-workspace.json":
            continue
        if file.suffix.lower() not in supported_exts:
            continue
        try:
            stat = file.stat()
            if stat.st_size == 0:
                continue
        except Exception:
            continue

        all_files.append(file)
        file_key = str(file)
        current_mtime = stat.st_mtime_ns

        # Skip files that haven't changed since last ingestion
        if file_key in mtime_cache and mtime_cache[file_key] == current_mtime:
            new_mtime_cache[file_key] = current_mtime
            skipped_unchanged += 1
            continue

        new_mtime_cache[file_key] = current_mtime
        files_to_ingest.append(file)

    log(f"[*] Found {len(all_files)} files ({skipped_unchanged} unchanged, {len(files_to_ingest)} to process)", level=1, verbose=verbose)

    for file in files_to_ingest:
        try:
            log(f"[*] Processing file: {file}", level=2, verbose=verbose)
            await ingest_file(file, session, dedupe=dedupe, verbose=verbose,
                              fp_lookup=fp_lookup, cache=cache)
            await session.flush()
            ingested_count += 1
            # Commit every 50 files to release DB locks and reduce memory
            if ingested_count % 50 == 0:
                await session.commit()
        except Exception as e:
            log(f"[!] Failed to ingest {file}: {e}", level=0, verbose=verbose)
            failed_files.append(file)
            # Remove mtime entry so this file is retried on next startup
            new_mtime_cache.pop(str(file), None)
            try:
                await session.rollback()
                # Rebuild cache after rollback since session state is lost
                cache = await build_ingestion_cache(session)
            except Exception:
                pass

    # Final commit for remaining changes
    await session.commit()

    # Persist mtime cache so unchanged files are skipped on next startup
    _save_mtime_cache(load_path, new_mtime_cache)

    elapsed = time.monotonic() - t0
    log(f"[+] Finished ingesting {ingested_count} files from {path} in {elapsed:.1f}s", level=1, verbose=verbose)

    if failed_files:
        log(f"[!] {len(failed_files)} files failed ingestion. See errors above.", level=0, verbose=verbose)

    # Print fingerprint summary at end of ingestion
    collector = get_fingerprint_collector()
    collector.print_summary(verbose=verbose)

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
        if not ip:
            # Never fabricate a host from the module/directory name -- that
            # created junk "hosts" like 'scan-data'/'nmap-nse'/'mitre-attack'
            # in the inventory. Skip entries with no real target instead.
            log(f"[i] Skipping host-less entry in {file.name}", level=2, verbose=verbose)
            continue
        db_host = await get_or_create_host(session, ip)

        output = flatten_entry(entry)
        await get_or_create_script(session, db_host, None, module_name, output)

    await session.commit()
    log(f"[+] Ingested {module_name} JSON: {file.name}", level=1, verbose=verbose)


# ---------------------------------------------------
# Ingestion Core
# ---------------------------------------------------
async def ingest_file(file: Path, session: AsyncSession, dedupe: bool = True, verbose: int = 0,
                      fp_lookup=None, cache: IngestionCache = None):
    log(f"[*] Processing file: {file}", level=2, verbose=verbose)
    if not file.exists():
        log(f"[!] File not found: {file}", level=0, verbose=verbose)
        return

    # Skip enrichment files - enrichment results should not be ingested into
    # the database. Accept both 'enrich/' (current) and 'enrichment/' (legacy
    # webapp path) so we keep working on workspaces that pre-date the rename.
    if ("enrich" in file.parts or "enrichment" in file.parts or
        file.name.startswith("enrich-") or file.name.startswith("enrichment-") or
        "enrich" in file.name.lower() or "enrichment" in file.name.lower()):
        log(f"[i] Skipping enrichment file (not ingesting): {file}", level=2, verbose=verbose)
        return

    # Choose cached or uncached functions based on whether cache is available
    _get_host = (lambda s, addr, **kw: cached_get_or_create_host(s, cache, addr, **kw)) if cache else get_or_create_host
    _get_port = (lambda s, h, p, **kw: cached_get_or_create_port(s, cache, h, p, **kw)) if cache else get_or_create_port
    _get_script = (lambda s, h, p, n, o, **kw: cached_get_or_create_script(s, cache, h, p, n, o, **kw)) if cache else get_or_create_script
    _get_osguess = (lambda s, h, **kw: cached_get_or_create_osguess(s, cache, h, **kw)) if cache else get_or_create_osguess
    _get_device_info = (lambda s, h, **kw: cached_get_or_create_device_info(s, cache, h, **kw)) if cache else get_or_create_device_info

    # ---------------------------------------------------
    # Handle Nmap XML  (single parse — no double ET.parse + NmapParser)
    # ---------------------------------------------------
    if file.suffix.lower() == ".xml":
        log(f"[i] XML detected, parsing {file}", level=2, verbose=verbose)

        # Quick root-tag check with iterparse (reads only the first element, not the whole tree)
        try:
            for _event, elem in ET.iterparse(str(file), events=("start",)):
                root_tag = elem.tag
                elem.clear()
                break
            else:
                log(f"[i] Skipping empty XML {file.name}", level=1, verbose=verbose)
                return
        except Exception as e:
            error_msg = str(e).lower()
            if any(phrase in error_msg for phrase in ["no element found", "unclosed token", "not well-formed"]):
                log(f"[i] Skipping incomplete XML {file.name} (likely from cancelled/interrupted scan)", level=1, verbose=verbose)
            else:
                log(f"[!] Failed to read XML {file}: {e}", level=0, verbose=verbose)
            return

        if root_tag != "nmaprun":
            log(f"[i] Skipping non-Nmap XML file: {file} (root={root_tag})", level=2, verbose=verbose)
            return

        try:
            nmap_report = NmapParser.parse_fromfile(str(file))
        except Exception as e:
            error_msg = str(e).lower()
            if any(phrase in error_msg for phrase in [
                "no element found", "unclosed token", "not well-formed",
                "cannot parse", "no data", "truncated",
            ]):
                log(f"[i] Skipping incomplete/truncated XML {file.name} (likely from cancelled/interrupted scan)", level=1, verbose=verbose)
            else:
                log(f"[!] Failed to parse {file} with NmapParser: {e}", level=0, verbose=verbose)
            return

        for host in nmap_report.hosts:
            if not host.is_up():
                continue

            # Prefer the longest hostname (FQDN) over short names
            _hnames = getattr(host, "hostnames", None) or []
            hostname = max(_hnames, key=len) if _hnames else None
            db_host = await _get_host(session, host.address, hostname=hostname)

            # --- OS Guesses ---
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

                    await _get_osguess(
                        session,
                        db_host,
                        name=guess_name,
                        accuracy=int(accuracy or 0),
                        family=family,
                        vendor=vendor,
                        type=type_,
                    )

                    # --- Create DeviceInfo from OS Detection ---
                    device_type = "workstation"
                    if type_:
                        type_lower = type_.lower()
                        if "router" in type_lower:
                            device_type = "router"
                        elif "switch" in type_lower:
                            device_type = "switch"
                        elif "firewall" in type_lower:
                            device_type = "firewall"
                        elif "server" in type_lower:
                            device_type = "server"
                        elif "printer" in type_lower:
                            device_type = "printer"
                        elif "phone" in type_lower or "mobile" in type_lower:
                            device_type = "mobile"
                        elif "storage" in type_lower or "nas" in type_lower:
                            device_type = "nas"
                        elif "media" in type_lower or "player" in type_lower:
                            device_type = "media_server"
                        elif "camera" in type_lower:
                            device_type = "camera"
                        elif "general purpose" in type_lower:
                            device_type = "workstation"

                    await _get_device_info(
                        session,
                        db_host,
                        device_type=device_type,
                        os_family=family,
                        os_name=guess_name,
                        manufacturer=vendor,
                        confidence=(int(accuracy or 0) / 100.0)
                    )
            except Exception as e:
                log(f"[!] Failed to ingest OS guesses for {host.address}: {e}", level=0, verbose=verbose)

            # --- Enhanced Fingerprinting (skip if host already fully fingerprinted) ---
            # Only skip if a FULL fingerprint was previously run (has validation_status
            # or sources). Basic OS detection (Phase 1 above) sets confidence from Nmap
            # accuracy but doesn't populate enriched fields — don't skip based on that.
            existing_di = cache.device_info.get(db_host.id) if cache else None
            _skip_fp = existing_di and (existing_di.validation_status is not None or existing_di.sources is not None)

            if not _skip_fp:
                try:
                    from cygor.fingerprinting.fingerprint import fingerprint_from_host

                    fp_result = await fingerprint_from_host(host, lookup=fp_lookup)
                    if fp_result:
                        evidence_json = json.dumps(fp_result.evidence) if fp_result.evidence else None

                        smb_os = None
                        samba_version = None
                        if fp_result.smb_info:
                            smb_os = fp_result.smb_info.get('os')
                            samba_version = fp_result.smb_info.get('samba_version')

                        ssl_cn = None
                        if fp_result.ssl_certs:
                            ssl_cn = fp_result.ssl_certs[0].get('cn') if fp_result.ssl_certs else None

                        await _get_device_info(
                            session,
                            db_host,
                            device_type=fp_result.device_type or "Unknown",
                            device_category=fp_result.device_category or "Unknown",
                            manufacturer=fp_result.manufacturer,
                            os_family=fp_result.os_family,
                            os_name=fp_result.os_name,
                            os_version=fp_result.os_version,
                            os_kernel=fp_result.os_kernel,
                            os_full=fp_result.os_full,
                            netbios_name=fp_result.netbios_name,
                            mac_address=fp_result.mac_address,
                            mac_vendor=fp_result.manufacturer if fp_result.mac_address else None,
                            validated=fp_result.validated,
                            validation_sources=fp_result.validation_sources,
                            confidence=fp_result.confidence,
                            evidence=evidence_json,
                            sources=fp_result.get_sources_summary() if hasattr(fp_result, 'get_sources_summary') else None,
                            ssl_common_name=ssl_cn,
                            smb_os=smb_os,
                            samba_version=samba_version,
                            nmap_os_raw=fp_result.nmap_os_raw,
                            inferred_os=fp_result.inferred_os,
                            inferred_firmware=fp_result.inferred_firmware,
                            validation_status=fp_result.validation_status,
                            validation_reason=fp_result.validation_reason,
                            plausibility_score=fp_result.plausibility_score,
                            device_type_certainty=getattr(fp_result, 'device_type_certainty', 0.0),
                            manufacturer_certainty=getattr(fp_result, 'manufacturer_certainty', 0.0),
                            os_family_certainty=getattr(fp_result, 'os_family_certainty', 0.0),
                        )
                        collector = get_fingerprint_collector()
                        collector.add(fp_result)

                        if verbose >= 1:
                            fp_parts = [fp_result.ip_address]
                            if fp_result.device_type and fp_result.device_type != "Unknown":
                                fp_parts.append(f"Type: {fp_result.device_type}")
                            if fp_result.os_full or fp_result.os_name or fp_result.os_family:
                                fp_parts.append(f"OS: {fp_result.os_full or fp_result.os_name or fp_result.os_family}")
                            if fp_result.manufacturer:
                                fp_parts.append(f"Vendor: {fp_result.manufacturer}")
                            confidence_pct = int(fp_result.confidence * 100)
                            fp_parts.append(f"Confidence: {confidence_pct}%")
                            log(f"[+] Fingerprint: {' | '.join(fp_parts)}", level=1, verbose=verbose)
                except ImportError:
                    log("[!] Fingerprinting module not available", level=1, verbose=verbose)
                except Exception as e:
                    log(f"[!] Enhanced fingerprinting failed for {host.address}: {e}", level=1, verbose=verbose)

            # --- Ports & Scripts ---
            for service in host.services:
                if service.state != "open":
                    continue

                service_dict = service.service_dict if hasattr(service, 'service_dict') else {}

                db_port = await _get_port(
                    session,
                    db_host,
                    service.port,
                    service=getattr(service, "service", None) or None,
                    protocol=getattr(service, "protocol", None) or None,
                    banner=getattr(service, "banner", None) or None,
                    product=service_dict.get('product') or None,
                    version=service_dict.get('version') or None,
                    extrainfo=service_dict.get('extrainfo') or None,
                    cpe=service_dict.get('cpelist', [None])[0] if service_dict.get('cpelist') else None,
                    state=getattr(service, "state", None) or None,
                    reason=getattr(service, "reason", None) or None,
                    confidence=service_dict.get('conf') or service_dict.get('confidence') or None,
                )

                scripts = getattr(service, "scripts_results", {})
                items = scripts.items() if hasattr(scripts, "items") else [
                    (s.get("id"), s.get("output", "")) for s in scripts or []
                ]
                for sid, out in items:
                    if not sid:
                        continue
                    await _get_script(session, db_host, db_port, sid, out or "")

        log(f"[+] Ingested {file.name}", level=2, verbose=verbose)
        return

    # ---------------------------------------------------
    # Handle JSONL Files
    # ---------------------------------------------------
    if file.suffix.lower() == ".jsonl":
        log(f"[i] Skipping unsupported JSONL file: {file.name}", level=2, verbose=verbose)
        return

    # ---------------------------------------------------
    # Handle JSON Modules
    # ---------------------------------------------------
    if file.suffix.lower() == ".json":
        # Check both parent and grandparent for module hint (handles timestamped subdirs)
        parent_name = (file.parent.name or "").lower()
        grandparent_name = (file.parent.parent.name or "").lower() if file.parent.parent else ""
        # Use grandparent if parent looks like a timestamp, otherwise use parent
        if parent_name.replace("_", "").isdigit() and grandparent_name:
            module_hint = grandparent_name
        else:
            module_hint = parent_name
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

        # Skip enrichment JSON files - they have a specific structure with "ioc", "type", and "enrichments"
        if isinstance(data, list) and len(data) > 0:
            # Check if first item has enrichment structure
            first_item = data[0] if isinstance(data[0], dict) else {}
            if "ioc" in first_item and "enrichments" in first_item:
                log(f"[i] Skipping enrichment JSON file: {file}", level=2, verbose=verbose)
                return
        elif isinstance(data, dict):
            # Check if it's a single enrichment result
            if "ioc" in data and "enrichments" in data:
                log(f"[i] Skipping enrichment JSON file: {file}", level=2, verbose=verbose)
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

                # Use cache for host lookup if available
                if cache:
                    db_host = cache.hosts.get(host)
                else:
                    res = await session.execute(select(Host).where(Host.address == host))
                    db_host = res.scalar_one_or_none()
                if not db_host:
                    log(f"[i] Skipping Lockon result for {host} (not in Nmap/Masscan data)", level=2, verbose=verbose)
                    continue

                parts = [f"URL: {url}"]
                raw_status = entry.get("status_code") or entry.get("status")
                status_code = None
                if raw_status is not None:
                    try:
                        status_code = int(raw_status)
                    except (ValueError, TypeError):
                        pass
                    parts.append(f"Status: {raw_status}")

                screenshot_file = entry.get("screenshot_file")
                if screenshot_file:
                    parts.append(f"Screenshot: {screenshot_file}")

                failed = entry.get("screenshot_failed", True)
                parts.append(f"Failed: {bool(failed)}")

                await _get_script(
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

                if cache:
                    db_host = cache.hosts.get(ip)
                else:
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

                await _get_script(session, db_host, None, "smbexplorer", ", ".join(parts))

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

                if cache:
                    db_host = cache.hosts.get(ip)
                else:
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

                await _get_script(session, db_host, None, "nfsexplorer", ", ".join(parts))

            await session.commit()
            log(f"[+] Ingested nfsexplorer JSON: {file.name}", level=1, verbose=verbose)
            return

        # ---------- CREDRECON ----------
        # Skip credrecon JSON files - they should not be ingested into Host/Port tables
        # Credrecon results are stored separately in CredReconScan and CredReconResult tables
        elif module_hint == "credrecon" or fname == "credrecon_results.json" or (
            isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict) and
            any(key in data[0] for key in ["username", "password", "status"]) and
            any(key in data[0] for key in ["ip", "target"]) and
            any(key in data[0] for key in ["protocol", "port"])
        ):
            log(f"[i] Skipping credrecon JSON file: {file.name} (credrecon results are stored separately)", level=2, verbose=verbose)
            return

        # ---------- GENERIC JSON FALLBACK ----------
        else:
            await ingest_generic_json(file, session, data, module_hint, verbose=verbose)
            return


# ---------------------------------------------------
# CLI Entrypoint
# ---------------------------------------------------
if __name__ == "__main__":
    import argparse, asyncio

    parser = argparse.ArgumentParser(description="Manually ingest a results directory")
    parser.add_argument("directory", type=str, help="Path to results directory")
    parser.add_argument("--db", type=str, default="results/cygor.db",
                        help="Database path or URL (auto-detects PostgreSQL if available)")
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity (-v shows more, -vv shows debug details)")
    args = parser.parse_args()

    db_url = get_default_database_url(args.db)
    print(f"[*] Using database: {db_url}")

    db.init_engine(db_url, debug=True)

    async def _main():
        async with db.SessionLocal() as session:
            await db.init_db()
            await ingest_directory(Path(args.directory), session, dedupe=True, verbose=args.verbose)

    asyncio.run(_main())
