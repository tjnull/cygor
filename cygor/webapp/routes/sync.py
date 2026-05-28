"""
Sync routes – database sync and fingerprint sync.

Extracted from main.py.
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..config import settings
from .. import db
from ..models import Host, Port
from ..ingest import ingest_directory

logger = logging.getLogger(__name__)

router = APIRouter(tags=["sync"])

templates = None


def set_templates(tmpl):
    global templates
    templates = tmpl


# ============================================================================
# Sync History (in-memory store shared with main app)
# ============================================================================

SYNC_HISTORY: List[Dict[str, Any]] = []


class SyncRequest(BaseModel):
    scan_dir: Optional[str] = None  # Optional specific directory to sync (e.g., ondemand-scans/2025-01-06_12-34-56)
    verbose: bool = False  # When true, emit per-file/per-host ingest output to stdout. Default is a one-line summary.


# ============================================================================
# Sync Status Page & API
# ============================================================================

@router.get("/sync-status", response_class=HTMLResponse)
async def sync_status_page(request: Request):
    """Sync status page."""
    if templates is None:
        return HTMLResponse("<h1>Sync status — check /api/sync-status for JSON</h1>")
    # New Starlette signature: (request, name, context). The legacy form
    # `TemplateResponse(name, {"request": request, ...})` raises
    # 'TypeError: unhashable type: dict' on current starlette because the
    # first positional is being interpreted as the request object.
    return templates.TemplateResponse(request, "sync_status.html", {})


@router.get("/api/sync-history")
async def get_sync_history():
    """Get the in-memory sync history (most recent first)."""
    return JSONResponse({"status": "success", "history": SYNC_HISTORY})


@router.get("/api/sync-status")
async def get_sync_status():
    """Get current database sync status (API endpoint)."""
    # Get current database stats
    async with db.SessionLocal() as session:
        from sqlalchemy import func, select
        total_hosts = await session.scalar(select(func.count(Host.id))) or 0
        total_ports = await session.scalar(select(func.count(Port.id))) or 0

    results_dir = os.environ.get("CYGOR_LOAD_DIR") or settings.RESULTS_DIR

    return JSONResponse({
        "total_hosts": total_hosts,
        "total_ports": total_ports,
        "results_dir": results_dir
    })


# ============================================================================
# Database Sync API
# ============================================================================

@router.post("/api/sync-database")
async def sync_database(req: Optional[SyncRequest] = None):
    """
    Sync database by ingesting scan results.

    If scan_dir is provided, only syncs that specific directory (fast, for on-demand scans).
    Otherwise, syncs the entire results directory (slower, for full refresh).
    """
    base_dir = os.environ.get("CYGOR_LOAD_DIR") or settings.RESULTS_DIR
    verbose_flag = bool(req and req.verbose)
    verbose_level = 1 if verbose_flag else 0

    # Determine which directory to sync
    if req and req.scan_dir:
        # Sync only the specific scan directory (relative to base_dir)
        load_dir = Path(base_dir) / req.scan_dir
        sync_label = req.scan_dir
        if not load_dir.exists():
            return JSONResponse({
                "status": "error",
                "error": f"Scan directory not found: {load_dir}"
            }, status_code=404)
        if verbose_flag:
            print(f"[*] Fast sync: ingesting only {req.scan_dir}")
    else:
        # Full sync of entire results directory
        load_dir = Path(base_dir)
        sync_label = "full"
        if verbose_flag:
            print(f"[*] Full database sync started from: {load_dir}")
        if not load_dir.exists():
            return JSONResponse({
                "status": "error",
                "error": f"Results directory not found: {load_dir}. Please set CYGOR_LOAD_DIR or ensure RESULTS_DIR exists."
            }, status_code=404)

    import time as _time
    _t0 = _time.monotonic()
    try:
        # Count hosts and ports before sync
        async with db.SessionLocal() as session:
            from sqlalchemy import func, select
            hosts_before = await session.scalar(select(func.count(Host.id))) or 0
            ports_before = await session.scalar(select(func.count(Port.id))) or 0

        if verbose_flag:
            print(f"[i] Database state before sync: {hosts_before} hosts, {ports_before} ports")

        async with db.SessionLocal() as session:
            count = await ingest_directory(load_dir, session, dedupe=True, verbose=verbose_level)
            await session.commit()

        if verbose_flag:
            print(f"[✓] Ingested {count} file(s)")

        # Count hosts and ports after sync
        async with db.SessionLocal() as session:
            hosts_after = await session.scalar(select(func.count(Host.id))) or 0
            ports_after = await session.scalar(select(func.count(Port.id))) or 0

        hosts_added = hosts_after - hosts_before
        ports_added = ports_after - ports_before
        elapsed = _time.monotonic() - _t0

        if verbose_flag:
            print(f"[✓] Database state after sync: {hosts_after} hosts (+{hosts_added}), {ports_after} ports (+{ports_added})")
        else:
            # One-line summary for the default (auto-sync) path.
            print(f"[+] auto-sync {sync_label} → +{hosts_added} hosts, +{ports_added} ports ({elapsed:.1f}s)")

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


# ============================================================================
# Fingerprint Database Sync API Endpoints
# ============================================================================

# Global state for fingerprint sync
_fingerprint_sync_active = False
_fingerprint_sync_task_id = None
_fingerprint_sync_log = []
_fingerprint_sync_progress = {
    "current_source": None,
    "current_source_name": None,
    "sources_completed": 0,
    "sources_total": 0,
    "bytes_downloaded": 0,
    "bytes_total": 0,
    "start_time": None,
    "current_file": None,
    "files_completed": 0,
    "files_total": 0,
}


@router.get("/api/fingerprint-sync/status")
async def get_fingerprint_sync_status(session: AsyncSession = Depends(get_session)):
    """
    Get fingerprint database status and record counts.
    Uses JSON file cache only - no SQLite required.
    """
    try:
        from cygor.fingerprinting import get_cache

        # Get file cache stats
        cache = get_cache()
        # Clear in-memory cache to ensure fresh data from files
        cache.clear_memory_cache()
        cache_stats = cache.get_stats()
        sync_status = cache.load_sync_status()

        # Get counts from JSON cache files
        oui_count = len(cache.load_oui()) if cache.oui_file.exists() else 0
        tcpip_count = len(cache.load_tcpip()) if cache.tcpip_file.exists() else 0
        banner_count = len(cache.load_banners()) if cache.banners_file.exists() else 0

        # Get Huginn-Muninn counts
        hm_devices_count = len(cache.load_huginn_devices()) if cache.huginn_devices_file.exists() else 0
        hm_dhcp_count = len(cache.load_huginn_dhcp()) if cache.huginn_dhcp_file.exists() else 0
        hm_vendor_count = len(cache.load_huginn_dhcp_vendor()) if cache.huginn_dhcp_vendor_file.exists() else 0
        hm_dhcpv6_count = len(cache.load_huginn_dhcpv6()) if cache.huginn_dhcpv6_file.exists() else 0
        hm_dhcpv6_enterprise_count = len(cache.load_huginn_dhcpv6_enterprise()) if cache.huginn_dhcpv6_enterprise_file.exists() else 0
        # For MAC vendors, use sync_status record count to avoid loading 10M+ records into memory
        hm_mac_vendors_count = sync_status.get("huginn_mac_vendors", {}).get("record_count", 0)

        # Get Satori & Combinations counts (use sync_status to avoid loading into memory)
        satori_ssh_count = sync_status.get("satori_ssh", {}).get("record_count", 0)
        satori_smb_count = sync_status.get("satori_smb", {}).get("record_count", 0)
        satori_http_count = sync_status.get("satori_http", {}).get("record_count", 0)
        satori_useragent_count = sync_status.get("satori_useragent", {}).get("record_count", 0)
        satori_dhcp_count = sync_status.get("satori_dhcp", {}).get("record_count", 0)
        satori_sip_count = sync_status.get("satori_sip", {}).get("record_count", 0)
        huginn_combinations_count = sync_status.get("huginn_combinations", {}).get("record_count", 0)

        # Get OS Fingerprint counts
        nmap_os_count = len(cache.load_nmap_os_db()) if cache.nmap_os_db_file.exists() else 0

        # Get OUI metadata for device type count (OUI-Master feature)
        oui_device_type_count = 0
        oui_source_name = "OUI Master"
        if cache.oui_file.exists():
            try:
                import json
                with open(cache.oui_file, 'r') as f:
                    oui_data = json.load(f)
                    oui_device_type_count = oui_data.get("entries_with_device_type", 0)
                    # Update name based on source
                    if oui_data.get("source") == "oui_master":
                        oui_source_name = "OUI Master"
                    else:
                        oui_source_name = "IEEE OUI"
            except Exception:
                pass

        # Build source status - Core sources
        sources = {
            "ieee_oui": {
                "name": oui_source_name,
                "description": "MAC Vendors + Device Types",
                "count": oui_count,
                "entries_with_device_type": oui_device_type_count,
                "last_sync": sync_status.get("ieee_oui", {}).get("last_sync"),
                "status": sync_status.get("ieee_oui", {}).get("status", "never"),
            },
            "p0f": {
                "name": "TCP/IP (p0f)",
                "description": "OS Stack Fingerprints",
                "count": tcpip_count,
                "last_sync": sync_status.get("p0f", {}).get("last_sync"),
                "status": sync_status.get("p0f", {}).get("status", "never"),
            },
            "cygor_patterns": {
                "name": "Banner Patterns",
                "description": "Service Identification",
                "count": banner_count,
                "last_sync": sync_status.get("cygor_patterns", {}).get("last_sync"),
                "status": sync_status.get("cygor_patterns", {}).get("status", "built-in"),
            },
            # Huginn-Muninn sources (https://github.com/Ringmast4r/Huginn-Muninn)
            "huginn_devices": {
                "name": "Device Profiles (Huginn-Muninn)",
                "description": "116K hierarchical device profiles",
                "count": hm_devices_count,
                "last_sync": sync_status.get("huginn_devices", {}).get("last_sync"),
                "status": sync_status.get("huginn_devices", {}).get("status", "never"),
            },
            "huginn_dhcp": {
                "name": "DHCP Signatures (Huginn-Muninn)",
                "description": "368K Option 55 fingerprints",
                "count": hm_dhcp_count,
                "last_sync": sync_status.get("huginn_dhcp", {}).get("last_sync"),
                "status": sync_status.get("huginn_dhcp", {}).get("status", "never"),
            },
            "huginn_dhcp_vendor": {
                "name": "DHCP Vendors (Huginn-Muninn)",
                "description": "425K Option 60 vendor classes",
                "count": hm_vendor_count,
                "last_sync": sync_status.get("huginn_dhcp_vendor", {}).get("last_sync"),
                "status": sync_status.get("huginn_dhcp_vendor", {}).get("status", "never"),
            },
            "huginn_dhcpv6": {
                "name": "DHCPv6 Signatures (Huginn-Muninn)",
                "description": "1.6K IPv6 option patterns",
                "count": hm_dhcpv6_count,
                "last_sync": sync_status.get("huginn_dhcpv6", {}).get("last_sync"),
                "status": sync_status.get("huginn_dhcpv6", {}).get("status", "never"),
            },
            "huginn_dhcpv6_enterprise": {
                "name": "DHCPv6 Enterprise (Huginn-Muninn)",
                "description": "58K IPv6 vendor IDs",
                "count": hm_dhcpv6_enterprise_count,
                "last_sync": sync_status.get("huginn_dhcpv6_enterprise", {}).get("last_sync"),
                "status": sync_status.get("huginn_dhcpv6_enterprise", {}).get("status", "never"),
            },
            "huginn_mac_vendors": {
                "name": "MAC Vendors (Huginn-Muninn)",
                "description": "10.1M MAC vendor mappings",
                "count": hm_mac_vendors_count,
                "last_sync": sync_status.get("huginn_mac_vendors", {}).get("last_sync"),
                "status": sync_status.get("huginn_mac_vendors", {}).get("status", "never"),
            },
            # Satori fingerprint sources (from Huginn-Muninn/Satori)
            "satori_ssh": {
                "name": "Satori SSH",
                "description": "SSH banner fingerprints",
                "count": satori_ssh_count,
                "last_sync": sync_status.get("satori_ssh", {}).get("last_sync"),
                "status": sync_status.get("satori_ssh", {}).get("status", "never"),
            },
            "satori_smb": {
                "name": "Satori SMB",
                "description": "SMB/CIFS fingerprints",
                "count": satori_smb_count,
                "last_sync": sync_status.get("satori_smb", {}).get("last_sync"),
                "status": sync_status.get("satori_smb", {}).get("status", "never"),
            },
            "satori_http": {
                "name": "Satori HTTP",
                "description": "HTTP server fingerprints",
                "count": satori_http_count,
                "last_sync": sync_status.get("satori_http", {}).get("last_sync"),
                "status": sync_status.get("satori_http", {}).get("status", "never"),
            },
            "satori_useragent": {
                "name": "Satori User-Agent",
                "description": "User-Agent fingerprints",
                "count": satori_useragent_count,
                "last_sync": sync_status.get("satori_useragent", {}).get("last_sync"),
                "status": sync_status.get("satori_useragent", {}).get("status", "never"),
            },
            "satori_dhcp": {
                "name": "Satori DHCP",
                "description": "DHCP fingerprints",
                "count": satori_dhcp_count,
                "last_sync": sync_status.get("satori_dhcp", {}).get("last_sync"),
                "status": sync_status.get("satori_dhcp", {}).get("status", "never"),
            },
            "satori_sip": {
                "name": "Satori SIP",
                "description": "SIP protocol fingerprints",
                "count": satori_sip_count,
                "last_sync": sync_status.get("satori_sip", {}).get("last_sync"),
                "status": sync_status.get("satori_sip", {}).get("status", "never"),
            },
            # Huginn-Muninn DHCP Combinations
            "huginn_combinations": {
                "name": "DHCP Combinations (Huginn-Muninn)",
                "description": "DHCP fingerprint+vendor combos",
                "count": huginn_combinations_count,
                "last_sync": sync_status.get("huginn_combinations", {}).get("last_sync"),
                "status": sync_status.get("huginn_combinations", {}).get("status", "never"),
            },
            # OS Fingerprint sources
            "nmap_os_db": {
                "name": "Nmap OS DB",
                "description": "6K+ OS signatures",
                "count": nmap_os_count,
                "last_sync": sync_status.get("nmap_os_db", {}).get("last_sync"),
                "status": sync_status.get("nmap_os_db", {}).get("status", "never"),
            },
        }

        # Calculate total
        total_count = (oui_count + tcpip_count + banner_count +
                      hm_devices_count + hm_dhcp_count + hm_vendor_count +
                      hm_dhcpv6_count + hm_dhcpv6_enterprise_count + hm_mac_vendors_count +
                      satori_ssh_count + satori_smb_count + satori_http_count +
                      satori_useragent_count + satori_dhcp_count + satori_sip_count +
                      huginn_combinations_count + nmap_os_count)

        return JSONResponse({
            "status": "success",
            "cache_dir": str(cache.cache_dir),
            "total_records": total_count,
            "sources": sources,
            "cache_files": cache_stats.get("files", {}),
            "sync_active": _fingerprint_sync_active,
        })

    except Exception as e:
        logger.error(f"Error getting fingerprint sync status: {e}")
        return JSONResponse({"status": "error", "error": str(e)}, status_code=500)


@router.post("/api/fingerprint-sync/start")
async def start_fingerprint_sync(
    request: Request,
    background_tasks: BackgroundTasks,
    session: AsyncSession = Depends(get_session)
):
    """
    Start fingerprint database sync.

    Request body:
        sync_type: 'all', 'oui', 'tcpip', 'patterns', 'selective', 'huginn'
        sources: List of specific sources to sync (for selective mode)
                 Options: ieee_oui, p0f, cygor_patterns, huginn_devices,
                         huginn_dhcp, huginn_dhcp_vendor, nmap_os_db
        force: Whether to force re-sync even if recently synced
    """
    global _fingerprint_sync_active, _fingerprint_sync_task_id, _fingerprint_sync_log

    if _fingerprint_sync_active:
        return JSONResponse({
            "status": "error",
            "error": "Sync already in progress",
            "task_id": _fingerprint_sync_task_id
        }, status_code=409)

    try:
        body = await request.json()
    except Exception:
        body = {}

    sync_type = body.get("sync_type", "all")
    force = body.get("force", False)
    sources = body.get("sources", None)  # List of specific sources for selective sync

    # Generate task ID
    import uuid
    task_id = f"fp-sync-{uuid.uuid4().hex[:8]}"

    _fingerprint_sync_active = True
    _fingerprint_sync_task_id = task_id
    _fingerprint_sync_log = []

    # Add to background tasks
    background_tasks.add_task(
        _run_fingerprint_sync_background,
        task_id,
        sync_type,
        force,
        sources
    )

    return JSONResponse({
        "status": "success",
        "message": f"Fingerprint sync started",
        "task_id": task_id,
        "sync_type": sync_type,
        "sources": sources
    })


async def _run_fingerprint_sync_background(task_id: str, sync_type: str, force: bool, sources_list: list = None):
    """Background task to run fingerprint sync (uses JSON cache, no database)."""
    global _fingerprint_sync_active, _fingerprint_sync_log, _fingerprint_sync_progress

    try:
        from cygor.fingerprinting import JSONSyncEngine

        # Determine sources description for logging
        if sources_list:
            sources_desc = f"{len(sources_list)} selected source(s)"
        else:
            sources_desc = sync_type

        _fingerprint_sync_log.append({"time": datetime.now().isoformat(), "message": f"Starting sync: {sources_desc}..."})

        sync_engine = JSONSyncEngine()

        # Determine which sources to sync
        if sync_type == "selective" and sources_list:
            # Use the provided sources list directly
            sources = sources_list
        elif sync_type == "all":
            sources = None  # Sync all
        elif sync_type == "oui":
            sources = ["ieee_oui"]
        elif sync_type == "tcpip":
            sources = ["p0f"]
        elif sync_type == "patterns":
            sources = ["cygor_patterns"]
        elif sync_type == "huginn" or sync_type == "fingerbank":
            # "fingerbank" kept for backwards compatibility, maps to huginn sources
            sources = ["huginn_devices", "huginn_dhcp", "huginn_dhcp_vendor"]
        else:
            sources = None

        # Log selected sources
        if sources:
            _fingerprint_sync_log.append({
                "time": datetime.now().isoformat(),
                "message": f"Sources: {', '.join(sources)}"
            })

        # Sync sources one at a time with progress updates
        actual_sources = sources or sync_engine.SYNC_ORDER
        results = {}

        # Initialize progress tracking
        _fingerprint_sync_progress["start_time"] = datetime.now()
        _fingerprint_sync_progress["sources_total"] = len(actual_sources)
        _fingerprint_sync_progress["sources_completed"] = 0
        _fingerprint_sync_progress["bytes_downloaded"] = 0
        _fingerprint_sync_progress["bytes_total"] = 0

        for idx, source in enumerate(actual_sources):
            # Check if sync was stopped
            if not _fingerprint_sync_active:
                break

            # Yield control to event loop
            await asyncio.sleep(0)

            # Update progress
            _fingerprint_sync_progress["current_source"] = source
            _fingerprint_sync_progress["current_source_name"] = sync_engine.SOURCE_NAMES.get(source, source)
            _fingerprint_sync_progress["sources_completed"] = idx

            _fingerprint_sync_log.append({
                "time": datetime.now().isoformat(),
                "message": f"Syncing {sync_engine.SOURCE_NAMES.get(source, source)}..."
            })

            try:
                # Check if source is in SOURCE_URLS before trying to sync
                if source not in sync_engine.SOURCE_URLS and source != "cygor_patterns":
                    logger.warning(f"Source {source} not in SOURCE_URLS, skipping")
                    _fingerprint_sync_log.append({
                        "time": datetime.now().isoformat(),
                        "message": f"⚠ {sync_engine.SOURCE_NAMES.get(source, source)}: source not configured"
                    })
                    continue

                # Sync single source
                source_results = await sync_engine.sync_all(
                    force=force,
                    sources=[source],
                    use_rich=False  # No TUI in background task
                )
                results.update(source_results)

                count = source_results.get(source, 0)
                if count > 0:
                    _fingerprint_sync_log.append({
                        "time": datetime.now().isoformat(),
                        "message": f"✓ {sync_engine.SOURCE_NAMES.get(source, source)}: {count:,} records"
                    })
                elif count == 0:
                    # Check if this is actually cached or just empty
                    status = sync_engine.cache.get_source_status(source)
                    if status and status.get("status") == "success":
                        _fingerprint_sync_log.append({
                            "time": datetime.now().isoformat(),
                            "message": f"○ {sync_engine.SOURCE_NAMES.get(source, source)}: cached (skipped)"
                        })
                    else:
                        _fingerprint_sync_log.append({
                            "time": datetime.now().isoformat(),
                            "message": f"⚠ {sync_engine.SOURCE_NAMES.get(source, source)}: no data returned"
                        })
                else:
                    _fingerprint_sync_log.append({
                        "time": datetime.now().isoformat(),
                        "message": f"✗ {sync_engine.SOURCE_NAMES.get(source, source)}: failed"
                    })

                # Update completed count
                _fingerprint_sync_progress["sources_completed"] = idx + 1

            except Exception as e:
                logger.error(f"Failed to sync {source}: {e}")
                _fingerprint_sync_log.append({
                    "time": datetime.now().isoformat(),
                    "message": f"✗ {sync_engine.SOURCE_NAMES.get(source, source)}: {str(e)}"
                })
                results[source] = -1
                _fingerprint_sync_progress["sources_completed"] = idx + 1

        total = sum(r if isinstance(r, int) and r > 0 else 0 for r in results.values())
        _fingerprint_sync_log.append({
            "time": datetime.now().isoformat(),
            "message": f"Sync complete: {total:,} total entries",
            "status": "completed",
            "total": total
        })

        # Final progress update
        _fingerprint_sync_progress["current_source"] = None
        _fingerprint_sync_progress["current_source_name"] = None

        logger.info(f"Fingerprint sync {task_id} completed: {total} entries")

    except Exception as e:
        logger.error(f"Fingerprint sync {task_id} failed: {e}")
        _fingerprint_sync_log.append({
            "time": datetime.now().isoformat(),
            "message": f"Error: {str(e)}",
            "status": "error"
        })
    finally:
        _fingerprint_sync_active = False
        # Reset progress
        _fingerprint_sync_progress["current_source"] = None
        _fingerprint_sync_progress["current_source_name"] = None


@router.get("/api/fingerprint-sync/progress")
async def get_fingerprint_sync_progress():
    """Get current fingerprint sync progress with detailed download info."""
    global _fingerprint_sync_active, _fingerprint_sync_task_id, _fingerprint_sync_log, _fingerprint_sync_progress

    # Calculate elapsed time
    elapsed_seconds = 0
    if _fingerprint_sync_progress.get("start_time"):
        elapsed_seconds = (datetime.now() - _fingerprint_sync_progress["start_time"]).total_seconds()

    # Calculate percentage
    percentage = 0
    if _fingerprint_sync_progress.get("sources_total", 0) > 0:
        percentage = int((_fingerprint_sync_progress.get("sources_completed", 0) / _fingerprint_sync_progress["sources_total"]) * 100)

    return JSONResponse({
        "status": "success",
        "active": _fingerprint_sync_active,
        "task_id": _fingerprint_sync_task_id,
        "log": _fingerprint_sync_log[-50:] if _fingerprint_sync_log else [],  # Last 50 entries
        "log_count": len(_fingerprint_sync_log),
        "progress": {
            "current_source": _fingerprint_sync_progress.get("current_source"),
            "current_source_name": _fingerprint_sync_progress.get("current_source_name"),
            "sources_completed": _fingerprint_sync_progress.get("sources_completed", 0),
            "sources_total": _fingerprint_sync_progress.get("sources_total", 0),
            "bytes_downloaded": _fingerprint_sync_progress.get("bytes_downloaded", 0),
            "bytes_total": _fingerprint_sync_progress.get("bytes_total", 0),
            "elapsed_seconds": elapsed_seconds,
            "percentage": percentage,
            "current_file": _fingerprint_sync_progress.get("current_file"),
            "files_completed": _fingerprint_sync_progress.get("files_completed", 0),
            "files_total": _fingerprint_sync_progress.get("files_total", 0),
        }
    })


@router.post("/api/fingerprint-sync/stop")
async def stop_fingerprint_sync():
    """Stop active fingerprint sync."""
    global _fingerprint_sync_active, _fingerprint_sync_log

    if not _fingerprint_sync_active:
        return JSONResponse({
            "status": "error",
            "error": "No sync in progress"
        }, status_code=400)

    _fingerprint_sync_active = False
    _fingerprint_sync_log.append({
        "time": datetime.now().isoformat(),
        "message": "Sync stopped by user",
        "status": "stopped"
    })

    return JSONResponse({
        "status": "success",
        "message": "Sync stop requested"
    })


@router.post("/api/fingerprint-sync/clear")
async def clear_fingerprint_cache(request: Request):
    """
    Clear fingerprint cache files.

    Request body:
        source: Optional specific source to clear, or None for all
    """
    global _fingerprint_sync_active

    if _fingerprint_sync_active:
        return JSONResponse({
            "status": "error",
            "error": "Cannot clear cache while sync is in progress"
        }, status_code=409)

    try:
        body = await request.json()
    except Exception:
        body = {}

    source = body.get("source", None)  # None = clear all

    try:
        from cygor.fingerprinting import get_cache

        cache = get_cache()

        if source:
            # Clear specific source
            success = cache.clear(source)
            if success:
                logger.info(f"Cleared fingerprint cache for source: {source}")
                return JSONResponse({
                    "status": "success",
                    "message": f"Cleared cache for {source}",
                    "cleared": [source]
                })
            else:
                return JSONResponse({
                    "status": "error",
                    "error": f"Failed to clear cache for {source}"
                }, status_code=500)
        else:
            # Clear all cache files
            success = cache.clear()
            if success:
                logger.info("Cleared all fingerprint cache files")
                return JSONResponse({
                    "status": "success",
                    "message": "Cleared all fingerprint cache files",
                    "cleared": list(cache.CACHE_FILES.keys())
                })
            else:
                return JSONResponse({
                    "status": "error",
                    "error": "Failed to clear cache files"
                }, status_code=500)

    except Exception as e:
        logger.error(f"Error clearing fingerprint cache: {e}")
        return JSONResponse({
            "status": "error",
            "error": str(e)
        }, status_code=500)
