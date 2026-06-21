"""
Core routes for Cygor Web Application.

Dashboard, hosts, and services views and APIs.
"""

import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Request, Depends, Query, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, exists
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..db import get_session
from ..models import (
    Host,
    Port,
    Script,
    OSGuess,
    HostTag,
    DeviceInfo,
    Note,
    NoteHostLink,
)
from ..config import settings
from ..helpers import (
    normalize_service,
    _bucket_family,
    _bucket_family_from_device_info,
    _top_guess,
    TopItem,
    gather_scan_times,
    gather_ondemand_scan_times,
    extract_host_key,
)

logger = logging.getLogger(__name__)

# Create router
router = APIRouter(tags=["core"])

# Templates (will be set by main app)
templates: Optional[Jinja2Templates] = None


def set_templates(tmpl: Jinja2Templates):
    """Set templates instance from main app."""
    global templates
    templates = tmpl


# ==========================================================
# Dashboard
# ==========================================================
@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, session: AsyncSession = Depends(get_session)):
    # ==========================================================
    # Accurate tile counts  — exclude script-only hosts
    # ==========================================================

    # Hosts that have at least one Port OR OSGuess (real Nmap/Masscan data)
    base_host_filter = exists().where(Port.host_id == Host.id) | exists().where(OSGuess.host_id == Host.id)

    # Hosts scanned = real scanned hosts only (from database)
    hosts_scanned = await session.scalar(
        select(func.count(func.distinct(Host.id))).where(base_host_filter)
    )
    hosts_enum = 0  # keep 0 if you dropped the enumerated tile

    # ==========================================================
    # Calculate total hosts discovered from scan files
    # ==========================================================
    try:
        scan_times = gather_scan_times(settings.RESULTS_DIR)
    except Exception:
        scan_times = []

    try:
        ondemand_scan_times = gather_ondemand_scan_times(settings.RESULTS_DIR)
    except Exception:
        ondemand_scan_times = []

    # Extract unique hosts from all scan files
    discovered_hosts = set()

    # From regular scans
    for entry in scan_times:
        key = extract_host_key(entry.get("label") or entry.get("path"))
        if key:
            discovered_hosts.add(key)

    # From on-demand scans
    for entry in ondemand_scan_times:
        key = extract_host_key(entry.get("label") or entry.get("path"))
        if key:
            discovered_hosts.add(key)

    # Total discovered hosts is the count of unique hosts from scan files
    hosts_total = len(discovered_hosts) if discovered_hosts else (hosts_scanned or 0)

    # If we have more scanned hosts in DB than discovered in files, use DB count
    # (this handles edge cases where scan files might be missing)
    if hosts_scanned and hosts_scanned > hosts_total:
        hosts_total = hosts_scanned

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
                selectinload(Host.device_info),
            )
        )
    ).scalars().unique().all()

    # ==========================================================
    # OS Discovery  — fingerprint-aware, deduplicated by host_id
    # ==========================================================
    buckets = {
        k: 0
        for k in [
            "Windows", "Linux", "macOS", "BSD/Unix", "Android", "iOS",
            "Network Device", "Virtualization/Hypervisor", "Printer/Peripheral",
            "Specialized Device", "Other", "Unknown",
        ]
    }

    # 1. Build per-host OS info using DeviceInfo (preferred) + OSGuess (fallback)
    all_host_os_info = []
    classified_host_ids = set()

    for h in hosts:
        di = h.device_info
        best_guess = _top_guess(h)

        # Determine OS family bucket
        fam = ""
        if di and (di.confidence or 0) > 0:
            fam = _bucket_family_from_device_info(di)
        if not fam and best_guess:
            fam = _bucket_family(best_guess)
        if not fam:
            fam = "Unknown"

        buckets[fam] = buckets.get(fam, 0) + 1
        classified_host_ids.add(h.id)

        # Resolve hostname: host.hostname > DeviceInfo.netbios_name > ssl_common_name > scripts.
        # Track the source so the UI can label it -- otherwise a TLS cert CN
        # (e.g. "gittea-server.brea") reads like a broken DNS hostname.
        hostname_display = h.hostname or ""
        hostname_source = "DNS (PTR)" if hostname_display else ""
        if not hostname_display and di:
            if di.netbios_name:
                hostname_display = di.netbios_name
                hostname_source = "NetBIOS"
            elif di.ssl_common_name:
                hostname_display = di.ssl_common_name
                hostname_source = "TLS cert"
        if not hostname_display and h.scripts:
            for s in h.scripts:
                if s.name in ("nbstat", "smb-os-discovery") and s.output:
                    m = re.search(r"(?:NetBIOS computer name|Computer name):\s*(\S+)", s.output, re.IGNORECASE)
                    if m:
                        hostname_display = m.group(1)
                        hostname_source = "SMB"
                        break

        # Best OS display string
        os_display = ""
        if di:
            os_display = di.os_full or di.inferred_os or di.nmap_os_raw or di.os_name or ""
        if not os_display and best_guess:
            os_display = best_guess.name or ""

        # Confidence / accuracy
        confidence = di.confidence if di else None
        accuracy = best_guess.accuracy if best_guess else None
        validation_status = di.validation_status if di else None
        manufacturer = di.manufacturer if di else None
        device_type = di.device_type if di else None

        # Sort key: prefer confidence, then accuracy
        sort_key = (confidence or 0, (accuracy or 0) / 100.0)

        all_host_os_info.append({
            "host": h,
            "os_display": os_display,
            "confidence": confidence,
            "accuracy": accuracy,
            "validation_status": validation_status,
            "manufacturer": manufacturer,
            "device_type": device_type,
            "hostname_display": hostname_display,
            "hostname_source": hostname_source,
            "os_family": fam,
            "_sort_key": sort_key,
        })

    # 2. Count hosts with ports but no OS data at all as "Unknown"
    unknown_hosts = (
        await session.execute(
            select(func.count(Host.id))
            .where(
                (exists().where(Port.host_id == Host.id))
                & (~Host.id.in_(classified_host_ids))
            )
            .where(base_host_filter)
        )
    ).scalar() or 0
    buckets["Unknown"] += unknown_hosts

    # 3. Sort by confidence desc then accuracy desc, take top 10
    all_host_os_info.sort(key=lambda x: x["_sort_key"], reverse=True)
    top_items = all_host_os_info[:10]
    # Remove internal sort key before passing to template
    for item in top_items:
        item.pop("_sort_key", None)
    # Also remove from the full list (not passed to template, just cleanup)
    for item in all_host_os_info:
        item.pop("_sort_key", None)

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
    # Add host_id mapping to scan timeline entries
    # (scan_times and ondemand_scan_times already gathered above)
    # ==========================================================
    ip_to_id = {h.address: h.id for h in hosts}
    for entry in scan_times:
        key = extract_host_key(entry.get("label") or entry.get("path"))
        entry["host_id"] = ip_to_id.get(key)

    for entry in ondemand_scan_times:
        key = extract_host_key(entry.get("label") or entry.get("path"))
        entry["host_id"] = ip_to_id.get(key)

    # ==========================================================
    # Device category breakdown for dashboard chart
    # ==========================================================
    try:
        device_cat_result = await session.execute(
            select(DeviceInfo.device_category, func.count(DeviceInfo.id))
            .where(DeviceInfo.device_category != "Unknown")
            .where(DeviceInfo.device_category != None)  # noqa: E711
            .group_by(DeviceInfo.device_category)
            .order_by(func.count(DeviceInfo.id).desc())
        )
        device_categories = [{"category": row[0], "count": row[1]} for row in device_cat_result.all()]
    except Exception:
        device_categories = []

    # ==========================================================
    # Identification trust: how well-corroborated each device's identity is.
    # Unique to cygor -- built on the multi-source fingerprint validation that
    # commercial discovery tools don't expose. Status breakdown answers "can I
    # trust this inventory", the source histogram shows depth of evidence.
    # ==========================================================
    identification_trust = None
    try:
        status_rows = (await session.execute(
            select(DeviceInfo.validation_status, func.count(DeviceInfo.id))
            .group_by(DeviceInfo.validation_status)
        )).all()
        # Normalise statuses into a fixed, ordered set so the chart is stable.
        order = ["VALIDATED", "PLAUSIBLE", "SUSPECT", "UNKNOWN"]
        status_counts = {s: 0 for s in order}
        for status, count in status_rows:
            key = (status or "UNKNOWN").upper()
            status_counts[key] = status_counts.get(key, 0) + count

        # Corroborating-source histogram, bucketed for readability.
        src_rows = (await session.execute(
            select(DeviceInfo.validation_sources, func.count(DeviceInfo.id))
            .group_by(DeviceInfo.validation_sources)
        )).all()
        buckets_src = {"1-2": 0, "3-4": 0, "5-6": 0, "7+": 0}
        for sources, count in src_rows:
            n = sources or 0
            if n <= 0:
                continue  # 0 sources == no corroboration; not plotted as a bar
            elif n <= 2:
                buckets_src["1-2"] += count
            elif n <= 4:
                buckets_src["3-4"] += count
            elif n <= 6:
                buckets_src["5-6"] += count
            else:
                buckets_src["7+"] += count

        total_devices = sum(status_counts.values())
        validated = status_counts.get("VALIDATED", 0)
        if total_devices > 0:
            identification_trust = {
                "status_counts": status_counts,
                "source_buckets": buckets_src,
                "total": total_devices,
                "validated_pct": round(validated * 100 / total_devices),
            }
    except Exception:
        identification_trust = None

    # ==========================================================
    # Render
    # ==========================================================
    logger.debug(f"[Dashboard] Rendering with {len(scan_times)} CLI scans and {len(ondemand_scan_times)} on-demand scans")
    return templates.TemplateResponse(
        request,
        "index.html",
        {
            "hosts_total": hosts_total or 0,
            "hosts_scanned": hosts_scanned or 0,
            "hosts_enum": hosts_enum,
            "not_scanned": not_scanned,
            "scanned_only": scanned_only,
            "os_summary": {"counts": buckets, "top_items": top_items},
            "scan_times": scan_times,
            "ondemand_scan_times": ondemand_scan_times,
            "service_summary": service_summary,
            "device_categories": device_categories,
            "identification_trust": identification_trust,
        },
    )


# ==========================================================
# Hosts list
# ==========================================================
@router.get("/hosts", response_class=HTMLResponse)
async def hosts_view(
    request: Request,
    os: str = Query(None, description="Filter by OS family"),
    ip: str = Query(None, description="Filter by IP address"),
    session: AsyncSession = Depends(get_session)
):
    # Filter to only show hosts with Ports or OSGuesses (real Nmap/Masscan data)
    # This excludes enrichment results and script-only hosts
    base_host_filter = exists().where(Port.host_id == Host.id) | exists().where(OSGuess.host_id == Host.id)

    # Also explicitly exclude any host with "enrichment" in address or hostname
    enrichment_filter = ~(
        Host.address.ilike('%enrichment%') |
        (Host.hostname.isnot(None) & Host.hostname.ilike('%enrichment%'))
    )

    # Always fetch filtered hosts + related data for filtering
    all_hosts = (await session.execute(
        select(Host)
        .where(base_host_filter)
        .where(enrichment_filter)
        .options(
            selectinload(Host.ports),
            selectinload(Host.scripts),
            selectinload(Host.os_guesses),
            selectinload(Host.device_info)  # Include device fingerprint info
        )
    )).scalars().unique().all()

    top_map = {h.id: _top_guess(h) for h in all_hosts}

    # Build device_info map for enhanced OS display
    device_info_map = {h.id: h.device_info for h in all_hosts if h.device_info}

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

    # Priority 2: OS family filter (DeviceInfo preferred, OSGuess fallback)
    elif os:
        os_lower = os.lower()
        filtered_hosts = []
        for h in all_hosts:
            di = h.device_info
            tg = top_map[h.id]
            # Determine family using same priority as dashboard
            fam = ""
            if di and (di.confidence or 0) > 0:
                fam = _bucket_family_from_device_info(di)
            if not fam and tg:
                fam = _bucket_family(tg)
            if not fam:
                fam = "Unknown"
            if fam.lower() == os_lower:
                filtered_hosts.append(h)
        hosts = filtered_hosts

    # Default: show all hosts
    else:
        hosts = all_hosts

    # Per-host count of (non-archived) notes that reference each host, for the
    # Notes column badge on each row.
    from sqlalchemy import func as _sa_func
    note_counts = (await session.execute(
        select(NoteHostLink.host_id, _sa_func.count(NoteHostLink.note_id))
        .join(Note, Note.id == NoteHostLink.note_id)
        .where(Note.archived == False)  # noqa: E712
        .group_by(NoteHostLink.host_id)
    )).all()
    note_count_map = {hid: cnt for hid, cnt in note_counts}

    # Send all hosts to the template — DataTables handles client-side
    # pagination, sorting, and searching over the full dataset.
    return templates.TemplateResponse(
        request,
        "hosts.html",
        {
            "hosts": hosts,
            "top_os_map": top_map,
            "device_info_map": device_info_map,  # Enhanced fingerprint data
            "note_count_map": note_count_map,
            "filter_os": os,
            "filter_ip": ip,
        }
    )


# ==========================================================
# Host detail
# ==========================================================
@router.get("/hosts/{host_id}", response_class=HTMLResponse)
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
            selectinload(Host.os_guesses),
            selectinload(Host.device_info)
        )
        .where(Host.id == host_id)
    )).scalars().first()

    if not host:
        return HTMLResponse(f"<h1>Host {host_id} not found</h1>", status_code=404)

    top_guess = _top_guess(host)

    # Try to locate raw scan files
    nmap_output = xml_output = gnmap_output = None

    # Search in standard nmap directory
    base = Path(settings.RESULTS_DIR) / "nmap"
    if base.exists():
        for sub in base.rglob(f"{host.address}*"):
            if sub.suffix == ".nmap" and not nmap_output:
                nmap_output = sub.read_text(errors="ignore")
            elif sub.suffix == ".xml" and not xml_output:
                xml_output = sub.read_text(errors="ignore")
            elif sub.suffix == ".gnmap" and not gnmap_output:
                gnmap_output = sub.read_text(errors="ignore")

    # Also search in ondemand-scans subdirectories
    ondemand_base = Path(settings.RESULTS_DIR) / "ondemand-scans"
    if ondemand_base.exists() and (not nmap_output or not xml_output or not gnmap_output):
        # Search through all timestamped scan directories
        for scan_dir in sorted(ondemand_base.iterdir(), reverse=True):
            if not scan_dir.is_dir():
                continue

            nmap_dir = scan_dir / "nmap"
            if not nmap_dir.exists():
                continue

            # Search for files matching the host address
            for sub in nmap_dir.rglob(f"{host.address}*"):
                if sub.suffix == ".nmap" and not nmap_output:
                    nmap_output = sub.read_text(errors="ignore")
                elif sub.suffix == ".xml" and not xml_output:
                    xml_output = sub.read_text(errors="ignore")
                elif sub.suffix == ".gnmap" and not gnmap_output:
                    gnmap_output = sub.read_text(errors="ignore")

            # If we found all files, we can stop searching
            if nmap_output and xml_output and gnmap_output:
                break

    # Extract scan timing information from XML if available
    scan_start = None
    scan_end = None
    if xml_output:
        try:
            root = ET.fromstring(xml_output)
            # Get start time from nmaprun element
            start_attr = root.get('start')
            if start_attr:
                scan_start = datetime.fromtimestamp(int(start_attr))
            # Get end time from runstats element
            runstats = root.find('.//runstats/finished')
            if runstats is not None:
                end_attr = runstats.get('time')
                if end_attr:
                    scan_end = datetime.fromtimestamp(int(end_attr))
        except Exception as e:
            logger.warning(f"Failed to extract scan timing from XML: {e}")

    # Parse evidence JSON for template (may be stored as string)
    evidence_parsed = []
    if host.device_info and host.device_info.evidence:
        ev = host.device_info.evidence
        if isinstance(ev, str):
            try:
                evidence_parsed = json.loads(ev)
            except (json.JSONDecodeError, TypeError):
                evidence_parsed = []
        elif isinstance(ev, list):
            evidence_parsed = ev

    # Gather plugin / module results filtered to this host. Each entry is a
    # subset of cygor-result.json with only the rows whose host/target/ip
    # field matches the current host. Empty modules are dropped so the UI
    # only shows what's actually relevant.
    host_module_results = []
    try:
        results_root = Path(os.environ.get("CYGOR_WORKSPACE") or os.environ.get("CYGOR_RESULTS_DIR") or settings.RESULTS_DIR)
        modules_dir = results_root / "cygor-enumeration-modules"
        addr = (host.address or "").lower()
        hostname = (host.hostname or "").lower() if hasattr(host, "hostname") else ""
        if modules_dir.exists() and addr:
            for slug_dir in sorted(modules_dir.iterdir()):
                if not slug_dir.is_dir():
                    continue
                jf = slug_dir / "cygor-result.json"
                if not jf.exists():
                    continue
                try:
                    parsed = json.loads(jf.read_text(encoding="utf-8"))
                except Exception:
                    continue
                if not isinstance(parsed, dict):
                    continue
                rows = parsed.get("results") or []
                matched = []
                for r in rows:
                    if not isinstance(r, dict):
                        continue
                    candidates = [
                        str(r.get("host", "")).lower(),
                        str(r.get("target", "")).lower(),
                        str(r.get("ip", "")).lower(),
                        str(r.get("address", "")).lower(),
                    ]
                    if addr in candidates or (hostname and hostname in candidates):
                        matched.append(r)
                if matched:
                    host_module_results.append({
                        "module": parsed.get("module", {"slug": slug_dir.name, "name": slug_dir.name}),
                        "schema": parsed.get("schema", {"columns": []}),
                        "results": matched,
                    })
    except Exception as e:
        logger.warning(f"Failed to gather host_module_results for {getattr(host, 'address', '?')}: {e}")

    # Pull EnrichmentFinding rows for this host. We bucket them so the
    # template can render dedicated cards: Certificate, External Visibility,
    # AI Services, MCP Services. The buckets are keyed off finding_kind so
    # adding a new kind in a future phase doesn't require a route change.
    enrichment_buckets: Dict[str, List[Any]] = {
        "cert": [],
        "ai": [],
        "mcp": [],
        "observation": [],   # External Visibility (shodan, vt, abuseipdb, ...)
    }
    enrichment_run_ids: List[int] = []
    try:
        from ..models import EnrichmentFinding as _EnrichmentFinding
        stmt = (
            select(_EnrichmentFinding)
            .where(_EnrichmentFinding.host_id == host.id)
            .order_by(_EnrichmentFinding.enriched_at.desc())
        )
        ef_rows = (await session.execute(stmt)).scalars().all()
        for row in ef_rows:
            if row.run_id and row.run_id not in enrichment_run_ids:
                enrichment_run_ids.append(row.run_id)
            kind = row.finding_kind or "observation"
            if kind == "cert":
                enrichment_buckets["cert"].append(row)
            elif kind == "ai_indicator":
                enrichment_buckets["ai"].append(row)
            elif kind == "mcp_indicator":
                enrichment_buckets["mcp"].append(row)
            else:
                enrichment_buckets["observation"].append(row)
    except Exception as e:
        logger.warning(f"Failed to gather enrichment findings for host {host.id}: {e}")

    # Suggested next steps: evidence-driven recommendations computed from what
    # cygor actually observed for this host (open ports + module results).
    next_steps = []
    try:
        from cygor.nextsteps import build_host_panel
        port_dicts = [{"port": p.port, "service": p.service, "state": p.state}
                      for p in host.ports]
        next_steps = build_host_panel(host.address, host_module_results,
                                      port_dicts)
    except Exception as e:
        logger.warning(f"Failed to build next steps for host {host.id}: {e}")

    # Backlinks: every (non-archived) note that references this host via the
    # many-to-many link table. Pinned notes float to the top.
    host_notes = (await session.execute(
        select(Note)
        .where(Note.id.in_(
            select(NoteHostLink.note_id).where(NoteHostLink.host_id == host_id)
        ))
        .where(Note.archived == False)  # noqa: E712
        .order_by(Note.pinned.desc(), Note.updated_at.desc())
    )).scalars().all()

    return templates.TemplateResponse(request, "host_detail.html", {
        "h": host,
        "host_notes": host_notes,
        "os_guesses": host.os_guesses,
        "top_guess": top_guess,
        "device_info": host.device_info,
        "evidence_data": evidence_parsed,
        "nmap_output": nmap_output,
        "xml_output": xml_output,
        "gnmap_output": gnmap_output,
        "scan_start": scan_start,
        "scan_end": scan_end,
        "scripts": host.scripts,
        "host_module_results": host_module_results,
        "next_steps": next_steps,
        "enrichment_buckets": enrichment_buckets,
        "enrichment_run_ids": enrichment_run_ids,
    })


# ==========================================================
# Services overview
# ==========================================================
@router.get("/services", response_class=HTMLResponse)
async def services_view(
    request: Request,
    session: AsyncSession = Depends(get_session)
):
    ports = (await session.execute(
        select(Port).options(selectinload(Port.host))
    )).scalars().unique().all()

    service_counts: dict[str, set] = {}
    service_ports: dict[str, Counter] = {}
    service_products: dict[str, Counter] = {}
    service_port_total: dict[str, int] = {}

    for p in ports:
        svc = normalize_service(p.service)
        service_counts.setdefault(svc, set()).add(p.host.address)
        service_port_total[svc] = service_port_total.get(svc, 0) + 1
        service_ports.setdefault(svc, Counter())[p.port] += 1
        if p.product:
            prod_str = p.product + (f" {p.version}" if p.version else "")
            service_products.setdefault(svc, Counter())[prod_str] += 1

    service_data = {}
    for svc, hosts in service_counts.items():
        service_data[svc] = {
            "host_count": len(hosts),
            "port_count": service_port_total.get(svc, 0),
            "common_ports": [port for port, _ in service_ports.get(svc, Counter()).most_common(3)],
            "top_products": [prod for prod, _ in service_products.get(svc, Counter()).most_common(2)],
        }

    total_hosts = len({p.host.address for p in ports})
    total_port_instances = sum(d["port_count"] for d in service_data.values())

    most_common = max(service_data.items(), key=lambda x: x[1]["host_count"], default=("none", {"host_count": 0}))
    most_common_service = (most_common[0], most_common[1]["host_count"])

    return templates.TemplateResponse(
        request,
        "services.html",
        {
            "service_data": service_data,
            "total_hosts": total_hosts,
            "total_services": len(service_data),
            "total_port_instances": total_port_instances,
            "most_common_service": most_common_service,
        }
    )


# --------------------------------------------------------
# Service detail page: /services/{service_name}
# --------------------------------------------------------
@router.get("/services/{service_name}", response_class=HTMLResponse)
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

    # Enrichment: common ports, top products
    port_counter: Counter = Counter()
    product_counter: Counter = Counter()
    for p in matching_ports:
        port_counter[p.port] += 1
        if p.product:
            prod_str = p.product + (f" {p.version}" if p.version else "")
            product_counter[prod_str] += 1
    common_ports = [port for port, _ in port_counter.most_common(5)]
    top_products = [prod for prod, _ in product_counter.most_common(3)]

    # Apply pagination
    total_items = len(matching_ports)
    total_pages = (total_items + per_page - 1) // per_page if total_items > 0 else 1
    page = min(page, total_pages)
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    host_services = matching_ports[start_idx:end_idx]

    return templates.TemplateResponse(
        request,
        "service_detail.html",
        {
            "service": service_name,
            "host_services": host_services,
            "host_count": host_count,
            "total_hosts": total_hosts,
            "total_port_instances": len(matching_ports),
            "common_ports": common_ports,
            "top_products": top_products,
            "page": page,
            "per_page": per_page,
            "total_items": total_items,
            "total_pages": total_pages,
        },
    )
