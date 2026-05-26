"""Search page, API search, saved searches, and dashboard analytics routes."""

import csv
import gzip
import json
import logging
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ..db import get_session
from ..models import Host, Port, Script, SavedSearch
from ..config import settings
from ..helpers import gather_scan_times, gather_ondemand_scan_times, extract_host_key

logger = logging.getLogger(__name__)

router = APIRouter(tags=["search"])

templates = None


def set_templates(tmpl):
    global templates
    templates = tmpl


# -------- Search Page --------
@router.get("/search", response_class=HTMLResponse)
async def search(
    request: Request,
    q: str = Query("", description="Search query"),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(settings.DEFAULT_PAGE_SIZE, ge=1, le=settings.MAX_PAGE_SIZE, description="Items per page"),
    filter: List[str] = Query(default=[], description="Filter types (hosts, services, scripts, banners)"),
    port_min: Optional[str] = Query(default=None, description="Minimum port"),
    port_max: Optional[str] = Query(default=None, description="Maximum port"),
    sort: str = Query("relevance", description="Sort order"),
    case_insensitive: bool = Query(True, description="Case-insensitive search"),
    session: AsyncSession = Depends(get_session)
):
    from ..search_parser import parse_search_query
    from ..search_builder import SearchQueryBuilder

    q = (q or "").strip()
    all_hosts = all_ports = all_scripts = []
    hosts_total = ports_total = scripts_total = 0

    # Parse the query
    filters = parse_search_query(q) if q else {}

    # Convert port range strings to integers, handling empty strings
    port_min_int = None
    port_max_int = None
    if port_min and port_min.strip():
        try:
            port_min_int = int(port_min)
            if port_min_int < 1 or port_min_int > 65535:
                port_min_int = None
        except ValueError:
            pass

    if port_max and port_max.strip():
        try:
            port_max_int = int(port_max)
            if port_max_int < 1 or port_max_int > 65535:
                port_max_int = None
        except ValueError:
            pass

    # Add port range from form if specified
    if port_min_int is not None or port_max_int is not None:
        if 'port_ranges' not in filters:
            filters['port_ranges'] = []
        filters['port_ranges'].append({
            'min': port_min_int or 1,
            'max': port_max_int or 65535,
            'negated': False
        })

    # Determine which result types to show based on filter checkboxes
    show_hosts = not filter or 'hosts' in filter
    show_services = not filter or 'services' in filter or 'banners' in filter
    show_scripts = not filter or 'scripts' in filter

    if q or port_min_int or port_max_int:
        builder = SearchQueryBuilder(session)

        # Build and execute host query
        if show_hosts:
            host_query = await builder.build_host_query(filters, case_insensitive)
            host_query = builder.apply_sorting(host_query, Host, sort)

            # Get total count
            count_result = await session.execute(
                select(func.count()).select_from(host_query.subquery())
            )
            hosts_total = count_result.scalar() or 0

            # Apply pagination
            host_query = builder.apply_pagination(host_query, page, per_page)
            host_result = await session.execute(host_query)
            all_hosts = host_result.scalars().unique().all()

        # Build and execute port query
        if show_services:
            port_query = await builder.build_port_query(filters, case_insensitive)
            port_query = builder.apply_sorting(port_query, Port, sort)

            # Get total count
            count_result = await session.execute(
                select(func.count()).select_from(port_query.subquery())
            )
            ports_total = count_result.scalar() or 0

            # Apply pagination
            port_query = builder.apply_pagination(port_query, page, per_page)
            port_result = await session.execute(port_query)
            all_ports = port_result.scalars().unique().all()

        # Build and execute script query
        if show_scripts:
            script_query = await builder.build_script_query(filters, case_insensitive)

            # Get total count
            count_result = await session.execute(
                select(func.count()).select_from(script_query.subquery())
            )
            scripts_total = count_result.scalar() or 0

            # Apply pagination
            script_query = builder.apply_pagination(script_query, page, per_page)
            script_result = await session.execute(script_query)
            all_scripts = script_result.scalars().unique().all()

    # Calculate page counts
    hosts_pages = (hosts_total + per_page - 1) // per_page if hosts_total > 0 else 1
    ports_pages = (ports_total + per_page - 1) // per_page if ports_total > 0 else 1
    scripts_pages = (scripts_total + per_page - 1) // per_page if scripts_total > 0 else 1

    return templates.TemplateResponse(request, "search.html", {
        "query": q,
        "hosts": all_hosts,
        "ports": all_ports,
        "scripts": all_scripts,
        "page": page,
        "per_page": per_page,
        "hosts_total": hosts_total,
        "ports_total": ports_total,
        "scripts_total": scripts_total,
        "hosts_pages": hosts_pages,
        "ports_pages": ports_pages,
        "scripts_pages": scripts_pages,
        "filters": filter,
        "port_min": port_min_int,
        "port_max": port_max_int,
        "sort": sort,
        "case_insensitive": case_insensitive,
    })


# -------- Dashboard API Endpoints --------
@router.get("/api/dashboard/identified-services")
async def get_identified_services():
    """
    Get identified services with product/version information from nmap scans.
    Parses XML files to extract service name, product, version, extrainfo, tunnel, etc.
    """
    services_data = defaultdict(lambda: {"count": 0})

    # Gather all scan files
    try:
        scan_times = gather_scan_times(settings.RESULTS_DIR)
    except Exception:
        scan_times = []

    try:
        ondemand_scan_times = gather_ondemand_scan_times(settings.RESULTS_DIR)
    except Exception:
        ondemand_scan_times = []

    all_scans = scan_times + ondemand_scan_times

    # Parse each XML file to extract service information
    for scan in all_scans:
        scan_path = Path(settings.RESULTS_DIR) / scan.get("path")

        # Only process XML files
        if not (scan_path.suffix.lower() == ".xml" or scan_path.suffix.lower() == ".gz"):
            continue

        try:
            # Handle gzipped XML files
            if scan_path.suffix.lower() == ".gz":
                with gzip.open(scan_path, 'rt', encoding='utf-8', errors='ignore') as f:
                    tree = ET.parse(f)
            else:
                tree = ET.parse(scan_path)

            root = tree.getroot()

            # Find all service elements
            for service_elem in root.findall(".//service"):
                name = service_elem.get("name", "unknown")
                product = service_elem.get("product", "")
                version = service_elem.get("version", "")
                extrainfo = service_elem.get("extrainfo", "")
                tunnel = service_elem.get("tunnel", "")

                # ONLY include services that have product information
                # This filters out basic service names (http, ssh, etc.) that don't have version detection
                if not product:
                    continue

                # Build service description with product and version
                service_desc = product
                if version:
                    service_desc += f" {version}"
                if extrainfo:
                    service_desc += f" ({extrainfo})"
                if tunnel:
                    service_desc += f" [tunnel: {tunnel}]"

                # Track this service
                service_key = service_desc
                services_data[service_key]["count"] += 1

        except Exception as e:
            logger.debug(f"Error parsing {scan_path}: {e}")
            continue

    # Convert to sorted list
    services_list = []
    for service_name, data in services_data.items():
        services_list.append({
            "service": service_name,
            "count": data["count"]
        })

    # Sort by count descending
    services_list.sort(key=lambda x: -x["count"])

    return JSONResponse({"services": services_list})


@router.get("/api/dashboard/timeline-data")
async def get_timeline_data(session: AsyncSession = Depends(get_session)):
    """
    Get cumulative hosts and ports over time for the dashboard timeline chart.
    Returns time-series data showing the growth of discovered hosts and open ports.
    """
    # Gather all scan times
    try:
        scan_times = gather_scan_times(settings.RESULTS_DIR)
    except Exception:
        scan_times = []

    try:
        ondemand_scan_times = gather_ondemand_scan_times(settings.RESULTS_DIR)
    except Exception:
        ondemand_scan_times = []

    # Combine all scans
    all_scans = scan_times + ondemand_scan_times

    # Sort by start time
    def parse_iso_safe(iso_str):
        if not iso_str:
            return datetime.fromtimestamp(0, tz=timezone.utc)
        try:
            dt = datetime.fromisoformat(iso_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return datetime.fromtimestamp(0, tz=timezone.utc)

    all_scans.sort(key=lambda s: parse_iso_safe(s.get("start")))

    # Track cumulative counts
    timestamps = []
    cumulative_hosts = []
    cumulative_ports = []

    unique_hosts = set()
    total_ports = 0

    # Get all ports from database for port counting (with eager loading of host)
    ports = (await session.execute(
        select(Port).options(selectinload(Port.host))
    )).scalars().all()
    host_to_ports = defaultdict(int)
    for p in ports:
        host_to_ports[p.host.address] += 1

    for scan in all_scans:
        start_time = scan.get("start")
        if not start_time:
            continue

        # Extract host from scan
        host_key = extract_host_key(scan.get("label") or scan.get("path"))
        if host_key:
            unique_hosts.add(host_key)
            # Add ports for this host if any
            if host_key in host_to_ports:
                total_ports += host_to_ports[host_key]
                # Remove from dict so we don't count twice
                del host_to_ports[host_key]

        # Record cumulative counts at this timestamp
        timestamps.append(start_time)
        cumulative_hosts.append(len(unique_hosts))
        cumulative_ports.append(total_ports)

    return JSONResponse({
        "timestamps": timestamps,
        "cumulative_hosts": cumulative_hosts,
        "cumulative_ports": cumulative_ports
    })


@router.get("/api/dashboard/scan-speed-data")
async def get_scan_speed_data(session: AsyncSession = Depends(get_session)):
    """
    Get ports tested per second for each host.
    Returns data for horizontal bar chart showing scan speed by host.
    """
    # Gather all scan times
    try:
        scan_times = gather_scan_times(settings.RESULTS_DIR)
    except Exception:
        scan_times = []

    try:
        ondemand_scan_times = gather_ondemand_scan_times(settings.RESULTS_DIR)
    except Exception:
        ondemand_scan_times = []

    # Combine all scans
    all_scans = scan_times + ondemand_scan_times

    # Get port counts per host from database (with eager loading of host)
    ports = (await session.execute(
        select(Port).options(selectinload(Port.host))
    )).scalars().all()
    host_to_ports = {}
    for p in ports:
        host_addr = p.host.address
        host_to_ports[host_addr] = host_to_ports.get(host_addr, 0) + 1

    # Calculate ports per second for each scan
    host_speeds = {}

    for scan in all_scans:
        start = scan.get("start")
        end = scan.get("end")

        if not start or not end:
            continue

        try:
            # Parse timestamps
            start_dt = datetime.fromisoformat(start.replace('Z', '+00:00'))
            end_dt = datetime.fromisoformat(end.replace('Z', '+00:00'))

            # Calculate duration in seconds
            duration = (end_dt - start_dt).total_seconds()

            if duration <= 0:
                continue

            # Get host from scan
            host_key = extract_host_key(scan.get("label") or scan.get("path"))
            if not host_key:
                continue

            # Get port count for this host
            port_count = host_to_ports.get(host_key, 0)

            if port_count > 0:
                # Calculate ports per second
                ports_per_second = port_count / duration

                # Store the highest speed for each host (in case multiple scans)
                if host_key not in host_speeds or ports_per_second > host_speeds[host_key]:
                    host_speeds[host_key] = ports_per_second

        except Exception as e:
            logger.debug(f"Error calculating scan speed: {e}")
            continue

    # Sort by speed (descending) and take top 20
    sorted_hosts = sorted(host_speeds.items(), key=lambda x: -x[1])[:20]

    hosts = [h[0] for h in sorted_hosts]
    speeds = [round(h[1], 2) for h in sorted_hosts]

    return JSONResponse({
        "hosts": hosts,
        "speeds": speeds
    })


# -------- Search API Endpoints --------
@router.get("/api/search")
async def api_search(
    q: str = Query("", description="Search query"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    filter: List[str] = Query(default=[]),
    port_min: Optional[int] = Query(default=None),
    port_max: Optional[int] = Query(default=None),
    sort: str = Query("relevance"),
    case_insensitive: bool = Query(True),
    session: AsyncSession = Depends(get_session)
):
    """JSON API endpoint for search."""
    from ..search_parser import parse_search_query
    from ..search_builder import SearchQueryBuilder

    q = (q or "").strip()
    filters = parse_search_query(q) if q else {}

    # Add port range
    if port_min is not None or port_max is not None:
        if 'port_ranges' not in filters:
            filters['port_ranges'] = []
        filters['port_ranges'].append({
            'min': port_min or 1,
            'max': port_max or 65535,
            'negated': False
        })

    show_hosts = not filter or 'hosts' in filter
    show_services = not filter or 'services' in filter
    show_scripts = not filter or 'scripts' in filter

    results = {
        'query': q,
        'page': page,
        'per_page': per_page,
        'hosts': {'total': 0, 'results': []},
        'ports': {'total': 0, 'results': []},
        'scripts': {'total': 0, 'results': []}
    }

    if q or port_min or port_max:
        builder = SearchQueryBuilder(session)

        # Hosts
        if show_hosts:
            host_query = await builder.build_host_query(filters, case_insensitive)
            host_query = builder.apply_sorting(host_query, Host, sort)

            count_result = await session.execute(
                select(func.count()).select_from(host_query.subquery())
            )
            total = count_result.scalar() or 0

            host_query = builder.apply_pagination(host_query, page, per_page)
            host_result = await session.execute(host_query)
            hosts = host_result.scalars().unique().all()

            results['hosts'] = {
                'total': total,
                'results': [{'id': h.id, 'address': h.address, 'hostname': h.hostname} for h in hosts]
            }

        # Ports
        if show_services:
            port_query = await builder.build_port_query(filters, case_insensitive)
            port_query = builder.apply_sorting(port_query, Port, sort)

            count_result = await session.execute(
                select(func.count()).select_from(port_query.subquery())
            )
            total = count_result.scalar() or 0

            port_query = builder.apply_pagination(port_query, page, per_page)
            port_result = await session.execute(port_query)
            ports = port_result.scalars().unique().all()

            results['ports'] = {
                'total': total,
                'results': [{
                    'id': p.id,
                    'port': p.port,
                    'protocol': p.protocol,
                    'service': p.service,
                    'banner': p.banner[:200] if p.banner else None,
                    'host': {'address': p.host.address, 'hostname': p.host.hostname} if p.host else None
                } for p in ports]
            }

        # Scripts
        if show_scripts:
            script_query = await builder.build_script_query(filters, case_insensitive)

            count_result = await session.execute(
                select(func.count()).select_from(script_query.subquery())
            )
            total = count_result.scalar() or 0

            script_query = builder.apply_pagination(script_query, page, per_page)
            script_result = await session.execute(script_query)
            scripts = script_result.scalars().unique().all()

            results['scripts'] = {
                'total': total,
                'results': [{
                    'id': s.id,
                    'name': s.name,
                    'output': s.output[:250],
                    'host': {'address': s.host.address} if s.host else None
                } for s in scripts]
            }

    return results


@router.get("/api/search/suggest")
async def search_suggest(
    q: str = Query("", min_length=0, max_length=200),
    limit: int = Query(8, ge=1, le=20),
    session: AsyncSession = Depends(get_session),
):
    """Live-typeahead suggestions for the search bar.

    Returns up to ``limit`` rows mixed across hosts (IP/hostname prefix
    match) and services (service name prefix match). Each row is a
    {kind, title, desc, value} object the editor's JS can render and
    insert into the search input.

    Empty / very short queries return an empty list — the frontend
    falls back to the static syntax cheat-sheet in that case so the
    dropdown is never spammy.
    """
    q = (q or "").strip()
    if len(q) < 2:
        return {"suggestions": []}

    pat = f"%{q}%"
    out = []

    # Hosts: prefix-match on address, contains on hostname
    host_q = (
        select(Host.id, Host.address, Host.hostname)
        .where((Host.address.ilike(pat)) | (Host.hostname.ilike(pat)))
        .order_by(Host.address)
        .limit(limit)
    )
    for hid, addr, hostname in (await session.execute(host_q)).all():
        out.append({
            "kind": "host",
            "title": addr,
            "desc": hostname or "host",
            "value": addr,
            "href": f"/hosts/{hid}",
        })

    remaining = max(0, limit - len(out))
    if remaining > 0:
        # Services: aggregate distinct service names matching q
        svc_q = (
            select(Port.service, func.count(Port.id).label("cnt"))
            .where(Port.service.ilike(pat))
            .group_by(Port.service)
            .order_by(func.count(Port.id).desc())
            .limit(remaining)
        )
        for service, cnt in (await session.execute(svc_q)).all():
            if not service:
                continue
            out.append({
                "kind": "service",
                "title": f"service:{service}",
                "desc": f"{cnt} port{'s' if cnt != 1 else ''}",
                "value": f"service:{service}",
            })

    return {"suggestions": out}


@router.post("/api/search/save")
async def save_search(
    name: str = Query(..., max_length=100),
    description: Optional[str] = Query(None, max_length=500),
    query: str = Query(..., max_length=1000),
    filters: Optional[str] = Query(None),
    is_shared: bool = Query(False),
    session: AsyncSession = Depends(get_session)
):
    """Save a search query for later use."""
    # Parse filters if provided
    filters_dict = None
    if filters:
        try:
            filters_dict = json.loads(filters)
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid filters JSON")

    saved_search = SavedSearch(
        name=name,
        description=description,
        query=query,
        filters=filters_dict,
        is_shared=is_shared
    )

    session.add(saved_search)
    await session.commit()
    await session.refresh(saved_search)

    return {
        "success": True,
        "id": saved_search.id,
        "message": f"Search '{name}' saved successfully"
    }


@router.get("/api/search/saved")
async def list_saved_searches(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=100),
    session: AsyncSession = Depends(get_session)
):
    """List all saved searches."""
    query = select(SavedSearch).order_by(SavedSearch.created_at.desc())
    result = await session.execute(query)
    searches = result.scalars().all()

    return {
        "total": len(searches),
        "saved_searches": [{
            "id": s.id,
            "name": s.name,
            "description": s.description,
            "query": s.query,
            "is_shared": s.is_shared,
            "use_count": s.use_count,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "last_used": s.last_used.isoformat() if s.last_used else None
        } for s in searches]
    }


@router.delete("/api/search/saved/{search_id}")
async def delete_saved_search(
    search_id: int,
    session: AsyncSession = Depends(get_session)
):
    """Delete a saved search."""
    result = await session.execute(
        select(SavedSearch).where(SavedSearch.id == search_id)
    )
    search = result.scalar_one_or_none()

    if not search:
        raise HTTPException(status_code=404, detail="Saved search not found")

    await session.delete(search)
    await session.commit()

    return {"success": True, "message": "Search deleted successfully"}


@router.get("/api/search/export")
async def export_search_results(
    q: str = Query("", description="Search query"),
    filter: List[str] = Query(default=[]),
    port_min: Optional[int] = Query(default=None),
    port_max: Optional[int] = Query(default=None),
    format: str = Query("csv", pattern="^(csv|json|xml)$"),
    session: AsyncSession = Depends(get_session)
):
    """Export search results in various formats."""
    from ..search_parser import parse_search_query
    from ..search_builder import SearchQueryBuilder

    q = (q or "").strip()
    filters = parse_search_query(q) if q else {}

    # Add port range
    if port_min is not None or port_max is not None:
        if 'port_ranges' not in filters:
            filters['port_ranges'] = []
        filters['port_ranges'].append({
            'min': port_min or 1,
            'max': port_max or 65535,
            'negated': False
        })

    show_hosts = not filter or 'hosts' in filter
    show_services = not filter or 'services' in filter

    builder = SearchQueryBuilder(session)
    all_data = []

    # Collect all results (no pagination for export)
    if q or port_min or port_max:
        if show_hosts:
            host_query = await builder.build_host_query(filters, case_insensitive=True)
            host_result = await session.execute(host_query)
            hosts = host_result.scalars().unique().all()

            for h in hosts:
                all_data.append({
                    'type': 'host',
                    'address': h.address,
                    'hostname': h.hostname or '',
                    'port': '',
                    'service': '',
                    'banner': ''
                })

        if show_services:
            port_query = await builder.build_port_query(filters, case_insensitive=True)
            port_result = await session.execute(port_query)
            ports = port_result.scalars().unique().all()

            for p in ports:
                all_data.append({
                    'type': 'service',
                    'address': p.host.address if p.host else '',
                    'hostname': p.host.hostname or '' if p.host else '',
                    'port': str(p.port),
                    'service': p.service or '',
                    'banner': (p.banner or '')[:500]
                })

    # Generate export based on format
    if format == "csv":
        output = StringIO()
        if all_data:
            writer = csv.DictWriter(output, fieldnames=['type', 'address', 'hostname', 'port', 'service', 'banner'])
            writer.writeheader()
            writer.writerows(all_data)

        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=cygor_search_export.csv"}
        )

    elif format == "json":
        return StreamingResponse(
            iter([json.dumps({'query': q, 'results': all_data}, indent=2)]),
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=cygor_search_export.json"}
        )

    elif format == "xml":
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<search_results>', f'  <query>{q}</query>', '  <results>']
        for item in all_data:
            xml_lines.append('    <item>')
            for key, value in item.items():
                xml_lines.append(f'      <{key}>{value}</{key}>')
            xml_lines.append('    </item>')
        xml_lines.extend(['  </results>', '</search_results>'])

        return StreamingResponse(
            iter(['\n'.join(xml_lines)]),
            media_type="application/xml",
            headers={"Content-Disposition": "attachment; filename=cygor_search_export.xml"}
        )
