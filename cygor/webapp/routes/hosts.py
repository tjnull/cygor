"""Host-related routes: hostlists, host targets, tags, module configs."""

from pathlib import Path

from fastapi import APIRouter, Request, Depends, Query
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import Host, Port, OSGuess, HostTag
from ..config import settings

router = APIRouter(tags=["hosts"])

templates = None


def set_templates(tmpl):
    global templates
    templates = tmpl


# -------- Helper: scan available hostlists --------

def scan_available_hostlists() -> dict:
    """Scan workspace for available parsed hostlists and discovery results."""
    available_hostlists = {}
    parsed_dir = Path(settings.RESULTS_DIR) / "parsed-hostlists"

    if parsed_dir.exists():
        # Common service directories to check
        service_dirs = {
            "http": "HTTP Hosts",
            "https": "HTTPS Hosts",
            "http-https": "All Web Services",
            "smb": "SMB Hosts",
            "nfs": "NFS Hosts",
            "ftp": "FTP Hosts",
            "ssh": "SSH Hosts",
            "rdp": "RDP Hosts",
            "vnc": "VNC Hosts",
            "telnet": "Telnet Hosts",
            "winrm": "WinRM Hosts",
            "dns": "DNS Servers",
            "proxmox": "Proxmox Hosts",
            "mysql": "MySQL Databases",
            "postgres": "PostgreSQL Databases",
            "mssql": "MSSQL Databases",
            "mongodb": "MongoDB Databases",
            "redis": "Redis Servers",
        }

        for service_dir, label in service_dirs.items():
            hostlist_file = parsed_dir / service_dir / f"{service_dir}-hostlist.txt"
            if hostlist_file.exists():
                # Store relative path from RESULTS_DIR
                rel_path = f"parsed-hostlists/{service_dir}/{service_dir}-hostlist.txt"
                available_hostlists[service_dir] = {
                    "label": label,
                    "path": rel_path,
                    "count": len(hostlist_file.read_text().strip().split('\n')) if hostlist_file.stat().st_size > 0 else 0
                }

    # Also check for discovery results
    discovery_dir = Path(settings.RESULTS_DIR) / "discovery"
    if discovery_dir.exists():
        discovery_files = {
            "all-discovered-hosts.txt": "All Discovered Hosts",
            "masscan-discovered.txt": "Masscan Results",
            "naabu-discovered.txt": "Naabu Results"
        }
        for filename, label in discovery_files.items():
            filepath = discovery_dir / filename
            if filepath.exists():
                rel_path = f"discovery/{filename}"
                available_hostlists[f"discovery_{filename}"] = {
                    "label": label,
                    "path": rel_path,
                    "count": len(filepath.read_text().strip().split('\n')) if filepath.stat().st_size > 0 else 0
                }

    return available_hostlists


# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------

@router.get("/tasks/module/new", response_class=HTMLResponse)
async def new_module_page(request: Request):
    """Run module form page."""
    available_hostlists = scan_available_hostlists()
    return templates.TemplateResponse(request, "module_run.html", {
        "available_hostlists": available_hostlists
    })

@router.get("/api/hostlists")
async def get_available_hostlists():
    """API endpoint to get available hostlists (for dynamic reloading)."""
    return JSONResponse(scan_available_hostlists())


@router.get("/api/hosts/targets")
async def get_hosts_for_targets(
    session: AsyncSession = Depends(get_session),
    search: str = Query(None, description="Search filter for address/hostname"),
    limit: int = Query(100, ge=1, le=500, description="Max hosts to return")
):
    """API endpoint to get hosts from database for target selection."""
    from sqlalchemy import exists, or_

    # Filter to only show hosts with real scan data (ports or OS guesses)
    base_host_filter = exists().where(Port.host_id == Host.id) | exists().where(OSGuess.host_id == Host.id)

    # Exclude enrichment-only hosts
    enrichment_filter = ~(
        Host.address.ilike('%enrichment%') |
        (Host.hostname.isnot(None) & Host.hostname.ilike('%enrichment%'))
    )

    query = select(Host).where(base_host_filter).where(enrichment_filter)

    # Apply search filter if provided
    if search:
        search_pattern = f"%{search}%"
        query = query.where(
            or_(
                Host.address.ilike(search_pattern),
                Host.hostname.ilike(search_pattern)
            )
        )

    query = query.order_by(Host.last_seen.desc()).limit(limit)

    result = await session.execute(query)
    hosts = result.scalars().unique().all()

    return JSONResponse({
        "hosts": [
            {
                "id": h.id,
                "address": h.address,
                "hostname": h.hostname,
                "last_seen": h.last_seen.isoformat() if h.last_seen else None,
                "scan_count": h.scan_count
            }
            for h in hosts
        ],
        "total": len(hosts)
    })


# -------------------------------------------------------------------
# Host Tag API Endpoints
# -------------------------------------------------------------------

@router.get("/api/hosts/tags")
async def get_all_host_tags(session: AsyncSession = Depends(get_session)):
    """List all unique tags with host counts."""
    from sqlalchemy import func as sa_func
    result = await session.execute(
        select(HostTag.tag_name, sa_func.count(HostTag.host_id).label("host_count"))
        .group_by(HostTag.tag_name)
        .order_by(sa_func.count(HostTag.host_id).desc())
    )
    tags = [{"tag_name": row[0], "host_count": row[1]} for row in result.all()]
    return JSONResponse({"tags": tags})


@router.get("/api/hosts/{host_id}/tags")
async def get_host_tags(host_id: int, session: AsyncSession = Depends(get_session)):
    """Get all tags for a specific host."""
    result = await session.execute(
        select(HostTag).where(HostTag.host_id == host_id).order_by(HostTag.tag_name)
    )
    tags = result.scalars().all()
    return JSONResponse({
        "host_id": host_id,
        "tags": [{"id": t.id, "tag_name": t.tag_name, "created_at": t.created_at.isoformat()} for t in tags]
    })


@router.post("/api/hosts/{host_id}/tags")
async def add_host_tags(host_id: int, request: Request, session: AsyncSession = Depends(get_session)):
    """Add tag(s) to a host."""
    body = await request.json()
    tag_names = body.get("tags", [])
    if isinstance(tag_names, str):
        tag_names = [tag_names]

    host = await session.get(Host, host_id)
    if not host:
        return JSONResponse({"error": "Host not found"}, status_code=404)

    added = []
    for tag_name in tag_names:
        tag_name = tag_name.strip().lower()
        if not tag_name or len(tag_name) > 100:
            continue
        existing = await session.execute(
            select(HostTag).where(HostTag.host_id == host_id, HostTag.tag_name == tag_name)
        )
        if existing.scalar_one_or_none():
            continue
        tag = HostTag(host_id=host_id, tag_name=tag_name, created_by=None)
        session.add(tag)
        added.append(tag_name)

    await session.commit()
    return JSONResponse({"added": added, "host_id": host_id})


@router.delete("/api/hosts/{host_id}/tags/{tag_name}")
async def remove_host_tag(host_id: int, tag_name: str, request: Request,
                          session: AsyncSession = Depends(get_session)):
    """Remove a tag from a host."""
    result = await session.execute(
        select(HostTag).where(HostTag.host_id == host_id, HostTag.tag_name == tag_name.lower())
    )
    tag = result.scalar_one_or_none()
    if not tag:
        return JSONResponse({"error": "Tag not found"}, status_code=404)

    await session.delete(tag)
    await session.commit()
    return JSONResponse({"removed": tag_name, "host_id": host_id})


@router.post("/api/hosts/bulk-tag")
async def bulk_tag_hosts(request: Request, session: AsyncSession = Depends(get_session)):
    """Bulk assign a tag to multiple hosts."""
    body = await request.json()
    tag_name = body.get("tag_name", "").strip().lower()
    host_ids = body.get("host_ids", [])

    if not tag_name:
        return JSONResponse({"error": "tag_name required"}, status_code=400)

    added = []
    for hid in host_ids:
        existing = await session.execute(
            select(HostTag).where(HostTag.host_id == hid, HostTag.tag_name == tag_name)
        )
        if existing.scalar_one_or_none():
            continue
        tag = HostTag(host_id=hid, tag_name=tag_name, created_by=None)
        session.add(tag)
        added.append(hid)

    await session.commit()
    return JSONResponse({"tag_name": tag_name, "hosts_tagged": added})


@router.get("/api/hosts/by-tag/{tag_name}")
async def get_hosts_by_tag(tag_name: str, session: AsyncSession = Depends(get_session)):
    """Get all hosts with a specific tag."""
    result = await session.execute(
        select(Host).join(HostTag, Host.id == HostTag.host_id)
        .where(HostTag.tag_name == tag_name.lower())
        .order_by(Host.address)
    )
    hosts = result.scalars().unique().all()
    return JSONResponse({
        "tag_name": tag_name,
        "hosts": [
            {"id": h.id, "address": h.address, "hostname": h.hostname}
            for h in hosts
        ]
    })


@router.get("/api/hosts/resolve")
async def resolve_host_addresses(
    addresses: str = Query(..., description="Comma-separated IP addresses"),
    session: AsyncSession = Depends(get_session)
):
    """Resolve IP addresses to host IDs and their tags."""
    addr_list = [a.strip() for a in addresses.split(",") if a.strip()]
    if not addr_list:
        return JSONResponse({"hosts": {}})

    result = await session.execute(
        select(Host).where(Host.address.in_(addr_list))
    )
    hosts = result.scalars().unique().all()
    host_map = {h.address: h for h in hosts}

    # Batch-load tags for all found hosts
    host_ids = [h.id for h in hosts]
    tags_by_host: dict = {}
    if host_ids:
        tag_result = await session.execute(
            select(HostTag).where(HostTag.host_id.in_(host_ids))
        )
        for t in tag_result.scalars().all():
            tags_by_host.setdefault(t.host_id, []).append(t.tag_name)

    response = {}
    for addr in addr_list:
        h = host_map.get(addr)
        if h:
            response[addr] = {
                "host_id": h.id,
                "hostname": h.hostname,
                "tags": tags_by_host.get(h.id, [])
            }
        else:
            response[addr] = {"host_id": None, "hostname": None, "tags": []}

    return JSONResponse({"hosts": response})


@router.get("/api/module-configs")
async def get_module_configs():
    """API endpoint to get module configuration options."""
    # Module configuration with all available options
    module_configs = {
        "lockon": {
            "name": "Lockon - Screenshot Capture",
            "description": "Captures screenshots of HTTP/HTTPS, RDP, VNC, and X11 services. Uses Playwright with WebKit (default), Chromium, or Firefox for web screenshots and protocol-specific tools for remote desktop services. Select the protocol below and provide targets in the appropriate format (e.g., <code>http://IP:PORT</code> for web, <code>IP:PORT</code> for RDP/VNC).",
            "options": [
                # -- Common options (always visible) --
                {
                    "name": "protocol",
                    "label": "Protocol",
                    "type": "select",
                    "choices": [
                        {"value": "web", "label": "Web (HTTP & HTTPS)"},
                        {"value": "http", "label": "HTTP only"},
                        {"value": "https", "label": "HTTPS only"},
                        {"value": "rdp", "label": "RDP"},
                        {"value": "vnc", "label": "VNC"},
                        {"value": "x11", "label": "X11"},
                        {"value": "all", "label": "All protocols"}
                    ],
                    "default": "web",
                    "help": "Protocol to capture screenshots for"
                },
                {
                    "name": "workers",
                    "label": "Worker Threads",
                    "type": "number",
                    "min": 1,
                    "max": 256,
                    "help": "Number of concurrent worker threads (default: auto based on CPU count)"
                },
                {
                    "name": "timeout",
                    "label": "Capture Timeout (seconds)",
                    "type": "number",
                    "default": "30",
                    "min": 1,
                    "max": 300,
                    "help": "General capture timeout in seconds"
                },
                {
                    "name": "viewport",
                    "label": "Viewport Size",
                    "type": "text",
                    "default": "1366x768",
                    "pattern": "\\d+x\\d+",
                    "help": "Browser viewport size (WIDTHxHEIGHT)",
                    "show_when": {"protocol": ["web", "http", "https", "rdp", "all"]}
                },
                {
                    "name": "output_format",
                    "label": "Output Format",
                    "type": "select",
                    "choices": [
                        {"value": "all", "label": "All formats (default)"},
                        {"value": "json", "label": "JSON"},
                        {"value": "csv", "label": "CSV"},
                        {"value": "xml", "label": "XML"},
                        {"value": "txt", "label": "Text"}
                    ],
                    "default": "all",
                    "help": "Output file format for results"
                },
                # -- Web (HTTP/HTTPS) options --
                {
                    "name": "nav_timeout",
                    "label": "Navigation Timeout (ms)",
                    "type": "number",
                    "default": "45000",
                    "min": 1000,
                    "help": "Playwright page navigation timeout in milliseconds",
                    "show_when": {"protocol": ["web", "http", "https", "all"]}
                },
                {
                    "name": "extra_wait",
                    "label": "Extra Wait After Load (ms)",
                    "type": "number",
                    "default": "2000",
                    "min": 0,
                    "help": "Extra wait time after page load before taking screenshot (milliseconds)",
                    "show_when": {"protocol": ["web", "http", "https", "all"]}
                },
                {
                    "name": "status_filter",
                    "label": "HTTP Status Filter",
                    "type": "text",
                    "default": "200,301,302,307,308",
                    "help": "Comma-separated HTTP status codes to screenshot (0 = capture all status codes)",
                    "show_when": {"protocol": ["web", "http", "https", "all"]}
                },
                {
                    "name": "browser",
                    "label": "Browser Engine",
                    "type": "select",
                    "choices": [
                        {"value": "chromium", "label": "Chromium (default, most reliable)"},
                        {"value": "webkit", "label": "WebKit (lightweight; may lack system libs)"},
                        {"value": "firefox", "label": "Firefox"}
                    ],
                    "default": "chromium",
                    "help": "Browser engine for web screenshots. Chromium is the most reliable; "
                            "WebKit is lighter but often lacks required system libraries.",
                    "show_when": {"protocol": ["web", "http", "https", "all"]}
                },
                {
                    "name": "install_browsers",
                    "label": "Auto-install Browser",
                    "type": "checkbox",
                    "default": False,
                    "help": "Automatically install the selected browser engine if not found",
                    "show_when": {"protocol": ["web", "http", "https", "all"]}
                },
                # -- RDP options --
                {
                    "name": "rdp_user",
                    "label": "RDP Username",
                    "type": "text",
                    "help": "Username for RDP authentication (optional — needed for NLA servers)",
                    "show_when": {"protocol": ["rdp", "all"]}
                },
                {
                    "name": "rdp_pass",
                    "label": "RDP Password",
                    "type": "password",
                    "help": "Password for RDP authentication (optional)",
                    "show_when": {"protocol": ["rdp", "all"]}
                },
                # -- VNC options --
                {
                    "name": "password",
                    "label": "VNC Password",
                    "type": "password",
                    "help": "Password for authenticated VNC connections",
                    "show_when": {"protocol": ["vnc", "all"]}
                },
                # -- X11 options --
                {
                    "name": "displays",
                    "label": "X11 Displays",
                    "type": "text",
                    "default": "0",
                    "help": "X11 display numbers to scan (e.g., '0', '0-5', '0,1,2')",
                    "show_when": {"protocol": ["x11", "all"]}
                },
            ]
        },
        "smbexplorer": {
            "name": "SMB Explorer",
            "description": "Enumerates SMB shares, permissions, and accessible files on Windows/Samba hosts",
            "options": [
                {
                    "name": "username",
                    "label": "Username",
                    "type": "text",
                    "default": "guest",
                    "help": "Authentication username (default: guest)"
                },
                {
                    "name": "password",
                    "label": "Password",
                    "type": "password",
                    "help": "Authentication password"
                },
                {
                    "name": "domain",
                    "label": "Domain",
                    "type": "text",
                    "help": "Domain name for authentication"
                },
                {
                    "name": "ntlm_hash",
                    "label": "NTLM Hash",
                    "type": "text",
                    "help": "NTLM hash for pass-the-hash (LMHASH:NTHASH format)"
                },
                {
                    "name": "use_kerberos",
                    "label": "Use Kerberos",
                    "type": "checkbox",
                    "default": False,
                    "help": "Enable Kerberos authentication (requires one of the Kerberos options below)"
                },
                {
                    "name": "kerberos_keytab",
                    "label": "Kerberos Keytab File",
                    "type": "text",
                    "help": "Path to Kerberos keytab file (most common for service accounts)"
                },
                {
                    "name": "kerberos_aeskey",
                    "label": "Kerberos AES Key",
                    "type": "text",
                    "help": "AES key (128/256-bit hex) for pass-the-key attack"
                },
                {
                    "name": "kerberos_principal",
                    "label": "Kerberos Principal",
                    "type": "text",
                    "help": "Kerberos principal (e.g., user@DOMAIN.COM). If not specified, uses username@DOMAIN"
                },
                {
                    "name": "kerberos_ccache",
                    "label": "Kerberos Ccache File",
                    "type": "text",
                    "help": "Path to Kerberos ccache file (overrides KRB5CCNAME environment variable)"
                },
                {
                    "name": "list_files",
                    "label": "List Files",
                    "type": "checkbox",
                    "default": False,
                    "help": "List accessible files in each share"
                },
                {
                    "name": "max_files",
                    "label": "Max Files Per Share",
                    "type": "number",
                    "default": "50",
                    "min": 1,
                    "help": "Maximum number of files to list per share"
                },
                {
                    "name": "smb_output_format",
                    "label": "Output Format",
                    "type": "select",
                    "choices": [
                        {"value": "txt,csv,json,xml", "label": "Multiple formats (default)"},
                        {"value": "txt", "label": "Text"},
                        {"value": "csv", "label": "CSV"},
                        {"value": "json", "label": "JSON"},
                        {"value": "xml", "label": "XML"},
                        {"value": "all", "label": "All formats"}
                    ],
                    "default": "txt,csv,json,xml",
                    "help": "Output file format(s)"
                }
            ]
        },
        "nfsexplorer": {
            "name": "NFS Explorer",
            "description": "Interacts with NFS exports to analyze access levels and test UID/GID mappings",
            "options": [
                {
                    "name": "uid",
                    "label": "User ID (UID)",
                    "type": "number",
                    "default": "0",
                    "min": 0,
                    "help": "Fake UID to use for NFS requests (default: 0/root)"
                },
                {
                    "name": "gid",
                    "label": "Group ID (GID)",
                    "type": "number",
                    "default": "0",
                    "min": 0,
                    "help": "Fake GID to use for NFS requests (default: 0/root)"
                },
                {
                    "name": "aux_gids",
                    "label": "Auxiliary GIDs",
                    "type": "text",
                    "help": "Comma-separated auxiliary GIDs (e.g., 100,1000)"
                },
                {
                    "name": "timeout",
                    "label": "RPC Timeout (seconds)",
                    "type": "number",
                    "default": "10",
                    "min": 1,
                    "help": "RPC timeout in seconds"
                },
                {
                    "name": "recurse",
                    "label": "Recursion Depth",
                    "type": "number",
                    "default": "1",
                    "min": 0,
                    "max": 10,
                    "help": "Directory recursion depth (default: 1)"
                },
                {
                    "name": "list_files",
                    "label": "List Files",
                    "type": "checkbox",
                    "default": False,
                    "help": "List files/directories inside each share"
                },
                {
                    "name": "info",
                    "label": "Info Only",
                    "type": "checkbox",
                    "default": False,
                    "help": "Only show supported NFS versions/exports"
                },
                {
                    "name": "check_root",
                    "label": "Check no_root_squash",
                    "type": "checkbox",
                    "default": False,
                    "help": "Attempt to detect no_root_squash misconfigurations"
                },
                {
                    "name": "version",
                    "label": "NFS Version",
                    "type": "select",
                    "choices": [
                        {"value": "", "label": "Auto-detect (default)"},
                        {"value": "2", "label": "NFSv2"},
                        {"value": "3", "label": "NFSv3"},
                        {"value": "4", "label": "NFSv4"}
                    ],
                    "help": "Force specific NFS protocol version"
                },
                {
                    "name": "nfs_output_format",
                    "label": "Output Format",
                    "type": "select",
                    "choices": [
                        {"value": "text,csv,json,xml", "label": "Multiple formats (default)"},
                        {"value": "text", "label": "Text"},
                        {"value": "csv", "label": "CSV"},
                        {"value": "json", "label": "JSON"},
                        {"value": "xml", "label": "XML"},
                        {"value": "all", "label": "All formats"}
                    ],
                    "default": "text,csv,json,xml",
                    "help": "Output file format(s)"
                }
            ]
        }
    }

    # Merge discovered modules' option schemas on top of the hardcoded built-in
    # configs. Both built-in modules (e.g. dbprobe, dnsexplorer) and community
    # plugins live in cygor.webapp.main.DISCOVERED_MODULES and expose an
    # "options" list (from each module's module_info) whose dicts mirror the
    # shape used above. The hardcoded lockon/smb/nfs configs are richer, so we
    # never overwrite an existing entry.
    try:
        from cygor.webapp import main as main_module
        for spec in getattr(main_module, "DISCOVERED_MODULES", []) or []:
            if spec.slug in module_configs:
                continue  # keep the richer hardcoded config
            if not spec.options:
                continue  # nothing to configure -> runs with defaults
            suffix = " (community plugin)" if spec.source == "plugin" else ""
            module_configs[spec.slug] = {
                "name": spec.name,
                "description": spec.description or f"{spec.name}{suffix}",
                "options": spec.options or [],
            }
    except Exception as e:
        # A malformed plugin shouldn't break the form for everyone else.
        import logging
        logging.getLogger(__name__).warning(f"Failed to merge plugin options: {e}")

    return JSONResponse(module_configs)


@router.post("/api/findings/ingest")
async def api_ingest_findings(session: AsyncSession = Depends(get_session)):
    """Re-derive the findings index from the current enumeration module results.

    Reads cygor-enumeration-modules/*/cygor-result.json in the active workspace
    and rewrites the finding table (full replace; files are the source of truth).
    """
    import os
    from cygor.webapp.findings import ingest_findings
    ws = (os.environ.get("CYGOR_WORKSPACE") or os.environ.get("CYGOR_RESULTS_DIR")
          or str(settings.RESULTS_DIR))
    n = await ingest_findings(session, ws)
    return JSONResponse({"ingested": n, "workspace": ws})
