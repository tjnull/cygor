"""
Module-related routes: Lockon screenshots, SMB/NFS explorers,
dynamic enumeration module registration, and static page helpers.
"""

import json
import os
from pathlib import Path

from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from ..config import settings

# ---------------------------------------------------------------------------
# Router for routes that live on the modules blueprint directly
# ---------------------------------------------------------------------------
router = APIRouter(tags=["modules"])

# Templates reference - set by the application during startup
templates = None


def set_templates(tmpl):
    """Called by the application to inject the Jinja2Templates instance."""
    global templates
    templates = tmpl


def _resolve_load_dir() -> str:
    """Resolve the active workspace at request time.

    Mirrors the generic enumeration-route resolution so the lockon
    screenshot routes follow a UI workspace switch (which updates these
    env vars) instead of being pinned to the value frozen in
    ``settings.RESULTS_DIR`` at import.
    """
    return (os.environ.get("CYGOR_LOAD_DIR")
            or os.environ.get("CYGOR_WORKSPACE")
            or str(settings.RESULTS_DIR))


# ===================================================================
# Dynamic enumeration-module route registration
# ===================================================================

def _register_module_routes(app: FastAPI, templates_dir: Path, results_dir: Path):
    """
    Register routes for all discovered enumeration modules.
    """
    from ..main import DISCOVERED_MODULES

    # Only register enumeration modules
    enumeration_modules = [m for m in DISCOVERED_MODULES if m.module_type == "enumeration"]

    # Register enumeration modules
    for spec in enumeration_modules:
        _register_enumeration_route(app, spec, templates_dir, results_dir)

    # ----------------------------------------------------------------
    # Network Shares Combined View (SMB + NFS)
    # ----------------------------------------------------------------
    @app.get("/modules/network-shares", response_class=HTMLResponse)
    async def network_shares(request: Request):
        """Render combined view of SMB and NFS shares."""
        from cygor.module_loader import load_cygor_result

        # Resolve the workspace at request time so the view follows the active
        # --load-dir, not whatever was configured when routes were registered.
        load_dir = (os.environ.get("CYGOR_LOAD_DIR")
                    or os.environ.get("CYGOR_WORKSPACE")
                    or str(results_dir))

        smb_results = []
        smb_file_rows = []
        nfs_results = []

        # Load SMB Explorer results. Prefer the cygor-result.json the module
        # emits today; fall back to legacy *_results.json files for old runs.
        smb_data = load_cygor_result("smbexplorer", load_dir)
        if smb_data:
            smb_results = smb_data.get("results", [])
        else:
            smb_base = Path(load_dir) / "cygor-enumeration-modules" / "smbexplorer"
            if smb_base.exists():
                for f in smb_base.glob("*.json"):
                    if f.name == "cygor-result.json":
                        continue
                    try:
                        data = json.loads(f.read_text())
                        if "smb_results" in f.name:
                            smb_results.extend(data)
                        elif "smb_files" in f.name:
                            smb_file_rows.extend(data)
                    except Exception:
                        continue

        # Normalize SMB share results
        seen = set()
        normalized_smb = []
        for r in smb_results:
            ip = r.get("IP Address") or r.get("ip")
            share = r.get("Share") or r.get("share")
            key = (ip, share)
            if key not in seen:
                seen.add(key)
                normalized_smb.append({
                    "ip": ip,
                    "share": share,
                    "status": r.get("Status") or r.get("status"),
                    "smb_version": r.get("SMB Version") or r.get("smb_version"),
                    "permissions": r.get("Permissions") or r.get("permissions"),
                    "information": r.get("Information") or r.get("information"),
                    "protocol": "smb",
                })

        # Normalize SMB file rows
        normalized_smb_files = []
        for f in smb_file_rows:
            normalized_smb_files.append({
                "ip": f.get("IP") or f.get("ip"),
                "share": f.get("Share") or f.get("share"),
                "name": f.get("Name") or f.get("name"),
                "size": f.get("Size") or f.get("size"),
                "mtime": f.get("Modified") or f.get("mtime"),
                "attributes": f.get("Attributes") or f.get("attributes"),
                "type": f.get("Type") or f.get("type"),
                "protocol": "smb",
            })

        # Load NFS Explorer results
        # First try new cygor-result.json format
        nfs_data = load_cygor_result("nfsexplorer", load_dir)
        nfs_results = []
        if nfs_data:
            nfs_results = nfs_data.get("results", [])
        else:
            # Fall back to legacy format (nfsexplorer_<ip>.json files)
            nfs_base = Path(load_dir) / "cygor-enumeration-modules" / "nfsexplorer"
            if nfs_base.exists():
                for f in nfs_base.glob("*.json"):
                    # Skip files results, load main results
                    if "_files" in f.name:
                        continue
                    try:
                        data = json.loads(f.read_text())
                        if isinstance(data, list):
                            nfs_results.extend(data)
                        elif isinstance(data, dict) and "results" in data:
                            nfs_results.extend(data.get("results", []))
                    except Exception:
                        continue

        normalized_nfs = []
        for r in nfs_results:
            normalized_nfs.append({
                "ip": r.get("ip"),
                "share": r.get("share") or r.get("export"),
                "name": r.get("name") or r.get("file"),
                "type": r.get("type"),
                "size": r.get("size"),
                "permissions": r.get("permissions"),
                "protocol": "nfs",
            })

        # Calculate stats
        smb_hosts = set(r["ip"] for r in normalized_smb if r["ip"])
        nfs_hosts = set(r["ip"] for r in normalized_nfs if r["ip"])
        all_hosts = smb_hosts | nfs_hosts

        smb_shares_count = len(set((r["ip"], r["share"]) for r in normalized_smb))
        nfs_exports_count = len(set((r["ip"], r["share"]) for r in normalized_nfs))

        # Count writable shares
        writable_count = 0
        for r in normalized_smb:
            perms = (r.get("permissions") or "").lower()
            if "write" in perms and "no write" not in perms and "no_write" not in perms:
                writable_count += 1
        for r in normalized_nfs:
            perms = (r.get("permissions") or "").upper()
            if "WRITE" in perms and "NO_WRITE" not in perms:
                writable_count += 1

        # Hosts with files
        smb_hosts_with_files = len(set(f["ip"] for f in normalized_smb_files if f["ip"]))

        return templates.TemplateResponse(
            request,
            "network_shares.html",
            {
                "smb_results": normalized_smb,
                "smb_file_rows": normalized_smb_files,
                "nfs_results": normalized_nfs,
                "total_hosts": len(all_hosts),
                "smb_hosts_count": len(smb_hosts),
                "nfs_hosts_count": len(nfs_hosts),
                "smb_shares_count": smb_shares_count,
                "nfs_exports_count": nfs_exports_count,
                "writable_count": writable_count,
                "smb_hosts_with_files": smb_hosts_with_files,
            },
        )


def _register_enumeration_route(app: FastAPI, spec, templates_dir: Path, results_dir: Path):
    """
    Register single route for enumeration module.
    Dynamically selects the best template based on the context returned
    by each module (rows, items, chart, etc.).

    Supports both:
    - New format: cygor-result.json with embedded schema (uses modules_unified.html)
    - Legacy format: module-specific loaders and templates
    """
    import inspect
    from cygor.module_loader import resolve_legacy_context, load_cygor_result
    from jinja2 import TemplateNotFound

    route_path = f"/modules/{spec.slug}"

    async def handler(request: Request, spec=spec):
        context = {}
        # Resolve the workspace at request time so module results follow the
        # active --load-dir, not the value captured when routes were registered.
        load_dir = (os.environ.get("CYGOR_LOAD_DIR")
                    or os.environ.get("CYGOR_WORKSPACE")
                    or results_dir)
        try:
            # --- Try new cygor-result.json format first ---
            new_result = load_cygor_result(spec.slug, load_dir)
            if new_result is not None:
                # Use new unified template with schema-driven rendering
                return templates.TemplateResponse(
                    request,
                    "modules_unified.html",
                    {
                        "module": new_result.get("module", {"name": spec.name, "slug": spec.slug}),
                        "metadata": new_result.get("metadata", {}),
                        "schema": new_result.get("schema", {"view": "table", "columns": []}),
                        "results": new_result.get("results", []),
                        "assets": new_result.get("assets", {}),
                    },
                )

            # --- Fall back to legacy context loading ---
            if spec.get_context:
                result = spec.get_context(request, None)
                if inspect.iscoroutine(result):
                    result = await result
                if isinstance(result, dict):
                    context.update(result)
            else:
                # legacy compatibility
                context.update(resolve_legacy_context(spec.slug, load_dir))

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
                    template_file = "modules_charts.html"
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
                request,
                template_file,
                {
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

    # Silent - logged at summary level in lifespan


# ===================================================================
# Lockon / Screenshots routes (on the router)
# ===================================================================

@router.get("/modules/lockon", response_class=RedirectResponse)
async def enum_lockon(request: Request):
    """Redirect to unified screenshots page (Web tab)"""
    return RedirectResponse(url="/modules/screenshots#web-panel", status_code=302)


@router.get("/modules/screenshots", response_class=HTMLResponse)
async def unified_screenshots(request: Request):
    """Unified Screenshots Gallery - All screenshot services in one view"""
    from urllib.parse import urlparse

    load_dir = _resolve_load_dir()
    base = Path(load_dir) / "cygor-enumeration-modules"

    # ---- LOCKON (Web) ----
    lockon_items = []
    lockon_base = base / "lockon"
    lockon_shots = lockon_base / "screenshots"
    # Lockon saves results as cygor-result.json (nested format with "results" key)
    # All protocols (http, https, rdp, vnc, x11) are in this single file.
    lockon_json = lockon_base / "cygor-result.json"
    rdp_items = []
    vnc_items = []
    x11_items = []

    if lockon_json.exists():
        try:
            raw = json.loads(lockon_json.read_text(encoding="utf-8", errors="ignore"))
            # cygor-result.json wraps results in {"results": [...]}
            all_results = raw.get("results", raw) if isinstance(raw, dict) else raw
            for entry in all_results:
                if not isinstance(entry, dict):
                    continue
                proto = entry.get("protocol", "")
                sf = entry.get("screenshot_file", "")
                screenshot_url = f"/modules/lockon/screenshots/{sf}" if sf and (lockon_shots / sf).exists() else None

                if proto in ("http", "https"):
                    url = entry.get("url")
                    if not url:
                        continue
                    parsed = urlparse(url)
                    lockon_items.append({
                        "url": url,
                        "host": parsed.hostname or "",
                        "port": str(parsed.port or (443 if parsed.scheme == "https" else 80)),
                        "status_code": entry.get("status_code"),
                        "screenshot_file": sf,
                        "screenshot_failed": entry.get("screenshot_failed", False),
                        "screenshot_url": screenshot_url,
                        "service": "web",
                        "source": entry.get("source", ""),
                    })
                elif proto == "rdp":
                    rdp_items.append({
                        "host": entry.get("host", ""),
                        "port": entry.get("port", 3389),
                        "status": entry.get("status", "UNKNOWN"),
                        "screenshot_file": sf,
                        "screenshot_failed": entry.get("screenshot_failed", True),
                        "screenshot_url": screenshot_url,
                        "rdp_info": entry.get("rdp_info", ""),
                        "service": "rdp",
                    })
                elif proto == "vnc":
                    vnc_items.append({
                        "host": entry.get("host", ""),
                        "port": entry.get("port", 5900),
                        "status": entry.get("status", "UNKNOWN"),
                        "screenshot_file": sf,
                        "screenshot_failed": entry.get("screenshot_failed", True),
                        "screenshot_url": screenshot_url,
                        "vnc_info": entry.get("vnc_info", ""),
                        "auth_type": entry.get("auth_type", ""),
                        "service": "vnc",
                    })
                elif proto == "x11":
                    x11_items.append({
                        "host": entry.get("host", ""),
                        "port": entry.get("port", 6000),
                        "display": entry.get("display", 0),
                        "status": entry.get("status", "UNKNOWN"),
                        "screenshot_file": sf,
                        "screenshot_failed": entry.get("screenshot_failed", True),
                        "screenshot_url": screenshot_url,
                        "x11_info": entry.get("x11_info", ""),
                        "auth_type": entry.get("auth_type", ""),
                        "service": "x11",
                    })
        except Exception:
            pass

    # ---- webenum-discovered pages (captured via lockon, tagged source=webenum) ----
    # The gallery aggregates these directly from webenum's result so they show up
    # (with a 'webenum' tag) regardless of whether lockon persisted its own JSON.
    seen_shots = {i.get("screenshot_url") for i in lockon_items if i.get("screenshot_url")}
    webenum_json = base / "webenum" / "cygor-result.json"
    if webenum_json.exists():
        try:
            wraw = json.loads(webenum_json.read_text(encoding="utf-8", errors="ignore"))
            for entry in wraw.get("results", []):
                surl = entry.get("screenshot_url")
                if not surl or surl in seen_shots:
                    continue
                seen_shots.add(surl)
                u = entry.get("url", "")
                parsed = urlparse(u)
                sc = entry.get("status")
                lockon_items.append({
                    "url": u,
                    "host": parsed.hostname or "",
                    "port": str(parsed.port or (443 if parsed.scheme == "https" else 80)),
                    "status_code": int(sc) if str(sc).isdigit() else None,
                    "screenshot_file": surl.rsplit("/", 1)[-1],
                    "screenshot_failed": False,
                    "screenshot_url": surl,
                    "service": "web",
                    "source": entry.get("source") or "webenum",
                })
        except Exception:
            pass

    # Count successful screenshots per service
    web_success = sum(1 for i in lockon_items if not i.get("screenshot_failed"))
    rdp_success = sum(1 for i in rdp_items if not i.get("screenshot_failed"))
    vnc_success = sum(1 for i in vnc_items if not i.get("screenshot_failed"))
    x11_success = sum(1 for i in x11_items if not i.get("screenshot_failed"))

    # Security concerns
    vnc_noauth = sum(1 for i in vnc_items if "None" in i.get("auth_type", ""))
    x11_open = sum(1 for i in x11_items if i.get("auth_type") == "open_access" or i.get("status") in ("SUCCESS", "ACCESS_ALLOWED"))

    return templates.TemplateResponse(request, "module_screenshots.html", {
        "lockon_items": lockon_items,
        "rdp_items": rdp_items,
        "vnc_items": vnc_items,
        "x11_items": x11_items,
        "web_count": len(lockon_items),
        "rdp_count": len(rdp_items),
        "vnc_count": len(vnc_items),
        "x11_count": len(x11_items),
        "web_success": web_success,
        "rdp_success": rdp_success,
        "vnc_success": vnc_success,
        "x11_success": x11_success,
        "vnc_noauth": vnc_noauth,
        "x11_open": x11_open,
        "total_screenshots": web_success + rdp_success + vnc_success + x11_success,
    })


@router.get("/modules/lockon/screenshots/{filename:path}")
async def serve_lockon_screenshot(filename: str):
    """Dynamic fallback for serving lockon screenshots (handles post-startup directory creation).
    Also serves archived screenshots via archive/{timestamp}/{filename} subpaths."""
    from fastapi.responses import FileResponse
    _ld = _resolve_load_dir()
    base = Path(_ld) / "cygor-enumeration-modules" / "lockon" / "screenshots"
    shot_path = (base / filename).resolve()
    # Prevent path traversal
    if not str(shot_path).startswith(str(base.resolve())):
        raise HTTPException(status_code=403, detail="Access denied")
    if shot_path.exists() and shot_path.is_file():
        return FileResponse(str(shot_path))
    raise HTTPException(status_code=404, detail="Screenshot not found")


@router.get("/api/lockon/history/{screenshot_file:path}")
async def lockon_screenshot_history(screenshot_file: str):
    """Return historical archived versions of a specific screenshot file."""
    _ld = _resolve_load_dir()
    archive_base = Path(_ld) / "cygor-enumeration-modules" / "lockon" / "screenshots" / "archive"

    history = []
    if archive_base.exists():
        for ts_dir in sorted(archive_base.iterdir()):
            if not ts_dir.is_dir():
                continue
            archived_file = ts_dir / screenshot_file
            if not archived_file.exists():
                continue

            meta = {}
            result_json = ts_dir / "cygor-result.json"
            if result_json.exists():
                try:
                    raw = json.loads(result_json.read_text(encoding="utf-8"))
                    meta = raw.get("metadata", {})
                    for entry in (raw.get("results", []) if isinstance(raw, dict) else raw):
                        if isinstance(entry, dict) and entry.get("screenshot_file") == screenshot_file:
                            meta["status"] = entry.get("status")
                            meta["status_code"] = entry.get("status_code")
                            break
                except Exception:
                    pass

            history.append({
                "timestamp": ts_dir.name,
                "screenshot_url": f"/modules/lockon/screenshots/archive/{ts_dir.name}/{screenshot_file}",
                "started_at": meta.get("started_at"),
                "completed_at": meta.get("completed_at"),
                "status": meta.get("status"),
                "status_code": meta.get("status_code"),
            })

    return JSONResponse({"screenshot_file": screenshot_file, "history": history})


@router.get("/api/lockon/archives")
async def lockon_archives():
    """List all archived Lockon scan snapshots (newest first)."""
    _ld = _resolve_load_dir()
    archive_base = Path(_ld) / "cygor-enumeration-modules" / "lockon" / "screenshots" / "archive"

    archives = []
    if archive_base.exists():
        for ts_dir in sorted(archive_base.iterdir(), reverse=True):
            if not ts_dir.is_dir():
                continue
            meta = {}
            result_json = ts_dir / "cygor-result.json"
            raw = None
            if result_json.exists():
                try:
                    raw = json.loads(result_json.read_text(encoding="utf-8"))
                    meta = raw.get("metadata", {})
                except Exception:
                    pass
            # Count screenshots by parsing cygor-result.json with protocol
            # validation (matches gallery filtering logic) instead of blind
            # *.png glob which over-counts orphaned/unrecognised files.
            screenshot_count = 0
            if result_json.exists() and raw is not None:
                try:
                    _results = raw.get("results", raw) if isinstance(raw, dict) else raw
                    _valid_protos = {"http", "https", "rdp", "vnc", "x11"}
                    for _entry in _results:
                        if isinstance(_entry, dict) and _entry.get("protocol", "") in _valid_protos:
                            _sf = _entry.get("screenshot_file", "")
                            if _sf and (ts_dir / _sf).exists():
                                screenshot_count += 1
                except Exception:
                    # Fallback to file glob if JSON parsing fails
                    screenshot_count = len(list(ts_dir.glob("*.png")))
            archives.append({
                "timestamp": ts_dir.name,
                "started_at": meta.get("started_at"),
                "completed_at": meta.get("completed_at"),
                "target_count": meta.get("target_count"),
                "success_count": meta.get("success_count"),
                "screenshot_count": screenshot_count,
            })

    return JSONResponse({"archives": archives})


@router.get("/api/lockon/archives/{timestamp}")
async def lockon_archive_snapshot(timestamp: str):
    """Return parsed screenshot items for a specific archived scan snapshot."""
    from urllib.parse import urlparse as _urlparse

    _ld = _resolve_load_dir()
    archive_dir = Path(_ld) / "cygor-enumeration-modules" / "lockon" / "screenshots" / "archive" / timestamp

    # Path traversal check
    archive_base = (Path(_ld) / "cygor-enumeration-modules" / "lockon" / "screenshots" / "archive").resolve()
    if not str(archive_dir.resolve()).startswith(str(archive_base)):
        raise HTTPException(status_code=403, detail="Access denied")

    result_json = archive_dir / "cygor-result.json"
    if not result_json.exists():
        raise HTTPException(status_code=404, detail="Archive not found")

    try:
        raw = json.loads(result_json.read_text(encoding="utf-8"))
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to read archive")

    all_results = raw.get("results", raw) if isinstance(raw, dict) else raw
    meta = raw.get("metadata", {}) if isinstance(raw, dict) else {}
    items = []

    for entry in all_results:
        if not isinstance(entry, dict):
            continue
        proto = entry.get("protocol", "")
        sf = entry.get("screenshot_file", "")
        has_png = sf and (archive_dir / sf).exists()
        screenshot_url = f"/modules/lockon/screenshots/archive/{timestamp}/{sf}" if has_png else None

        item = {
            "protocol": proto,
            "screenshot_file": sf,
            "screenshot_url": screenshot_url,
            "screenshot_failed": entry.get("screenshot_failed", not has_png),
        }

        if proto in ("http", "https"):
            url = entry.get("url", "")
            parsed = _urlparse(url)
            item.update({
                "url": url,
                "host": parsed.hostname or "",
                "port": str(parsed.port or (443 if parsed.scheme == "https" else 80)),
                "status_code": entry.get("status_code"),
                "service": "web",
            })
        elif proto == "rdp":
            item.update({
                "host": entry.get("host", ""),
                "port": entry.get("port", 3389),
                "status": entry.get("status", "UNKNOWN"),
                "rdp_info": entry.get("rdp_info", ""),
                "service": "rdp",
            })
        elif proto == "vnc":
            item.update({
                "host": entry.get("host", ""),
                "port": entry.get("port", 5900),
                "status": entry.get("status", "UNKNOWN"),
                "vnc_info": entry.get("vnc_info", ""),
                "auth_type": entry.get("auth_type", ""),
                "service": "vnc",
            })
        elif proto == "x11":
            item.update({
                "host": entry.get("host", ""),
                "port": entry.get("port", 6000),
                "display": entry.get("display", 0),
                "status": entry.get("status", "UNKNOWN"),
                "x11_info": entry.get("x11_info", ""),
                "auth_type": entry.get("auth_type", ""),
                "service": "x11",
            })
        else:
            continue

        items.append(item)

    return JSONResponse({
        "timestamp": timestamp,
        "metadata": meta,
        "items": items,
    })


# ===================================================================
# SMBExplorer / NFSExplorer redirect routes (on the router)
# ===================================================================

@router.get("/modules/smbexplorer", response_class=RedirectResponse)
async def enum_smbexplorer(request: Request):
    """Redirect to unified network shares page (SMB section)"""
    return RedirectResponse(url="/modules/network-shares#smb-panel", status_code=302)


@router.get("/modules/nfsexplorer", response_class=RedirectResponse)
async def enum_nfsexplorer(request: Request):
    """Redirect to unified network shares page (NFS section)"""
    return RedirectResponse(url="/modules/network-shares#nfs-panel", status_code=302)
