"""Plugin management routes."""

import logging
import shutil
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.requests import Request
from fastapi.responses import JSONResponse

from ...db import get_session
from ...config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["plugins"])

# Cap upload size — plugin files are tiny (typically <50KB), but a hostile
# client could try to fill /tmp. 1MB is generous.
_MAX_PLUGIN_BYTES = 1 * 1024 * 1024


def _get_discovered_modules():
    """Get the DISCOVERED_MODULES list from main module."""
    from ...main import DISCOVERED_MODULES
    return DISCOVERED_MODULES


@router.get("/api/plugins")
async def list_plugins(request: Request):
    """List all discovered modules and plugins."""
    from ...simple_auth import get_current_user_from_request
    user = await get_current_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    modules = []
    for spec in _get_discovered_modules():
        modules.append({
            "name": spec.name,
            "slug": spec.slug,
            "description": spec.description,
            "author": spec.author,
            "version": spec.version,
            "view": spec.view,
            "source": spec.source,
            "plugin_path": spec.plugin_path,
            "module_type": spec.module_type,
            "requires_cygor": getattr(spec, "requires_cygor", ""),
            "fingerprint": getattr(spec, "fingerprint", ""),
        })
    return JSONResponse(modules)


@router.post("/api/plugins/reload")
async def reload_plugins(request: Request):
    """Re-scan plugin directories and reload module registry."""
    from ...simple_auth import get_current_user_from_request
    user = await get_current_user_from_request(request)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    import cygor.webapp.main as main_module
    from cygor.module_loader import discover_modules
    from cygor.plugin_loader import get_plugin_errors
    main_module.DISCOVERED_MODULES = discover_modules()
    DISCOVERED_MODULES = main_module.DISCOVERED_MODULES
    return JSONResponse({
        "success": True,
        "total": len(DISCOVERED_MODULES),
        "builtins": sum(1 for m in DISCOVERED_MODULES if m.source == "builtin"),
        "plugins": sum(1 for m in DISCOVERED_MODULES if m.source == "plugin"),
        "errors": len(get_plugin_errors()),
    })


@router.get("/api/plugins/errors")
async def list_plugin_errors(request: Request):
    """Return errors recorded during the most recent plugin discovery."""
    from ...simple_auth import get_current_user_from_request
    user = await get_current_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    from cygor.plugin_loader import get_plugin_errors
    return JSONResponse({"errors": get_plugin_errors()})


def _safe_plugin_filename(name: str) -> str:
    """Strip path components and verify the upload is a .py file."""
    base = Path(name).name  # drop any directory parts the client sent
    if not base.endswith(".py"):
        raise HTTPException(status_code=400, detail="Plugin filename must end in .py")
    if base.startswith("_") or base in {"__init__.py", "setup.py", "conftest.py"}:
        raise HTTPException(status_code=400, detail=f"Reserved filename: {base}")
    # Reject any sneaky chars; allow only ascii letters/digits/_/-/.
    if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-." for ch in base):
        raise HTTPException(status_code=400, detail="Filename contains disallowed characters")
    return base


async def _read_upload(file: UploadFile) -> bytes:
    """Read the upload up to the size cap. Raises HTTPException on overflow."""
    body = await file.read(_MAX_PLUGIN_BYTES + 1)
    if len(body) > _MAX_PLUGIN_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Plugin file exceeds {_MAX_PLUGIN_BYTES} bytes",
        )
    return body


@router.post("/api/plugins/validate")
async def validate_plugin_upload(request: Request, file: UploadFile = File(...)):
    """
    Run plugin validation against an uploaded file without installing it.

    Returns the same shape as cygor.plugin_loader.validate_plugin().
    """
    from ...simple_auth import get_current_user_from_request
    user = await get_current_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    from cygor.plugin_loader import validate_plugin

    safe_name = _safe_plugin_filename(file.filename or "")
    body = await _read_upload(file)

    # Write to a temp file under a private dir so the import has a real path.
    with tempfile.TemporaryDirectory(prefix="cygor-plugin-validate-") as tmp:
        tmp_path = Path(tmp) / safe_name
        tmp_path.write_bytes(body)
        result = validate_plugin(tmp_path)

    return JSONResponse(result)


@router.post("/api/plugins/install")
async def install_plugin_upload(request: Request, file: UploadFile = File(...)):
    """
    Validate and install an uploaded plugin to ~/.cygor/plugins/.

    Admin only. Refuses to overwrite an existing file.
    """
    from ...simple_auth import get_current_user_from_request
    user = await get_current_user_from_request(request)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    from cygor.plugin_loader import validate_plugin, PLUGIN_DIRS

    safe_name = _safe_plugin_filename(file.filename or "")
    body = await _read_upload(file)

    # Stage in a temp file so we can validate before committing to the
    # plugin directory.
    with tempfile.TemporaryDirectory(prefix="cygor-plugin-install-") as tmp:
        staged = Path(tmp) / safe_name
        staged.write_bytes(body)

        validation = validate_plugin(staged)
        if not validation["valid"]:
            return JSONResponse(
                {"success": False, "errors": validation["errors"]},
                status_code=400,
            )

        target_dir = PLUGIN_DIRS[0]
        target_dir.mkdir(parents=True, exist_ok=True)
        dest = target_dir / safe_name

        if dest.exists():
            return JSONResponse(
                {"success": False, "errors": [f"Plugin already exists at {dest}"]},
                status_code=409,
            )

        shutil.copy2(staged, dest)

    # Reload discovery so the new plugin shows up immediately.
    import cygor.webapp.main as main_module
    from cygor.module_loader import discover_modules
    main_module.DISCOVERED_MODULES = discover_modules()

    return JSONResponse({
        "success": True,
        "path": str(dest),
        "name": validation["name"],
        "slug": validation["slug"],
        "version": validation.get("version", ""),
        "fingerprint": validation.get("fingerprint", ""),
        "warnings": validation.get("warnings", []),
    })


@router.post("/api/plugins/{slug}/update")
async def update_plugin(slug: str, request: Request):
    """
    Update a single plugin: git pull if it lives in a git checkout, otherwise
    re-validate (so the fingerprint and gates refresh).
    """
    from ...simple_auth import get_current_user_from_request
    user = await get_current_user_from_request(request)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    from cygor.plugin_loader import validate_plugin
    import subprocess

    target = None
    for spec in _get_discovered_modules():
        if spec.slug == slug:
            target = spec
            break
    if target is None or target.source != "plugin":
        raise HTTPException(status_code=404, detail=f"Plugin '{slug}' not found")

    plugin_path = Path(target.plugin_path)
    if not plugin_path.exists():
        raise HTTPException(status_code=404, detail=f"Plugin file missing: {plugin_path}")

    git_root = None
    for parent in [plugin_path.parent, *plugin_path.parents]:
        if (parent / ".git").exists():
            git_root = parent
            break

    git_output = None
    if git_root:
        try:
            proc = subprocess.run(
                ["git", "-C", str(git_root), "pull", "--ff-only"],
                capture_output=True, text=True, check=False, timeout=60,
            )
            git_output = (proc.stdout + proc.stderr).strip()
            if proc.returncode != 0:
                return JSONResponse(
                    {"success": False, "git_output": git_output, "error": "git pull failed"},
                    status_code=500,
                )
        except subprocess.TimeoutExpired:
            return JSONResponse(
                {"success": False, "error": "git pull timed out"},
                status_code=504,
            )

    validation = validate_plugin(plugin_path)
    if not validation["valid"]:
        return JSONResponse(
            {
                "success": False,
                "git_output": git_output,
                "errors": validation["errors"],
            },
            status_code=400,
        )

    # Reload discovery so the new version (and refreshed fingerprint) is picked up.
    import cygor.webapp.main as main_module
    from cygor.module_loader import discover_modules
    main_module.DISCOVERED_MODULES = discover_modules()

    return JSONResponse({
        "success": True,
        "slug": slug,
        "fingerprint": validation.get("fingerprint", ""),
        "git_output": git_output,
        "had_git": git_root is not None,
    })


@router.delete("/api/plugins/{slug}")
async def uninstall_plugin(slug: str, request: Request):
    """Delete a plugin file by slug. Admin only. Built-ins are not removable."""
    from ...simple_auth import get_current_user_from_request
    user = await get_current_user_from_request(request)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    target = None
    for spec in _get_discovered_modules():
        if spec.slug == slug:
            target = spec
            break

    if target is None:
        raise HTTPException(status_code=404, detail=f"Module '{slug}' not found")

    if target.source != "plugin" or not target.plugin_path:
        raise HTTPException(status_code=400, detail="Built-in modules cannot be removed")

    path = Path(target.plugin_path)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Plugin file missing: {path}")

    path.unlink()

    import cygor.webapp.main as main_module
    from cygor.module_loader import discover_modules
    main_module.DISCOVERED_MODULES = discover_modules()

    return JSONResponse({"success": True, "removed": str(path)})


@router.get("/api/plugins/{slug}/info")
async def get_plugin_info(slug: str, request: Request):
    """Get detailed info for a specific plugin/module."""
    from ...simple_auth import get_current_user_from_request
    user = await get_current_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    for spec in _get_discovered_modules():
        if spec.slug == slug:
            return JSONResponse({
                "name": spec.name,
                "slug": spec.slug,
                "description": spec.description,
                "author": spec.author,
                "version": spec.version,
                "view": spec.view,
                "source": spec.source,
                "plugin_path": spec.plugin_path,
                "module_type": spec.module_type,
                "columns": spec.columns,
                "option_flags": spec.option_flags,
                "requires_cygor": getattr(spec, "requires_cygor", ""),
                "fingerprint": getattr(spec, "fingerprint", ""),
            })

    raise HTTPException(status_code=404, detail="Plugin not found")
