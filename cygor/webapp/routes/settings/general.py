"""General settings routes – settings pages, enrich API, sudo/privileges, task config."""

import os
import logging
from typing import Dict, Any

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from ...db import get_session
from ...config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["settings"])

templates = None


def set_templates(tmpl):
    """Receive the shared Jinja2Templates instance from the main app."""
    global templates
    templates = tmpl


# ============================================================================
# Settings Pages
# ============================================================================

@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Unified settings page with tabs."""
    response = templates.TemplateResponse(request, "settings_unified.html", {})
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@router.get("/settings/enrich", response_class=HTMLResponse)
async def enrich_settings_page(request: Request):
    """Enrichment API settings page - redirects to unified settings."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/settings#apiKeysTab", status_code=303)


# ============================================================================
# Enrichment API Settings (instance-wide on dev, stored in AppSettings)
# ============================================================================

_ENRICHMENT_KEYS_SETTING = "enrichment_api_keys"


@router.get("/api/settings/enrich")
async def get_enrich_settings(request: Request):
    """Return the instance-wide enrichment API keys (stored in AppSettings)."""
    from ...models import AppSettings
    from sqlalchemy import select as sa_select
    import json

    api_keys: Dict[str, Any] = {}
    async for session in get_session():
        row = await session.execute(sa_select(AppSettings).where(AppSettings.key == _ENRICHMENT_KEYS_SETTING))
        setting = row.scalar_one_or_none()
        if setting and setting.value:
            try:
                api_keys = json.loads(setting.value) or {}
            except (json.JSONDecodeError, TypeError):
                api_keys = {}
        break

    return JSONResponse({"api_keys": api_keys, "user_id": None})


@router.post("/api/settings/enrich")
async def save_enrich_settings(request: Request, req: Dict[str, Any]):
    """Save the instance-wide enrichment API keys to AppSettings."""
    from ...models import AppSettings
    from sqlalchemy import select as sa_select
    from datetime import datetime
    import json

    try:
        api_keys = req.get("api_keys", {})
        filtered_keys = {k: v for k, v in api_keys.items() if v and v.strip()}
        value = json.dumps(filtered_keys) if filtered_keys else None

        async for session in get_session():
            row = await session.execute(sa_select(AppSettings).where(AppSettings.key == _ENRICHMENT_KEYS_SETTING))
            setting = row.scalar_one_or_none()
            if setting:
                setting.value = value
                setting.updated_at = datetime.utcnow()
                session.add(setting)
            else:
                session.add(AppSettings(
                    key=_ENRICHMENT_KEYS_SETTING,
                    value=value,
                    description="Enrichment API keys (Shodan, VirusTotal, etc.) shared across the instance.",
                ))
            await session.commit()
            break

        return JSONResponse({
            "status": "success",
            "message": "API keys saved successfully",
            "keys_configured": list(filtered_keys.keys()),
        })

    except Exception as e:
        logger.error(f"Error saving enrichment settings: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# Sudo/Scan Privileges API Endpoints
# ============================================================================

@router.get("/api/settings/sudo/status")
async def get_sudo_status():
    """Get current sudo authentication status, including capabilities and sudoers config."""
    import subprocess

    try:
        from cygor.privileges import get_privilege_status
        status = get_privilege_status()
    except Exception:
        # Fallback if privileges module fails
        status = {"is_root": False, "tools": [], "passwordless_sudo": False, "sudoers_exists": False, "user": "unknown"}
        try:
            status["is_root"] = os.geteuid() == 0
        except (AttributeError, OSError):
            pass

    # Also include session-based sudo validation
    sudo_validated = os.environ.get('CYGOR_SUDO_VALIDATED') == '1'

    # Check if passwordless sudo is available (may be cached from session or sudoers)
    passwordless = status.get("passwordless_sudo", False)
    if not passwordless and not status["is_root"]:
        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                timeout=5
            )
            passwordless = result.returncode == 0
        except Exception:
            pass

    # A tool is "ready" if: root, has caps, has sudoers, or sudo is validated in this session
    tools_status = []
    for t in status.get("tools", []):
        ready = t.get("privileged", False) or sudo_validated or passwordless
        tools_status.append({
            "name": t["name"],
            "installed": t["installed"],
            "path": t.get("path"),
            "has_caps": t.get("has_caps", False),
            "caps": t.get("caps", ""),
            "has_sudoers": t.get("has_sudoers", False),
            "ready": ready if t["installed"] else False,
        })

    return JSONResponse({
        "is_root": status["is_root"],
        "sudo_validated": sudo_validated or passwordless,
        "passwordless": passwordless,
        "user": status.get("user", "unknown"),
        "sudoers_configured": status.get("sudoers_exists", False),
        "tools": tools_status,
        "setup_hint": "Run 'sudo cygor setup-privileges' to configure" if not all(
            t["ready"] for t in tools_status if t["installed"]
        ) else None,
    })


@router.get("/api/settings/sudo/tools")
async def get_sudo_tools():
    """Get status of scanning tools that require elevated privileges."""
    import shutil

    tools = [
        {"name": "masscan", "available": False, "path": None},
        {"name": "nmap", "available": False, "path": None},
        {"name": "naabu", "available": False, "path": None},
    ]

    for tool in tools:
        path = shutil.which(tool["name"])
        if path:
            tool["available"] = True
            tool["path"] = path
            # Check capabilities
            try:
                from cygor.privileges import _get_caps
                caps = _get_caps(path)
                tool["has_caps"] = bool(caps)
                tool["caps"] = caps
            except Exception:
                tool["has_caps"] = False
                tool["caps"] = ""

    return JSONResponse({"tools": tools})


@router.post("/api/settings/sudo/authenticate")
async def authenticate_sudo(request: Request, req: Dict[str, Any]):
    """Authenticate sudo credentials for scan operations."""
    import subprocess
    import threading
    import time as time_module

    password = req.get("password", "")

    if not password:
        return JSONResponse({"success": False, "error": "Password is required"}, status_code=400)

    # Check if already running as root
    try:
        if os.geteuid() == 0:
            return JSONResponse({
                "success": True,
                "message": "Already running as root - no authentication needed"
            })
    except (AttributeError, OSError):
        pass

    # Validate the password
    try:
        validate_proc = subprocess.run(
            ["sudo", "-S", "-v"],
            input=f"{password}\n",
            capture_output=True,
            text=True,
            timeout=30
        )

        if validate_proc.returncode == 0:
            # Set environment variable to indicate sudo is validated
            os.environ["CYGOR_SUDO_VALIDATED"] = "1"

            # Start a background thread to keep sudo credentials alive
            def sudo_keepalive(pwd: str, stop_event: threading.Event):
                """Background thread to keep sudo credentials alive."""
                while not stop_event.is_set():
                    try:
                        subprocess.run(
                            ["sudo", "-S", "-v"],
                            input=f"{pwd}\n",
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                    except Exception:
                        pass
                    # Wait 4 minutes before next refresh
                    for _ in range(240):
                        if stop_event.is_set():
                            break
                        time_module.sleep(1)

            # Check if there's already a keepalive thread running
            # (simple check - just start a new one, the daemon threads will be cleaned up)
            stop_event = threading.Event()
            keepalive_thread = threading.Thread(
                target=sudo_keepalive,
                args=(password, stop_event),
                daemon=True,
                name="sudo-keepalive-web"
            )
            keepalive_thread.start()

            logger.info("Sudo authentication successful via web UI")
            return JSONResponse({
                "success": True,
                "message": "Sudo authentication successful! Elevated privileges are now available for scan operations."
            })
        else:
            logger.warning("Sudo authentication failed via web UI")
            return JSONResponse({
                "success": False,
                "error": "Invalid password. Please try again."
            }, status_code=401)

    except subprocess.TimeoutExpired:
        return JSONResponse({
            "success": False,
            "error": "Authentication timed out. Please try again."
        }, status_code=500)
    except Exception as e:
        logger.error(f"Sudo authentication error: {e}")
        return JSONResponse({
            "success": False,
            "error": f"Authentication error: {str(e)}"
        }, status_code=500)


# ============================================================================
# Task Settings API Endpoints
# ============================================================================

@router.get("/api/settings/tasks")
async def get_task_settings(request: Request):
    """Get task settings (admin only)."""
    from ...simple_auth import get_current_user_from_request
    user = await get_current_user_from_request(request)
    if not user or user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")

    from ...task_config import get_task_config
    return JSONResponse(get_task_config())


@router.post("/api/settings/tasks")
async def set_task_settings(request: Request):
    """Set task settings (admin only)."""
    from ...simple_auth import get_current_user_from_request
    user = await get_current_user_from_request(request)
    if not user or user.get('role') != 'admin':
        raise HTTPException(status_code=403, detail="Admin access required")

    data = await request.json()
    track_user_tasks = data.get("track_user_tasks", False)

    from ...task_config import set_task_user_tracking
    set_task_user_tracking(track_user_tasks)

    return JSONResponse({
        "success": True,
        "message": "Task settings updated",
        "track_user_tasks": track_user_tasks
    })
