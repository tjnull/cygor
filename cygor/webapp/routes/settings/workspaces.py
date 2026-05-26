"""Workspace management API routes."""

import datetime
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

router = APIRouter(tags=["workspaces"])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _apply_workspace_to_process(ws_path: Path) -> None:
    """Point the running web process at ``ws_path``.

    Routes read the active workspace from the environment
    (``CYGOR_LOAD_DIR`` / ``CYGOR_WORKSPACE``) and ``settings.RESULTS_DIR``,
    both of which are otherwise frozen at startup. Without updating them a
    UI workspace switch only rewrites the config file and the running app
    keeps serving the old workspace's results. Update all three so every
    route (generic modules, lockon screenshots, hosts, etc.) follows the
    switch immediately -- no web-server restart required.
    """
    resolved = str(ws_path)
    os.environ["CYGOR_WORKSPACE"] = resolved
    os.environ["CYGOR_LOAD_DIR"] = resolved
    try:
        from cygor.webapp.config import settings
        settings.RESULTS_DIR = Path(resolved)
        settings.WORKSPACE_CONFIGURED = True
    except Exception as e:
        logger.warning(f"Could not update settings.RESULTS_DIR on workspace switch: {e}")




def _get_workspace_size(path: Path) -> int:
    """Calculate total size of workspace directory in bytes."""
    total = 0
    try:
        for dirpath, dirnames, filenames in os.walk(path):
            for f in filenames:
                fp = os.path.join(dirpath, f)
                try:
                    total += os.path.getsize(fp)
                except (OSError, FileNotFoundError):
                    pass
    except Exception:
        pass
    return total


def _format_size(size_bytes: int) -> str:
    """Format bytes to human-readable size."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} PB"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.get("/api/workspaces")
async def list_workspaces():
    """List all registered workspaces."""
    from cygor.workspace import _load_config, _migrate_old_config

    try:
        cfg = _load_config()
        cfg = _migrate_old_config(cfg)

        workspaces = cfg.get("workspaces", {})
        active = cfg.get("active_workspace") or cfg.get("default_workspace")

        result = []
        for name, ws_data in workspaces.items():
            ws_path = Path(ws_data.get("path", ""))
            size = 0
            exists = False
            if ws_path.exists():
                exists = True
                try:
                    size = _get_workspace_size(ws_path)
                except Exception:
                    pass

            result.append({
                "name": name,
                "path": str(ws_path),
                "active": name == active,
                "created_at": ws_data.get("created_at", ""),
                "last_used": ws_data.get("last_used", ""),
                "description": ws_data.get("description", ""),
                "size": size,
                "size_formatted": _format_size(size),
                "exists": exists,
            })

        # Sort by last_used (most recent first), then by name
        result.sort(key=lambda x: (
            x["last_used"] if x["last_used"] else "",
            x["name"]
        ), reverse=True)

        return JSONResponse({
            "workspaces": result,
            "active": active,
        })
    except Exception as e:
        logger.error(f"Error listing workspaces: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@router.get("/api/workspaces/current")
async def get_current_workspace():
    """Get current active workspace."""
    from cygor.workspace import _load_config, _migrate_old_config, _get_workspace_metadata

    try:
        cfg = _load_config()
        cfg = _migrate_old_config(cfg)

        active = cfg.get("active_workspace") or cfg.get("default_workspace")
        if not active:
            return JSONResponse({"active": None, "workspace": None})

        workspaces = cfg.get("workspaces", {})
        if active in workspaces:
            ws_data = workspaces[active]
            ws_path = Path(ws_data["path"])

            workspace_info = {
                "name": active,
                "path": str(ws_path),
                "created_at": ws_data.get("created_at", ""),
                "last_used": ws_data.get("last_used", ""),
                "description": ws_data.get("description", ""),
            }

            if ws_path.exists():
                meta = _get_workspace_metadata(ws_path)
                if meta:
                    workspace_info["metadata"] = meta

            return JSONResponse({
                "active": active,
                "workspace": workspace_info,
            })

        # Fallback to old format
        old_ws = cfg.get("default_workspace")
        if old_ws and isinstance(old_ws, str):
            return JSONResponse({
                "active": None,
                "workspace": {"path": old_ws},
            })

        return JSONResponse({"active": None, "workspace": None})
    except Exception as e:
        logger.error(f"Error getting current workspace: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@router.post("/api/workspaces/create")
async def create_workspace(req: Dict[str, Any]):
    """Create and initialize a new workspace."""
    from cygor.workspace import _load_config, _migrate_old_config, _resolve_path, _save_config, SUBDIRS

    try:
        path = req.get("path")
        name = req.get("name")
        description = req.get("description", "")
        set_as_default = req.get("set_as_default", False)

        if not path:
            return JSONResponse({"error": "path is required"}, status_code=400)

        ws = _resolve_path(path)

        # Create directory if it doesn't exist
        ws.mkdir(parents=True, exist_ok=True)

        # Create the standardized workspace subdirectories
        for rel in SUBDIRS:
            base = ws / rel
            base.mkdir(parents=True, exist_ok=True)

            # Auto-create subfolders for enumeration modules
            if rel == "cygor-enumeration-modules":
                for module in ["lockon", "smbexplorer", "nfsexplorer"]:
                    (base / module).mkdir(parents=True, exist_ok=True)

        # Write metadata file
        meta = {
            "workspace": str(ws),
            "created_at": datetime.datetime.utcnow().isoformat() + "Z",
            "schema": 2,
            "description": "Cygor workspace directory structure for scan and enumeration data.",
            "subdirectories": {
                "nmap": "Nmap scan data and parsed XML output",
                "masscan": "Masscan discovery results",
                "naabu": "Naabu discovery results",
                "parsed-hostlists": "Aggregated and categorized hostlists",
                "cygor-enumeration-modules": {
                    "description": "Output directories for enumeration modules",
                    "modules": ["lockon", "smbexplorer", "nfsexplorer", "httpx", "rdpmapper"]
                },
                "logs": "General log output and runtime information"
            },
        }
        (ws / ".cygor-workspace.json").write_text(json.dumps(meta, indent=2))

        # Register workspace in config
        cfg = _load_config()
        cfg = _migrate_old_config(cfg)

        # Generate workspace name
        ws_name = name or ws.name or "workspace"
        base_name = ws_name
        counter = 1
        while ws_name in cfg.get("workspaces", {}):
            ws_name = f"{base_name}-{counter}"
            counter += 1

        # Add to workspaces
        if "workspaces" not in cfg:
            cfg["workspaces"] = {}

        cfg["workspaces"][ws_name] = {
            "path": str(ws),
            "created_at": meta["created_at"],
            "last_used": datetime.datetime.utcnow().isoformat() + "Z",
        }
        if description:
            cfg["workspaces"][ws_name]["description"] = description

        # Set as default/active if requested
        if set_as_default:
            cfg["default_workspace"] = ws_name
            cfg["active_workspace"] = ws_name

        _save_config(cfg)

        # If this new workspace is now active, point the running process at it
        # so the UI reflects it without a restart.
        if set_as_default:
            _apply_workspace_to_process(ws)

        return JSONResponse({
            "status": "success",
            "message": f"Workspace created: {ws_name}",
            "workspace": ws_name,
            "path": str(ws),
        })
    except Exception as e:
        logger.error(f"Error creating workspace: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@router.post("/api/workspaces/switch")
async def switch_workspace(req: Dict[str, Any]):
    """Switch active workspace."""
    from cygor.workspace import _load_config, _migrate_old_config, _get_workspace_by_name_or_path, _save_config

    def _update_last_used(name: str, cfg: dict) -> None:
        """Update last_used timestamp for a workspace."""
        if name in cfg.get("workspaces", {}):
            cfg["workspaces"][name]["last_used"] = datetime.datetime.utcnow().isoformat() + "Z"
            _save_config(cfg)

    try:
        name_or_path = req.get("name_or_path")
        if not name_or_path:
            return JSONResponse({"error": "name_or_path is required"}, status_code=400)

        cfg = _load_config()
        cfg = _migrate_old_config(cfg)

        result = _get_workspace_by_name_or_path(name_or_path, cfg)
        if not result:
            return JSONResponse({"error": f"Workspace not found: {name_or_path}"}, status_code=404)

        name, ws_data = result
        ws_path = Path(ws_data["path"])

        if not ws_path.exists():
            return JSONResponse({"error": f"Workspace path does not exist: {ws_path}"}, status_code=404)

        # Switch workspace
        cfg["active_workspace"] = name
        cfg["default_workspace"] = name
        _update_last_used(name, cfg)

        # Point the running web process at the new workspace so results show
        # up immediately without a restart.
        _apply_workspace_to_process(ws_path)

        return JSONResponse({
            "status": "success",
            "message": f"Switched to workspace: {name}",
            "workspace": name,
            "path": str(ws_path),
        })
    except Exception as e:
        logger.error(f"Error switching workspace: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@router.post("/api/workspaces/clear")
async def clear_active_workspace():
    """Clear the active workspace (set to None)."""
    from cygor.workspace import _load_config, _migrate_old_config, _save_config

    try:
        cfg = _load_config()
        cfg = _migrate_old_config(cfg)

        # Clear active workspace
        cfg.pop("active_workspace", None)
        cfg.pop("default_workspace", None)
        _save_config(cfg)

        return JSONResponse({
            "status": "success",
            "message": "Active workspace cleared",
        })
    except Exception as e:
        logger.error(f"Error clearing active workspace: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@router.post("/api/workspaces/add")
async def add_workspace(req: Dict[str, Any]):
    """Add/register a workspace."""
    from cygor.workspace import (
        _load_config, _migrate_old_config, _resolve_path,
        _validate_workspace, _get_workspace_by_name_or_path,
        _get_workspace_metadata, _save_config,
    )

    try:
        path = req.get("path")
        name = req.get("name")
        description = req.get("description", "")

        if not path:
            return JSONResponse({"error": "path is required"}, status_code=400)

        ws = _resolve_path(path)

        if not ws.exists():
            return JSONResponse({"error": f"Workspace does not exist: {ws}"}, status_code=404)

        if not _validate_workspace(ws):
            return JSONResponse({
                "error": f"Path is not a valid workspace: {ws}",
                "hint": f"Initialize it first with: cygor workspace init \"{ws}\""
            }, status_code=400)

        cfg = _load_config()
        cfg = _migrate_old_config(cfg)

        # Check if already registered
        result = _get_workspace_by_name_or_path(str(ws), cfg)
        if result:
            existing_name, _ = result
            return JSONResponse({
                "status": "exists",
                "message": f"Workspace already registered as: {existing_name}",
                "workspace": existing_name,
            })

        # Generate name
        ws_name = name or ws.name or "workspace"
        base_name = ws_name
        counter = 1
        while ws_name in cfg.get("workspaces", {}):
            ws_name = f"{base_name}-{counter}"
            counter += 1

        # Add workspace
        if "workspaces" not in cfg:
            cfg["workspaces"] = {}

        meta = _get_workspace_metadata(ws)
        cfg["workspaces"][ws_name] = {
            "path": str(ws),
            "created_at": meta.get("created_at", datetime.datetime.utcnow().isoformat() + "Z"),
            "last_used": datetime.datetime.utcnow().isoformat() + "Z",
        }
        if description:
            cfg["workspaces"][ws_name]["description"] = description

        _save_config(cfg)

        return JSONResponse({
            "status": "success",
            "message": f"Workspace registered: {ws_name}",
            "workspace": ws_name,
        })
    except Exception as e:
        logger.error(f"Error adding workspace: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@router.delete("/api/workspaces/{name}")
async def remove_workspace(name: str):
    """Remove a workspace from the registry."""
    from cygor.workspace import _load_config, _migrate_old_config, _get_workspace_by_name_or_path, _save_config

    try:
        cfg = _load_config()
        cfg = _migrate_old_config(cfg)

        result = _get_workspace_by_name_or_path(name, cfg)
        if not result:
            return JSONResponse({"error": f"Workspace not found: {name}"}, status_code=404)

        ws_name, ws_data = result

        # Check if it's the active workspace
        if ws_name == cfg.get("active_workspace"):
            return JSONResponse({
                "error": f"Cannot remove active workspace: {ws_name}",
                "hint": "Switch to another workspace first"
            }, status_code=400)

        # Remove from registry
        cfg["workspaces"].pop(ws_name)
        if cfg.get("default_workspace") == ws_name:
            cfg.pop("default_workspace", None)

        _save_config(cfg)

        return JSONResponse({
            "status": "success",
            "message": f"Workspace removed from registry: {ws_name}",
        })
    except Exception as e:
        logger.error(f"Error removing workspace: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@router.get("/api/workspaces/{name}/info")
async def get_workspace_info(name: str):
    """Get detailed information about a workspace."""
    from cygor.workspace import _load_config, _migrate_old_config, _get_workspace_by_name_or_path, _get_workspace_metadata

    try:
        cfg = _load_config()
        cfg = _migrate_old_config(cfg)

        result = _get_workspace_by_name_or_path(name, cfg)
        if not result:
            return JSONResponse({"error": f"Workspace not found: {name}"}, status_code=404)

        ws_name, ws_data = result
        ws_path = Path(ws_data["path"])
        active = cfg.get("active_workspace") == ws_name

        info = {
            "name": ws_name,
            "path": str(ws_path),
            "active": active,
            "created_at": ws_data.get("created_at", ""),
            "last_used": ws_data.get("last_used", ""),
            "description": ws_data.get("description", ""),
            "exists": ws_path.exists(),
        }

        if ws_path.exists():
            try:
                size = _get_workspace_size(ws_path)
                info["size"] = size
                info["size_formatted"] = _format_size(size)
            except Exception:
                pass

            # Get metadata from workspace file
            meta = _get_workspace_metadata(ws_path)
            if meta:
                info["metadata"] = meta

        return JSONResponse(info)
    except Exception as e:
        logger.error(f"Error getting workspace info: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


@router.post("/api/settings/test-key")
async def test_api_key(req: Dict[str, Any]):
    """Test an API key to verify it's valid."""
    import requests as http_requests

    # Temporarily disable debug logging for urllib3 and requests to prevent API key disclosure
    urllib3_logger = logging.getLogger("urllib3")
    requests_logger = logging.getLogger("requests")
    httpcore_logger = logging.getLogger("httpcore")

    original_urllib3_level = urllib3_logger.level
    original_requests_level = requests_logger.level
    original_httpcore_level = httpcore_logger.level

    # Set to WARNING level to suppress DEBUG logs that might contain API keys
    urllib3_logger.setLevel(logging.WARNING)
    requests_logger.setLevel(logging.WARNING)
    httpcore_logger.setLevel(logging.WARNING)

    source = req.get("source")
    api_key = req.get("api_key")

    if not source or not api_key:
        # Restore original logging levels
        urllib3_logger.setLevel(original_urllib3_level)
        requests_logger.setLevel(original_requests_level)
        httpcore_logger.setLevel(original_httpcore_level)
        raise HTTPException(status_code=400, detail="Missing source or api_key")

    try:
        # Test the API key with a simple request
        if source == "shodan":
            url = f"https://api.shodan.io/api-info?key={api_key}"
            response = http_requests.get(url, timeout=10)
            valid = response.status_code == 200

        elif source == "virustotal":
            url = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
            headers = {"x-apikey": api_key}
            response = http_requests.get(url, headers=headers, timeout=10)
            valid = response.status_code == 200

        elif source == "abuseipdb":
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Accept": "application/json", "Key": api_key}
            params = {"ipAddress": "8.8.8.8", "maxAgeInDays": 90}
            response = http_requests.get(url, headers=headers, params=params, timeout=10)
            valid = response.status_code == 200

        elif source == "otx":
            url = "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general"
            headers = {"X-OTX-API-KEY": api_key}
            response = http_requests.get(url, headers=headers, timeout=10)
            valid = response.status_code == 200

        elif source == "urlscan":
            url = "https://urlscan.io/api/v1/search/?q=domain:google.com"
            headers = {"API-Key": api_key}
            response = http_requests.get(url, headers=headers, timeout=10)
            valid = response.status_code == 200

        elif source == "censys":
            # Censys requires API_ID:SECRET format
            if ":" not in api_key:
                urllib3_logger.setLevel(original_urllib3_level)
                requests_logger.setLevel(original_requests_level)
                httpcore_logger.setLevel(original_httpcore_level)
                return JSONResponse({"valid": False, "error": "API key must be in format API_ID:SECRET"})
            api_id, api_secret = api_key.split(":", 1)
            url = "https://search.censys.io/api/v2/hosts/8.8.8.8"
            response = http_requests.get(url, auth=(api_id, api_secret), timeout=10)
            valid = response.status_code == 200

        elif source == "greynoise":
            url = "https://api.greynoise.io/v3/community/8.8.8.8"
            headers = {"key": api_key, "Accept": "application/json"}
            response = http_requests.get(url, headers=headers, timeout=10)
            valid = response.status_code == 200

        elif source == "spur":
            url = "https://api.spur.us/v2/context/8.8.8.8"
            headers = {"Token": api_key, "Accept": "application/json"}
            response = http_requests.get(url, headers=headers, timeout=10)
            valid = response.status_code == 200

        elif source == "dehashed":
            # Dehashed requires email:api_key format
            if ":" not in api_key:
                urllib3_logger.setLevel(original_urllib3_level)
                requests_logger.setLevel(original_requests_level)
                httpcore_logger.setLevel(original_httpcore_level)
                return JSONResponse({"valid": False, "error": "API key must be in format email:api_key"})
            api_email, api_secret = api_key.split(":", 1)
            url = "https://api.dehashed.com/search"
            params = {"query": "email:test@example.com", "size": 1}
            headers = {"Accept": "application/json"}
            response = http_requests.get(url, params=params, auth=(api_email, api_secret), headers=headers, timeout=10)
            valid = response.status_code == 200

        elif source == "bazaar":
            # MalwareBazaar - test with recent samples query
            url = "https://mb-api.abuse.ch/api/v1/"
            data = {"query": "get_recent"}
            headers = {"API-KEY": api_key} if api_key and api_key != "none" else {}
            response = http_requests.post(url, data=data, headers=headers, timeout=10)
            if response.status_code == 200:
                result = response.json()
                valid = result.get("query_status") == "ok"
            else:
                valid = False

        elif source == "prospeo":
            # Prospeo - test with simple domain search
            url = "https://api.prospeo.io/domain-search"
            headers = {
                "Content-Type": "application/json",
                "X-KEY": api_key
            }
            data = {"domain": "example.com"}
            response = http_requests.post(url, json=data, headers=headers, timeout=10)
            valid = response.status_code == 200

        else:
            # Restore original logging levels
            urllib3_logger.setLevel(original_urllib3_level)
            requests_logger.setLevel(original_requests_level)
            httpcore_logger.setLevel(original_httpcore_level)
            raise HTTPException(status_code=400, detail=f"Unknown source: {source}")

        # Restore original logging levels before returning
        urllib3_logger.setLevel(original_urllib3_level)
        requests_logger.setLevel(original_requests_level)
        httpcore_logger.setLevel(original_httpcore_level)

        if valid:
            return JSONResponse({"valid": True, "message": "API key is valid"})
        else:
            return JSONResponse({
                "valid": False,
                "error": f"HTTP {response.status_code}: {response.text[:200]}"
            })

    except http_requests.exceptions.Timeout:
        # Restore original logging levels
        urllib3_logger.setLevel(original_urllib3_level)
        requests_logger.setLevel(original_requests_level)
        httpcore_logger.setLevel(original_httpcore_level)
        return JSONResponse({"valid": False, "error": "Request timed out"})
    except http_requests.exceptions.RequestException as e:
        # Restore original logging levels
        urllib3_logger.setLevel(original_urllib3_level)
        requests_logger.setLevel(original_requests_level)
        httpcore_logger.setLevel(original_httpcore_level)
        return JSONResponse({"valid": False, "error": str(e)})
    except Exception as e:
        # Restore original logging levels
        urllib3_logger.setLevel(original_urllib3_level)
        requests_logger.setLevel(original_requests_level)
        httpcore_logger.setLevel(original_httpcore_level)
        logger.error(f"Error testing API key for {source}: {e}")
        return JSONResponse({"valid": False, "error": str(e)})
