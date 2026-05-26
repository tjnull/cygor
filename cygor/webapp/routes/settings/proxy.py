"""Proxy settings routes."""

import json
import logging
import os
from pathlib import Path

from fastapi import APIRouter
from fastapi.requests import Request
from fastapi.responses import JSONResponse

from ...db import get_session
from ...config import settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["proxy"])


def _get_proxy_config_path() -> Path:
    """Get path to proxy configuration file."""
    config_dir = Path.home() / ".cygor"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "proxy_config.json"


def _load_proxy_config() -> dict:
    """Load proxy configuration from file."""
    config_path = _get_proxy_config_path()
    if config_path.exists():
        try:
            return json.loads(config_path.read_text())
        except Exception:
            pass
    return {
        "enabled": False,
        "http_proxy": "",
        "https_proxy": "",
        "no_proxy": ""
    }


def _save_proxy_config(config: dict) -> None:
    """Save proxy configuration to file."""
    config_path = _get_proxy_config_path()
    config_path.write_text(json.dumps(config, indent=2))
    config_path.chmod(0o600)


@router.get("/api/settings/proxy")
async def get_proxy_settings(request: Request):
    """Get proxy configuration."""
    try:
        config = _load_proxy_config()

        # Get active proxy info from proxy_config module
        try:
            from cygor.proxy_config import get_active_proxy_info
            active_info = get_active_proxy_info()

            # If configured proxy is enabled, update active_info
            if config.get("enabled") and (config.get("http_proxy") or config.get("https_proxy")):
                if not active_info.get("active") or active_info.get("type") == "environment":
                    active_info = {
                        "active": True,
                        "type": "configured",
                        "http_proxy": config.get("http_proxy"),
                        "https_proxy": config.get("https_proxy")
                    }
        except ImportError:
            active_info = {"active": False, "type": None}

        config["active_info"] = active_info
        return JSONResponse(config)
    except Exception as e:
        return JSONResponse({
            "enabled": False,
            "http_proxy": "",
            "https_proxy": "",
            "no_proxy": "",
            "active_info": {"active": False, "type": None},
            "error": str(e)
        })


@router.post("/api/settings/proxy")
async def save_proxy_settings(request: Request):
    """Save proxy configuration."""
    try:
        data = await request.json()

        config = {
            "enabled": data.get("enabled", False),
            "http_proxy": data.get("http_proxy", "").strip(),
            "https_proxy": data.get("https_proxy", "").strip(),
            "no_proxy": data.get("no_proxy", "").strip()
        }

        _save_proxy_config(config)

        # Apply to environment if enabled
        if config["enabled"]:
            if config["http_proxy"]:
                os.environ["HTTP_PROXY"] = config["http_proxy"]
                os.environ["http_proxy"] = config["http_proxy"]
            if config["https_proxy"]:
                os.environ["HTTPS_PROXY"] = config["https_proxy"]
                os.environ["https_proxy"] = config["https_proxy"]
            if config["no_proxy"]:
                os.environ["NO_PROXY"] = config["no_proxy"]
                os.environ["no_proxy"] = config["no_proxy"]
        else:
            # Clear environment variables if disabled
            for var in ["HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"]:
                os.environ.pop(var, None)

        return JSONResponse({"success": True, "message": "Proxy settings saved"})
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)


@router.post("/api/settings/proxy/test")
async def test_proxy_connection(request: Request):
    """Test proxy connection by fetching external IP."""
    try:
        import requests as req_lib

        # Get configured proxies
        try:
            from cygor.proxy_config import get_requests_proxies
            proxies = get_requests_proxies()
        except ImportError:
            proxies = {}

        # Also check for configured proxy settings
        config = _load_proxy_config()
        if config.get("enabled"):
            if config.get("http_proxy"):
                proxies["http"] = config["http_proxy"]
            if config.get("https_proxy"):
                proxies["https"] = config["https_proxy"]

        # Test connection
        resp = req_lib.get(
            "https://ipinfo.io/json",
            proxies=proxies if proxies else None,
            timeout=10
        )

        if resp.status_code == 200:
            data = resp.json()
            return JSONResponse({
                "success": True,
                "external_ip": data.get("ip"),
                "geo": f"{data.get('city', '')}, {data.get('region', '')}, {data.get('country', '')}".strip(", "),
                "using_proxy": bool(proxies)
            })
        else:
            return JSONResponse({
                "success": False,
                "error": f"HTTP {resp.status_code}"
            })
    except req_lib.exceptions.Timeout:
        return JSONResponse({
            "success": False,
            "error": "Connection timed out"
        })
    except req_lib.exceptions.ProxyError as e:
        return JSONResponse({
            "success": False,
            "error": f"Proxy error: {str(e)}"
        })
    except Exception as e:
        return JSONResponse({
            "success": False,
            "error": str(e)
        })
