"""
Cygor Proxy Configuration Module
==================================

Centralized proxy configuration that:
- Reads HTTP_PROXY, HTTPS_PROXY, NO_PROXY environment variables
- Integrates with jumpbox SOCKS5 tunnel for routing through pivot hosts
- Detects proxychains by checking LD_PRELOAD environment variable
- Provides helper functions for requests library configuration
- Returns properly formatted proxy dictionaries for Python requests

Usage:
    from cygor.proxy_config import get_requests_proxies, is_proxychains_active

    # In your code using requests
    proxies = get_requests_proxies()
    response = requests.get(url, proxies=proxies)

    # Check if proxychains is active
    if is_proxychains_active():
        print("Running through proxychains")

    # Check if jumpbox routing is active
    if is_jumpbox_routing_active():
        print("Routing through jumpbox")
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Optional, List, Any

logger = logging.getLogger(__name__)

# Tools that need proxychains for SOCKS support (no native support)
TOOLS_NEEDING_PROXYCHAINS = {
    'nmap', 'masscan', 'naabu', 'fping', 'nc', 'netcat',
    'mysql', 'psql', 'mssql',
    'smbclient', 'rpcclient',
    'snmpwalk', 'snmpget',
}


def _get_configured_proxy() -> Optional[Dict[str, str]]:
    """
    Load proxy settings from ~/.cygor/proxy_config.json if enabled.

    Returns:
        Dict with 'http', 'https', 'no_proxy' keys if enabled, None otherwise
    """
    try:
        config_path = Path.home() / ".cygor" / "proxy_config.json"
        if not config_path.exists():
            return None

        config = json.loads(config_path.read_text())
        if not config.get("enabled"):
            return None

        http_proxy = config.get("http_proxy", "").strip()
        https_proxy = config.get("https_proxy", "").strip()

        if not http_proxy and not https_proxy:
            return None

        return {
            'http': http_proxy or None,
            'https': https_proxy or None,
            'no_proxy': config.get("no_proxy", "").strip() or None
        }
    except Exception:
        return None


def is_jumpbox_routing_active() -> bool:
    """
    Check if traffic should be routed through jumpbox.

    Returns False if:
    - Jumpbox not enabled in settings
    - No active profile selected
    - Tunnel not connected
    - jumpbox_config.py not accessible (graceful import failure)

    Returns:
        True if jumpbox routing is active, False otherwise
    """
    try:
        from cygor.jumpbox_config import is_tunnel_active
        return is_tunnel_active()
    except (ImportError, FileNotFoundError, Exception):
        return False  # Fail silently - run without proxy


def _get_jumpbox_socks_url() -> Optional[str]:
    """Get SOCKS5 proxy URL from jumpbox if active."""
    try:
        from cygor.jumpbox_config import get_socks_proxy_url
        return get_socks_proxy_url()
    except (ImportError, Exception):
        return None


def get_proxy_config() -> Dict[str, Optional[str]]:
    """
    Get proxy configuration from jumpbox tunnel, configured settings, OR environment variables.

    Priority order:
    1. Jumpbox tunnel (if active)
    2. Configured proxy settings (~/.cygor/proxy_config.json)
    3. Environment variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY)

    Reads standard proxy environment variables:
    - HTTP_PROXY / http_proxy
    - HTTPS_PROXY / https_proxy
    - NO_PROXY / no_proxy

    Returns:
        Dict with keys 'http', 'https', 'no_proxy', '_source' (values may be None)
    """
    # Check for active jumpbox tunnel first
    if is_jumpbox_routing_active():
        socks_url = _get_jumpbox_socks_url()
        if socks_url:
            return {
                'http': socks_url,
                'https': socks_url,
                'no_proxy': None,
                '_source': 'jumpbox'
            }

    # Check for configured proxy settings
    configured = _get_configured_proxy()
    if configured:
        return {
            'http': configured.get('http'),
            'https': configured.get('https'),
            'no_proxy': configured.get('no_proxy'),
            '_source': 'configured'
        }

    # Fallback to environment variables
    return {
        'http': os.environ.get('HTTP_PROXY') or os.environ.get('http_proxy'),
        'https': os.environ.get('HTTPS_PROXY') or os.environ.get('https_proxy'),
        'no_proxy': os.environ.get('NO_PROXY') or os.environ.get('no_proxy'),
        '_source': 'environment'
    }


def is_proxychains_active() -> bool:
    """
    Detect if proxychains is active by checking LD_PRELOAD.

    Proxychains works by preloading a shared library that intercepts
    network calls. This is detectable via the LD_PRELOAD environment variable.

    Returns:
        True if proxychains appears to be active, False otherwise
    """
    ld_preload = os.environ.get('LD_PRELOAD', '')
    return 'proxychains' in ld_preload.lower() or 'libproxychains' in ld_preload.lower()


def get_requests_proxies() -> Dict[str, str]:
    """
    Get proxy configuration formatted for Python requests library.

    Checks jumpbox tunnel first, then falls back to environment variables.

    Returns a dict suitable for the `proxies` parameter in requests.get/post:
        proxies = get_requests_proxies()
        requests.get(url, proxies=proxies)

    Returns:
        Dict with 'http' and 'https' keys pointing to proxy URLs.
        Empty dict if no proxy is configured.

    Note:
        If proxychains is detected, returns empty dict since proxychains
        handles proxying at the system call level (no need to pass proxies
        to requests library).
    """
    # If proxychains is active, let it handle proxying
    if is_proxychains_active():
        return {}

    config = get_proxy_config()
    proxies = {}

    if config['http']:
        proxies['http'] = config['http']

    if config['https']:
        proxies['https'] = config['https']

    return proxies


def get_playwright_proxy() -> Optional[Dict[str, str]]:
    """
    Get proxy configuration formatted for Playwright browser launch.

    Checks jumpbox tunnel first, then falls back to environment variables.

    Playwright requires a different format than requests:
        {
            'server': 'http://proxy:port',
            'username': 'user',  # optional
            'password': 'pass'   # optional
        }

    Returns:
        Dict suitable for browser.launch(proxy=...) or None if no proxy configured.
    """
    # If proxychains is active, don't configure Playwright proxy
    # (proxychains operates at a lower level)
    if is_proxychains_active():
        return None

    config = get_proxy_config()

    # Prefer HTTPS proxy for Playwright, fall back to HTTP
    proxy_url = config['https'] or config['http']

    if not proxy_url:
        return None

    # Parse proxy URL for potential auth
    # Format: http://[user:pass@]host:port or socks5://host:port
    proxy_config = {'server': proxy_url}

    # Extract username/password if present in URL
    if '@' in proxy_url:
        # Simple parsing - full URL parsing could use urllib.parse
        try:
            protocol, rest = proxy_url.split('://', 1)
            if '@' in rest:
                auth, server = rest.split('@', 1)
                if ':' in auth:
                    username, password = auth.split(':', 1)
                    proxy_config = {
                        'server': f'{protocol}://{server}',
                        'username': username,
                        'password': password
                    }
        except Exception:
            # If parsing fails, just use the full URL
            pass

    return proxy_config


def format_proxy_for_subprocess(include_no_proxy: bool = True) -> Dict[str, str]:
    """
    Get proxy environment variables to pass to subprocess calls.

    Useful when spawning external tools that respect proxy environment variables.

    Args:
        include_no_proxy: Whether to include NO_PROXY in the returned dict

    Returns:
        Dict of environment variables to merge into subprocess env.
        Empty dict if no proxy is configured.

    Example:
        env = os.environ.copy()
        env.update(format_proxy_for_subprocess())
        subprocess.run(['nmap', ...], env=env)
    """
    config = get_proxy_config()
    env = {}

    if config['http']:
        env['HTTP_PROXY'] = config['http']
        env['http_proxy'] = config['http']

    if config['https']:
        env['HTTPS_PROXY'] = config['https']
        env['https_proxy'] = config['https']

    if include_no_proxy and config.get('no_proxy'):
        env['NO_PROXY'] = config['no_proxy']
        env['no_proxy'] = config['no_proxy']

    return env


def format_socks_proxy_for_subprocess() -> Dict[str, str]:
    """
    Get SOCKS proxy environment variables for subprocess calls.

    Returns ALL_PROXY and related vars if jumpbox tunnel is active.
    Tools like curl respect ALL_PROXY for SOCKS.

    Returns:
        Dict of environment variables to merge into subprocess env.
        Empty dict if no SOCKS proxy is active.

    Example:
        env = os.environ.copy()
        socks_env = format_socks_proxy_for_subprocess()
        if socks_env:
            env.update(socks_env)
            logger.info("Routing through jumpbox")
        subprocess.run(cmd, env=env)
    """
    if not is_jumpbox_routing_active():
        return {}

    socks_url = _get_jumpbox_socks_url()
    if not socks_url:
        return {}

    return {
        'ALL_PROXY': socks_url,
        'all_proxy': socks_url,
        'HTTPS_PROXY': socks_url,
        'https_proxy': socks_url,
        'HTTP_PROXY': socks_url,
        'http_proxy': socks_url,
    }


def get_active_proxy_info() -> Dict[str, Any]:
    """
    Get information about the currently active proxy configuration.

    Returns details about whether jumpbox or environment proxy is active.

    Returns:
        Dict with active, type, and relevant details
    """
    # Check jumpbox first
    if is_jumpbox_routing_active():
        try:
            from cygor.jumpbox_config import get_tunnel_status, get_jumpbox_config
            status = get_tunnel_status()
            config = get_jumpbox_config()
            return {
                "active": True,
                "type": "jumpbox",
                "socks_port": config.get("socks_port", 9050),
                "connected_at": status.get("connected_at"),
                "profile_name": status.get("profile_name"),
                "socks_url": _get_jumpbox_socks_url()
            }
        except ImportError:
            pass

    # Check proxychains
    if is_proxychains_active():
        return {
            "active": True,
            "type": "proxychains",
            "note": "Proxychains detected via LD_PRELOAD"
        }

    # Check configured or environment proxy
    config = get_proxy_config()
    if config.get('http') or config.get('https'):
        proxy_type = config.get('_source', 'environment')
        if proxy_type == 'configured':
            return {
                "active": True,
                "type": "configured",
                "http_proxy": config.get('http'),
                "https_proxy": config.get('https')
            }
        else:
            return {
                "active": True,
                "type": "environment",
                "http_proxy": config.get('http'),
                "https_proxy": config.get('https')
            }

    return {"active": False, "type": None}


# =============================================================================
# Proxychains Integration
# =============================================================================

def should_use_proxychains(tool_name: str) -> bool:
    """
    Check if a tool needs proxychains for SOCKS support.

    Returns True for tools that don't natively support SOCKS proxies.

    Args:
        tool_name: Name of the tool (e.g., 'nmap', 'masscan')

    Returns:
        True if tool needs proxychains, False if it has native support
    """
    return tool_name.lower() in TOOLS_NEEDING_PROXYCHAINS


def get_proxychains_wrapper() -> Optional[List[str]]:
    """
    Get proxychains wrapper command if jumpbox tunnel is active.

    Returns:
        ['proxychains4', '-q', '-f', '/path/to/conf'] or None
    """
    if not is_jumpbox_routing_active():
        return None

    try:
        from cygor.jumpbox_config import get_proxychains_command
        return get_proxychains_command()
    except ImportError:
        return None


def get_proxychains_wrapper_if_needed(tool_name: str) -> Optional[List[str]]:
    """
    Get proxychains wrapper for tools that need it.

    Returns None if:
    - Tool supports SOCKS natively
    - Tunnel not active
    - Proxychains not installed

    Args:
        tool_name: Name of the tool (e.g., 'nmap', 'masscan')

    Returns:
        Wrapper command list or None
    """
    if not is_jumpbox_routing_active():
        return None

    if not should_use_proxychains(tool_name):
        return None

    return get_proxychains_wrapper()


def wrap_command_if_needed(cmd: List[str], tool_name: str) -> List[str]:
    """
    Wrap a command with proxychains if jumpbox is active and tool needs it.

    Args:
        cmd: Command as list of strings
        tool_name: Name of the tool for proxy method detection

    Returns:
        Wrapped command if needed, original command otherwise
    """
    wrapper = get_proxychains_wrapper_if_needed(tool_name)
    if wrapper:
        logger.info(f"Wrapping {tool_name} with proxychains for jumpbox routing")
        return wrapper + cmd
    return cmd


# =============================================================================
# Tunnel Health Check
# =============================================================================

def verify_proxy_or_warn() -> bool:
    """
    Check if proxy is still active, log warning if it dropped.

    Call this periodically during long operations to detect tunnel drops.

    Returns:
        True if proxy active, False if not (operation should continue either way)
    """
    if not is_jumpbox_routing_active():
        return False  # No proxy configured - normal operation

    try:
        from cygor.jumpbox_config import check_tunnel_health
        healthy, msg = check_tunnel_health()
        if not healthy:
            logger.warning(f"[!] Jumpbox tunnel dropped: {msg}")
            logger.warning("[!] Continuing without proxy")
            return False
        return True
    except ImportError:
        return False


if __name__ == "__main__":
    """Quick test/debug output"""
    print("Proxy Configuration")
    print("=" * 50)
    print(f"Jumpbox routing active: {is_jumpbox_routing_active()}")
    print(f"Proxychains active: {is_proxychains_active()}")
    print(f"Raw config: {get_proxy_config()}")
    print(f"Requests format: {get_requests_proxies()}")
    print(f"Playwright format: {get_playwright_proxy()}")
    print(f"Subprocess env: {format_proxy_for_subprocess()}")
    print(f"SOCKS subprocess env: {format_socks_proxy_for_subprocess()}")
    print(f"Active proxy info: {get_active_proxy_info()}")
    print()
    print("Proxychains wrapper:", get_proxychains_wrapper())
    print("Tools needing proxychains:", TOOLS_NEEDING_PROXYCHAINS)
