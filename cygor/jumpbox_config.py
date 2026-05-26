"""
Jumpbox/Pivot Host Configuration Module
========================================

Manages SSH SOCKS5 proxy tunnels for routing scan traffic through a jumpbox.

Features:
- Profile management (create, update, delete, list)
- SSH tunnel lifecycle (connect, disconnect, status)
- Secure credential storage with encryption
- Tunnel health monitoring
- Proxychains config generation

Usage:
    from cygor.jumpbox_config import (
        connect_tunnel, disconnect_tunnel, is_tunnel_active,
        get_socks_proxy_url, list_profiles
    )

    # Connect to active profile
    success, msg = connect_tunnel()

    # Check if routing through jumpbox
    if is_tunnel_active():
        proxy_url = get_socks_proxy_url()  # socks5://127.0.0.1:9050
"""

import os
import json
import subprocess
import shutil
import signal
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime
import uuid
import base64

logger = logging.getLogger(__name__)

# Configuration paths
JUMPBOX_CONFIG_DIR = Path.home() / ".cygor" / "jumpbox"
JUMPBOX_CONFIG_FILE = JUMPBOX_CONFIG_DIR / "jumpbox_config.json"
JUMPBOX_KEY_FILE = JUMPBOX_CONFIG_DIR / ".encryption_key"
SSH_KEY_STORAGE_DIR = JUMPBOX_CONFIG_DIR / "ssh_keys"
PROXYCHAINS_CONF_FILE = JUMPBOX_CONFIG_DIR / "proxychains.conf"

# Default configuration
DEFAULT_CONFIG = {
    "enabled": False,
    "active_profile_id": None,
    "socks_port": 9050,
    "execution_mode": "local_socks",
    "profiles": [],
    "tunnel_state": {
        "connected": False,
        "profile_id": None,
        "pid": None,
        "connected_at": None,
        "last_test_ip": None,
        "last_test_geo": None
    }
}


def _ensure_config_dir() -> None:
    """Ensure configuration directory exists with proper permissions."""
    JUMPBOX_CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    JUMPBOX_CONFIG_DIR.chmod(0o700)
    SSH_KEY_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    SSH_KEY_STORAGE_DIR.chmod(0o700)


def _get_encryption_key() -> bytes:
    """
    Get or create encryption key for password storage.
    Uses Fernet symmetric encryption.
    """
    _ensure_config_dir()

    if JUMPBOX_KEY_FILE.exists():
        return JUMPBOX_KEY_FILE.read_bytes()

    # Generate new key
    try:
        from cryptography.fernet import Fernet
        key = Fernet.generate_key()
    except ImportError:
        # Fallback to base64-encoded random bytes if cryptography not available
        import secrets
        key = base64.urlsafe_b64encode(secrets.token_bytes(32))

    JUMPBOX_KEY_FILE.write_bytes(key)
    JUMPBOX_KEY_FILE.chmod(0o600)
    return key


def _encrypt_value(value: str) -> str:
    """Encrypt a sensitive value (e.g., password)."""
    if not value:
        return ""

    try:
        from cryptography.fernet import Fernet
        key = _get_encryption_key()
        f = Fernet(key)
        encrypted = f.encrypt(value.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    except ImportError:
        # Fallback: simple base64 encoding (not secure, but functional)
        logger.warning("cryptography not installed - passwords stored with basic encoding")
        return base64.urlsafe_b64encode(value.encode()).decode()


def _decrypt_value(encrypted: str) -> str:
    """Decrypt a sensitive value."""
    if not encrypted:
        return ""

    try:
        from cryptography.fernet import Fernet
        key = _get_encryption_key()
        f = Fernet(key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted.encode())
        return f.decrypt(encrypted_bytes).decode()
    except ImportError:
        # Fallback: simple base64 decoding
        return base64.urlsafe_b64decode(encrypted.encode()).decode()
    except Exception as e:
        logger.error(f"Failed to decrypt value: {e}")
        return ""


def _get_config() -> Dict[str, Any]:
    """Load configuration from file."""
    _ensure_config_dir()

    if not JUMPBOX_CONFIG_FILE.exists():
        return DEFAULT_CONFIG.copy()

    try:
        with open(JUMPBOX_CONFIG_FILE, 'r') as f:
            config = json.load(f)
        # Merge with defaults to ensure all keys exist
        merged = DEFAULT_CONFIG.copy()
        merged.update(config)
        # Ensure nested dicts are properly merged
        merged["tunnel_state"] = {**DEFAULT_CONFIG["tunnel_state"], **config.get("tunnel_state", {})}
        return merged
    except (json.JSONDecodeError, IOError) as e:
        logger.error(f"Failed to load jumpbox config: {e}")
        return DEFAULT_CONFIG.copy()


def _save_config(config: Dict[str, Any]) -> None:
    """Save configuration to file."""
    _ensure_config_dir()

    try:
        with open(JUMPBOX_CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        JUMPBOX_CONFIG_FILE.chmod(0o600)
    except IOError as e:
        logger.error(f"Failed to save jumpbox config: {e}")
        raise


def _update_tunnel_state(**kwargs) -> None:
    """Update tunnel state fields."""
    config = _get_config()
    config["tunnel_state"].update(kwargs)
    _save_config(config)


def _is_process_running(pid: int) -> bool:
    """Check if a process with given PID is running."""
    try:
        os.kill(pid, 0)
        return True
    except (OSError, ProcessLookupError):
        return False


def _find_ssh_tunnel_pid(socks_port: int) -> Optional[int]:
    """Find the PID of SSH tunnel process using the given SOCKS port."""
    try:
        # Use lsof to find process listening on the port
        result = subprocess.run(
            ["lsof", "-t", "-i", f"TCP@127.0.0.1:{socks_port}", "-sTCP:LISTEN"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.strip().split('\n')[0])
    except Exception:
        pass

    try:
        # Fallback: use ss/netstat
        result = subprocess.run(
            ["ss", "-tlnp"],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in result.stdout.split('\n'):
            if f":{socks_port}" in line and "ssh" in line.lower():
                # Extract PID from ss output
                import re
                match = re.search(r'pid=(\d+)', line)
                if match:
                    return int(match.group(1))
    except Exception:
        pass

    return None


# =============================================================================
# Public API - Configuration
# =============================================================================

def get_jumpbox_config() -> Dict[str, Any]:
    """
    Get full jumpbox configuration (without sensitive data).

    Returns:
        Dict with enabled, active_profile_id, socks_port, execution_mode
    """
    config = _get_config()
    # Don't expose passwords
    safe_config = {
        "enabled": config.get("enabled", False),
        "active_profile_id": config.get("active_profile_id"),
        "socks_port": config.get("socks_port", 9050),
        "execution_mode": config.get("execution_mode", "local_socks"),
    }
    return safe_config


def set_jumpbox_enabled(enabled: bool) -> None:
    """Enable or disable jumpbox routing."""
    config = _get_config()
    config["enabled"] = enabled
    _save_config(config)
    logger.info(f"Jumpbox {'enabled' if enabled else 'disabled'}")


def set_socks_port(port: int) -> None:
    """Set the local SOCKS5 proxy port."""
    if not 1024 <= port <= 65535:
        raise ValueError("Port must be between 1024 and 65535")
    config = _get_config()
    config["socks_port"] = port
    _save_config(config)
    logger.info(f"Jumpbox SOCKS port set to {port}")


def set_execution_mode(mode: str) -> None:
    """Set execution mode (currently only 'local_socks' supported)."""
    valid_modes = ["local_socks"]
    if mode not in valid_modes:
        raise ValueError(f"Invalid mode. Must be one of: {valid_modes}")
    config = _get_config()
    config["execution_mode"] = mode
    _save_config(config)


# =============================================================================
# Public API - Profile Management
# =============================================================================

def create_profile(
    name: str,
    host: str,
    port: int = 22,
    username: str = "root",
    auth_type: str = "password",
    password: Optional[str] = None,
    ssh_key_path: Optional[str] = None,
    ssh_key_passphrase: Optional[str] = None
) -> str:
    """
    Create a new jumpbox profile.

    Args:
        name: Display name for the profile
        host: SSH host/IP address
        port: SSH port (default 22)
        username: SSH username
        auth_type: "password" or "ssh_key"
        password: SSH password (if auth_type is "password")
        ssh_key_path: Path to SSH private key (if auth_type is "ssh_key")
        ssh_key_passphrase: Passphrase for SSH key (optional)

    Returns:
        Profile ID (UUID string)
    """
    if not host:
        raise ValueError("Host is required")
    if not username:
        raise ValueError("Username is required")
    if auth_type not in ["password", "ssh_key"]:
        raise ValueError("auth_type must be 'password' or 'ssh_key'")

    profile_id = str(uuid.uuid4())

    profile = {
        "id": profile_id,
        "name": name or f"Profile {host}",
        "host": host,
        "port": port,
        "username": username,
        "auth_type": auth_type,
        "password": _encrypt_value(password) if password else None,
        "ssh_key_path": ssh_key_path,
        "ssh_key_passphrase": _encrypt_value(ssh_key_passphrase) if ssh_key_passphrase else None,
        "created_at": datetime.utcnow().isoformat(),
        "last_used": None
    }

    config = _get_config()
    config["profiles"].append(profile)
    _save_config(config)

    logger.info(f"Created jumpbox profile: {name} ({username}@{host})")
    return profile_id


def update_profile(profile_id: str, **kwargs) -> bool:
    """
    Update an existing profile.

    Args:
        profile_id: Profile UUID
        **kwargs: Fields to update (name, host, port, username, auth_type, password, ssh_key_path, ssh_key_passphrase)

    Returns:
        True if updated, False if profile not found
    """
    config = _get_config()

    for i, profile in enumerate(config["profiles"]):
        if profile["id"] == profile_id:
            # Encrypt sensitive fields if provided
            if "password" in kwargs and kwargs["password"]:
                kwargs["password"] = _encrypt_value(kwargs["password"])
            if "ssh_key_passphrase" in kwargs and kwargs["ssh_key_passphrase"]:
                kwargs["ssh_key_passphrase"] = _encrypt_value(kwargs["ssh_key_passphrase"])

            config["profiles"][i].update(kwargs)
            _save_config(config)
            logger.info(f"Updated jumpbox profile: {profile_id}")
            return True

    return False


def delete_profile(profile_id: str) -> bool:
    """
    Delete a profile.

    Args:
        profile_id: Profile UUID

    Returns:
        True if deleted, False if not found
    """
    config = _get_config()

    for i, profile in enumerate(config["profiles"]):
        if profile["id"] == profile_id:
            # If this is the active profile, clear it
            if config["active_profile_id"] == profile_id:
                config["active_profile_id"] = None

            del config["profiles"][i]
            _save_config(config)
            logger.info(f"Deleted jumpbox profile: {profile_id}")
            return True

    return False


def get_profile(profile_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a profile by ID (with decrypted credentials for internal use).

    Args:
        profile_id: Profile UUID

    Returns:
        Profile dict or None if not found
    """
    config = _get_config()

    for profile in config["profiles"]:
        if profile["id"] == profile_id:
            # Return copy with decrypted values for internal use
            result = profile.copy()
            if result.get("password"):
                result["password"] = _decrypt_value(result["password"])
            if result.get("ssh_key_passphrase"):
                result["ssh_key_passphrase"] = _decrypt_value(result["ssh_key_passphrase"])
            return result

    return None


def list_profiles() -> List[Dict[str, Any]]:
    """
    List all profiles (without sensitive data).

    Returns:
        List of profile dicts (passwords masked)
    """
    config = _get_config()
    profiles = []

    for profile in config["profiles"]:
        safe_profile = {
            "id": profile["id"],
            "name": profile["name"],
            "host": profile["host"],
            "port": profile["port"],
            "username": profile["username"],
            "auth_type": profile["auth_type"],
            "has_password": bool(profile.get("password")),
            "ssh_key_path": profile.get("ssh_key_path"),
            "created_at": profile.get("created_at"),
            "last_used": profile.get("last_used")
        }
        profiles.append(safe_profile)

    return profiles


def set_active_profile(profile_id: Optional[str]) -> bool:
    """
    Set the active profile for connections.

    Args:
        profile_id: Profile UUID or None to clear

    Returns:
        True if set, False if profile not found
    """
    config = _get_config()

    if profile_id is None:
        config["active_profile_id"] = None
        _save_config(config)
        return True

    # Verify profile exists
    for profile in config["profiles"]:
        if profile["id"] == profile_id:
            config["active_profile_id"] = profile_id
            _save_config(config)
            logger.info(f"Active jumpbox profile set to: {profile['name']}")
            return True

    return False


def save_ssh_key_for_profile(profile_id: str, key_content: bytes) -> Path:
    """
    Save an uploaded SSH key file for a profile.

    Args:
        profile_id: Profile UUID
        key_content: SSH private key content

    Returns:
        Path to saved key file
    """
    _ensure_config_dir()

    key_path = SSH_KEY_STORAGE_DIR / f"{profile_id}.key"
    key_path.write_bytes(key_content)
    key_path.chmod(0o600)

    return key_path


# =============================================================================
# Public API - Tunnel Management
# =============================================================================

def connect_tunnel() -> Tuple[bool, str]:
    """
    Create SSH SOCKS5 tunnel using the active profile.

    Uses: ssh -D <port> -N -f -o StrictHostKeyChecking=accept-new <user>@<host>

    Returns:
        Tuple of (success: bool, message: str)
    """
    config = _get_config()

    if not config["enabled"]:
        return False, "Jumpbox is not enabled. Enable it in settings first."

    profile_id = config["active_profile_id"]
    if not profile_id:
        return False, "No active profile selected. Select a profile first."

    profile = get_profile(profile_id)
    if not profile:
        return False, "Active profile not found. It may have been deleted."

    # Check if already connected
    if config["tunnel_state"]["connected"]:
        pid = config["tunnel_state"]["pid"]
        if pid and _is_process_running(pid):
            return False, "Tunnel is already connected"
        # Process died, clean up state
        _update_tunnel_state(connected=False, pid=None, connected_at=None)

    # Check if port is available
    socks_port = config["socks_port"]
    existing_pid = _find_ssh_tunnel_pid(socks_port)
    if existing_pid:
        return False, f"Port {socks_port} is already in use (PID: {existing_pid})"

    # Build SSH command
    ssh_port = profile.get("port", 22)
    cmd = [
        "ssh",
        "-D", str(socks_port),
        "-N",  # No remote command
        "-f",  # Fork to background
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "BatchMode=yes",  # Prevent interactive prompts
        "-p", str(ssh_port),
    ]

    # Add SSH key if using key auth
    if profile["auth_type"] == "ssh_key":
        key_path = profile.get("ssh_key_path")
        if key_path:
            # Expand ~ in path
            key_path = os.path.expanduser(key_path)
            if os.path.exists(key_path):
                cmd.extend(["-i", key_path])
            else:
                return False, f"SSH key not found: {key_path}"

    cmd.append(f"{profile['username']}@{profile['host']}")

    # Execute
    try:
        env = os.environ.copy()

        if profile["auth_type"] == "password":
            password = profile.get("password", "")
            if not password:
                return False, "Password not set for this profile"

            # Check if sshpass is installed
            if not shutil.which("sshpass"):
                return False, "sshpass is required for password authentication. Install with: sudo apt install sshpass"

            # Use sshpass for password authentication
            cmd = ["sshpass", "-p", password] + cmd

        logger.info(f"Connecting to jumpbox: {profile['username']}@{profile['host']}:{ssh_port}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            env=env
        )

        if result.returncode == 0:
            # Wait a moment for the tunnel to establish
            import time
            time.sleep(1)

            # Find the SSH process PID
            pid = _find_ssh_tunnel_pid(socks_port)

            # Update profile last_used
            update_profile(profile_id, last_used=datetime.utcnow().isoformat())

            # Update tunnel state
            _update_tunnel_state(
                connected=True,
                profile_id=profile_id,
                pid=pid,
                connected_at=datetime.utcnow().isoformat(),
                last_test_ip=None,
                last_test_geo=None
            )

            # Generate proxychains config
            generate_proxychains_config()

            logger.info(f"SSH tunnel connected on port {socks_port} (PID: {pid})")
            return True, f"Connected successfully on port {socks_port}"
        else:
            error_msg = result.stderr.strip() or result.stdout.strip() or "Unknown error"
            logger.error(f"SSH tunnel failed: {error_msg}")
            return False, f"SSH connection failed: {error_msg}"

    except subprocess.TimeoutExpired:
        return False, "Connection timed out after 30 seconds"
    except FileNotFoundError as e:
        return False, f"Required command not found: {e}"
    except Exception as e:
        logger.exception("Failed to connect tunnel")
        return False, f"Connection error: {str(e)}"


def connect_tunnel_streaming():
    """
    Generator that yields step-by-step log events during SSH tunnel connection.

    Yields dicts with keys: event, message, level, and optional extra data.
    Events: 'log', 'connected', 'ip_result', 'error', 'done'
    """
    config = _get_config()

    if not config["enabled"]:
        yield {"event": "error", "message": "Jumpbox is not enabled. Enable it in settings first."}
        yield {"event": "done"}
        return

    profile_id = config["active_profile_id"]
    if not profile_id:
        yield {"event": "error", "message": "No active profile selected. Select a profile first."}
        yield {"event": "done"}
        return

    profile = get_profile(profile_id)
    if not profile:
        yield {"event": "error", "message": "Active profile not found. It may have been deleted."}
        yield {"event": "done"}
        return

    yield {"event": "log", "message": f"Using profile: {profile.get('name', 'unknown')}", "level": "info"}
    yield {"event": "log", "message": f"Target: {profile['username']}@{profile['host']}:{profile.get('port', 22)}", "level": "info"}

    # Check if already connected
    if config["tunnel_state"]["connected"]:
        pid = config["tunnel_state"]["pid"]
        if pid and _is_process_running(pid):
            yield {"event": "error", "message": "Tunnel is already connected"}
            yield {"event": "done"}
            return
        yield {"event": "log", "message": "Previous tunnel process died, cleaning up state...", "level": "warn"}
        _update_tunnel_state(connected=False, pid=None, connected_at=None)

    # Check if port is available
    socks_port = config["socks_port"]
    yield {"event": "log", "message": f"Checking if SOCKS port {socks_port} is available...", "level": "info"}
    existing_pid = _find_ssh_tunnel_pid(socks_port)
    if existing_pid:
        yield {"event": "error", "message": f"Port {socks_port} is already in use (PID: {existing_pid})"}
        yield {"event": "done"}
        return
    yield {"event": "log", "message": f"Port {socks_port} is available", "level": "info"}

    # Build SSH command
    ssh_port = profile.get("port", 22)
    cmd = [
        "ssh",
        "-D", str(socks_port),
        "-N", "-f",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ServerAliveInterval=30",
        "-o", "ServerAliveCountMax=3",
        "-o", "ExitOnForwardFailure=yes",
        "-o", "BatchMode=yes",
        "-p", str(ssh_port),
    ]

    # Add SSH key if using key auth
    if profile["auth_type"] == "ssh_key":
        key_path = profile.get("ssh_key_path")
        if key_path:
            key_path = os.path.expanduser(key_path)
            if os.path.exists(key_path):
                cmd.extend(["-i", key_path])
                yield {"event": "log", "message": f"Using SSH key: {key_path}", "level": "info"}
            else:
                yield {"event": "error", "message": f"SSH key not found: {key_path}"}
                yield {"event": "done"}
                return
    elif profile["auth_type"] == "password":
        yield {"event": "log", "message": "Using password authentication", "level": "info"}

    cmd.append(f"{profile['username']}@{profile['host']}")

    # Execute
    try:
        env = os.environ.copy()

        if profile["auth_type"] == "password":
            password = profile.get("password", "")
            if not password:
                yield {"event": "error", "message": "Password not set for this profile"}
                yield {"event": "done"}
                return

            if not shutil.which("sshpass"):
                yield {"event": "error", "message": "sshpass is required for password auth. Install with: sudo apt install sshpass"}
                yield {"event": "done"}
                return

            cmd = ["sshpass", "-p", password] + cmd

        yield {"event": "log", "message": f"Establishing SSH SOCKS5 tunnel on port {socks_port}...", "level": "step"}

        # Log the command (without password)
        safe_cmd = [c for c in cmd]
        if "sshpass" in safe_cmd:
            # Mask the password in logs
            try:
                pw_idx = safe_cmd.index("-p") + 1
                safe_cmd[pw_idx] = "********"
            except (ValueError, IndexError):
                pass
        yield {"event": "log", "message": f"Command: {' '.join(safe_cmd)}", "level": "info"}

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            env=env
        )

        if result.returncode == 0:
            yield {"event": "log", "message": "SSH process started, waiting for tunnel to establish...", "level": "info"}
            import time
            time.sleep(1)

            pid = _find_ssh_tunnel_pid(socks_port)

            update_profile(profile_id, last_used=datetime.utcnow().isoformat())
            _update_tunnel_state(
                connected=True,
                profile_id=profile_id,
                pid=pid,
                connected_at=datetime.utcnow().isoformat(),
                last_test_ip=None,
                last_test_geo=None
            )
            generate_proxychains_config()

            yield {"event": "log", "message": f"Tunnel established (PID: {pid})", "level": "info"}
            yield {"event": "log", "message": "Proxychains config generated", "level": "info"}
            yield {"event": "connected", "message": f"Connected successfully on port {socks_port}"}

            # Auto-test the tunnel IP
            yield {"event": "log", "message": "Testing tunnel by fetching external IP...", "level": "step"}
            try:
                ip_result = test_tunnel_ip()
                yield {
                    "event": "ip_result",
                    "success": ip_result.get("success", False),
                    "ip": ip_result.get("ip"),
                    "geo": ip_result.get("geo"),
                    "error": ip_result.get("error"),
                }
            except Exception as e:
                yield {"event": "ip_result", "success": False, "error": str(e)}

        else:
            stderr = result.stderr.strip()
            stdout = result.stdout.strip()
            error_msg = stderr or stdout or "Unknown error"
            yield {"event": "log", "message": f"SSH stderr: {stderr}", "level": "error"} if stderr else None
            yield {"event": "log", "message": f"SSH stdout: {stdout}", "level": "error"} if stdout else None
            yield {"event": "error", "message": f"SSH connection failed (exit code {result.returncode}): {error_msg}"}

    except subprocess.TimeoutExpired:
        yield {"event": "error", "message": "Connection timed out after 30 seconds"}
    except FileNotFoundError as e:
        yield {"event": "error", "message": f"Required command not found: {e}"}
    except Exception as e:
        logger.exception("Failed to connect tunnel")
        yield {"event": "error", "message": f"Connection error: {str(e)}"}

    yield {"event": "done"}


def disconnect_tunnel() -> Tuple[bool, str]:
    """
    Disconnect the active SSH tunnel.

    Returns:
        Tuple of (success: bool, message: str)
    """
    config = _get_config()

    if not config["tunnel_state"]["connected"]:
        return False, "No tunnel is connected"

    pid = config["tunnel_state"]["pid"]

    if pid:
        try:
            # Try graceful termination first
            os.kill(pid, signal.SIGTERM)

            # Wait a moment
            import time
            time.sleep(0.5)

            # Check if still running
            if _is_process_running(pid):
                # Force kill
                os.kill(pid, signal.SIGKILL)
                time.sleep(0.2)

            logger.info(f"SSH tunnel disconnected (PID: {pid})")

        except ProcessLookupError:
            # Process already dead
            pass
        except Exception as e:
            logger.warning(f"Error killing tunnel process: {e}")

    # Update state
    _update_tunnel_state(
        connected=False,
        profile_id=None,
        pid=None,
        connected_at=None
    )

    return True, "Tunnel disconnected"


def get_tunnel_status() -> Dict[str, Any]:
    """
    Get current tunnel connection status.

    Returns:
        Dict with connected, profile_id, profile_name, pid, connected_at, last_test_ip, last_test_geo
    """
    config = _get_config()
    state = config["tunnel_state"]

    # Verify tunnel is actually still running
    if state["connected"] and state["pid"]:
        if not _is_process_running(state["pid"]):
            # Tunnel died - update state
            _update_tunnel_state(connected=False, pid=None, connected_at=None)
            state = {"connected": False, "profile_id": None, "pid": None}

    # Get profile name if connected
    profile_name = None
    if state.get("profile_id"):
        for profile in config["profiles"]:
            if profile["id"] == state["profile_id"]:
                profile_name = profile["name"]
                break

    return {
        "connected": state.get("connected", False),
        "profile_id": state.get("profile_id"),
        "profile_name": profile_name,
        "pid": state.get("pid"),
        "connected_at": state.get("connected_at"),
        "last_test_ip": state.get("last_test_ip"),
        "last_test_geo": state.get("last_test_geo"),
        "socks_port": config.get("socks_port", 9050)
    }


def test_tunnel_ip() -> Dict[str, Any]:
    """
    Test the tunnel by fetching external IP through the SOCKS proxy.

    Returns:
        {"success": bool, "ip": str, "geo": dict, "error": str}
    """
    config = _get_config()

    if not config["tunnel_state"]["connected"]:
        return {"success": False, "error": "Tunnel not connected"}

    socks_port = config["socks_port"]

    # Verify tunnel process is still running
    pid = config["tunnel_state"]["pid"]
    if pid and not _is_process_running(pid):
        _update_tunnel_state(connected=False, pid=None)
        return {"success": False, "error": "Tunnel process has died"}

    try:
        # Use curl with SOCKS5 proxy to test
        result = subprocess.run([
            "curl", "-s", "--max-time", "10",
            "--socks5-hostname", f"127.0.0.1:{socks_port}",
            "https://ipinfo.io/json"
        ], capture_output=True, text=True, timeout=15)

        if result.returncode == 0:
            try:
                data = json.loads(result.stdout)
                ip = data.get("ip", "Unknown")
                geo = {
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "org": data.get("org")
                }

                # Update config with last test results
                _update_tunnel_state(last_test_ip=ip, last_test_geo=geo)

                return {
                    "success": True,
                    "ip": ip,
                    "geo": geo
                }
            except json.JSONDecodeError:
                return {"success": False, "error": "Invalid response from IP service"}
        else:
            error = result.stderr.strip() or "curl command failed"
            return {"success": False, "error": error}

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Request timed out"}
    except FileNotFoundError:
        return {"success": False, "error": "curl not found - please install curl"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def check_tunnel_health() -> Tuple[bool, str]:
    """
    Verify tunnel is still active.

    Returns:
        Tuple of (healthy: bool, message: str)
    """
    config = _get_config()

    if not config["tunnel_state"]["connected"]:
        return False, "Tunnel not connected"

    pid = config["tunnel_state"]["pid"]
    if pid and not _is_process_running(pid):
        # Tunnel died - update state
        _update_tunnel_state(connected=False, pid=None, connected_at=None)
        logger.warning("Jumpbox tunnel dropped - SSH process died")
        return False, "Tunnel process died"

    return True, "Tunnel healthy"


def is_tunnel_active() -> bool:
    """
    Check if traffic should be routed through jumpbox.

    Returns:
        True if jumpbox is enabled, has active profile, and tunnel is connected
    """
    try:
        config = _get_config()

        if not config.get("enabled", False):
            return False

        if not config.get("active_profile_id"):
            return False

        if not config["tunnel_state"].get("connected", False):
            return False

        # Verify process is running
        pid = config["tunnel_state"].get("pid")
        if pid and not _is_process_running(pid):
            # Update state silently
            _update_tunnel_state(connected=False, pid=None)
            return False

        return True

    except Exception:
        return False


def get_socks_proxy_url() -> Optional[str]:
    """
    Get SOCKS5 proxy URL if tunnel is active.

    Returns:
        "socks5://127.0.0.1:PORT" or None
    """
    if not is_tunnel_active():
        return None

    config = _get_config()
    port = config.get("socks_port", 9050)
    return f"socks5://127.0.0.1:{port}"


# =============================================================================
# Proxychains Integration
# =============================================================================

def generate_proxychains_config() -> Path:
    """
    Generate proxychains config for current SOCKS tunnel.

    Returns:
        Path to generated config file
    """
    _ensure_config_dir()

    config = _get_config()
    socks_port = config.get("socks_port", 9050)

    conf_content = f"""# Auto-generated by Cygor jumpbox
# Do not edit - this file is regenerated on tunnel connect

strict_chain
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 {socks_port}
"""

    PROXYCHAINS_CONF_FILE.write_text(conf_content)
    PROXYCHAINS_CONF_FILE.chmod(0o644)

    return PROXYCHAINS_CONF_FILE


def get_proxychains_command() -> Optional[List[str]]:
    """
    Get proxychains wrapper command if tunnel is active.

    Returns:
        ['proxychains4', '-q', '-f', '/path/to/conf'] or None
    """
    if not is_tunnel_active():
        return None

    # Check for proxychains4 first (newer), then proxychains
    for cmd in ['proxychains4', 'proxychains']:
        if shutil.which(cmd):
            conf_path = generate_proxychains_config()
            return [cmd, '-q', '-f', str(conf_path)]

    return None  # proxychains not installed


def wrap_command_with_proxychains(cmd: List[str]) -> List[str]:
    """
    Wrap a command with proxychains if tunnel is active.

    Args:
        cmd: Command as list of strings

    Returns:
        Wrapped command if tunnel active, original command otherwise
    """
    wrapper = get_proxychains_command()
    if wrapper:
        return wrapper + cmd
    return cmd


def is_proxychains_available() -> bool:
    """Check if proxychains is installed."""
    return bool(shutil.which('proxychains4') or shutil.which('proxychains'))


# =============================================================================
# Utility Functions
# =============================================================================

def check_dependencies() -> Dict[str, bool]:
    """
    Check if required dependencies are available.

    Returns:
        Dict with dependency names and availability status
    """
    deps = {
        "ssh": bool(shutil.which("ssh")),
        "sshpass": bool(shutil.which("sshpass")),
        "curl": bool(shutil.which("curl")),
        "proxychains": is_proxychains_available(),
        "cryptography": False
    }

    try:
        import cryptography
        deps["cryptography"] = True
    except ImportError:
        pass

    return deps


if __name__ == "__main__":
    """Quick test/debug output"""
    print("Jumpbox Configuration")
    print("=" * 50)
    print(f"Config dir: {JUMPBOX_CONFIG_DIR}")
    print(f"Config file exists: {JUMPBOX_CONFIG_FILE.exists()}")
    print()
    print("Dependencies:")
    for dep, available in check_dependencies().items():
        status = "OK" if available else "MISSING"
        print(f"  {dep}: {status}")
    print()
    print("Current config:")
    print(json.dumps(get_jumpbox_config(), indent=2))
    print()
    print("Tunnel status:")
    print(json.dumps(get_tunnel_status(), indent=2))
    print()
    print("Profiles:")
    for p in list_profiles():
        print(f"  - {p['name']}: {p['username']}@{p['host']}:{p['port']}")
