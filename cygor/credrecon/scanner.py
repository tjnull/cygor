#!/usr/bin/env python3
"""
Cygor Default Credentials Scanner (CredScanner)
================================================

A comprehensive credential testing module for discovering default and weak
credentials across multiple protocols and services.

Inspired by changeme (https://github.com/ztgrace/changeme) and credential
stuffing techniques, this module tests common default credentials against
various services to identify security misconfigurations.

Supported Protocols:
-------------------
- HTTP/HTTPS (Basic Auth, Digest Auth, Form-based)
- SSH
- FTP
- MySQL
- PostgreSQL
- MSSQL
- MongoDB
- Redis
- SNMP
- RDP (Remote Desktop Protocol)
- VNC (Virtual Network Computing)

Note: SMB/CIFS testing is available through the dedicated smbexplorer module

Features:
---------
- YAML-based credential database
- Multi-threaded scanning
- Workspace-aware output
- JSON/CSV/XML reporting
- Web UI integration
- Service auto-detection
- Rate limiting and throttling
- Custom credential support

Author: Tj Null
Version: 1.0
"""

import os
import sys
import json
import csv
import yaml
import logging
import argparse
import threading
import socket
import time
import re
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

# Import protocol handlers
try:
    import requests
    from requests.auth import HTTPBasicAuth, HTTPDigestAuth
    requests.packages.urllib3.disable_warnings()
except ImportError:
    requests = None

try:
    import paramiko
except ImportError:
    paramiko = None

try:
    from ftplib import FTP
except ImportError:
    FTP = None

try:
    from impacket.smbconnection import SMBConnection
except ImportError:
    SMBConnection = None

try:
    import pymysql
except ImportError:
    pymysql = None

try:
    import psycopg2
except ImportError:
    psycopg2 = None

try:
    import pymssql
except ImportError:
    pymssql = None

try:
    import pymongo
except ImportError:
    pymongo = None

try:
    import redis
except ImportError:
    redis = None

try:
    from pysnmp.hlapi import *
except ImportError:
    pass

try:
    from pyVmomi import vim
    from pyVim.connect import SmartConnect, Disconnect
except ImportError:
    vim = None

try:
    from rdpy.protocol.rdp import rdp
    from twisted.internet import reactor
except ImportError:
    rdp = None
    reactor = None

try:
    import vncdotool.api as vnc_api
except ImportError:
    vnc_api = None

# Colorama for CLI output
try:
    from colorama import Fore, Style, init as _color_init
    _color_init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# Module metadata
module_info = {
    "name": "CredRecon — Default Credentials Scanner",
    "slug": "credrecon",
    "author": "Cygor Development Team",
    "version": "1.0",
    "description": "Tests default and weak credentials across multiple protocols (HTTP, SSH, FTP, SMB, databases, etc.)",
    "view": "table",
    "table": {
        "columns": [
            {"key": "ip", "label": "Target"},
            {"key": "port", "label": "Port"},
            {"key": "protocol", "label": "Protocol"},
            {"key": "service", "label": "Service"},
            {"key": "username", "label": "Username"},
            {"key": "password", "label": "Password"},
            {"key": "status", "label": "Status"},
            {"key": "details", "label": "Details"},
            {"key": "timestamp", "label": "Timestamp"},
        ]
    },
}

# ----------------------------------------------------------------------
# Logging setup
# ----------------------------------------------------------------------
class CleanFormatter(logging.Formatter):
    """Clean formatter that only shows message content without timestamps."""
    def format(self, record):
        # Just return the message without any formatting
        return record.getMessage()

logger = logging.getLogger("credrecon")
logger.setLevel(logging.INFO)
logger.propagate = False  # Prevent duplicate output from parent loggers

# Only add handler if none exist
if not logger.handlers:
    ch = logging.StreamHandler(sys.stdout)  # Output to stdout instead of stderr
    ch.setLevel(logging.INFO)
    ch.setFormatter(CleanFormatter())
    logger.addHandler(ch)

# ----------------------------------------------------------------------
# Result dataclass
# ----------------------------------------------------------------------
@dataclass
class CredentialResult:
    """Represents a single credential test result."""
    ip: str
    port: int
    protocol: str
    service: str
    username: str
    password: str
    status: str  # "success", "failed", "error"
    details: str = ""
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ----------------------------------------------------------------------
# Workspace-aware output helpers
# ----------------------------------------------------------------------
def get_module_output_dir(module_name: str = "credrecon") -> Path:
    """Returns a workspace-aware path for the module's data directory with timestamp."""
    env_ws = os.environ.get("CYGOR_RESULTS_DIR")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if env_ws:
        base = Path(env_ws) / module_name / ts
    else:
        base = Path(module_name) / ts
    base.mkdir(parents=True, exist_ok=True)
    return base

def resolve_output_dir(cli_output_dir: str | None, module_name: str) -> Path:
    """Resolve final output directory with timestamp subdirectory."""
    env_ws = os.environ.get("CYGOR_RESULTS_DIR")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if cli_output_dir and cli_output_dir not in ("", None):
        outdir = Path(cli_output_dir)
    else:
        # Always use timestamped subdirectories
        if env_ws:
            outdir = Path(env_ws) / module_name / ts
        else:
            outdir = Path(module_name) / ts

    outdir.mkdir(parents=True, exist_ok=True)
    return outdir

# ----------------------------------------------------------------------
# Default credentials database
# ----------------------------------------------------------------------
def load_default_credentials():
    """Load default credentials from YAML file."""
    default_creds_file = Path(__file__).parent / "default_credentials.yaml"

    if default_creds_file.exists():
        try:
            with open(default_creds_file, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            logger.warning(f"Failed to load default credentials from {default_creds_file}: {e}")
            return {}
    else:
        logger.warning(f"Default credentials file not found: {default_creds_file}")
        return {}

# Load credentials at module import time
DEFAULT_CREDENTIALS_DB = load_default_credentials()

# ----------------------------------------------------------------------
# Protocol testers
# ----------------------------------------------------------------------
class ProtocolTester:
    """Base class for protocol-specific credential testers."""

    def __init__(self, timeout: int = 5, rate_limit: float = 0.1):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.lock = threading.Lock()
        self.last_test = 0

    def rate_limited_test(self):
        """Enforce rate limiting between tests."""
        with self.lock:
            elapsed = time.time() - self.last_test
            if elapsed < self.rate_limit:
                time.sleep(self.rate_limit - elapsed)
            self.last_test = time.time()

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        """Override in subclass."""
        raise NotImplementedError()

class HTTPTester(ProtocolTester):
    """Test HTTP/HTTPS Basic Auth."""

    def detect_login_form(self, url: str) -> tuple[bool, str]:
        """
        Detect if a URL has a login form or authentication mechanism.
        Returns (has_login, detection_method)

        Stricter detection to avoid false positives:
        - Requires password field + form/username field on the SAME page
        - Or HTTP Basic Auth challenge (401)
        - Or URL path indicating it's a login page
        """
        if not requests:
            return False, "requests library not installed"

        try:
            resp = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=True)
            content = resp.text.lower() if resp.text else ""

            # Check for HTTP Basic Auth challenge
            if resp.status_code == 401:
                www_auth = resp.headers.get('WWW-Authenticate', '').lower()
                if 'basic' in www_auth:
                    return True, "HTTP Basic Auth (401 challenge)"
                return True, "Authentication required (401)"

            # CRITICAL: Check if this is actually a login page by URL path first
            # This catches redirects to login pages
            parsed_url = resp.url.lower()
            login_paths = [
                '/login', '/admin', '/wp-admin', '/wp-login.php',
                '/user/login', '/auth', '/signin', '/sign-in',
                '/administrator', '/admin/login', '/manager/html',
                '/console', '/dashboard', '/logon'
            ]

            if any(path in parsed_url for path in login_paths):
                return True, f"Login URL path detected ({resp.url})"

            # Check for password input field (REQUIRED for form-based login)
            password_patterns = [
                'type="password"',
                'type=\'password\'',
                '<input type="password"',
                'name="password"',
                'id="password"',
                'name="passwd"',
                'id="passwd"',
                'name="pwd"',
                'id="pwd"'
            ]

            has_password_field = any(pattern in content for pattern in password_patterns)

            if not has_password_field:
                # No password field = definitely not a login form on this page
                return False, "No password input field detected"

            # If we have a password field, check for form element
            has_form = '<form' in content

            # Check for username field
            username_patterns = [
                'name="username"',
                'id="username"',
                'name="user"',
                'id="user"',
                'name="email"',
                'id="email"',
                'name="login"',
                'id="login"',
                'type="text"',
                'type=\'text\''
            ]
            has_username_field = any(pattern in content for pattern in username_patterns)

            # STRICT REQUIREMENT: Password field + (Form OR Username field)
            if has_password_field and (has_form or has_username_field):
                indicators = ["password field"]
                if has_form:
                    indicators.append("form element")
                if has_username_field:
                    indicators.append("username/email field")
                return True, f"Login form detected ({', '.join(indicators)})"

            # If we only have a password field without form/username context, it's suspicious
            # but we'll be conservative and reject it
            return False, "Password field present but no complete login form structure"

        except requests.exceptions.Timeout:
            return False, "Timeout during detection"
        except Exception as e:
            return False, f"Detection error: {str(e)}"

    def test(self, ip: str, port: int, username: str, password: str, use_https: bool = False) -> CredentialResult:
        if not requests:
            return CredentialResult(ip, port, "http", "http", username, password, "error", "requests library not installed")

        self.rate_limited_test()
        scheme = "https" if use_https or port == 443 else "http"
        url = f"{scheme}://{ip}:{port}/"

        try:
            resp = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=self.timeout, verify=False)
            if resp.status_code == 200:
                return CredentialResult(ip, port, "http", "http-basic", username, password, "success", f"HTTP {resp.status_code}")
            elif resp.status_code == 401:
                return CredentialResult(ip, port, "http", "http-basic", username, password, "failed", "Unauthorized")
            else:
                return CredentialResult(ip, port, "http", "http-basic", username, password, "failed", f"HTTP {resp.status_code}")
        except requests.exceptions.Timeout:
            return CredentialResult(ip, port, "http", "http-basic", username, password, "error", "Timeout")
        except Exception as e:
            return CredentialResult(ip, port, "http", "http-basic", username, password, "error", str(e))

    def test_url(self, url: str, port: int, username: str, password: str) -> CredentialResult:
        """Test HTTP authentication against a full URL with path."""
        if not requests:
            return CredentialResult(url, port, "http", "http", username, password, "error", "requests library not installed")

        self.rate_limited_test()

        try:
            # First, test without credentials to establish a baseline
            resp_no_auth = None
            try:
                resp_no_auth = requests.get(url, timeout=self.timeout, verify=False, allow_redirects=False)
            except requests.exceptions.Timeout:
                return CredentialResult(url, port, "http", "http-basic", username, password, "error", f"Connection timeout - website not responding within {self.timeout}s")
            except requests.exceptions.ConnectionError as e:
                error_str = str(e).lower()
                if 'refused' in error_str:
                    return CredentialResult(url, port, "http", "http-basic", username, password, "error", f"Connection refused - HTTP service not running on {url}")
                elif 'name resolution' in error_str or 'dns' in error_str:
                    return CredentialResult(url, port, "http", "http-basic", username, password, "error", f"DNS resolution failed - cannot resolve hostname")
                else:
                    return CredentialResult(url, port, "http", "http-basic", username, password, "error", f"Connection error: {str(e)}")
            except Exception as e:
                # For other errors on baseline, continue but note it
                pass

            # Now test with credentials
            try:
                resp = requests.get(url, auth=HTTPBasicAuth(username, password), timeout=self.timeout, verify=False, allow_redirects=False)
            except requests.exceptions.Timeout:
                return CredentialResult(url, port, "http", "http-basic", username, password, "error", f"Authentication request timeout - service not responding")
            except requests.exceptions.ConnectionError as e:
                return CredentialResult(url, port, "http", "http-basic", username, password, "error", f"Connection error during authentication: {str(e)}")

            # Check if authentication succeeded
            if resp.status_code == 200:
                # Enhanced false positive detection
                content_lower = resp.text.lower() if resp.text else ""
                content_length = len(resp.text) if resp.text else 0

                # Extended failure indicators
                failure_indicators = [
                    'invalid password', 'invalid username', 'login failed',
                    'incorrect password', 'incorrect username', 'authentication failed',
                    'access denied', 'unauthorized', 'forbidden',
                    'wrong password', 'wrong username', 'bad credentials',
                    'login error', 'authentication error', 'incorrect login',
                    'login unsuccessful', 'authentication unsuccessful',
                    'please log in', 'sign in', 'enter your password',
                    'password incorrect', 'username incorrect', 'invalid credentials'
                ]

                # Check for failure indicators
                if any(indicator in content_lower for indicator in failure_indicators):
                    return CredentialResult(url, port, "http", "http-basic", username, password, "failed", "Login page indicates authentication failure")

                # If baseline response was also 200, compare content to detect real auth
                if resp_no_auth and resp_no_auth.status_code == 200:
                    # Calculate similarity
                    if resp.text == resp_no_auth.text:
                        return CredentialResult(url, port, "http", "http-basic", username, password, "failed", "Response identical to unauthenticated request - authentication likely failed")
                    
                    # Check if content length is very similar (within 5% difference)
                    no_auth_length = len(resp_no_auth.text) if resp_no_auth.text else 0
                    if content_length > 0 and no_auth_length > 0:
                        length_diff = abs(content_length - no_auth_length) / max(content_length, no_auth_length)
                        if length_diff < 0.05:  # Less than 5% difference
                            # Check if they're mostly the same (simple similarity check)
                            if content_lower[:500] == resp_no_auth.text.lower()[:500]:
                                return CredentialResult(url, port, "http", "http-basic", username, password, "failed", "Response very similar to unauthenticated request - possible false positive")

                # Additional validation: Check for success indicators
                success_indicators = [
                    'welcome', 'dashboard', 'logout', 'sign out', 'profile',
                    'settings', 'account', 'user panel', 'admin panel'
                ]
                has_success_indicators = any(indicator in content_lower for indicator in success_indicators)
                
                # If we have success indicators and no failure indicators, it's likely a real success
                if has_success_indicators:
                    return CredentialResult(url, port, "http", "http-basic", username, password, "success", f"HTTP {resp.status_code} - Authenticated content detected")
                
                # If content length changed significantly from baseline, likely success
                if resp_no_auth and resp_no_auth.status_code == 200:
                    no_auth_length = len(resp_no_auth.text) if resp_no_auth.text else 0
                    if content_length > no_auth_length * 1.2:  # 20% larger
                        return CredentialResult(url, port, "http", "http-basic", username, password, "success", f"HTTP {resp.status_code} - Response size indicates authentication")
                
                # Default: mark as success but note it needs verification
                return CredentialResult(url, port, "http", "http-basic", username, password, "success", f"HTTP {resp.status_code} - Verify manually (no clear success indicators)")
                
            elif resp.status_code == 401:
                return CredentialResult(url, port, "http", "http-basic", username, password, "failed", "Unauthorized - Invalid credentials")
            elif resp.status_code == 403:
                return CredentialResult(url, port, "http", "http-basic", username, password, "failed", "Forbidden - Access denied even with credentials")
            elif resp.status_code in [301, 302, 303, 307, 308]:
                # Check redirect location
                location = resp.headers.get('Location', '')
                if 'login' in location.lower() or 'auth' in location.lower() or 'signin' in location.lower():
                    return CredentialResult(url, port, "http", "http-basic", username, password, "failed", f"Redirected to login page ({location}) - authentication failed")
                return CredentialResult(url, port, "http", "http-basic", username, password, "failed", f"HTTP {resp.status_code} redirect to {location}")
            elif resp.status_code == 404:
                return CredentialResult(url, port, "http", "http-basic", username, password, "error", f"Page not found (404) - URL may be incorrect")
            elif resp.status_code >= 500:
                return CredentialResult(url, port, "http", "http-basic", username, password, "error", f"Server error (HTTP {resp.status_code}) - cannot test authentication")
            else:
                return CredentialResult(url, port, "http", "http-basic", username, password, "failed", f"HTTP {resp.status_code} - Unexpected response")
        except requests.exceptions.Timeout:
            return CredentialResult(url, port, "http", "http-basic", username, password, "error", f"Request timeout - website not responding within {self.timeout}s")
        except requests.exceptions.SSLError as e:
            return CredentialResult(url, port, "http", "http-basic", username, password, "error", f"SSL/TLS error - {str(e)}")
        except Exception as e:
            return CredentialResult(url, port, "http", "http-basic", username, password, "error", f"Unexpected error: {str(e)}")

class SSHTester(ProtocolTester):
    """Test SSH authentication."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not paramiko:
            return CredentialResult(ip, port, "ssh", "ssh", username, password, "error", "paramiko library not installed - install with: pip install paramiko")

        self.rate_limited_test()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(ip, port=port, username=username, password=password, timeout=self.timeout, look_for_keys=False, allow_agent=False)
            # Verify we can actually execute a command (reduces false positives)
            try:
                stdin, stdout, stderr = client.exec_command('echo test', timeout=2)
                stdout.read()  # Wait for command to complete
            except:
                pass  # If command execution fails, still consider auth successful if connection worked
            client.close()
            return CredentialResult(ip, port, "ssh", "ssh", username, password, "success", "SSH authentication successful - connection established")
        except paramiko.AuthenticationException:
            return CredentialResult(ip, port, "ssh", "ssh", username, password, "failed", "SSH authentication failed - invalid credentials")
        except paramiko.BadHostKeyException as e:
            return CredentialResult(ip, port, "ssh", "ssh", username, password, "error", f"SSH host key verification failed: {str(e)}")
        except paramiko.SSHException as e:
            error_str = str(e).lower()
            if 'not a valid ssh' in error_str or 'not ssh' in error_str:
                return CredentialResult(ip, port, "ssh", "ssh", username, password, "error", f"Not an SSH service - wrong protocol detected: {str(e)}")
            elif 'connection reset' in error_str:
                return CredentialResult(ip, port, "ssh", "ssh", username, password, "error", f"SSH connection reset - service may have closed connection")
            else:
                return CredentialResult(ip, port, "ssh", "ssh", username, password, "error", f"SSH protocol error: {str(e)}")
        except socket.timeout:
            return CredentialResult(ip, port, "ssh", "ssh", username, password, "error", f"SSH connection timeout - service not responding within {self.timeout}s")
        except ConnectionRefusedError:
            return CredentialResult(ip, port, "ssh", "ssh", username, password, "error", f"Connection refused - SSH service not running on {ip}:{port}")
        except socket.gaierror as e:
            return CredentialResult(ip, port, "ssh", "ssh", username, password, "error", f"DNS resolution failed - cannot resolve hostname: {str(e)}")
        except Exception as e:
            error_str = str(e).lower()
            if 'refused' in error_str:
                return CredentialResult(ip, port, "ssh", "ssh", username, password, "error", f"Connection refused - SSH service not available")
            elif 'timeout' in error_str:
                return CredentialResult(ip, port, "ssh", "ssh", username, password, "error", f"Connection timeout - SSH service not responding")
            else:
                return CredentialResult(ip, port, "ssh", "ssh", username, password, "error", f"SSH connection error: {str(e)}")
        finally:
            try:
                client.close()
            except:
                pass

class FTPTester(ProtocolTester):
    """Test FTP authentication."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not FTP:
            return CredentialResult(ip, port, "ftp", "ftp", username, password, "error", "ftplib not available - standard library should be available")

        self.rate_limited_test()
        try:
            ftp = FTP(timeout=self.timeout)
            ftp.connect(ip, port)
            welcome = ftp.getwelcome() if hasattr(ftp, 'getwelcome') else None
            ftp.login(username, password)
            # Verify we can actually list directory (reduces false positives)
            try:
                ftp.retrlines('LIST', lambda x: None)  # Try to list directory
            except:
                pass  # If listing fails, still consider login successful
            ftp.quit()
            welcome_msg = f" - {welcome}" if welcome else ""
            return CredentialResult(ip, port, "ftp", "ftp", username, password, "success", f"FTP login successful{welcome_msg}")
        except socket.timeout:
            return CredentialResult(ip, port, "ftp", "ftp", username, password, "error", f"FTP connection timeout - service not responding within {self.timeout}s")
        except ConnectionRefusedError:
            return CredentialResult(ip, port, "ftp", "ftp", username, password, "error", f"Connection refused - FTP service not running on {ip}:{port}")
        except socket.gaierror as e:
            return CredentialResult(ip, port, "ftp", "ftp", username, password, "error", f"DNS resolution failed - cannot resolve hostname: {str(e)}")
        except Exception as e:
            error_msg = str(e).lower()
            if "530" in error_msg or ("login" in error_msg and "incorrect" in error_msg) or "authentication failed" in error_msg:
                return CredentialResult(ip, port, "ftp", "ftp", username, password, "failed", "FTP authentication failed - invalid credentials")
            elif "421" in error_msg or "connection closed" in error_msg:
                return CredentialResult(ip, port, "ftp", "ftp", username, password, "error", f"FTP connection closed by server: {str(e)}")
            elif "not a valid ftp" in error_msg or "not ftp" in error_msg:
                return CredentialResult(ip, port, "ftp", "ftp", username, password, "error", f"Not an FTP service - wrong protocol detected: {str(e)}")
            elif "refused" in error_msg:
                return CredentialResult(ip, port, "ftp", "ftp", username, password, "error", f"Connection refused - FTP service not available")
            else:
                return CredentialResult(ip, port, "ftp", "ftp", username, password, "error", f"FTP error: {str(e)}")

class SMBTester(ProtocolTester):
    """Test SMB authentication."""

    def test(self, ip: str, port: int, username: str, password: str, domain: str = "") -> CredentialResult:
        if not SMBConnection:
            return CredentialResult(ip, port, "smb", "smb", username, password, "error", "impacket library not installed")

        self.rate_limited_test()
        try:
            smb = SMBConnection(ip, ip, timeout=self.timeout)
            user = f"{domain}\\{username}" if domain else username
            smb.login(user, password)
            shares = smb.listShares()
            smb.close()
            return CredentialResult(ip, port, "smb", "smb", username, password, "success", f"Login successful, {len(shares)} shares")
        except Exception as e:
            error_msg = str(e).lower()
            if "status_logon_failure" in error_msg or "authentication" in error_msg:
                return CredentialResult(ip, port, "smb", "smb", username, password, "failed", "Authentication failed")
            return CredentialResult(ip, port, "smb", "smb", username, password, "error", str(e))

class MySQLTester(ProtocolTester):
    """Test MySQL authentication."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not pymysql:
            return CredentialResult(ip, port, "mysql", "mysql", username, password, "error", "pymysql library not installed - install with: pip install pymysql")

        self.rate_limited_test()
        try:
            conn = pymysql.connect(host=ip, port=port, user=username, password=password, connect_timeout=self.timeout)
            version = conn.get_server_info()
            # Verify we can actually query (reduces false positives)
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    cursor.fetchone()
            except:
                pass  # If query fails, still consider connection successful
            conn.close()
            return CredentialResult(ip, port, "mysql", "mysql", username, password, "success", f"MySQL authentication successful - Server version: {version}")
        except pymysql.err.OperationalError as e:
            error_msg = str(e).lower()
            if "access denied" in error_msg or ("authentication" in error_msg and "failed" in error_msg):
                return CredentialResult(ip, port, "mysql", "mysql", username, password, "failed", "MySQL authentication failed - invalid credentials")
            elif "can't connect" in error_msg or "connection refused" in error_msg:
                return CredentialResult(ip, port, "mysql", "mysql", username, password, "error", f"MySQL connection refused - service not running on {ip}:{port}")
            elif "unknown host" in error_msg:
                return CredentialResult(ip, port, "mysql", "mysql", username, password, "error", f"DNS resolution failed - cannot resolve hostname")
            elif "timeout" in error_msg:
                return CredentialResult(ip, port, "mysql", "mysql", username, password, "error", f"MySQL connection timeout - service not responding within {self.timeout}s")
            else:
                return CredentialResult(ip, port, "mysql", "mysql", username, password, "error", f"MySQL connection error: {str(e)}")
        except Exception as e:
            error_str = str(e).lower()
            if 'not a valid mysql' in error_str or 'not mysql' in error_str:
                return CredentialResult(ip, port, "mysql", "mysql", username, password, "error", f"Not a MySQL service - wrong protocol detected: {str(e)}")
            else:
                return CredentialResult(ip, port, "mysql", "mysql", username, password, "error", f"MySQL error: {str(e)}")

class PostgreSQLTester(ProtocolTester):
    """Test PostgreSQL authentication."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not psycopg2:
            return CredentialResult(ip, port, "postgres", "postgresql", username, password, "error", "psycopg2 library not installed - install with: pip install psycopg2-binary")

        self.rate_limited_test()
        try:
            conn = psycopg2.connect(host=ip, port=port, user=username, password=password, connect_timeout=self.timeout)
            version = conn.server_version
            # Verify we can actually query (reduces false positives)
            try:
                with conn.cursor() as cursor:
                    cursor.execute("SELECT version()")
                    cursor.fetchone()
            except:
                pass  # If query fails, still consider connection successful
            conn.close()
            return CredentialResult(ip, port, "postgres", "postgresql", username, password, "success", f"PostgreSQL authentication successful - Server version: {version}")
        except psycopg2.OperationalError as e:
            error_msg = str(e).lower()
            if "password authentication failed" in error_msg or ("authentication" in error_msg and "failed" in error_msg):
                return CredentialResult(ip, port, "postgres", "postgresql", username, password, "failed", "PostgreSQL authentication failed - invalid credentials")
            elif "could not connect" in error_msg or "connection refused" in error_msg:
                return CredentialResult(ip, port, "postgres", "postgresql", username, password, "error", f"PostgreSQL connection refused - service not running on {ip}:{port}")
            elif "could not translate hostname" in error_msg or "dns" in error_msg:
                return CredentialResult(ip, port, "postgres", "postgresql", username, password, "error", f"DNS resolution failed - cannot resolve hostname")
            elif "timeout" in error_msg:
                return CredentialResult(ip, port, "postgres", "postgresql", username, password, "error", f"PostgreSQL connection timeout - service not responding within {self.timeout}s")
            else:
                return CredentialResult(ip, port, "postgres", "postgresql", username, password, "error", f"PostgreSQL connection error: {str(e)}")
        except Exception as e:
            error_str = str(e).lower()
            if 'not a valid postgres' in error_str or 'not postgres' in error_str:
                return CredentialResult(ip, port, "postgres", "postgresql", username, password, "error", f"Not a PostgreSQL service - wrong protocol detected: {str(e)}")
            else:
                return CredentialResult(ip, port, "postgres", "postgresql", username, password, "error", f"PostgreSQL error: {str(e)}")

class RDPTester(ProtocolTester):
    """Test RDP authentication using socket-based approach."""

    def test(self, ip: str, port: int, username: str, password: str, domain: str = "") -> CredentialResult:
        self.rate_limited_test()

        # Use a simpler socket-based approach since RDP libraries are complex
        # We'll test if we can connect and send initial handshake
        try:
            import socket
            import struct

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Send X.224 Connection Request
            # This is a simplified RDP handshake to test connectivity
            x224_req = bytes([
                0x03, 0x00,  # TPKT version and reserved
                0x00, 0x2c,  # Length (44 bytes)
                0x27,        # X.224 length
                0xe0,        # X.224 PDU type (Connection Request)
                0x00, 0x00,  # Destination reference
                0x00, 0x00,  # Source reference
                0x00,        # Class and options
            ])
            # Add RDP negotiation request
            x224_req += bytes([
                0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20,  # "Cookie: "
                0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3d, 0x20, 0x0d, 0x0a,  # "mstshash= \r\n"
                0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00  # RDP Negotiation Request
            ])

            sock.send(x224_req)
            response = sock.recv(1024)
            sock.close()

            if response and len(response) > 0:
                # We got a response, RDP is alive
                # Note: Full RDP authentication requires complex NLA/CredSSP which needs pyRDP or FreeRDP
                # For now, we can only verify the service is running
                return CredentialResult(ip, port, "rdp", "rdp", username, password, "error", "RDP service detected - full auth requires rdpy/freerdp libraries")
            else:
                return CredentialResult(ip, port, "rdp", "rdp", username, password, "error", "No RDP response")

        except socket.timeout:
            return CredentialResult(ip, port, "rdp", "rdp", username, password, "error", "Connection timeout")
        except ConnectionRefusedError:
            return CredentialResult(ip, port, "rdp", "rdp", username, password, "error", "Connection refused - RDP not available")
        except Exception as e:
            return CredentialResult(ip, port, "rdp", "rdp", username, password, "error", f"RDP error: {str(e)}")

class VNCTester(ProtocolTester):
    """Test VNC authentication."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        self.rate_limited_test()

        # VNC typically doesn't use username, only password
        # We'll use a socket-based approach for VNC RFB protocol
        try:
            import socket

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Receive VNC version (RFB protocol version)
            version = sock.recv(12)
            if not version.startswith(b'RFB '):
                sock.close()
                return CredentialResult(ip, port, "vnc", "vnc", username, password, "error", "Not a VNC server")

            # Send back the same version
            sock.send(version)

            # Receive security types
            num_security_types = ord(sock.recv(1))
            if num_security_types == 0:
                # Security handshake failed
                sock.close()
                return CredentialResult(ip, port, "vnc", "vnc", username, password, "failed", "VNC connection failed")

            security_types = sock.recv(num_security_types)

            # Check if VNC authentication (type 2) is available
            if b'\x02' in security_types:
                # Select VNC authentication
                sock.send(b'\x02')

                # Receive challenge
                challenge = sock.recv(16)
                if len(challenge) != 16:
                    sock.close()
                    return CredentialResult(ip, port, "vnc", "vnc", username, password, "error", "Invalid VNC challenge")

                # VNC uses DES encryption for password
                # For simplicity, we'll try with vncdotool if available
                if vnc_api:
                    try:
                        sock.close()
                        # Try using vncdotool
                        client = vnc_api.connect(f"{ip}:{port}", password=password)
                        client.disconnect()
                        return CredentialResult(ip, port, "vnc", "vnc", username, password, "success", "VNC authentication successful")
                    except Exception as e:
                        if "Authentication" in str(e) or "password" in str(e).lower():
                            return CredentialResult(ip, port, "vnc", "vnc", username, password, "failed", "Authentication failed")
                        return CredentialResult(ip, port, "vnc", "vnc", username, password, "error", str(e))
                else:
                    sock.close()
                    return CredentialResult(ip, port, "vnc", "vnc", username, password, "error", "vncdotool library not installed (required for VNC password auth)")

            elif b'\x01' in security_types:
                # No authentication required!
                sock.send(b'\x01')
                sock.close()
                return CredentialResult(ip, port, "vnc", "vnc", "", "", "success", "No authentication required!")

            else:
                sock.close()
                return CredentialResult(ip, port, "vnc", "vnc", username, password, "error", f"Unsupported security types: {security_types.hex()}")

        except socket.timeout:
            return CredentialResult(ip, port, "vnc", "vnc", username, password, "error", "Connection timeout")
        except ConnectionRefusedError:
            return CredentialResult(ip, port, "vnc", "vnc", username, password, "error", "Connection refused - VNC not available")
        except Exception as e:
            return CredentialResult(ip, port, "vnc", "vnc", username, password, "error", f"VNC error: {str(e)}")

# ----------------------------------------------------------------------
# Connection validation helpers
# ----------------------------------------------------------------------
def validate_connection(ip: str, port: int, timeout: int = 5) -> Tuple[bool, str]:
    """
    Validate that a connection can be established to the target.
    Returns: (is_connected, error_message)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        
        if result == 0:
            return True, "Connection successful"
        elif result == 111:
            return False, f"Connection refused - service not running on {ip}:{port}"
        elif result == 113:
            return False, f"No route to host - network unreachable"
        elif result == 110:
            return False, f"Connection timeout - service may be firewalled or down"
        else:
            return False, f"Connection failed (error code: {result})"
    except socket.gaierror as e:
        return False, f"DNS resolution failed - {str(e)}"
    except socket.timeout:
        return False, f"Connection timeout - service not responding within {timeout}s"
    except Exception as e:
        return False, f"Connection error: {str(e)}"

def detect_service_banner(ip: str, port: int, timeout: int = 5) -> Tuple[bool, str, Optional[str]]:
    """
    Attempt to detect the service running on a port by reading the banner.
    Returns: (is_service_detected, service_name, banner_or_error)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Try to read initial banner/response
        sock.settimeout(2)  # Shorter timeout for banner read
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
        except:
            banner = None
        
        sock.close()
        
        if banner:
            banner_lower = banner.lower()
            # Detect common service banners
            if 'ssh' in banner_lower:
                return True, "ssh", banner.strip()
            elif 'ftp' in banner_lower or '220' in banner:
                return True, "ftp", banner.strip()
            elif 'mysql' in banner_lower:
                return True, "mysql", banner.strip()
            elif 'postgresql' in banner_lower or 'postgres' in banner_lower:
                return True, "postgres", banner.strip()
            elif 'redis' in banner_lower:
                return True, "redis", banner.strip()
            elif 'microsoft sql server' in banner_lower or 'mssql' in banner_lower:
                return True, "mssql", banner.strip()
            else:
                return True, "unknown", banner.strip()[:100]  # Truncate long banners
        
        return True, "unknown", "No banner received"
    except socket.timeout:
        return False, "unknown", "Banner read timeout"
    except Exception as e:
        return False, "unknown", f"Banner detection error: {str(e)}"

# ----------------------------------------------------------------------
# Protocol mapper
# ----------------------------------------------------------------------
def detect_protocol(port: int) -> str:
    """Detect protocol based on common port numbers."""
    port_map = {
        21: "ftp",
        22: "ssh",
        80: "http",
        443: "http",
        1433: "mssql",
        3306: "mysql",
        3389: "rdp",
        5432: "postgres",
        5800: "vnc",
        5900: "vnc",
        5901: "vnc",
        5902: "vnc",
        6379: "redis",
        8080: "http",
        8443: "http",
        27017: "mongodb",
    }
    return port_map.get(port, "unknown")

# ----------------------------------------------------------------------
# Main scanner
# ----------------------------------------------------------------------
def scan_target_http(url: str, port: int, creds: List[Dict], timeout: int = 5, rate_limit: float = 0.1, scheme: str = "http", verbose: bool = True, scan_id: str = None) -> Tuple[List[CredentialResult], Optional[Dict]]:
    """Scan an HTTP/HTTPS URL with multiple credentials.
    Returns: (results, skip_info) where skip_info is None if tested, or a dict with skip details if skipped."""
    results = []
    tester = HTTPTester(timeout, rate_limit)

    # Pre-flight: Check if URL is reachable
    if verbose:
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Checking if website is reachable...")
    
    try:
        if not requests:
            error_msg = "requests library not installed - cannot test HTTP/HTTPS"
            logger.error(f"{Fore.RED}[✗]{Style.RESET_ALL} {error_msg}")
            if scan_id:
                for cred in creds:
                    error_result = CredentialResult(url, port, "http", "http", cred['username'], cred.get('password'), "error", error_msg)
                    save_result_to_db_sync(scan_id, result=error_result)
            return [CredentialResult(url, port, "http", "http", creds[0]['username'] if creds else "", creds[0].get('password') if creds else "", "error", error_msg)], None
        
        # Quick connectivity check
        try:
            test_resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        except requests.exceptions.Timeout:
            error_msg = f"Website timeout - {url} not responding within {timeout}s"
            logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {error_msg}")
            if scan_id:
                for cred in creds:
                    error_result = CredentialResult(url, port, "http", "http", cred['username'], cred.get('password'), "error", error_msg)
                    save_result_to_db_sync(scan_id, result=error_result)
            return [CredentialResult(url, port, "http", "http", creds[0]['username'] if creds else "", creds[0].get('password') if creds else "", "error", error_msg)], None
        except requests.exceptions.ConnectionError as e:
            error_str = str(e).lower()
            if 'refused' in error_str:
                error_msg = f"Connection refused - HTTP service not running on {url}"
            elif 'name resolution' in error_str or 'dns' in error_str:
                error_msg = f"DNS resolution failed - cannot resolve hostname for {url}"
            else:
                error_msg = f"Connection error - cannot reach {url}: {str(e)}"
            logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {error_msg}")
            if scan_id:
                for cred in creds:
                    error_result = CredentialResult(url, port, "http", "http", cred['username'], cred.get('password'), "error", error_msg)
                    save_result_to_db_sync(scan_id, result=error_result)
            return [CredentialResult(url, port, "http", "http", creds[0]['username'] if creds else "", creds[0].get('password') if creds else "", "error", error_msg)], None
        except Exception as e:
            error_msg = f"Error accessing {url}: {str(e)}"
            logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {error_msg}")
            if scan_id:
                for cred in creds:
                    error_result = CredentialResult(url, port, "http", "http", cred['username'], cred.get('password'), "error", error_msg)
                    save_result_to_db_sync(scan_id, result=error_result)
            return [CredentialResult(url, port, "http", "http", creds[0]['username'] if creds else "", creds[0].get('password') if creds else "", "error", error_msg)], None
        
        if verbose:
            logger.info(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Website is reachable (HTTP {test_resp.status_code})")
    except Exception as e:
        # If pre-flight check itself fails, continue anyway
        if verbose:
            logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Pre-flight check failed: {str(e)}, continuing anyway...")

    # First, detect if there's a login form/panel
    if verbose:
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Checking for login form/panel...")

    has_login, detection_info = tester.detect_login_form(url)

    if not has_login:
        detailed_reason = f"No authentication mechanism detected - {detection_info}"
        logger.info(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {detection_info}")
        logger.info(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Skipping credential testing - {detailed_reason}")

        # Save skipped credentials to DB if scan_id provided
        if scan_id:
            for cred in creds:
                skip_info = {
                    'target': url,
                    'port': port,
                    'protocol': 'http',
                    'service': 'http',
                    'username': cred['username'],
                    'password': cred.get('password'),
                    'reason': detailed_reason
                }
                save_result_to_db_sync(scan_id, skip_info=skip_info)

        # Return skip information for reporting
        skip_info = {
            'target': url,
            'port': port,
            'protocol': 'http',
            'service': 'http',
            'credentials': creds,
            'reason': detailed_reason
        }
        return results, skip_info

    if verbose:
        logger.info(f"{Fore.GREEN}[✓]{Style.RESET_ALL} {detection_info}")

    for i, cred in enumerate(creds, 1):
        if verbose:
            logger.info(f"  [{i}/{len(creds)}] Testing {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password'] or '(empty)'}{Style.RESET_ALL}")

        result = tester.test_url(url, port, cred["username"], cred["password"])
        results.append(result)

        # Save to DB if scan_id provided
        if scan_id:
            save_result_to_db_sync(scan_id, result=result)

        if result.status == "success":
            logger.info(f"{Fore.GREEN}[✓ SUCCESS]{Style.RESET_ALL} {url} - {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password']}{Style.RESET_ALL}")
            break  # Stop on first success

    return results, None

def scan_target(ip: str, port: int, protocol: str, creds: List[Dict], timeout: int = 5, rate_limit: float = 0.1, verbose: bool = True, scan_id: str = None) -> List[CredentialResult]:
    """Scan a single target with multiple credentials."""
    results = []

    # Pre-flight: Validate connection before testing credentials
    if verbose:
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Validating connection to {ip}:{port}...")
    
    is_connected, conn_error = validate_connection(ip, port, timeout)
    if not is_connected:
        error_msg = f"Cannot connect to {ip}:{port} - {conn_error}"
        logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {error_msg}")
        
        # Save error for all credentials
        if scan_id:
            for cred in creds:
                error_result = CredentialResult(ip, port, protocol, protocol, cred['username'], cred.get('password'), "error", error_msg)
                save_result_to_db_sync(scan_id, result=error_result)
        
        # Return error result for first credential as representative
        if creds:
            return [CredentialResult(ip, port, protocol, protocol, creds[0]['username'], creds[0].get('password'), "error", error_msg)]
        return [CredentialResult(ip, port, protocol, protocol, "", "", "error", error_msg)]
    
    if verbose:
        logger.info(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Connection successful")
    
    # Optional: Try to detect service banner for non-HTTP protocols
    if protocol != "http" and protocol != "unknown":
        if verbose:
            logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Detecting service type...")
        banner_detected, detected_service, banner_info = detect_service_banner(ip, port, timeout)
        if banner_detected and detected_service != "unknown":
            if detected_service != protocol:
                warning_msg = f"Protocol mismatch: Expected {protocol}, but banner suggests {detected_service}"
                logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {warning_msg}")
                if verbose and banner_info:
                    logger.info(f"{Fore.CYAN}[i]{Style.RESET_ALL} Banner: {banner_info[:100]}")
        elif banner_detected and verbose:
            logger.info(f"{Fore.CYAN}[i]{Style.RESET_ALL} Service detected but type unknown")

    # Select tester
    tester = None
    if protocol == "http":
        tester = HTTPTester(timeout, rate_limit)

        # First, detect if there's a login form/panel
        scheme = "https" if port == 443 else "http"
        url = f"{scheme}://{ip}:{port}/"

        if verbose:
            logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Checking for login form/panel...")

        has_login, detection_info = tester.detect_login_form(url)

        if not has_login:
            logger.info(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {detection_info}")
            logger.info(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Skipping credential testing - no authentication mechanism detected")

            # Save skipped credentials to DB if scan_id provided
            if scan_id:
                for cred in creds:
                    skip_info = {
                        'target': f"{ip}:{port}",
                        'port': port,
                        'protocol': 'http',
                        'service': 'http',
                        'username': cred['username'],
                        'password': cred.get('password'),
                        'reason': detection_info
                    }
                    save_result_to_db_sync(scan_id, skip_info=skip_info)

            return results

        if verbose:
            logger.info(f"{Fore.GREEN}[✓]{Style.RESET_ALL} {detection_info}")

        for i, cred in enumerate(creds, 1):
            if verbose:
                logger.info(f"  [{i}/{len(creds)}] Testing {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password'] or '(empty)'}{Style.RESET_ALL}")
            result = tester.test(ip, port, cred["username"], cred["password"], use_https=(port == 443))
            results.append(result)

            # Save to DB if scan_id provided
            if scan_id:
                save_result_to_db_sync(scan_id, result=result)

            if result.status == "success":
                logger.info(f"{Fore.GREEN}[✓ SUCCESS]{Style.RESET_ALL} {ip}:{port} - {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password']}{Style.RESET_ALL}")
                break  # Stop on first success

    elif protocol == "ssh" and paramiko:
        tester = SSHTester(timeout, rate_limit)
        for i, cred in enumerate(creds, 1):
            if verbose:
                logger.info(f"  [{i}/{len(creds)}] Testing {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password'] or '(empty)'}{Style.RESET_ALL}")
            result = tester.test(ip, port, cred["username"], cred["password"])
            results.append(result)
            if result.status == "success":
                logger.info(f"{Fore.GREEN}[✓ SUCCESS]{Style.RESET_ALL} {ip}:{port} - {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password']}{Style.RESET_ALL}")
                break

    elif protocol == "ftp" and FTP:
        tester = FTPTester(timeout, rate_limit)
        for i, cred in enumerate(creds, 1):
            if verbose:
                logger.info(f"  [{i}/{len(creds)}] Testing {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password'] or '(empty)'}{Style.RESET_ALL}")
            result = tester.test(ip, port, cred["username"], cred["password"])
            results.append(result)
            if result.status == "success":
                logger.info(f"{Fore.GREEN}[✓ SUCCESS]{Style.RESET_ALL} {ip}:{port} - {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password']}{Style.RESET_ALL}")
                break

    elif protocol == "mysql" and pymysql:
        tester = MySQLTester(timeout, rate_limit)
        for i, cred in enumerate(creds, 1):
            if verbose:
                logger.info(f"  [{i}/{len(creds)}] Testing {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password'] or '(empty)'}{Style.RESET_ALL}")
            result = tester.test(ip, port, cred["username"], cred["password"])
            results.append(result)
            if result.status == "success":
                logger.info(f"{Fore.GREEN}[✓ SUCCESS]{Style.RESET_ALL} {ip}:{port} - {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password']}{Style.RESET_ALL}")
                break

    elif protocol == "postgres" and psycopg2:
        tester = PostgreSQLTester(timeout, rate_limit)
        for i, cred in enumerate(creds, 1):
            if verbose:
                logger.info(f"  [{i}/{len(creds)}] Testing {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password'] or '(empty)'}{Style.RESET_ALL}")
            result = tester.test(ip, port, cred["username"], cred["password"])
            results.append(result)
            if result.status == "success":
                logger.info(f"{Fore.GREEN}[✓ SUCCESS]{Style.RESET_ALL} {ip}:{port} - {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password']}{Style.RESET_ALL}")
                break

    elif protocol == "rdp":
        tester = RDPTester(timeout, rate_limit)
        for i, cred in enumerate(creds, 1):
            if verbose:
                logger.info(f"  [{i}/{len(creds)}] Testing {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password'] or '(empty)'}{Style.RESET_ALL}")
            result = tester.test(ip, port, cred["username"], cred["password"])
            results.append(result)
            if result.status == "success":
                logger.info(f"{Fore.GREEN}[✓ SUCCESS]{Style.RESET_ALL} {ip}:{port} - {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password']}{Style.RESET_ALL}")
                break

    elif protocol == "vnc":
        tester = VNCTester(timeout, rate_limit)
        for i, cred in enumerate(creds, 1):
            if verbose:
                logger.info(f"  [{i}/{len(creds)}] Testing {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password'] or '(empty)'}{Style.RESET_ALL}")
            result = tester.test(ip, port, cred["username"], cred["password"])
            results.append(result)
            if result.status == "success":
                logger.info(f"{Fore.GREEN}[✓ SUCCESS]{Style.RESET_ALL} {ip}:{port} - {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password']}{Style.RESET_ALL}")
                break

    elif protocol == "unknown":
        error_msg = f"Unknown protocol for port {port} - cannot determine service type. Specify protocol manually with --protocol"
        logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {error_msg}")
        
        # Save error for all credentials
        if scan_id:
            for cred in creds:
                error_result = CredentialResult(ip, port, protocol, protocol, cred['username'], cred.get('password'), "error", error_msg)
                save_result_to_db_sync(scan_id, result=error_result)
        
        if creds:
            results.append(CredentialResult(ip, port, protocol, protocol, creds[0]['username'], creds[0].get('password'), "error", error_msg))
        else:
            results.append(CredentialResult(ip, port, protocol, protocol, "", "", "error", error_msg))
    
    else:
        # Protocol not supported or library missing
        missing_lib_msg = ""
        if protocol == "ssh" and not paramiko:
            missing_lib_msg = " - paramiko library not installed"
        elif protocol == "ftp" and not FTP:
            missing_lib_msg = " - ftplib not available"
        elif protocol == "mysql" and not pymysql:
            missing_lib_msg = " - pymysql library not installed"
        elif protocol == "postgres" and not psycopg2:
            missing_lib_msg = " - psycopg2 library not installed"
        elif protocol == "mssql" and not pymssql:
            missing_lib_msg = " - pymssql library not installed"
        
        error_msg = f"Protocol {protocol} not supported{missing_lib_msg}. Install required library or use a different protocol."
        logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {error_msg}")
        
        # Save error for all credentials
        if scan_id:
            for cred in creds:
                error_result = CredentialResult(ip, port, protocol, protocol, cred['username'], cred.get('password'), "error", error_msg)
                save_result_to_db_sync(scan_id, result=error_result)
        
        if creds:
            results.append(CredentialResult(ip, port, protocol, protocol, creds[0]['username'], creds[0].get('password'), "error", error_msg))
        else:
            results.append(CredentialResult(ip, port, protocol, protocol, "", "", "error", error_msg))

    return results

# ----------------------------------------------------------------------
# Save results
# ----------------------------------------------------------------------
def save_results(results: List[CredentialResult], output_dir: Path, formats: str = "json,csv"):
    """Save scan results in multiple formats."""
    formats_list = [f.strip().lower() for f in formats.split(',') if f.strip()]
    saved_files = []

    # Convert results to dicts
    results_dicts = [asdict(r) for r in results]

    # JSON
    if "json" in formats_list:
        json_file = output_dir / "credrecon_results.json"
        with open(json_file, "w") as f:
            json.dump(results_dicts, f, indent=2)
        saved_files.append(json_file)

    # CSV
    if "csv" in formats_list and results_dicts:
        csv_file = output_dir / "credrecon_results.csv"
        with open(csv_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results_dicts[0].keys())
            writer.writeheader()
            writer.writerows(results_dicts)
        saved_files.append(csv_file)

    return saved_files

def save_result_to_db_sync(scan_id: str, result: CredentialResult = None, skip_info: Dict = None):
    """Save a single credential test result or skipped credential to database (synchronous)."""
    try:
        from sqlmodel import Session, select, create_engine
        from cygor.webapp.models import CredReconScan, CredReconResult
        from cygor.webapp.config import settings
        from datetime import datetime

        # Create synchronous engine for subprocess
        # Use the sync version of the database URL
        db_url = settings.DATABASE_URL
        if db_url.startswith("postgresql+psycopg://"):
            db_url = db_url.replace("postgresql+psycopg://", "postgresql://")

        sync_engine = create_engine(db_url, echo=False)

        with Session(sync_engine) as session:
            # Get the scan record - explicitly select only columns that exist (excluding output_dir)
            statement = (
                select(CredReconScan.id, CredReconScan.scan_id)
                .where(CredReconScan.scan_id == scan_id)
            )
            scan_row = session.exec(statement).first()
            # Create a simple object with just the id attribute for compatibility
            class ScanRow:
                def __init__(self, id_value):
                    self.id = id_value
            scan = ScanRow(scan_row.id) if scan_row else None

            if not scan:
                return

            if result:
                # Save tested credential result
                db_result = CredReconResult(
                    scan_id=scan.id,
                    target=result.ip,
                    port=result.port,
                    protocol=result.protocol,
                    service=result.service,
                    username=result.username,
                    password=result.password,
                    status=result.status,
                    reason=result.details,
                    tested_at=datetime.utcnow().isoformat()
                )
                session.add(db_result)

            elif skip_info:
                # Save skipped credential
                db_result = CredReconResult(
                    scan_id=scan.id,
                    target=skip_info['target'],
                    port=skip_info['port'],
                    protocol=skip_info['protocol'],
                    service=skip_info.get('service'),
                    username=skip_info['username'],
                    password=skip_info.get('password'),
                    status='skipped',
                    reason=skip_info.get('reason', 'No login form detected'),
                    tested_at=None
                )
                session.add(db_result)

            session.commit()

    except ImportError:
        # Database not available (running from CLI without web UI)
        pass
    except Exception as e:
        pass  # Silently fail to not interrupt scanning

# ----------------------------------------------------------------------
# Main function
# ----------------------------------------------------------------------
def credrecon(input_file: str = None, target: str = None, output_dir: str = None,
              protocol: str = "auto", port: int = None, threads: int = 10,
              timeout: int = 5, rate_limit: float = 0.1, creds_file: str = None,
              usernames_file: str = None, passwords_file: str = None,
              max_attempts: int = 3, output_format: str = "json,csv", scan_id: str = None, **kwargs):
    """Main credential reconnaissance function.

    Args:
        scan_id: Optional scan ID for web UI integration (saves results to database)
    """

    start_time = time.time()

    # Determine if we should save output
    # Only save if output_dir is explicitly provided (not None)
    save_output = output_dir is not None
    out_dir = None
    output_file_handler = None

    if save_output:
        out_dir = resolve_output_dir(output_dir, "credrecon")
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Output directory: {out_dir}")
        
        # Set up file handler to capture all output to output.txt
        output_file = out_dir / "output.txt"
        try:
            output_file_handler = logging.FileHandler(output_file, mode='w', encoding='utf-8')
            output_file_handler.setLevel(logging.INFO)
            # Use a formatter that strips ANSI codes for file output
            class FileFormatter(logging.Formatter):
                """Formatter that strips ANSI color codes for file output."""
                def format(self, record):
                    message = record.getMessage()
                    # Remove ANSI color codes
                    import re
                    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    message = ansi_escape.sub('', message)
                    return message
            output_file_handler.setFormatter(FileFormatter())
            logger.addHandler(output_file_handler)
            logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Output will be saved to: {output_file}")
        except Exception as e:
            logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Could not create output file: {e}")
    else:
        logger.info(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Running in check-only mode (no output will be saved)")

    # Parse targets (support both IP:PORT and full URL formats)
    from urllib.parse import urlparse

    def parse_target(target_str: str, default_port: int = None):
        """Parse target string - supports both IP:PORT and full URL formats."""
        target_str = target_str.strip()

        # Check if it's a full URL (http:// or https://)
        if target_str.startswith(('http://', 'https://')):
            parsed = urlparse(target_str)
            host = parsed.hostname or parsed.netloc.split(':')[0]
            port_val = parsed.port or (443 if parsed.scheme == 'https' else 80)
            # Store full URL as host for HTTP protocol
            return (target_str, port_val, 'http', parsed.scheme)

        # Otherwise treat as IP:PORT format
        if ':' in target_str:
            try:
                host, port_str = target_str.rsplit(':', 1)
                port_val = int(port_str)
                return (host.strip(), port_val, None, None)
            except ValueError:
                # If port parsing fails, treat entire string as host
                return (target_str, default_port or 22, None, None)
        else:
            return (target_str, default_port or 22, None, None)

    targets = []
    if target:
        targets.append(parse_target(target, port))
    elif input_file and Path(input_file).exists():
        with open(input_file, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                targets.append(parse_target(line, port))

    if not targets:
        logger.error("No targets specified. Use -t or -i")
        return

    logger.info(f"Loaded {len(targets)} targets")

    # Load credentials
    custom_creds = None
    if creds_file and Path(creds_file).exists():
        logger.info(f"Loading credentials from {creds_file}")
        with open(creds_file, "r") as f:
            if creds_file.endswith(".yaml") or creds_file.endswith(".yml"):
                custom_creds = yaml.safe_load(f)
            else:
                custom_creds = json.load(f)
    elif usernames_file and passwords_file:
        # Build credentials from separate username/password files
        logger.info(f"Loading usernames from {usernames_file} and passwords from {passwords_file}")
        usernames = []
        passwords = []

        if Path(usernames_file).exists():
            with open(usernames_file, "r") as f:
                usernames = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        if Path(passwords_file).exists():
            with open(passwords_file, "r") as f:
                passwords = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        if usernames and passwords:
            # Create a credential list for all protocols with all combinations
            combined_creds = []
            for username in usernames:
                for password in passwords:
                    combined_creds.append({"username": username, "password": password, "service": "custom"})

            # Build custom_creds dict with same structure as default
            custom_creds = {
                "http": combined_creds,
                "ssh": combined_creds,
                "ftp": combined_creds,
                "mysql": combined_creds,
                "postgres": combined_creds,
                "mssql": combined_creds,
                "mongodb": combined_creds,
                "redis": combined_creds,
                "snmp": combined_creds,
                "rdp": combined_creds,
                "vnc": combined_creds,
            }
            logger.info(f"Generated {len(combined_creds)} credential combinations ({len(usernames)} users x {len(passwords)} passwords)")
        else:
            logger.warning("Username or password file is empty or not found")

    # Scan all targets
    all_results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for target_data in targets:
            # Unpack target data (could be 2-tuple for legacy or 4-tuple for URL)
            if len(target_data) == 4:
                ip, target_port, force_proto, scheme = target_data
            else:
                ip, target_port = target_data
                force_proto, scheme = None, None

            # Determine protocol
            if force_proto:
                # URL was provided, use the detected HTTP protocol
                detected_proto = force_proto
            elif protocol == "auto":
                # Auto-detect protocol by port
                detected_proto = detect_protocol(target_port)
            else:
                # User specified protocol
                detected_proto = protocol

            # Get credentials for this protocol
            if custom_creds and detected_proto in custom_creds:
                creds = custom_creds[detected_proto]
            else:
                creds = DEFAULT_CREDENTIALS_DB.get(detected_proto, [])

            if not creds:
                logger.warning(f"No credentials defined for {detected_proto}")
                continue

            # Limit credentials to max_attempts
            limited_creds = creds[:max_attempts] if max_attempts > 0 else creds

            logger.info(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Testing {Fore.WHITE}{ip}:{target_port}{Style.RESET_ALL} ({Fore.MAGENTA}{detected_proto.upper()}{Style.RESET_ALL}) with {Fore.GREEN}{len(limited_creds)}{Style.RESET_ALL} credential(s)")

            # Pass scheme information for HTTP testing
            if detected_proto == 'http' and scheme:
                future = executor.submit(scan_target_http, ip, target_port, limited_creds, timeout, rate_limit, scheme, True, scan_id)
            else:
                future = executor.submit(scan_target, ip, target_port, detected_proto, limited_creds, timeout, rate_limit, True, scan_id)
            futures.append(future)

        for future in as_completed(futures):
            try:
                results = future.result()
                # Handle tuple return from scan_target_http
                if isinstance(results, tuple):
                    results, skip_info = results
                all_results.extend(results)
            except Exception as e:
                logger.error(f"Error scanning target: {e}")

    # Save results (only if output_dir was specified)
    if save_output and all_results:
        saved_files = save_results(all_results, out_dir, output_format)
        logger.info(f"\n{Fore.GREEN}[✓]{Style.RESET_ALL} Results saved to:")
        for f in saved_files:
            logger.info(f"    {Fore.CYAN}{f}{Style.RESET_ALL}")

    # Summary
    elapsed = time.time() - start_time
    successful_results = [r for r in all_results if r.status == "success"]
    failed_count = sum(1 for r in all_results if r.status == "failed")
    error_count = sum(1 for r in all_results if r.status == "error")

    # Summary
    logger.info(f"\n{Fore.CYAN}Scan Summary:{Style.RESET_ALL}")
    logger.info(f"  Targets scanned:     {Fore.WHITE}{len(targets)}{Style.RESET_ALL}")
    logger.info(f"  Credentials tested:  {Fore.WHITE}{len(all_results)}{Style.RESET_ALL}")
    logger.info(f"  Successful logins:   {Fore.GREEN}{len(successful_results)}{Style.RESET_ALL}")
    logger.info(f"  Failed attempts:     {Fore.YELLOW}{failed_count}{Style.RESET_ALL}")
    logger.info(f"  Errors:              {Fore.RED}{error_count}{Style.RESET_ALL}")
    logger.info(f"  Time elapsed:        {Fore.WHITE}{elapsed:.1f}s{Style.RESET_ALL}")
    
    # Clean up file handler if it was added
    if output_file_handler:
        try:
            logger.removeHandler(output_file_handler)
            output_file_handler.close()
            if save_output:
                logger.info(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Complete output saved to: {out_dir / 'output.txt'}")
        except Exception as e:
            pass  # Silently fail cleanup

    # Display successful credentials
    if successful_results:
        logger.info(f"\n{Fore.GREEN}✓ SUCCESSFUL CREDENTIALS:{Style.RESET_ALL}\n")
        for i, result in enumerate(successful_results, 1):
            if len(successful_results) > 1:
                logger.info(f"{Fore.GREEN}[{i}]{Style.RESET_ALL} {Fore.CYAN}{result.ip}:{result.port}{Style.RESET_ALL} ({Fore.MAGENTA}{result.protocol.upper()}{Style.RESET_ALL}) → {Fore.CYAN}{result.username}{Style.RESET_ALL}:{Fore.YELLOW}{result.password or '(empty)'}{Style.RESET_ALL}")
            else:
                logger.info(f"    {Fore.CYAN}{result.ip}:{result.port}{Style.RESET_ALL} ({Fore.MAGENTA}{result.protocol.upper()}{Style.RESET_ALL}) → {Fore.CYAN}{result.username}{Style.RESET_ALL}:{Fore.YELLOW}{result.password or '(empty)'}{Style.RESET_ALL}")
    else:
        logger.info(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} No successful credentials found")

# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def parse_args():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog="cygor credrecon",
        description="Test default credentials across multiple protocols",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.MAGENTA}Examples:{Style.RESET_ALL}

{Fore.YELLOW}# Scan single target with auto-detection{Style.RESET_ALL}
cygor credrecon -t 192.168.1.100:22

{Fore.YELLOW}# Scan multiple targets from file{Style.RESET_ALL}
cygor credrecon -i targets.txt

{Fore.YELLOW}# Scan specific protocol{Style.RESET_ALL}
cygor credrecon -t 192.168.1.100:3306 --protocol mysql

{Fore.YELLOW}# Use custom credentials file{Style.RESET_ALL}
cygor credrecon -i targets.txt --creds-file my_creds.yaml

{Fore.YELLOW}# Increase threads and timeout{Style.RESET_ALL}
cygor credrecon -i targets.txt --threads 20 --timeout 10

{Fore.CYAN}Supported Protocols:{Style.RESET_ALL}
  http, ssh, ftp, mysql, postgres, mssql, mongodb, redis, snmp, rdp, vnc

{Fore.CYAN}Notes:{Style.RESET_ALL}
  - SMB/CIFS testing available via dedicated smbexplorer module
  - RDP testing detects service availability (full auth requires additional libraries)
  - VNC testing supports password authentication and detects unauthenticated instances
  - Some protocols require additional Python libraries (install as needed)
  - Use --usernames-file and --passwords-file for custom credential lists
"""
    )

    parser.add_argument("-t", "--target", help="Single target (IP:PORT)")
    parser.add_argument("-i", "--input-file", help="File with targets (one per line, format IP:PORT)")
    parser.add_argument("-o", "--output-dir", nargs="?", const="", help="Output directory")
    parser.add_argument("--protocol", default="auto", help="Protocol to test (default: auto-detect)")
    parser.add_argument("--port", type=int, help="Default port if not specified in target")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout in seconds")
    parser.add_argument("--rate-limit", type=float, default=0.1, help="Rate limit between tests (seconds)")
    parser.add_argument("--creds-file", help="Custom credentials YAML/JSON file")
    parser.add_argument("--usernames-file", help="File with usernames (one per line)")
    parser.add_argument("--passwords-file", help="File with passwords (one per line)")
    parser.add_argument("--max-attempts", type=int, default=3, help="Maximum number of credential attempts per target (default: 3)")
    parser.add_argument("--output-format", default="json,csv", help="Output formats (json,csv)")
    parser.add_argument("--scan-id", help="Scan ID for web UI integration (internal use)")

    return parser.parse_args()

# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
if __name__ == "__main__":
    args = parse_args()
    credrecon(
        input_file=args.input_file,
        target=args.target,
        output_dir=args.output_dir,
        protocol=args.protocol,
        port=args.port,
        threads=args.threads,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
        creds_file=args.creds_file,
        usernames_file=args.usernames_file,
        passwords_file=args.passwords_file,
        max_attempts=args.max_attempts,
        output_format=args.output_format,
        scan_id=args.scan_id,
    )
