#!/usr/bin/env python3
"""
Cygor Default Credentials Scanner (CredScanner)
================================================

A comprehensive credential testing module for discovering default and weak
credentials across multiple protocols and services.

Inspired by changeme (https://github.com/ztgrace/changeme) and credential
stuffing techniques, this module tests common default credentials against
various services to identify security misconfigurations.

Supported Protocols (27):
-------------------------
- HTTP/HTTPS (Basic Auth, Digest Auth, Form-based)
- SSH (password, key, certificate, bad key detection)
- FTP
- SMB (password + NTLM hash pass-the-hash)
- MySQL, PostgreSQL, MSSQL, MongoDB, Redis
- Elasticsearch, CouchDB, InfluxDB, Cassandra, Neo4j, Memcached
- SMTP/SMTPS, IMAP/IMAPS, POP3/POP3S
- RDP (socket detection + NLA/CredSSP with aardwolf)
- VNC (Virtual Network Computing)
- WinRM/WinRM-SSL (Windows Remote Management)
- LDAP/LDAPS (Simple bind + NTLM)
- SNMP (tiered community string wordlists)
- IPMI (Intelligent Platform Management Interface)
- MQTT/MQTTS (Message Queuing Telemetry Transport)
- Telnet

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
import random
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED
from collections import defaultdict
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from urllib.parse import urlparse, urljoin

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

# LDAP support
try:
    import ldap3
    from ldap3 import Server, Connection, ALL, SIMPLE, NTLM
except ImportError:
    ldap3 = None

# IPMI support
try:
    from pyghmi.ipmi import command as ipmi_command
except ImportError:
    ipmi_command = None

# MQTT support
try:
    import paho.mqtt.client as mqtt
except ImportError:
    mqtt = None

# WinRM support
try:
    import winrm
    from winrm.protocol import Protocol as WinRMProtocol
except ImportError:
    winrm = None
    WinRMProtocol = None

# Cassandra support
try:
    from cassandra.cluster import Cluster as CassandraCluster
    from cassandra.auth import PlainTextAuthProvider as CassandraAuth
except ImportError:
    CassandraCluster = None
    CassandraAuth = None

# Neo4j support (optional - falls back to HTTP REST API via requests)
try:
    from neo4j import GraphDatabase as Neo4jDriver
except ImportError:
    Neo4jDriver = None

# RDP full auth support (optional - falls back to socket detection)
try:
    from aardwolf.connection import RDPConnection as AardwolfRDP
except ImportError:
    AardwolfRDP = None

# Colorama for CLI output
try:
    from colorama import Fore, Style, init as _color_init
    _color_init(autoreset=True, strip=False)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# Import proxy configuration for jumpbox warning
try:
    from cygor.proxy_config import is_jumpbox_routing_active
except ImportError:
    def is_jumpbox_routing_active():
        return False

# Module metadata
module_info = {
    "name": "CredRecon — Default Credentials Scanner",
    "slug": "credrecon",
    "author": "Cygor Development Team",
    "version": "1.0",
    "description": "Tests default and weak credentials across multiple protocols (HTTP, SSH, FTP, SMB, WinRM, LDAP, databases, etc.)",
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
    # Service fingerprinting fields
    fingerprint_product: str = ""
    fingerprint_version: str = ""
    fingerprint_confidence: float = 0.0
    fingerprint_raw: str = ""  # JSON string with full fingerprint details
    credential_selection: str = ""  # Rationale for why these credentials were selected
    source_ip: str = ""  # Source IP used for this credential attempt (IP rotation)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ----------------------------------------------------------------------
# Workspace-aware output helpers
# ----------------------------------------------------------------------
def get_module_output_dir(module_name: str = "credrecon") -> Path:
    """Returns a workspace-aware path for the module's data directory with timestamp."""
    env_ws = os.environ.get("CYGOR_WORKSPACE") or os.environ.get("CYGOR_RESULTS_DIR")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if env_ws:
        base = Path(env_ws) / module_name / ts
    else:
        base = Path(module_name) / ts
    base.mkdir(parents=True, exist_ok=True)
    return base

def resolve_output_dir(cli_output_dir: str | None, module_name: str) -> Path:
    """Resolve final output directory with timestamp subdirectory."""
    env_ws = os.environ.get("CYGOR_WORKSPACE") or os.environ.get("CYGOR_RESULTS_DIR")
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
    """
    Load default credentials from the new hierarchical credential system.

    Falls back to legacy YAML file if new system is not available.
    Returns credentials in legacy format for backward compatibility.
    """
    # Try new credential system first
    try:
        from .credentials.loader import load_default_credentials_legacy
        return load_default_credentials_legacy()
    except ImportError:
        pass

    # Fall back to legacy YAML file
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


def get_credential_database():
    """
    Get the full credential database with metadata.

    Returns a CredentialDatabase object for advanced credential selection.
    """
    try:
        from .credentials.loader import load_all_credentials
        return load_all_credentials()
    except ImportError:
        return None


def get_credential_stats():
    """Get statistics about the credential database."""
    try:
        from .credentials.loader import get_credential_stats as _get_stats
        return _get_stats()
    except ImportError:
        return {"error": "New credential system not available"}


def _load_snmp_communities(tier: str = "default") -> List[Dict]:
    """Load SNMP community strings from tiered wordlist file.

    Returns list of credential dicts with username="" and password=community_string.
    """
    yaml_path = Path(__file__).parent / "credentials" / "builtin" / "snmp_communities.yaml"
    if not yaml_path.exists():
        return []
    try:
        with open(yaml_path) as f:
            data = yaml.safe_load(f)
        tiers = data.get("tiers", {})
        communities = set()

        # Always include default tier
        if "default" in tiers:
            communities.update(tiers["default"].get("communities", []))

        # Include extended if requested
        if tier in ("extended", "full") and "extended" in tiers:
            communities.update(tiers["extended"].get("communities", []))

        # Include full if requested
        if tier == "full" and "full" in tiers:
            communities.update(tiers["full"].get("communities", []))

        return [{"username": "", "password": c, "service": "snmp"} for c in communities]
    except Exception as e:
        logger.warning(f"Failed to load SNMP communities: {e}")
        return []


def get_credentials_for_service(protocol: str, fingerprint: dict = None, max_credentials: int = None) -> Tuple[List[Dict], str]:
    """
    Get credentials prioritized by fingerprint match.

    Uses smart credential selection when a service fingerprint is available,
    prioritizing product/vendor-specific credentials over generic ones.

    Args:
        protocol: Protocol name (ssh, http, mysql, etc.)
        fingerprint: Dict with product/vendor info from service probe
        max_credentials: Maximum credentials to return

    Returns:
        Tuple of (credentials_list, selection_rationale)
    """
    try:
        from .credentials.loader import get_credentials_by_fingerprint
        return get_credentials_by_fingerprint(protocol, fingerprint, max_credentials=max_credentials)
    except ImportError:
        # Fall back to generic credentials
        creds = DEFAULT_CREDENTIALS_DB.get(protocol, [])
        if max_credentials:
            creds = creds[:max_credentials]
        return creds, f"Selected {len(creds)} generic {protocol} credentials"


# Load credentials at module import time
DEFAULT_CREDENTIALS_DB = load_default_credentials()

# ----------------------------------------------------------------------
# Protocol testers
# ----------------------------------------------------------------------
class ProtocolTester:
    """Base class for protocol-specific credential testers."""

    def __init__(self, timeout: int = 5, rate_limit: float = 0.1, jitter: float = 0.0, source_ip: str = None):
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.jitter = jitter
        self.source_ip = source_ip
        self.lock = threading.Lock()
        self.last_test = 0

    def rate_limited_test(self):
        """Enforce rate limiting between tests with optional jitter for evasion."""
        with self.lock:
            elapsed = time.time() - self.last_test
            delay = self.rate_limit
            if self.jitter > 0:
                delay += random.uniform(0, self.jitter)
            if elapsed < delay:
                time.sleep(delay - elapsed)
            self.last_test = time.time()

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        """Override in subclass."""
        raise NotImplementedError()

    def _get_requests_session(self):
        """Return a requests.Session bound to self.source_ip, or None if not needed."""
        if not self.source_ip or not requests:
            return None
        session = requests.Session()
        adapter = _SourceIPAdapter(self.source_ip)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session


# Source-IP-binding adapter for the requests library.
# Only defined when requests is available (it is imported inside a try/except above).
if requests is not None:
    class _SourceIPAdapter(requests.adapters.HTTPAdapter):
        """Requests transport adapter that binds to a specific source IP."""
        def __init__(self, source_address, **kwargs):
            self._source_address = source_address
            super().__init__(**kwargs)

        def init_poolmanager(self, *args, **kwargs):
            kwargs['source_address'] = (self._source_address, 0)
            super().init_poolmanager(*args, **kwargs)
else:
    _SourceIPAdapter = None


# Strings in a response body that indicate authentication failed / a login
# page is still being shown. Shared by Basic-auth and form-login evaluation.
HTTP_AUTH_FAILURE_INDICATORS = [
    'invalid password', 'invalid username', 'login failed',
    'incorrect password', 'incorrect username', 'authentication failed',
    'access denied', 'wrong password', 'wrong username', 'bad credentials',
    'login error', 'authentication error', 'incorrect login',
    'login unsuccessful', 'authentication unsuccessful',
    'enter your password', 'password incorrect', 'username incorrect',
    'invalid credentials', 'invalid login',
]

# Strings that indicate a successful, authenticated session.
HTTP_AUTH_SUCCESS_INDICATORS = [
    'welcome', 'dashboard', 'logout', 'sign out', 'signout', 'log out',
    'profile', 'settings', 'account', 'user panel', 'admin panel',
    'control panel',
]


class HTTPTester(ProtocolTester):
    """Test HTTP/HTTPS credentials across Basic/Digest auth, HTML login forms,
    and product-specific login APIs (e.g. OpenMediaVault JSON-RPC)."""

    # Common login page/endpoint paths to probe when the landing page has no
    # usable form on its own (single-page apps render the form client-side, so
    # the root HTML carries no <form>/password field at all).
    LOGIN_PATH_CANDIDATES = [
        "/login", "/admin", "/admin/login", "/auth/login", "/user/login",
        "/users/login", "/account/login", "/signin", "/sign-in", "/logon",
        "/administrator", "/manager/html", "/wp-login.php", "/wp-admin/",
        "/cgi-bin/luci", "/index.php?option=com_login",
    ]

    # Product-specific auth handlers. Each entry is (signature, handler, name):
    #   signature - lowercase string matched against the fingerprint
    #               product/vendor and the landing-page content/headers; also
    #               used to pull that product's credentials from the DB.
    #   handler   - HTTPTester method that authenticates the product.
    #   name      - human-readable product name for reporting.
    PRODUCT_AUTH_HANDLERS = [
        ("openmediavault", "_test_omv", "OpenMediaVault"),
    ]

    @staticmethod
    def _origin(url: str) -> str:
        """Return scheme://host[:port] for a URL, stripping path/query/fragment."""
        p = urlparse(url)
        if p.scheme and p.netloc:
            return f"{p.scheme}://{p.netloc}"
        return url.split('#', 1)[0].rstrip('/')

    @staticmethod
    def _host_label(*candidates: str) -> str:
        """Return a bare hostname/IP from the first usable candidate (a full URL
        or a host string). Used so results render as host:port instead of
        embedding a full URL (which would produce e.g. http://h:80/:80)."""
        for c in candidates:
            if not c:
                continue
            p = urlparse(c if "://" in c else f"//{c}")
            if p.hostname:
                return p.hostname
        return next((c for c in candidates if c), "")

    def _match_product_handler(self, *texts: str) -> Optional[Dict[str, str]]:
        """Return {handler, product, name} for the first product signature found
        in any of the given text blobs, or None."""
        blob = " ".join(t for t in texts if t).lower()
        if not blob:
            return None
        for needle, handler, name in self.PRODUCT_AUTH_HANDLERS:
            if needle in blob:
                return {"handler": handler, "product": needle, "name": name}
        return None

    def _identify_http_product(self, *texts: str) -> Optional[str]:
        """Identify a known web application from page content/headers using the
        shared HTTP_APPLICATION_PATTERNS table. Returns the product name (aligned
        to credential-DB product keys) or None. This is identification only - the
        actual login still uses the generic Basic/Digest/form tester unless a
        product has a dedicated handler in PRODUCT_AUTH_HANDLERS."""
        try:
            from cygor.credrecon.validation import HTTP_APPLICATION_PATTERNS
        except Exception:
            return None
        blob = " ".join(t for t in texts if t).lower()
        if not blob:
            return None
        for patterns, product, vendor, _cred_category in HTTP_APPLICATION_PATTERNS:
            for pat in patterns:
                if pat.lower() in blob:
                    return product
        return None

    @staticmethod
    def _attach_product(plan: Optional[Dict[str, Any]], product: Optional[str]) -> Optional[Dict[str, Any]]:
        """Tag a non-product-handler auth plan (basic/digest/form) with an
        identified web app so the scanner front-loads that product's default
        creds. The auth method is unchanged - the generic tester still logs in."""
        if plan and product and not plan.get("product"):
            plan["product"] = product
            base = plan.get("detail") or plan.get("method") or "login"
            plan["detail"] = f"{base} - identified as {product}"
        return plan

    def _parse_login_form(self, html: str, page_url: str) -> Optional[Dict[str, Any]]:
        """Find the first HTML <form> containing a password input and return a
        form plan: action URL, method, username/password field names, and any
        hidden fields (CSRF tokens, etc.). Returns None if no login form found."""
        if not html:
            return None
        low = html.lower()
        if 'type="password"' not in low and "type='password'" not in low and 'type=password' not in low:
            return None

        user_hints = ('user', 'email', 'login', 'name', 'account', 'uid', 'mail')
        forms = re.findall(r'<form\b[^>]*>.*?</form>', html, re.IGNORECASE | re.DOTALL)
        # Fall back to treating the whole document as one form region if no
        # explicit <form> close tag was matched (some apps stream markup).
        if not forms and ('<form' in low):
            forms = [html[low.index('<form'):]]

        for form_html in forms:
            if 'password' not in form_html.lower():
                continue

            pass_field = None
            user_field = None
            hidden: Dict[str, str] = {}

            for inp in re.findall(r'<input\b[^>]*>', form_html, re.IGNORECASE):
                m_type = re.search(r'type\s*=\s*["\']?([^"\'\s>]+)', inp, re.IGNORECASE)
                m_name = re.search(r'name\s*=\s*["\']?([^"\'\s>]+)', inp, re.IGNORECASE)
                m_value = re.search(r'value\s*=\s*["\']([^"\']*)["\']', inp, re.IGNORECASE)
                itype = (m_type.group(1).lower() if m_type else "text")
                name = (m_name.group(1) if m_name else None)
                value = (m_value.group(1) if m_value else "")
                if not name:
                    continue
                if itype == "password":
                    pass_field = name
                elif itype == "hidden":
                    hidden[name] = value
                elif itype in ("text", "email", "tel", "search"):
                    if user_field is None:
                        # Prefer a name that looks like a username/email field
                        if itype == "email" or any(h in name.lower() for h in user_hints):
                            user_field = name
                        elif user_field is None:
                            user_field = name  # first text field as fallback

            if not pass_field:
                continue

            m_action = re.search(r'<form\b[^>]*?\baction\s*=\s*["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            m_method = re.search(r'<form\b[^>]*?\bmethod\s*=\s*["\']?([^"\'\s>]+)', form_html, re.IGNORECASE)
            action = m_action.group(1).strip() if m_action else ""
            method = (m_method.group(1).lower() if m_method else "post")
            action_url = urljoin(page_url, action) if action else page_url

            return {
                "method": "form",
                "url": action_url,
                "page_url": page_url,
                "form_method": method or "post",
                "user_field": user_field or "username",
                "pass_field": pass_field,
                "form_fields": hidden,
            }
        return None

    def discover_login(self, base_url: str, product: str = None, vendor: str = None) -> Optional[Dict[str, Any]]:
        """Determine how to authenticate to a web service.

        Returns an auth-plan dict (keyed by ``method``) or None if no login
        mechanism could be found. Detection order:
          1. Product-specific handler matched by fingerprint product/vendor.
          2. HTTP Basic/Digest challenge (401) on the landing page.
          3. Product-specific handler matched by landing-page content/headers
             (covers single-page apps whose root HTML names the product).
          4. HTML login form on the landing page.
          5. Probe common login paths + known login APIs (handles SPAs that
             render the form client-side, e.g. a ``/#/login`` hash route).
        """
        if not requests:
            return None

        # 1. Fingerprint-driven product handler (most reliable when available).
        match = self._match_product_handler(product, vendor)
        if match:
            return {"method": "product", "handler": match["handler"], "product": match["product"],
                    "url": self._origin(base_url),
                    "detail": f"Identified portal: {match['name']} (fingerprint match)"}

        session = self._get_requests_session() or (requests.Session() if requests else None)
        try:
            resp = session.get(base_url, timeout=self.timeout, verify=False, allow_redirects=True)
        except requests.exceptions.Timeout:
            return None
        except Exception:
            return None

        origin = self._origin(resp.url or base_url)
        content = resp.text or ""
        header_blob = " ".join(f"{k}:{v}" for k, v in resp.headers.items())

        # Identify the web application from the landing page (broad signature
        # match) so non-product-handler plans can still front-load that app's
        # default creds. Fall back to any fingerprint product hint.
        app = self._identify_http_product(content[:30000], header_blob) or product

        # 2. Basic/Digest challenge.
        if resp.status_code == 401:
            www = resp.headers.get('WWW-Authenticate', '').lower()
            method = "digest" if "digest" in www else "basic"
            plan = {"method": method, "url": base_url,
                    "detail": f"HTTP {method} auth (401 challenge)"}
            return self._attach_product(plan, app)

        # 3. Product handler (custom auth, e.g. OMV JSON-RPC) from the landing page.
        match = self._match_product_handler(content[:30000], header_blob)
        if match:
            return {"method": "product", "handler": match["handler"], "product": match["product"], "url": origin,
                    "detail": f"Identified portal: {match['name']} (detected from landing page)"}

        # 4. Login form directly on the landing page.
        form = self._parse_login_form(content, resp.url or base_url)
        if form:
            form["detail"] = "HTML login form on landing page"
            return self._attach_product(form, app)

        # 5. Probe common login paths + known login APIs.
        return self._probe_login_endpoints(session, origin, app)

    def _probe_login_endpoints(self, session, origin: str, app: str = None) -> Optional[Dict[str, Any]]:
        """Probe candidate login pages/APIs under ``origin``. Returns the first
        usable auth plan, or None. ``app`` is a web application identified from
        the landing page, used to tag form/basic plans for credential front-loading."""
        # 5a. Known login-API signatures (recognize a product by its API even
        #     when the SPA shell HTML reveals nothing).
        omv_plan = self._probe_omv_rpc(session, origin)
        if omv_plan:
            return omv_plan

        # 5b. Common HTML login pages / Basic-auth endpoints.
        for path in self.LOGIN_PATH_CANDIDATES:
            cand = origin + path
            try:
                r = session.get(cand, timeout=self.timeout, verify=False, allow_redirects=True)
            except Exception:
                continue
            if r.status_code == 401:
                www = r.headers.get('WWW-Authenticate', '').lower()
                method = "digest" if "digest" in www else "basic"
                plan = {"method": method, "url": cand,
                        "detail": f"HTTP {method} auth at {path}"}
                return self._attach_product(plan, app or self._identify_http_product((r.text or "")[:30000]))
            if r.status_code >= 400:
                continue
            page_app = app or self._identify_http_product((r.text or "")[:30000])
            match = self._match_product_handler((r.text or "")[:30000])
            if match:
                return {"method": "product", "handler": match["handler"], "product": match["product"], "url": origin,
                        "detail": f"Identified portal: {match['name']} (detected at {path})"}
            form = self._parse_login_form(r.text or "", r.url or cand)
            if form:
                form["detail"] = f"HTML login form at {path}"
                return self._attach_product(form, page_app)
        return None

    def _probe_omv_rpc(self, session, origin: str) -> Optional[Dict[str, Any]]:
        """Detect OpenMediaVault by its JSON-RPC envelope at /rpc.php."""
        rpc_url = origin + "/rpc.php"
        try:
            r = session.post(rpc_url, json={"service": "Session", "method": "noop", "params": None},
                             timeout=self.timeout, verify=False)
        except Exception:
            return None
        ctype = r.headers.get("Content-Type", "").lower()
        if "json" not in ctype and not (r.text or "").lstrip().startswith("{"):
            return None
        try:
            data = r.json()
        except Exception:
            return None
        # OMV always answers RPC calls with a {"response":..., "error":...} envelope.
        if isinstance(data, dict) and ("response" in data and "error" in data):
            return {"method": "product", "handler": "_test_omv", "product": "openmediavault", "url": origin,
                    "detail": "Identified portal: OpenMediaVault (JSON-RPC at /rpc.php)"}
        return None

    def test_auth(self, plan: Dict[str, Any], ip: str, port: int, username: str, password: str) -> CredentialResult:
        """Dispatch a credential test according to the discovered auth plan."""
        method = plan.get("method")
        if method == "product":
            handler = getattr(self, plan.get("handler", ""), None)
            if handler is None:
                result = CredentialResult(ip, port, "http", "http", username, password, "error",
                                          f"Unknown product handler: {plan.get('handler')}")
            else:
                result = handler(plan["url"], ip, port, username, password)
        elif method in ("basic", "digest"):
            result = self.test_url(plan["url"], port, username, password, auth_type=method)
        elif method == "form":
            result = self._test_form(plan, ip, port, username, password)
        else:
            result = CredentialResult(ip, port, "http", "http", username, password, "error",
                                      f"Unsupported auth method: {method}")
        # Normalize the result label to a bare host so the results table renders
        # host:port. Callers may pass a full URL as `ip`, and the Basic/Digest
        # branch labels with plan["url"]; both would otherwise show a URL:port.
        result.ip = self._host_label(ip, plan.get("url"))
        return result

    def _test_form(self, plan: Dict[str, Any], ip: str, port: int, username: str, password: str) -> CredentialResult:
        """Submit an HTML login form and evaluate the response."""
        if not requests:
            return CredentialResult(ip, port, "http", "http-form", username, password, "error", "requests library not installed")

        self.rate_limited_test()
        # Fresh session per attempt so cookies from one credential never leak
        # into the next (a stale authenticated cookie would fake a success).
        session = self._get_requests_session() or requests.Session()
        page_url = plan.get("page_url") or plan["url"]
        fields = dict(plan.get("form_fields") or {})

        # Re-fetch the login page so CSRF tokens / session cookies are current.
        try:
            pg = session.get(page_url, timeout=self.timeout, verify=False, allow_redirects=True)
            fresh = self._parse_login_form(pg.text or "", pg.url or page_url)
            if fresh:
                if fresh.get("form_fields"):
                    fields.update(fresh["form_fields"])
                action = fresh.get("url") or plan["url"]
                form_method = fresh.get("form_method", plan.get("form_method", "post"))
                user_field = fresh.get("user_field", plan["user_field"])
                pass_field = fresh.get("pass_field", plan["pass_field"])
            else:
                action, form_method = plan["url"], plan.get("form_method", "post")
                user_field, pass_field = plan["user_field"], plan["pass_field"]
        except Exception:
            action, form_method = plan["url"], plan.get("form_method", "post")
            user_field, pass_field = plan["user_field"], plan["pass_field"]

        fields[user_field] = username
        fields[pass_field] = password

        try:
            if form_method == "get":
                resp = session.get(action, params=fields, timeout=self.timeout, verify=False, allow_redirects=False)
            else:
                resp = session.post(action, data=fields, timeout=self.timeout, verify=False, allow_redirects=False)
        except requests.exceptions.Timeout:
            return CredentialResult(ip, port, "http", "http-form", username, password, "error", "Timeout during form login")
        except requests.exceptions.ConnectionError as e:
            return CredentialResult(ip, port, "http", "http-form", username, password, "error", f"Connection error during form login: {e}")
        except Exception as e:
            return CredentialResult(ip, port, "http", "http-form", username, password, "error", f"Form login error: {e}")

        return self._evaluate_form_response(resp, session, ip, port, username, password)

    def _evaluate_form_response(self, resp, session, ip, port, username, password) -> CredentialResult:
        """Decide success/failure for a form-login response. Conservative: only
        report success on positive evidence (redirect away from login, success
        markers, or a session cookie + the login form disappearing)."""
        svc = "http-form"
        body = resp.text or ""
        low = body.lower()

        # Redirects are the strongest signal for form logins.
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            loc_low = location.lower()
            if any(k in loc_low for k in ("login", "signin", "sign-in", "logon", "auth", "error", "denied", "invalid")):
                return CredentialResult(ip, port, "http", svc, username, password, "failed",
                                        f"Redirected back to login ({location})")
            return CredentialResult(ip, port, "http", svc, username, password, "success",
                                    f"Login redirected to {location or 'authenticated page'}")

        if resp.status_code in (401, 403):
            return CredentialResult(ip, port, "http", svc, username, password, "failed",
                                    f"HTTP {resp.status_code} - credentials rejected")

        if resp.status_code == 200:
            if any(ind in low for ind in HTTP_AUTH_FAILURE_INDICATORS):
                return CredentialResult(ip, port, "http", svc, username, password, "failed",
                                        "Login page reports authentication failure")
            has_success = any(ind in low for ind in HTTP_AUTH_SUCCESS_INDICATORS)
            session_cookie = any(
                any(tok in c.name.lower() for tok in ("sess", "sid", "token", "auth"))
                for c in session.cookies
            )
            still_login_form = ('type="password"' in low or "type='password'" in low)

            if has_success and not still_login_form:
                return CredentialResult(ip, port, "http", svc, username, password, "success",
                                        "Login succeeded (authenticated content detected)")
            if session_cookie and not still_login_form:
                return CredentialResult(ip, port, "http", svc, username, password, "success",
                                        "Login succeeded (session cookie set, login form cleared)")
            return CredentialResult(ip, port, "http", svc, username, password, "failed",
                                    "No success indicators - login form still present")

        return CredentialResult(ip, port, "http", svc, username, password, "failed",
                                f"HTTP {resp.status_code} - unexpected form-login response")

    def _test_omv(self, base_url: str, ip: str, port: int, username: str, password: str) -> CredentialResult:
        """Authenticate to OpenMediaVault via its JSON-RPC Session.login endpoint.

        OMV is a single-page app (``/#/login`` is a client-side route); the real
        login is a POST of {"service":"Session","method":"login",...} to /rpc.php.
        Success is confirmed by the JSON envelope (error==null, authenticated)
        and the session cookie OMV sets on the response."""
        svc = "openmediavault"
        if not requests:
            return CredentialResult(ip, port, "http", svc, username, password, "error", "requests library not installed")

        self.rate_limited_test()
        session = self._get_requests_session() or requests.Session()
        rpc_url = base_url.rstrip("/") + "/rpc.php"
        payload = {"service": "Session", "method": "login",
                   "params": {"username": username, "password": password}}
        try:
            resp = session.post(rpc_url, json=payload, timeout=self.timeout, verify=False,
                                headers={"Content-Type": "application/json"})
        except requests.exceptions.Timeout:
            return CredentialResult(ip, port, "http", svc, username, password, "error", "Timeout contacting OMV /rpc.php")
        except requests.exceptions.ConnectionError as e:
            return CredentialResult(ip, port, "http", svc, username, password, "error", f"Connection error to OMV /rpc.php: {e}")
        except Exception as e:
            return CredentialResult(ip, port, "http", svc, username, password, "error", f"OMV login error: {e}")

        try:
            data = resp.json()
        except Exception:
            return CredentialResult(ip, port, "http", svc, username, password, "error",
                                    f"OMV /rpc.php returned non-JSON (HTTP {resp.status_code}) - not an OMV endpoint?")

        if not isinstance(data, dict):
            return CredentialResult(ip, port, "http", svc, username, password, "error", "Unexpected OMV RPC response")

        err = data.get("error")
        if err:
            msg = err.get("message") if isinstance(err, dict) else str(err)
            return CredentialResult(ip, port, "http", svc, username, password, "failed", f"OMV: {msg or 'login rejected'}")

        response = data.get("response")
        authenticated = isinstance(response, dict) and response.get("authenticated") is True
        has_session = any("SESSIONID" in c.name.upper() for c in session.cookies)

        if authenticated or has_session:
            detail = "OMV JSON-RPC login OK"
            if has_session:
                detail += " - session cookie established"
            return CredentialResult(ip, port, "http", svc, username, password, "success", detail)

        return CredentialResult(ip, port, "http", svc, username, password, "failed",
                                "OMV login returned no error but no session/authentication")

    def test(self, ip: str, port: int, username: str, password: str, use_https: bool = False) -> CredentialResult:
        if not requests:
            return CredentialResult(ip, port, "http", "http", username, password, "error", "requests library not installed")

        self.rate_limited_test()
        scheme = "https" if use_https or port == 443 else "http"
        url = f"{scheme}://{ip}:{port}/"

        try:
            _session = self._get_requests_session()
            _get = _session.get if _session else requests.get
            resp = _get(url, auth=HTTPBasicAuth(username, password), timeout=self.timeout, verify=False)
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

    def test_url(self, url: str, port: int, username: str, password: str, auth_type: str = "basic") -> CredentialResult:
        """Test HTTP Basic/Digest authentication against a full URL with path."""
        if not requests:
            return CredentialResult(url, port, "http", "http", username, password, "error", "requests library not installed")

        self.rate_limited_test()
        auth_obj = HTTPDigestAuth(username, password) if auth_type == "digest" else HTTPBasicAuth(username, password)

        try:
            _session = self._get_requests_session()
            _get = _session.get if _session else requests.get

            # First, test without credentials to establish a baseline
            resp_no_auth = None
            try:
                resp_no_auth = _get(url, timeout=self.timeout, verify=False, allow_redirects=False)
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
                resp = _get(url, auth=auth_obj, timeout=self.timeout, verify=False, allow_redirects=False)
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
            connect_kwargs = dict(
                hostname=ip, port=port, username=username, password=password,
                timeout=self.timeout, look_for_keys=False, allow_agent=False
            )
            if self.source_ip:
                try:
                    sock = socket.create_connection((ip, port), timeout=self.timeout, source_address=(self.source_ip, 0))
                    connect_kwargs['sock'] = sock
                except Exception:
                    pass  # Fall back to unbound connection
            client.connect(**connect_kwargs)
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

    def test_key(self, ip: str, port: int, username: str, key_file: str, key_passphrase: str = None, cert_file: str = None) -> CredentialResult:
        """Test SSH authentication using a private key, optionally with an SSH certificate.

        Args:
            ip: Target host
            port: Target port
            username: SSH username
            key_file: Path to private key file (RSA, Ed25519, ECDSA)
            key_passphrase: Optional passphrase for encrypted private keys
            cert_file: Optional path to SSH certificate file (-cert.pub) or public key (.pub)
                       for CA-signed certificate authentication
        """
        if not paramiko:
            return CredentialResult(ip, port, "ssh", "ssh-key", username, f"key:{key_file}", "error", "paramiko library not installed - install with: pip install paramiko")

        key_path = Path(key_file)
        if not key_path.exists():
            return CredentialResult(ip, port, "ssh", "ssh-key", username, f"key:{key_file}", "error", f"SSH key file not found: {key_file}")

        # Validate key file is readable and not empty
        try:
            key_size = key_path.stat().st_size
            if key_size == 0:
                return CredentialResult(ip, port, "ssh", "ssh-key", username, f"key:{key_file}", "error", f"SSH key file is empty: {key_file}")
            logger.debug(f"    SSH key file: {key_file} ({key_size} bytes)")
        except OSError as e:
            return CredentialResult(ip, port, "ssh", "ssh-key", username, f"key:{key_file}", "error", f"Cannot read SSH key file: {str(e)}")

        if cert_file:
            cert_path = Path(cert_file)
            if not cert_path.exists():
                return CredentialResult(ip, port, "ssh", "ssh-cert", username, f"key:{key_file}+cert:{cert_file}", "error", f"SSH certificate file not found: {cert_file}")

        self.rate_limited_test()
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Try to load the private key (supports RSA, Ed25519, ECDSA)
        pkey = None
        key_type = "unknown"
        key_loaders = [
            ("RSA", paramiko.RSAKey.from_private_key_file),
            ("Ed25519", paramiko.Ed25519Key.from_private_key_file),
            ("ECDSA", paramiko.ECDSAKey.from_private_key_file),
        ]

        load_errors = []
        for ktype, loader in key_loaders:
            try:
                pkey = loader(key_file, password=key_passphrase)
                key_type = ktype
                logger.info(f"    {Fore.GREEN}→{Style.RESET_ALL} Loaded {Fore.CYAN}{ktype}{Style.RESET_ALL} key ({key_size} bytes)")
                break
            except paramiko.PasswordRequiredException:
                return CredentialResult(ip, port, "ssh", "ssh-key", username, f"key:{key_file}", "error", f"SSH key is encrypted - passphrase required for {ktype} key")
            except paramiko.SSHException as e:
                load_errors.append(f"{ktype}: {str(e)}")
                continue
            except Exception as e:
                load_errors.append(f"{ktype}: {str(e)}")
                continue

        if pkey is None:
            detail = "Could not load SSH key - unsupported key format or invalid file"
            if load_errors:
                detail += f". Tried: {'; '.join(load_errors)}"
            return CredentialResult(ip, port, "ssh", "ssh-key", username, f"key:{key_file}", "error", detail)

        # Load SSH certificate if provided (CA-signed cert for the key)
        auth_label = f"{key_type} key"
        cred_display = f"key:{key_file}"
        service_name = "ssh-key"
        if cert_file:
            try:
                pkey.load_certificate(cert_file)
                auth_label = f"{key_type} key + certificate"
                cred_display = f"key:{key_file}+cert:{cert_file}"
                service_name = "ssh-cert"
                logger.info(f"    {Fore.GREEN}→{Style.RESET_ALL} Loaded SSH certificate: {Fore.CYAN}{cert_file}{Style.RESET_ALL}")
            except Exception as e:
                return CredentialResult(ip, port, "ssh", "ssh-cert", username, f"key:{key_file}+cert:{cert_file}", "error", f"Failed to load SSH certificate: {str(e)}")

        try:
            logger.debug(f"    Connecting to {ip}:{port} as '{username}' with {auth_label}...")
            key_connect_kwargs = dict(
                hostname=ip, port=port, username=username, pkey=pkey,
                timeout=self.timeout, look_for_keys=False, allow_agent=False
            )
            if self.source_ip:
                try:
                    sock = socket.create_connection((ip, port), timeout=self.timeout, source_address=(self.source_ip, 0))
                    key_connect_kwargs['sock'] = sock
                except Exception:
                    pass  # Fall back to unbound connection
            client.connect(**key_connect_kwargs)
            # Verify we can actually execute a command
            exec_verified = False
            try:
                stdin, stdout, stderr = client.exec_command('id', timeout=5)
                output = stdout.read().decode('utf-8', errors='replace').strip()
                err_output = stderr.read().decode('utf-8', errors='replace').strip()
                exec_verified = True
                if output:
                    logger.info(f"    {Fore.GREEN}→{Style.RESET_ALL} Command execution verified: {Fore.WHITE}{output}{Style.RESET_ALL}")
            except Exception as exec_err:
                logger.debug(f"    Command execution check failed (shell may be restricted): {str(exec_err)}")

            client.close()
            success_detail = f"SSH authentication successful ({auth_label})"
            if exec_verified and output:
                success_detail += f" - {output}"
            else:
                success_detail += " - connection established"
            return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "success", success_detail)
        except paramiko.AuthenticationException as e:
            detail = f"SSH {auth_label} not accepted for user '{username}'"
            # Include the actual exception message for more context
            err_msg = str(e)
            if err_msg and err_msg != "Authentication failed.":
                detail += f" ({err_msg})"
            return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "failed", detail)
        except paramiko.BadHostKeyException as e:
            return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "error", f"SSH host key verification failed: {str(e)}")
        except paramiko.SSHException as e:
            error_str = str(e).lower()
            if 'not a valid ssh' in error_str or 'not ssh' in error_str:
                return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "error", f"Not an SSH service - wrong protocol detected: {str(e)}")
            elif 'connection reset' in error_str:
                return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "error", "SSH connection reset - service may have closed connection")
            elif 'no acceptable' in error_str or 'key type' in error_str:
                return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "failed", f"SSH server rejected key type ({key_type}): {str(e)}")
            elif 'publickey' in error_str:
                return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "failed", f"SSH publickey auth not accepted: {str(e)}")
            else:
                return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "error", f"SSH protocol error: {str(e)}")
        except socket.timeout:
            return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "error", f"SSH connection timeout - service not responding within {self.timeout}s")
        except ConnectionRefusedError:
            return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "error", f"Connection refused - SSH service not running on {ip}:{port}")
        except socket.gaierror as e:
            return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "error", f"DNS resolution failed - cannot resolve hostname: {str(e)}")
        except Exception as e:
            error_str = str(e).lower()
            if 'refused' in error_str:
                return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "error", "Connection refused - SSH service not available")
            elif 'timeout' in error_str:
                return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "error", "Connection timeout - SSH service not responding")
            else:
                return CredentialResult(ip, port, "ssh", service_name, username, cred_display, "error", f"SSH connection error: {str(e)}")
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
            ftp_kwargs = dict(timeout=self.timeout)
            if self.source_ip:
                ftp_kwargs['source_address'] = (self.source_ip, 0)
            ftp = FTP(**ftp_kwargs)
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
    """Test SMB authentication with password or NTLM hash (pass-the-hash)."""

    def test(self, ip: str, port: int, username: str, password: str, domain: str = "", nthash: str = "") -> CredentialResult:
        if not SMBConnection:
            return CredentialResult(ip, port, "smb", "smb", username, password, "error",
                                   "impacket library not installed - install with: pip install impacket")

        self.rate_limited_test()
        try:
            if self.source_ip:
                try:
                    sock = socket.create_connection((ip, port), timeout=self.timeout, source_address=(self.source_ip, 0))
                    from impacket.nmb import NetBIOSTCPSession
                    nbt = NetBIOSTCPSession(ip, ip, sess_port=port, timeout=self.timeout, sock=sock)
                    from impacket import smb as _impacket_smb
                    smb_internal = _impacket_smb.SMB(ip, ip, sess_port=port, timeout=self.timeout, session=nbt)
                    smb = SMBConnection(ip, ip, sess_port=port, timeout=self.timeout, existingConnection=smb_internal)
                except Exception:
                    # Fall back to standard connection if source binding fails
                    smb = SMBConnection(ip, ip, timeout=self.timeout)
            else:
                smb = SMBConnection(ip, ip, timeout=self.timeout)

            if nthash:
                # Pass-the-hash: parse LMHASH:NTHASH or just NTHASH
                lm_hash = ""
                nt_hash = nthash
                if ":" in nthash:
                    parts = nthash.split(":", 1)
                    lm_hash = parts[0]
                    nt_hash = parts[1]
                smb.login(username, '', domain=domain, lmhash=lm_hash, nthash=nt_hash)
                auth_method = "NTLM hash (Pass-the-Hash)"
                cred_display = nt_hash
            else:
                smb.login(username, password, domain=domain)
                auth_method = "password"
                cred_display = password

            # Enumerate shares
            shares = smb.listShares()
            share_names = []
            for s in shares:
                try:
                    name = s['shi1_netname'][:-1]  # Strip null terminator
                    share_names.append(name)
                except Exception:
                    pass

            smb.close()
            domain_info = f" (domain: {domain})" if domain else ""
            return CredentialResult(ip, port, "smb", "smb", username, cred_display, "success",
                                   f"SMB {auth_method} login OK{domain_info}, {len(share_names)} shares: {', '.join(share_names[:8])}")
        except Exception as e:
            error_msg = str(e).lower()
            if "status_logon_failure" in error_msg or "authentication" in error_msg or "logon_failure" in error_msg:
                return CredentialResult(ip, port, "smb", "smb", username, nthash or password, "failed",
                                       "SMB authentication failed - invalid credentials")
            elif "status_account_disabled" in error_msg:
                return CredentialResult(ip, port, "smb", "smb", username, nthash or password, "failed",
                                       "SMB account disabled")
            elif "status_account_locked_out" in error_msg:
                return CredentialResult(ip, port, "smb", "smb", username, nthash or password, "failed",
                                       "SMB account locked out")
            elif "refused" in error_msg:
                return CredentialResult(ip, port, "smb", "smb", username, nthash or password, "error",
                                       f"Connection refused - SMB not running on {ip}:{port}")
            elif "timeout" in error_msg or "timed out" in error_msg:
                return CredentialResult(ip, port, "smb", "smb", username, nthash or password, "error",
                                       f"SMB connection timeout within {self.timeout}s")
            return CredentialResult(ip, port, "smb", "smb", username, nthash or password, "error",
                                   f"SMB error: {str(e)}")

class MySQLTester(ProtocolTester):
    """Test MySQL authentication."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not pymysql:
            return CredentialResult(ip, port, "mysql", "mysql", username, password, "error", "pymysql library not installed - install with: pip install pymysql")

        self.rate_limited_test()
        try:
            connect_kwargs = dict(host=ip, port=port, user=username, password=password, connect_timeout=self.timeout)
            if self.source_ip:
                connect_kwargs['bind_address'] = self.source_ip
            conn = pymysql.connect(**connect_kwargs)
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
            pg_kwargs = dict(host=ip, port=port, user=username, password=password, connect_timeout=self.timeout)
            if self.source_ip:
                # psycopg2 supports tcp_user_timeout via options but not source_address directly.
                # Use a pre-bound socket via the keepalives_idle workaround is not possible.
                # Log a debug note; source binding is best-effort for PostgreSQL.
                logger.debug(f"Source IP binding ({self.source_ip}) not natively supported by psycopg2")
            conn = psycopg2.connect(**pg_kwargs)
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
            if self.source_ip:
                try:
                    sock.bind((self.source_ip, 0))
                except Exception:
                    pass  # Best-effort source binding
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
            if self.source_ip:
                try:
                    sock.bind((self.source_ip, 0))
                except Exception:
                    pass  # Best-effort source binding
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

class MSSQLTester(ProtocolTester):
    """Test Microsoft SQL Server authentication."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not pymssql:
            return CredentialResult(ip, port, "mssql", "mssql", username, password, "error", "pymssql library not installed - install with: pip install pymssql")

        self.rate_limited_test()
        if self.source_ip:
            logger.debug(f"Source IP binding ({self.source_ip}) not natively supported by pymssql")
        try:
            conn = pymssql.connect(
                server=ip,
                port=str(port),
                user=username,
                password=password,
                login_timeout=self.timeout,
                as_dict=True
            )
            # Verify we can actually query
            cursor = conn.cursor()
            cursor.execute("SELECT @@VERSION")
            version_row = cursor.fetchone()
            version = list(version_row.values())[0] if version_row else "Unknown"
            conn.close()

            # Truncate version for display
            version_short = version.split('\n')[0][:80] if version else "Unknown"
            return CredentialResult(ip, port, "mssql", "mssql", username, password, "success", f"MSSQL authentication successful - {version_short}")
        except Exception as e:
            error_msg = str(e).lower()
            if "login failed" in error_msg or "authentication" in error_msg:
                return CredentialResult(ip, port, "mssql", "mssql", username, password, "failed", "MSSQL authentication failed - invalid credentials")
            elif "connection refused" in error_msg or "cannot connect" in error_msg:
                return CredentialResult(ip, port, "mssql", "mssql", username, password, "error", f"MSSQL connection refused - service not running on {ip}:{port}")
            elif "timeout" in error_msg:
                return CredentialResult(ip, port, "mssql", "mssql", username, password, "error", f"MSSQL connection timeout - service not responding within {self.timeout}s")
            else:
                return CredentialResult(ip, port, "mssql", "mssql", username, password, "error", f"MSSQL error: {str(e)}")

class MongoDBTester(ProtocolTester):
    """Test MongoDB authentication."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not pymongo:
            return CredentialResult(ip, port, "mongodb", "mongodb", username, password, "error", "pymongo library not installed - install with: pip install pymongo")

        self.rate_limited_test()
        if self.source_ip:
            logger.debug(f"Source IP binding ({self.source_ip}) not natively supported by pymongo")
        try:
            # If no credentials provided, test for unauthenticated access
            if not username and not password:
                client = pymongo.MongoClient(
                    f"mongodb://{ip}:{port}/",
                    serverSelectionTimeoutMS=self.timeout * 1000,
                    connectTimeoutMS=self.timeout * 1000
                )
                # Try to run a command - this will fail if auth is required
                client.admin.command('ping')
                server_info = client.server_info()
                version = server_info.get('version', 'Unknown')
                client.close()
                return CredentialResult(ip, port, "mongodb", "mongodb", "", "", "success", f"MongoDB NO AUTHENTICATION REQUIRED - Version: {version}")

            # Test with credentials
            uri = f"mongodb://{username}:{password}@{ip}:{port}/?authSource=admin"
            client = pymongo.MongoClient(
                uri,
                serverSelectionTimeoutMS=self.timeout * 1000,
                connectTimeoutMS=self.timeout * 1000
            )
            client.admin.command('ping')
            server_info = client.server_info()
            version = server_info.get('version', 'Unknown')
            client.close()

            return CredentialResult(ip, port, "mongodb", "mongodb", username, password, "success", f"MongoDB authentication successful - Version: {version}")
        except pymongo.errors.OperationFailure as e:
            error_msg = str(e).lower()
            if "authentication failed" in error_msg or "auth" in error_msg:
                return CredentialResult(ip, port, "mongodb", "mongodb", username, password, "failed", "MongoDB authentication failed - invalid credentials")
            return CredentialResult(ip, port, "mongodb", "mongodb", username, password, "error", f"MongoDB error: {str(e)}")
        except pymongo.errors.ServerSelectionTimeoutError:
            return CredentialResult(ip, port, "mongodb", "mongodb", username, password, "error", f"MongoDB connection timeout - service not responding within {self.timeout}s")
        except pymongo.errors.ConnectionFailure as e:
            return CredentialResult(ip, port, "mongodb", "mongodb", username, password, "error", f"MongoDB connection failed - {str(e)}")
        except Exception as e:
            error_msg = str(e).lower()
            if "refused" in error_msg:
                return CredentialResult(ip, port, "mongodb", "mongodb", username, password, "error", f"MongoDB connection refused - service not running on {ip}:{port}")
            return CredentialResult(ip, port, "mongodb", "mongodb", username, password, "error", f"MongoDB error: {str(e)}")

class RedisTester(ProtocolTester):
    """Test Redis authentication."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not redis:
            return CredentialResult(ip, port, "redis", "redis", username, password, "error", "redis library not installed - install with: pip install redis")

        self.rate_limited_test()
        try:
            _redis_extra = {}
            if self.source_ip:
                _redis_extra['socket_bind_address'] = self.source_ip
            # Redis 6+ supports ACL with username/password, older versions only password
            if username:
                # Redis 6+ with ACL
                client = redis.Redis(
                    host=ip,
                    port=port,
                    username=username,
                    password=password,
                    socket_timeout=self.timeout,
                    socket_connect_timeout=self.timeout,
                    **_redis_extra
                )
            else:
                # Password only (pre-Redis 6 or default user)
                client = redis.Redis(
                    host=ip,
                    port=port,
                    password=password if password else None,
                    socket_timeout=self.timeout,
                    socket_connect_timeout=self.timeout,
                    **_redis_extra
                )

            # Test connection
            client.ping()

            # Try to get version
            try:
                info = client.info("server")
                version = info.get("redis_version", "Unknown")
            except:
                version = "Unknown"

            client.close()

            auth_type = "NO AUTHENTICATION REQUIRED" if not password else "authentication successful"
            return CredentialResult(ip, port, "redis", "redis", username or "", password or "", "success", f"Redis {auth_type} - Version: {version}")
        except redis.AuthenticationError:
            return CredentialResult(ip, port, "redis", "redis", username or "", password or "", "failed", "Redis authentication failed - invalid password")
        except redis.ResponseError as e:
            error_msg = str(e)
            if "NOAUTH" in error_msg or "Authentication required" in error_msg:
                return CredentialResult(ip, port, "redis", "redis", username or "", password or "", "failed", "Redis authentication required")
            elif "WRONGPASS" in error_msg:
                return CredentialResult(ip, port, "redis", "redis", username or "", password or "", "failed", "Redis authentication failed - invalid password")
            return CredentialResult(ip, port, "redis", "redis", username or "", password or "", "error", f"Redis error: {error_msg}")
        except redis.ConnectionError as e:
            error_msg = str(e).lower()
            if "refused" in error_msg:
                return CredentialResult(ip, port, "redis", "redis", username or "", password or "", "error", f"Redis connection refused - service not running on {ip}:{port}")
            elif "timeout" in error_msg:
                return CredentialResult(ip, port, "redis", "redis", username or "", password or "", "error", f"Redis connection timeout - service not responding within {self.timeout}s")
            return CredentialResult(ip, port, "redis", "redis", username or "", password or "", "error", f"Redis connection error: {str(e)}")
        except Exception as e:
            return CredentialResult(ip, port, "redis", "redis", username or "", password or "", "error", f"Redis error: {str(e)}")

class SNMPTester(ProtocolTester):
    """Test SNMP community strings."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        # SNMP uses 'password' field as community string
        community = password or "public"
        if self.source_ip:
            logger.debug(f"Source IP binding ({self.source_ip}) not natively supported by pysnmp hlapi")

        try:
            from pysnmp.hlapi import (
                getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity
            )
        except ImportError:
            return CredentialResult(ip, port, "snmp", "snmp", "", community, "error", "pysnmp library not installed - install with: pip install pysnmp")

        self.rate_limited_test()
        try:
            error_indication, error_status, error_index, var_binds = next(
                getCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=0),  # SNMPv1
                    UdpTransportTarget((ip, port), timeout=self.timeout, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
                )
            )

            if error_indication:
                # Timeout or no response - community string likely invalid
                return CredentialResult(ip, port, "snmp", "snmp", "", community, "failed", f"SNMP community string invalid or no response - {error_indication}")
            elif error_status:
                return CredentialResult(ip, port, "snmp", "snmp", "", community, "failed", f"SNMP error: {error_status.prettyPrint()}")
            else:
                sys_descr = str(var_binds[0][1]) if var_binds else "Unknown"
                sys_descr_short = sys_descr[:150] if sys_descr else "Unknown"
                return CredentialResult(ip, port, "snmp", "snmp", "", community, "success", f"SNMP community string valid - {sys_descr_short}")
        except Exception as e:
            return CredentialResult(ip, port, "snmp", "snmp", "", community, "error", f"SNMP error: {str(e)}")

class TelnetTester(ProtocolTester):
    """Test Telnet authentication."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        import telnetlib

        self.rate_limited_test()
        try:
            if self.source_ip:
                # Create a pre-bound socket for Telnet
                try:
                    _sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    _sock.settimeout(self.timeout)
                    _sock.bind((self.source_ip, 0))
                    _sock.connect((ip, port))
                    tn = telnetlib.Telnet()
                    tn.sock = _sock
                    tn.host = ip
                    tn.port = port
                    tn.timeout = self.timeout
                except Exception:
                    tn = telnetlib.Telnet(ip, port, timeout=self.timeout)
            else:
                tn = telnetlib.Telnet(ip, port, timeout=self.timeout)

            # Read until we get a login prompt (with timeout)
            try:
                index, match, data = tn.expect([b"login:", b"Login:", b"username:", b"Username:", b"User:"], timeout=5)
                if index == -1:
                    tn.close()
                    return CredentialResult(ip, port, "telnet", "telnet", username, password, "error", "No login prompt received")
            except EOFError:
                tn.close()
                return CredentialResult(ip, port, "telnet", "telnet", username, password, "error", "Connection closed before login prompt")

            # Send username
            tn.write(username.encode() + b"\n")

            # Wait for password prompt
            try:
                index, match, data = tn.expect([b"assword:", b"Password:", b"password:"], timeout=5)
                if index == -1:
                    tn.close()
                    return CredentialResult(ip, port, "telnet", "telnet", username, password, "error", "No password prompt received")
            except EOFError:
                tn.close()
                return CredentialResult(ip, port, "telnet", "telnet", username, password, "error", "Connection closed before password prompt")

            # Send password
            tn.write(password.encode() + b"\n")

            # Check result - look for shell prompt or failure message
            try:
                result = tn.read_until(b"\n", timeout=3)
                result += tn.read_very_eager()
            except EOFError:
                result = b""

            result_str = result.decode('utf-8', errors='ignore').lower()

            # Check for failure indicators
            failure_indicators = ["incorrect", "failed", "denied", "invalid", "authentication failure", "bad password", "login incorrect"]
            for indicator in failure_indicators:
                if indicator in result_str:
                    tn.close()
                    return CredentialResult(ip, port, "telnet", "telnet", username, password, "failed", "Telnet authentication failed - invalid credentials")

            # Check for success indicators (shell prompts)
            success_indicators = ["$", "#", ">", "~", "welcome", "last login"]
            for indicator in success_indicators:
                if indicator in result_str:
                    tn.close()
                    return CredentialResult(ip, port, "telnet", "telnet", username, password, "success", "Telnet authentication successful")

            # If we got here and connection is still open, likely success
            tn.close()
            return CredentialResult(ip, port, "telnet", "telnet", username, password, "success", "Telnet authentication successful (no clear failure)")

        except socket.timeout:
            return CredentialResult(ip, port, "telnet", "telnet", username, password, "error", f"Telnet connection timeout - service not responding within {self.timeout}s")
        except ConnectionRefusedError:
            return CredentialResult(ip, port, "telnet", "telnet", username, password, "error", f"Telnet connection refused - service not running on {ip}:{port}")
        except EOFError:
            return CredentialResult(ip, port, "telnet", "telnet", username, password, "error", "Telnet connection closed by host")
        except Exception as e:
            return CredentialResult(ip, port, "telnet", "telnet", username, password, "error", f"Telnet error: {str(e)}")


class LDAPTester(ProtocolTester):
    """Test LDAP/LDAPS authentication."""

    def test(self, ip: str, port: int, username: str, password: str, use_ssl: bool = False, domain: str = "") -> CredentialResult:
        if not ldap3:
            return CredentialResult(ip, port, "ldap", "ldap", username, password, "error", "ldap3 library not installed - install with: pip install ldap3")

        self.rate_limited_test()

        # Determine SSL usage based on port if not explicitly specified
        if port == 636:
            use_ssl = True

        protocol = "ldaps" if use_ssl else "ldap"

        try:
            # Create server connection
            server = Server(ip, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=self.timeout)
            _ldap_extra = {}
            if self.source_ip:
                _ldap_extra['source_address'] = self.source_ip

            # First, check if anonymous bind is allowed
            if not username and not password:
                try:
                    anon_conn = Connection(server, auto_bind=True, **_ldap_extra)
                    server_info = str(server.info) if server.info else "Unknown"
                    anon_conn.unbind()
                    return CredentialResult(ip, port, protocol, "ldap", "", "", "success", f"LDAP ANONYMOUS BIND ALLOWED - {server_info[:100]}")
                except Exception:
                    return CredentialResult(ip, port, protocol, "ldap", "", "", "failed", "LDAP anonymous bind not allowed")

            # Determine bind DN format
            # Try multiple formats: user@domain, domain\\user, cn=user, direct username
            bind_dns = []
            if domain:
                bind_dns.append(f"{username}@{domain}")  # UPN format
                bind_dns.append(f"{domain}\\{username}")  # NetBIOS format
            bind_dns.append(username)  # Direct username
            if '@' not in username and '\\' not in username and '=' not in username:
                bind_dns.append(f"cn={username}")  # Simple CN

            last_error = None
            for bind_dn in bind_dns:
                try:
                    # Try simple authentication first
                    conn = Connection(
                        server,
                        user=bind_dn,
                        password=password,
                        authentication=SIMPLE,
                        auto_bind=True,
                        raise_exceptions=True,
                        **_ldap_extra
                    )
                    # Get server info
                    server_info = str(server.info) if server.info else "Unknown"
                    conn.unbind()
                    return CredentialResult(ip, port, protocol, "ldap", username, password, "success", f"LDAP authentication successful (bind: {bind_dn}) - {server_info[:80]}")
                except ldap3.core.exceptions.LDAPInvalidCredentialsResult:
                    last_error = "Invalid credentials"
                    continue
                except ldap3.core.exceptions.LDAPBindError as e:
                    last_error = str(e)
                    continue
                except Exception as e:
                    last_error = str(e)
                    continue

            # If domain is specified, try NTLM authentication
            if domain and ldap3:
                try:
                    conn = Connection(
                        server,
                        user=f"{domain}\\{username}",
                        password=password,
                        authentication=NTLM,
                        auto_bind=True,
                        raise_exceptions=True,
                        **_ldap_extra
                    )
                    server_info = str(server.info) if server.info else "Unknown"
                    conn.unbind()
                    return CredentialResult(ip, port, protocol, "ldap", username, password, "success", f"LDAP NTLM authentication successful - {server_info[:80]}")
                except Exception as e:
                    last_error = str(e)

            return CredentialResult(ip, port, protocol, "ldap", username, password, "failed", f"LDAP authentication failed - {last_error}")

        except ldap3.core.exceptions.LDAPSocketOpenError as e:
            error_msg = str(e).lower()
            if "refused" in error_msg:
                return CredentialResult(ip, port, protocol, "ldap", username, password, "error", f"LDAP connection refused - service not running on {ip}:{port}")
            elif "timeout" in error_msg:
                return CredentialResult(ip, port, protocol, "ldap", username, password, "error", f"LDAP connection timeout - service not responding within {self.timeout}s")
            return CredentialResult(ip, port, protocol, "ldap", username, password, "error", f"LDAP connection error: {str(e)}")
        except Exception as e:
            return CredentialResult(ip, port, protocol, "ldap", username, password, "error", f"LDAP error: {str(e)}")


class WinRMTester(ProtocolTester):
    """Test WinRM authentication (ports 5985 HTTP, 5986 HTTPS)."""

    def test(self, ip: str, port: int, username: str, password: str, use_ssl: bool = False, domain: str = "", transport: str = "ntlm") -> CredentialResult:
        if not winrm:
            return CredentialResult(ip, port, "winrm", "winrm", username, password, "error", "pywinrm library not installed - install with: pip install pywinrm")

        self.rate_limited_test()

        # Determine SSL usage based on port if not explicitly specified
        if port == 5986:
            use_ssl = True

        protocol = "winrm-ssl" if use_ssl else "winrm"
        scheme = "https" if use_ssl else "http"

        # Build the endpoint URL
        endpoint = f"{scheme}://{ip}:{port}/wsman"

        # Format username with domain if provided
        if domain:
            full_username = f"{domain}\\{username}"
        else:
            full_username = username

        if self.source_ip:
            logger.debug(f"Source IP binding ({self.source_ip}) not natively supported by pywinrm")
        try:
            # Create WinRM session
            session = winrm.Session(
                target=endpoint,
                auth=(full_username, password),
                transport=transport,
                server_cert_validation='ignore' if use_ssl else 'validate',
                read_timeout_sec=self.timeout,
                operation_timeout_sec=self.timeout
            )

            # Try to run a simple command to verify authentication
            # Using 'whoami' as it's available on all Windows systems
            result = session.run_cmd('whoami')

            if result.status_code == 0:
                # Authentication successful
                whoami_output = result.std_out.decode('utf-8', errors='ignore').strip()
                return CredentialResult(ip, port, protocol, "winrm", username, password, "success", f"WinRM authentication successful - User: {whoami_output}")
            else:
                # Command executed but returned error (still means auth worked)
                stderr = result.std_err.decode('utf-8', errors='ignore').strip()[:100]
                return CredentialResult(ip, port, protocol, "winrm", username, password, "success", f"WinRM authentication successful (cmd error: {stderr})")

        except winrm.exceptions.InvalidCredentialsError:
            return CredentialResult(ip, port, protocol, "winrm", username, password, "failed", "WinRM authentication failed - invalid credentials")
        except winrm.exceptions.AuthenticationError as e:
            error_msg = str(e).lower()
            if "401" in error_msg or "unauthorized" in error_msg:
                return CredentialResult(ip, port, protocol, "winrm", username, password, "failed", "WinRM authentication failed - unauthorized")
            return CredentialResult(ip, port, protocol, "winrm", username, password, "error", f"WinRM authentication error: {str(e)}")
        except winrm.exceptions.WinRMTransportError as e:
            error_msg = str(e).lower()
            if "refused" in error_msg or "connection refused" in error_msg:
                return CredentialResult(ip, port, protocol, "winrm", username, password, "error", f"WinRM connection refused - service not running on {ip}:{port}")
            elif "timeout" in error_msg:
                return CredentialResult(ip, port, protocol, "winrm", username, password, "error", f"WinRM connection timeout - service not responding within {self.timeout}s")
            elif "ssl" in error_msg or "certificate" in error_msg:
                return CredentialResult(ip, port, protocol, "winrm", username, password, "error", f"WinRM SSL/TLS error: {str(e)}")
            return CredentialResult(ip, port, protocol, "winrm", username, password, "error", f"WinRM transport error: {str(e)}")
        except ConnectionRefusedError:
            return CredentialResult(ip, port, protocol, "winrm", username, password, "error", f"WinRM connection refused - service not running on {ip}:{port}")
        except TimeoutError:
            return CredentialResult(ip, port, protocol, "winrm", username, password, "error", f"WinRM connection timeout - service not responding within {self.timeout}s")
        except Exception as e:
            error_msg = str(e).lower()
            if "refused" in error_msg:
                return CredentialResult(ip, port, protocol, "winrm", username, password, "error", f"WinRM connection refused - service not available")
            elif "timeout" in error_msg:
                return CredentialResult(ip, port, protocol, "winrm", username, password, "error", f"WinRM connection timeout - service not responding")
            elif "401" in error_msg or "unauthorized" in error_msg:
                return CredentialResult(ip, port, protocol, "winrm", username, password, "failed", "WinRM authentication failed - invalid credentials")
            return CredentialResult(ip, port, protocol, "winrm", username, password, "error", f"WinRM error: {str(e)}")


class IPMITester(ProtocolTester):
    """Test IPMI/BMC authentication (port 623 UDP)."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not ipmi_command:
            return CredentialResult(ip, port, "ipmi", "ipmi", username, password, "error", "pyghmi library not installed - install with: pip install pyghmi")

        self.rate_limited_test()
        if self.source_ip:
            logger.debug(f"Source IP binding ({self.source_ip}) not natively supported by pyghmi")

        try:
            # Create IPMI command session
            # pyghmi uses IPMI over LAN (RMCP+)
            ipmi_session = ipmi_command.Command(
                bmc=ip,
                userid=username,
                password=password,
                port=port,
                onlogon=None
            )

            # Try to get BMC info to verify authentication
            try:
                device_id = ipmi_session.get_device_id()
                if device_id:
                    manufacturer = device_id.get('manufacturer', 'Unknown')
                    product = device_id.get('product_name', 'Unknown')
                    firmware = device_id.get('firmware_revision', 'Unknown')
                    ipmi_session.close_session()
                    return CredentialResult(
                        ip, port, "ipmi", "ipmi", username, password, "success",
                        f"IPMI authentication successful - {manufacturer} {product} (FW: {firmware})"
                    )
                else:
                    ipmi_session.close_session()
                    return CredentialResult(ip, port, "ipmi", "ipmi", username, password, "success", "IPMI authentication successful")
            except Exception as e:
                try:
                    ipmi_session.close_session()
                except:
                    pass
                raise e

        except Exception as e:
            error_msg = str(e).lower()
            if "unauthorized" in error_msg or "authentication" in error_msg or "invalid" in error_msg:
                return CredentialResult(ip, port, "ipmi", "ipmi", username, password, "failed", "IPMI authentication failed - invalid credentials")
            elif "timeout" in error_msg or "no response" in error_msg:
                return CredentialResult(ip, port, "ipmi", "ipmi", username, password, "error", f"IPMI connection timeout - BMC not responding on {ip}:{port}")
            elif "refused" in error_msg:
                return CredentialResult(ip, port, "ipmi", "ipmi", username, password, "error", f"IPMI connection refused - service not running on {ip}:{port}")
            else:
                return CredentialResult(ip, port, "ipmi", "ipmi", username, password, "error", f"IPMI error: {str(e)}")


class MQTTTester(ProtocolTester):
    """Test MQTT broker authentication."""

    def test(self, ip: str, port: int, username: str, password: str, use_tls: bool = False) -> CredentialResult:
        if not mqtt:
            return CredentialResult(ip, port, "mqtt", "mqtt", username, password, "error", "paho-mqtt library not installed - install with: pip install paho-mqtt")

        self.rate_limited_test()

        # Determine TLS based on port
        if port == 8883:
            use_tls = True

        protocol = "mqtts" if use_tls else "mqtt"

        # Result container for callback
        result_container = {"connected": False, "error": None, "reason_code": None}
        connection_event = threading.Event()

        def on_connect(client, userdata, flags, reason_code, properties=None):
            """Callback for when connection is established."""
            result_container["connected"] = True
            result_container["reason_code"] = reason_code
            connection_event.set()

        def on_connect_fail(client, userdata):
            """Callback for connection failure."""
            result_container["connected"] = False
            result_container["error"] = "Connection failed"
            connection_event.set()

        try:
            # Create MQTT client (v5 protocol for better error handling)
            client = mqtt.Client(
                callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
                protocol=mqtt.MQTTv5
            )

            client.on_connect = on_connect

            # Set credentials if provided
            if username or password:
                client.username_pw_set(username, password if password else None)

            # Configure TLS if needed
            if use_tls:
                import ssl
                client.tls_set(cert_reqs=ssl.CERT_NONE)
                client.tls_insecure_set(True)

            # Attempt connection
            try:
                _mqtt_kwargs = dict(host=ip, port=port, keepalive=self.timeout)
                if self.source_ip:
                    _mqtt_kwargs['bind_address'] = self.source_ip
                client.connect(**_mqtt_kwargs)
            except Exception as e:
                error_str = str(e).lower()
                if "refused" in error_str:
                    return CredentialResult(ip, port, protocol, "mqtt", username or "", password or "", "error", f"MQTT connection refused - broker not running on {ip}:{port}")
                elif "timeout" in error_str or "timed out" in error_str:
                    return CredentialResult(ip, port, protocol, "mqtt", username or "", password or "", "error", f"MQTT connection timeout - broker not responding within {self.timeout}s")
                raise e

            # Start network loop and wait for connection result
            client.loop_start()
            connection_event.wait(timeout=self.timeout)
            client.loop_stop()

            if result_container["connected"]:
                reason = result_container["reason_code"]
                # MQTT v5 reason codes: 0 = Success
                if hasattr(reason, 'value'):
                    reason_value = reason.value
                else:
                    reason_value = int(reason) if reason else 0

                if reason_value == 0:
                    client.disconnect()
                    auth_type = "NO AUTHENTICATION REQUIRED" if not username and not password else "authentication successful"
                    return CredentialResult(ip, port, protocol, "mqtt", username or "", password or "", "success", f"MQTT {auth_type}")
                elif reason_value == 134:  # Bad username/password
                    client.disconnect()
                    return CredentialResult(ip, port, protocol, "mqtt", username or "", password or "", "failed", "MQTT authentication failed - invalid credentials")
                elif reason_value == 135:  # Not authorized
                    client.disconnect()
                    return CredentialResult(ip, port, protocol, "mqtt", username or "", password or "", "failed", "MQTT not authorized")
                else:
                    client.disconnect()
                    return CredentialResult(ip, port, protocol, "mqtt", username or "", password or "", "failed", f"MQTT connection failed (reason code: {reason_value})")
            else:
                error = result_container.get("error", "Connection timeout")
                return CredentialResult(ip, port, protocol, "mqtt", username or "", password or "", "error", f"MQTT error: {error}")

        except Exception as e:
            error_msg = str(e).lower()
            if "authentication" in error_msg or "not authorized" in error_msg:
                return CredentialResult(ip, port, protocol, "mqtt", username or "", password or "", "failed", "MQTT authentication failed")
            return CredentialResult(ip, port, protocol, "mqtt", username or "", password or "", "error", f"MQTT error: {str(e)}")


# ----------------------------------------------------------------------
# Email Protocol Testers (SMTP, IMAP, POP3)
# ----------------------------------------------------------------------

class SMTPTester(ProtocolTester):
    """Test SMTP authentication."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        import smtplib
        self.rate_limited_test()

        proto_name = "smtps" if port == 465 else "smtp"

        try:
            _smtp_src = (self.source_ip, 0) if self.source_ip else None
            if port == 465:
                server = smtplib.SMTP_SSL(ip, port, timeout=self.timeout, source_address=_smtp_src)
            else:
                server = smtplib.SMTP(ip, port, timeout=self.timeout, source_address=_smtp_src)

            # Grab banner
            banner = ""
            try:
                server.ehlo()
                if server.ehlo_resp:
                    banner = server.ehlo_resp.decode('utf-8', errors='ignore')[:200]
            except Exception:
                pass

            # Try STARTTLS on submission port
            if port == 587:
                try:
                    server.starttls()
                    server.ehlo()
                except smtplib.SMTPNotSupportedError:
                    pass
                except Exception:
                    pass

            # Attempt authentication
            try:
                server.login(username, password)
                server.quit()
                return CredentialResult(ip, port, proto_name, "smtp", username, password, "success",
                                       f"SMTP AUTH successful. Banner: {banner[:100]}")
            except smtplib.SMTPAuthenticationError:
                try:
                    server.quit()
                except Exception:
                    pass
                return CredentialResult(ip, port, proto_name, "smtp", username, password, "failed",
                                       "SMTP authentication failed - invalid credentials")
            except smtplib.SMTPNotSupportedError:
                # No AUTH mechanism — check for open relay
                try:
                    code, _msg = server.mail("test@test.com")
                    if code == 250:
                        server.rset()
                        server.quit()
                        return CredentialResult(ip, port, proto_name, "smtp", "", "", "success",
                                               f"SMTP OPEN RELAY detected (no auth required). Banner: {banner[:100]}")
                except Exception:
                    pass
                try:
                    server.quit()
                except Exception:
                    pass
                return CredentialResult(ip, port, proto_name, "smtp", username, password, "error",
                                       f"SMTP AUTH not supported by server. Banner: {banner[:100]}")
        except socket.timeout:
            return CredentialResult(ip, port, proto_name, "smtp", username, password, "error",
                                   f"SMTP connection timeout - service not responding within {self.timeout}s")
        except ConnectionRefusedError:
            return CredentialResult(ip, port, proto_name, "smtp", username, password, "error",
                                   f"Connection refused - SMTP service not running on {ip}:{port}")
        except Exception as e:
            return CredentialResult(ip, port, proto_name, "smtp", username, password, "error",
                                   f"SMTP error: {str(e)}")


class IMAPTester(ProtocolTester):
    """Test IMAP authentication."""

    def test(self, ip: str, port: int, username: str, password: str, use_ssl: bool = False) -> CredentialResult:
        import imaplib
        self.rate_limited_test()

        if port == 993:
            use_ssl = True
        proto_name = "imaps" if use_ssl else "imap"

        try:
            if use_ssl:
                server = imaplib.IMAP4_SSL(ip, port, timeout=self.timeout)
            else:
                server = imaplib.IMAP4(ip, port, timeout=self.timeout)
            if self.source_ip:
                logger.debug(f"Source IP binding ({self.source_ip}) not natively supported by imaplib")

            # Grab welcome
            welcome = getattr(server, 'welcome', b'').decode('utf-8', errors='ignore')[:150] if hasattr(server, 'welcome') else ""

            try:
                status, _data = server.login(username, password)
                server.logout()
                return CredentialResult(ip, port, proto_name, "imap", username, password, "success",
                                       f"IMAP login successful ({status}). {welcome}")
            except imaplib.IMAP4.error as e:
                try:
                    server.logout()
                except Exception:
                    pass
                error_str = str(e)
                if "AUTHENTICATIONFAILED" in error_str.upper() or "LOGIN" in error_str.upper() or "INVALID" in error_str.upper():
                    return CredentialResult(ip, port, proto_name, "imap", username, password, "failed",
                                           "IMAP authentication failed - invalid credentials")
                return CredentialResult(ip, port, proto_name, "imap", username, password, "error",
                                       f"IMAP error: {error_str}")
        except socket.timeout:
            return CredentialResult(ip, port, proto_name, "imap", username, password, "error",
                                   f"IMAP connection timeout - service not responding within {self.timeout}s")
        except ConnectionRefusedError:
            return CredentialResult(ip, port, proto_name, "imap", username, password, "error",
                                   f"Connection refused - IMAP service not running on {ip}:{port}")
        except Exception as e:
            return CredentialResult(ip, port, proto_name, "imap", username, password, "error",
                                   f"IMAP error: {str(e)}")


class POP3Tester(ProtocolTester):
    """Test POP3 authentication."""

    def test(self, ip: str, port: int, username: str, password: str, use_ssl: bool = False) -> CredentialResult:
        import poplib
        self.rate_limited_test()

        if port == 995:
            use_ssl = True
        proto_name = "pop3s" if use_ssl else "pop3"

        if self.source_ip:
            logger.debug(f"Source IP binding ({self.source_ip}) not natively supported by poplib")
        try:
            if use_ssl:
                server = poplib.POP3_SSL(ip, port, timeout=self.timeout)
            else:
                server = poplib.POP3(ip, port, timeout=self.timeout)

            welcome = server.getwelcome().decode('utf-8', errors='ignore')[:150] if server.getwelcome() else ""

            try:
                server.user(username)
                resp = server.pass_(password)
                server.quit()
                return CredentialResult(ip, port, proto_name, "pop3", username, password, "success",
                                       f"POP3 login successful. {welcome}")
            except poplib.error_proto as e:
                try:
                    server.quit()
                except Exception:
                    pass
                error_str = str(e)
                if "authentication" in error_str.lower() or "login" in error_str.lower() or "denied" in error_str.lower() or "-ERR" in error_str:
                    return CredentialResult(ip, port, proto_name, "pop3", username, password, "failed",
                                           "POP3 authentication failed - invalid credentials")
                return CredentialResult(ip, port, proto_name, "pop3", username, password, "error",
                                       f"POP3 error: {error_str}")
        except socket.timeout:
            return CredentialResult(ip, port, proto_name, "pop3", username, password, "error",
                                   f"POP3 connection timeout - service not responding within {self.timeout}s")
        except ConnectionRefusedError:
            return CredentialResult(ip, port, proto_name, "pop3", username, password, "error",
                                   f"Connection refused - POP3 service not running on {ip}:{port}")
        except Exception as e:
            return CredentialResult(ip, port, proto_name, "pop3", username, password, "error",
                                   f"POP3 error: {str(e)}")


# ----------------------------------------------------------------------
# REST API Testers (Elasticsearch, CouchDB, InfluxDB)
# ----------------------------------------------------------------------

class ElasticsearchTester(ProtocolTester):
    """Test Elasticsearch authentication via REST API."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not requests:
            return CredentialResult(ip, port, "elasticsearch", "elasticsearch", username, password,
                                   "error", "requests library not installed")
        self.rate_limited_test()
        url = f"http://{ip}:{port}/_cluster/health"
        try:
            # Test with credentials (or without for no-auth detection)
            auth = HTTPBasicAuth(username, password) if (username or password) else None
            _session = self._get_requests_session()
            _get = _session.get if _session else requests.get
            resp = _get(url, auth=auth, timeout=self.timeout, verify=False)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    cluster_name = data.get("cluster_name", "unknown")
                    status = data.get("status", "unknown")
                    nodes = data.get("number_of_nodes", "?")
                except Exception:
                    cluster_name, status, nodes = "unknown", "unknown", "?"
                auth_type = "NO AUTH REQUIRED" if not auth else "auth successful"
                return CredentialResult(ip, port, "elasticsearch", "elasticsearch", username or "", password or "",
                                       "success", f"Elasticsearch {auth_type} - Cluster: {cluster_name}, Status: {status}, Nodes: {nodes}")
            elif resp.status_code == 401:
                return CredentialResult(ip, port, "elasticsearch", "elasticsearch", username, password,
                                       "failed", "Elasticsearch authentication failed (401)")
            elif resp.status_code == 403:
                return CredentialResult(ip, port, "elasticsearch", "elasticsearch", username, password,
                                       "failed", "Elasticsearch access forbidden (403)")
            else:
                return CredentialResult(ip, port, "elasticsearch", "elasticsearch", username, password,
                                       "error", f"Elasticsearch HTTP {resp.status_code}")
        except requests.exceptions.ConnectTimeout:
            return CredentialResult(ip, port, "elasticsearch", "elasticsearch", username, password,
                                   "error", f"Connection timeout within {self.timeout}s")
        except requests.exceptions.ConnectionError:
            return CredentialResult(ip, port, "elasticsearch", "elasticsearch", username, password,
                                   "error", f"Connection refused - service not running on {ip}:{port}")
        except Exception as e:
            return CredentialResult(ip, port, "elasticsearch", "elasticsearch", username, password,
                                   "error", f"Elasticsearch error: {str(e)}")


class CouchDBTester(ProtocolTester):
    """Test CouchDB authentication via REST API."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not requests:
            return CredentialResult(ip, port, "couchdb", "couchdb", username, password,
                                   "error", "requests library not installed")
        self.rate_limited_test()
        try:
            # Check root URL for admin party detection
            auth = HTTPBasicAuth(username, password) if (username or password) else None
            _session = self._get_requests_session()
            _get = _session.get if _session else requests.get
            resp = _get(f"http://{ip}:{port}/_session", auth=auth,
                              timeout=self.timeout, verify=False)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    user_ctx = data.get("userCtx", {})
                    roles = user_ctx.get("roles", [])
                    ctx_name = user_ctx.get("name")
                except Exception:
                    roles, ctx_name = [], None
                auth_type = "ADMIN PARTY (no auth)" if not auth and "_admin" in roles else "auth successful"
                return CredentialResult(ip, port, "couchdb", "couchdb", username or "", password or "",
                                       "success", f"CouchDB {auth_type} - User: {ctx_name}, Roles: {roles}")
            elif resp.status_code == 401:
                return CredentialResult(ip, port, "couchdb", "couchdb", username, password,
                                       "failed", "CouchDB authentication failed (401)")
            else:
                return CredentialResult(ip, port, "couchdb", "couchdb", username, password,
                                       "error", f"CouchDB HTTP {resp.status_code}")
        except requests.exceptions.ConnectTimeout:
            return CredentialResult(ip, port, "couchdb", "couchdb", username, password,
                                   "error", f"Connection timeout within {self.timeout}s")
        except requests.exceptions.ConnectionError:
            return CredentialResult(ip, port, "couchdb", "couchdb", username, password,
                                   "error", f"Connection refused - service not running on {ip}:{port}")
        except Exception as e:
            return CredentialResult(ip, port, "couchdb", "couchdb", username, password,
                                   "error", f"CouchDB error: {str(e)}")


class InfluxDBTester(ProtocolTester):
    """Test InfluxDB authentication via REST API."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not requests:
            return CredentialResult(ip, port, "influxdb", "influxdb", username, password,
                                   "error", "requests library not installed")
        self.rate_limited_test()
        try:
            # Try query endpoint with auth
            auth = HTTPBasicAuth(username, password) if (username or password) else None
            _session = self._get_requests_session()
            _get = _session.get if _session else requests.get
            resp = _get(f"http://{ip}:{port}/query",
                              params={"q": "SHOW DATABASES"},
                              auth=auth, timeout=self.timeout, verify=False)

            if resp.status_code == 200:
                try:
                    data = resp.json()
                    results_data = data.get("results", [{}])
                    db_count = len(results_data[0].get("series", [{}])[0].get("values", [])) if results_data else 0
                except Exception:
                    db_count = "?"
                auth_type = "NO AUTH REQUIRED" if not auth else "auth successful"
                return CredentialResult(ip, port, "influxdb", "influxdb", username or "", password or "",
                                       "success", f"InfluxDB {auth_type} - {db_count} databases")
            elif resp.status_code == 401:
                return CredentialResult(ip, port, "influxdb", "influxdb", username, password,
                                       "failed", "InfluxDB authentication failed (401)")
            elif resp.status_code == 403:
                return CredentialResult(ip, port, "influxdb", "influxdb", username, password,
                                       "failed", "InfluxDB access forbidden (403)")
            else:
                return CredentialResult(ip, port, "influxdb", "influxdb", username, password,
                                       "error", f"InfluxDB HTTP {resp.status_code}")
        except requests.exceptions.ConnectTimeout:
            return CredentialResult(ip, port, "influxdb", "influxdb", username, password,
                                   "error", f"Connection timeout within {self.timeout}s")
        except requests.exceptions.ConnectionError:
            return CredentialResult(ip, port, "influxdb", "influxdb", username, password,
                                   "error", f"Connection refused - service not running on {ip}:{port}")
        except Exception as e:
            return CredentialResult(ip, port, "influxdb", "influxdb", username, password,
                                   "error", f"InfluxDB error: {str(e)}")


# ----------------------------------------------------------------------
# Database/Socket Testers (Cassandra, Neo4j, Memcached)
# ----------------------------------------------------------------------

class CassandraTester(ProtocolTester):
    """Test Cassandra authentication."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        if not CassandraCluster:
            return CredentialResult(ip, port, "cassandra", "cassandra", username, password,
                                   "error", "cassandra-driver library not installed - install with: pip install cassandra-driver")
        self.rate_limited_test()
        if self.source_ip:
            logger.debug(f"Source IP binding ({self.source_ip}) not natively supported by cassandra-driver")
        cluster = None
        try:
            if username or password:
                auth = CassandraAuth(username=username or "", password=password or "")
                cluster = CassandraCluster([ip], port=port, auth_provider=auth,
                                           connect_timeout=self.timeout)
            else:
                cluster = CassandraCluster([ip], port=port, connect_timeout=self.timeout)

            session = cluster.connect()
            # Get version
            try:
                row = session.execute("SELECT release_version FROM system.local").one()
                version = row.release_version if row else "Unknown"
            except Exception:
                version = "Unknown"
            cluster.shutdown()

            auth_type = "NO AUTH REQUIRED" if not username else "auth successful"
            return CredentialResult(ip, port, "cassandra", "cassandra", username or "", password or "",
                                   "success", f"Cassandra {auth_type} - Version: {version}")
        except Exception as e:
            if cluster:
                try:
                    cluster.shutdown()
                except Exception:
                    pass
            error_msg = str(e).lower()
            if "authentication" in error_msg or "credentials" in error_msg or "unauthorized" in error_msg:
                return CredentialResult(ip, port, "cassandra", "cassandra", username, password,
                                       "failed", "Cassandra authentication failed - invalid credentials")
            elif "refused" in error_msg:
                return CredentialResult(ip, port, "cassandra", "cassandra", username, password,
                                       "error", f"Connection refused - Cassandra not running on {ip}:{port}")
            elif "timeout" in error_msg or "timed out" in error_msg:
                return CredentialResult(ip, port, "cassandra", "cassandra", username, password,
                                       "error", f"Cassandra connection timeout within {self.timeout}s")
            return CredentialResult(ip, port, "cassandra", "cassandra", username, password,
                                   "error", f"Cassandra error: {str(e)}")


class Neo4jTester(ProtocolTester):
    """Test Neo4j authentication via HTTP REST API or Bolt protocol."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        self.rate_limited_test()

        # Try HTTP REST API first (port 7474) - no extra dependency
        if requests:
            http_port = port if port == 7474 else 7474
            try:
                auth = HTTPBasicAuth(username, password) if (username or password) else None
                _session = self._get_requests_session()
                _get = _session.get if _session else requests.get
                resp = _get(f"http://{ip}:{http_port}/", auth=auth,
                                  timeout=self.timeout, verify=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        neo4j_version = data.get("neo4j_version", "Unknown")
                    except Exception:
                        neo4j_version = "Unknown"
                    auth_type = "NO AUTH REQUIRED" if not auth else "auth successful"
                    return CredentialResult(ip, port, "neo4j", "neo4j", username or "", password or "",
                                           "success", f"Neo4j {auth_type} - Version: {neo4j_version}")
                elif resp.status_code == 401:
                    return CredentialResult(ip, port, "neo4j", "neo4j", username, password,
                                           "failed", "Neo4j authentication failed (401)")
                elif resp.status_code == 403:
                    return CredentialResult(ip, port, "neo4j", "neo4j", username, password,
                                           "failed", "Neo4j access forbidden (403)")
            except requests.exceptions.ConnectionError:
                pass  # Fall through to bolt if HTTP port didn't work
            except Exception:
                pass

        # Try Bolt protocol (port 7687) if neo4j driver available
        if Neo4jDriver and port == 7687:
            try:
                driver = Neo4jDriver.driver(f"bolt://{ip}:{port}", auth=(username, password),
                                            connection_timeout=self.timeout)
                driver.verify_connectivity()
                info = driver.get_server_info()
                version = getattr(info, 'agent', 'Unknown')
                driver.close()
                return CredentialResult(ip, port, "neo4j", "neo4j-bolt", username, password,
                                       "success", f"Neo4j Bolt auth successful - {version}")
            except Exception as e:
                error_msg = str(e).lower()
                if "authentication" in error_msg or "unauthorized" in error_msg:
                    return CredentialResult(ip, port, "neo4j", "neo4j-bolt", username, password,
                                           "failed", "Neo4j Bolt authentication failed")
                return CredentialResult(ip, port, "neo4j", "neo4j-bolt", username, password,
                                       "error", f"Neo4j Bolt error: {str(e)}")

        if not requests and not Neo4jDriver:
            return CredentialResult(ip, port, "neo4j", "neo4j", username, password,
                                   "error", "Neither requests nor neo4j driver available")

        return CredentialResult(ip, port, "neo4j", "neo4j", username, password,
                               "error", f"Could not connect to Neo4j on {ip}:{port}")


class MemcachedTester(ProtocolTester):
    """Test Memcached access (typically unauthenticated)."""

    def test(self, ip: str, port: int, username: str, password: str) -> CredentialResult:
        self.rate_limited_test()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            if self.source_ip:
                try:
                    sock.bind((self.source_ip, 0))
                except Exception:
                    pass  # Best-effort source binding
            sock.connect((ip, port))
            sock.send(b"stats\r\n")
            response = sock.recv(4096).decode('utf-8', errors='ignore')
            sock.close()

            if "STAT" in response:
                # Extract version from stats
                version = "unknown"
                for line in response.split('\r\n'):
                    if line.startswith("STAT version"):
                        parts = line.split()
                        if len(parts) >= 3:
                            version = parts[2]
                        break
                return CredentialResult(ip, port, "memcached", "memcached", "", "",
                                       "success", f"Memcached NO AUTH - open access detected, Version: {version}")
            elif "ERROR" in response:
                return CredentialResult(ip, port, "memcached", "memcached", "", "",
                                       "error", "Memcached returned ERROR - may require SASL auth")
            else:
                return CredentialResult(ip, port, "memcached", "memcached", "", "",
                                       "error", "Not a memcached service or unexpected response")
        except socket.timeout:
            return CredentialResult(ip, port, "memcached", "memcached", "", "",
                                   "error", f"Memcached connection timeout within {self.timeout}s")
        except ConnectionRefusedError:
            return CredentialResult(ip, port, "memcached", "memcached", "", "",
                                   "error", f"Connection refused - Memcached not running on {ip}:{port}")
        except Exception as e:
            return CredentialResult(ip, port, "memcached", "memcached", "", "",
                                   "error", f"Memcached error: {str(e)}")


# ----------------------------------------------------------------------
# Connection validation helpers
# ----------------------------------------------------------------------
def validate_connection(ip: str, port: int, timeout: int = 5, source_ip: str = None) -> Tuple[bool, str]:
    """
    Validate that a connection can be established to the target.
    Returns: (is_connected, error_message)
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if source_ip:
            sock.bind((source_ip, 0))
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

# Comprehensive port-to-protocol mapping
PORT_PROTOCOL_MAP = {
    # FTP
    21: "ftp",

    # SSH
    22: "ssh",
    2222: "ssh",  # Common alternative SSH port

    # Telnet
    23: "telnet",

    # SMTP
    25: "smtp",
    465: "smtps",    # SMTP over SSL
    587: "smtp",     # SMTP Submission

    # DNS (for reference)
    53: "dns",

    # HTTP/HTTPS
    80: "http",
    443: "https",
    8000: "http",
    8008: "http",
    8080: "http",
    8081: "http",
    8443: "https",
    8888: "http",
    9000: "http",
    9090: "http",  # Prometheus, Cockpit
    9443: "https",

    # POP3/IMAP
    110: "pop3",
    143: "imap",
    993: "imaps",
    995: "pop3s",

    # SNMP
    161: "snmp",
    162: "snmp",  # SNMP trap

    # LDAP
    389: "ldap",
    636: "ldaps",
    3268: "ldap",   # Global Catalog
    3269: "ldaps",  # Global Catalog SSL

    # SMB/NetBIOS
    139: "smb",
    445: "smb",

    # WinRM (Windows Remote Management)
    5985: "winrm",    # WinRM HTTP
    5986: "winrm-ssl",  # WinRM HTTPS

    # IPMI
    623: "ipmi",

    # MQTT
    1883: "mqtt",
    8883: "mqtts",

    # Databases
    1433: "mssql",
    1434: "mssql",   # MSSQL Browser
    1521: "oracle",  # Oracle
    3306: "mysql",
    5432: "postgres",
    5433: "postgres",
    6379: "redis",
    6380: "redis",
    11211: "memcached",
    27017: "mongodb",
    27018: "mongodb",
    28017: "mongodb",  # MongoDB HTTP interface
    5984: "couchdb",
    9200: "elasticsearch",
    9300: "elasticsearch",
    8086: "influxdb",
    9042: "cassandra",
    7000: "cassandra",
    7199: "cassandra",  # JMX
    7474: "neo4j",      # Neo4j HTTP
    7687: "neo4j",      # Neo4j Bolt

    # RDP/VNC
    3389: "rdp",
    5800: "vnc",
    5900: "vnc",
    5901: "vnc",
    5902: "vnc",
    5903: "vnc",
    5904: "vnc",
    5905: "vnc",

    # Message Queues
    5672: "amqp",      # RabbitMQ
    15672: "http",     # RabbitMQ Management
    61613: "stomp",    # ActiveMQ STOMP
    61616: "activemq", # ActiveMQ OpenWire
    9092: "kafka",
    2181: "zookeeper",

    # Container/Orchestration
    2375: "docker",    # Docker API (unencrypted)
    2376: "docker",    # Docker API (TLS)
    6443: "https",     # Kubernetes API
    10250: "https",    # Kubelet API

    # CI/CD & DevOps
    8081: "http",      # Nexus
    9000: "http",      # SonarQube, Portainer
    50000: "http",     # Jenkins agent

    # Network Equipment
    830: "netconf",    # NETCONF SSH
    8291: "winbox",    # MikroTik Winbox

    # Miscellaneous
    111: "rpcbind",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    873: "rsync",
    1099: "rmi",       # Java RMI
    2049: "nfs",
    4786: "cisco-smart-install",
    8009: "ajp",       # Apache JServ
    8161: "http",      # ActiveMQ Web Console
    9001: "http",      # Various web UIs
    10000: "http",     # Webmin
    50070: "http",     # Hadoop NameNode
}


def detect_protocol(port: int) -> str:
    """Detect protocol based on common port numbers."""
    return PORT_PROTOCOL_MAP.get(port, "unknown")


def get_default_port(service: str) -> Optional[int]:
    """Return the default port for a known service, or None."""
    defaults = {
        "ssh": 22, "ftp": 21, "http": 80, "https": 443,
        "smb": 445, "rdp": 3389, "vnc": 5900, "telnet": 23,
        "mysql": 3306, "postgres": 5432, "mssql": 1433,
        "mongodb": 27017, "redis": 6379, "elasticsearch": 9200,
        "couchdb": 5984, "influxdb": 8086, "cassandra": 9042,
        "neo4j": 7687, "memcached": 11211,
        "smtp": 25, "smtps": 465, "imap": 143, "imaps": 993,
        "pop3": 110, "pop3s": 995,
        "ldap": 389, "ldaps": 636,
        "snmp": 161, "ipmi": 623,
        "mqtt": 1883, "mqtts": 8883,
        "winrm": 5985, "winrm-ssl": 5986,
    }
    return defaults.get(service.lower())


def detect_protocol_with_probe(host: str, port: int, timeout: float = 5.0, verbose: bool = True) -> tuple:
    """
    Detect protocol using actual service probing.

    Returns:
        tuple: (protocol, confidence, service_info)
            - protocol: Detected protocol name
            - confidence: Confidence level (0.0-1.0)
            - service_info: Dict with additional service details (vendor, product, version, etc.)
    """
    from cygor.credrecon.validation import (
        PORT_PROBE_MAP, PROTOCOL_PROBE_MAP, ServiceFingerprint
    )

    # First, try port-based detection with probing
    if port in PORT_PROBE_MAP:
        expected_protocol, probe_func = PORT_PROBE_MAP[port]

        if verbose:
            logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Probing {host}:{port} for {expected_protocol.upper()}...")

        try:
            fingerprint = probe_func(host, port, timeout)

            if fingerprint and fingerprint.confidence >= 0.5:
                service_info = {
                    "vendor": fingerprint.vendor,
                    "product": fingerprint.product,
                    "version": fingerprint.version,
                    "os_hint": fingerprint.os_hint,
                    "features": fingerprint.features or [],
                    "detection_method": fingerprint.detection_method,
                    "banner": fingerprint.raw_banner,
                }

                if verbose:
                    # Build info string
                    info_parts = []
                    if fingerprint.product:
                        info_parts.append(fingerprint.product)
                    if fingerprint.version:
                        info_parts.append(f"v{fingerprint.version}")
                    if fingerprint.vendor:
                        info_parts.append(f"({fingerprint.vendor})")

                    info_str = " ".join(info_parts) if info_parts else expected_protocol.upper()
                    confidence_color = Fore.GREEN if fingerprint.confidence >= 0.8 else Fore.YELLOW
                    logger.info(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Service confirmed: {Fore.WHITE}{info_str}{Style.RESET_ALL} [{confidence_color}{fingerprint.confidence*100:.0f}% confidence{Style.RESET_ALL}]")

                return (fingerprint.service or expected_protocol, fingerprint.confidence, service_info)

            # Probe returned low confidence - service might be different
            if verbose:
                logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Service probe inconclusive for port {port}")

        except Exception as e:
            if verbose:
                logger.debug(f"Probe error for {host}:{port}: {e}")

    # Fall back to port-based guess
    guessed_protocol = PORT_PROTOCOL_MAP.get(port, "unknown")

    if guessed_protocol != "unknown":
        if verbose:
            logger.info(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Using port-based guess: {guessed_protocol.upper()} (no probe confirmation)")
        return (guessed_protocol, 0.3, {"detection_method": "port-based guess"})

    return ("unknown", 0.0, {"detection_method": "unknown port"})


def probe_fingerprint_for_protocol(host: str, port: int, protocol: str,
                                   timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """Probe a service whose protocol is ALREADY known to obtain its
    product/vendor fingerprint, without changing the protocol verdict.

    Used when the user forces ``--protocol`` (or the protocol was decided by URL
    detection): we still want a fingerprint so credential selection can put the
    service's proper defaults first instead of spraying generic creds. Returns a
    service_info dict (vendor/product/version/...) or None if no confident match.
    """
    try:
        from cygor.credrecon.validation import PROTOCOL_PROBE_MAP
    except Exception:
        return None
    probe = PROTOCOL_PROBE_MAP.get(protocol)
    if probe is None:
        return None
    try:
        fp = probe(host, port, timeout)
    except Exception:
        return None
    if not fp or fp.confidence < 0.5:
        return None
    return {
        "vendor": fp.vendor,
        "product": fp.product,
        "version": fp.version,
        "os_hint": fp.os_hint,
        "features": fp.features or [],
        "detection_method": fp.detection_method,
        "banner": fp.raw_banner,
    }

# ----------------------------------------------------------------------
# Main scanner
# ----------------------------------------------------------------------
def scan_target_http(url: str, port: int, creds: List[Dict], timeout: int = 5, rate_limit: float = 0.1, scheme: str = "http", verbose: bool = True, scan_id: str = None, source_ip: str = None) -> Tuple[List[CredentialResult], Optional[Dict]]:
    """Scan an HTTP/HTTPS URL with multiple credentials.
    Returns: (results, skip_info) where skip_info is None if tested, or a dict with skip details if skipped."""
    results = []
    tester = HTTPTester(timeout, rate_limit, source_ip=source_ip)

    # Normalize to a fully-qualified URL (callers may pass a bare host/IP, e.g.
    # from a credfile, or a URL with a client-side fragment like /#/login).
    if not url.startswith(("http://", "https://")):
        url = f"{scheme or 'http'}://{url.rstrip('/')}:{port}/"

    # Fingerprint hints carried on the selected credentials (set when probing
    # identified the product/vendor) steer login discovery to the right handler.
    product_hint = next((c.get("product") for c in creds if c.get("product")), None)
    vendor_hint = next((c.get("vendor") for c in creds if c.get("vendor")), None)

    # Pre-flight: Check if URL is reachable
    if verbose:
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Checking if website is reachable...")
    
    try:
        if not requests:
            error_msg = "requests library not installed - cannot test HTTP/HTTPS"
            logger.error(f"{Fore.RED}[✗]{Style.RESET_ALL} {error_msg}")
            if scan_id:
                for cred in creds:
                    error_result = CredentialResult(url, port, "http", "http", cred['username'], cred.get('password'), "error", error_msg, source_ip=source_ip or "")
                    save_result_to_db_sync(scan_id, result=error_result)
            return [CredentialResult(url, port, "http", "http", creds[0]['username'] if creds else "", creds[0].get('password') if creds else "", "error", error_msg, source_ip=source_ip or "")], None
        
        # Quick connectivity check
        try:
            _preflight_get = requests.get
            if source_ip and _SourceIPAdapter is not None:
                _pf_session = requests.Session()
                _pf_adapter = _SourceIPAdapter(source_ip)
                _pf_session.mount('http://', _pf_adapter)
                _pf_session.mount('https://', _pf_adapter)
                _preflight_get = _pf_session.get
            test_resp = _preflight_get(url, timeout=timeout, verify=False, allow_redirects=True)
        except requests.exceptions.Timeout:
            error_msg = f"Website timeout - {url} not responding within {timeout}s"
            logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {error_msg}")
            if scan_id:
                for cred in creds:
                    error_result = CredentialResult(url, port, "http", "http", cred['username'], cred.get('password'), "error", error_msg, source_ip=source_ip or "")
                    save_result_to_db_sync(scan_id, result=error_result)
            return [CredentialResult(url, port, "http", "http", creds[0]['username'] if creds else "", creds[0].get('password') if creds else "", "error", error_msg, source_ip=source_ip or "")], None
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
                    error_result = CredentialResult(url, port, "http", "http", cred['username'], cred.get('password'), "error", error_msg, source_ip=source_ip or "")
                    save_result_to_db_sync(scan_id, result=error_result)
            return [CredentialResult(url, port, "http", "http", creds[0]['username'] if creds else "", creds[0].get('password') if creds else "", "error", error_msg, source_ip=source_ip or "")], None
        except Exception as e:
            error_msg = f"Error accessing {url}: {str(e)}"
            logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {error_msg}")
            if scan_id:
                for cred in creds:
                    error_result = CredentialResult(url, port, "http", "http", cred['username'], cred.get('password'), "error", error_msg, source_ip=source_ip or "")
                    save_result_to_db_sync(scan_id, result=error_result)
            return [CredentialResult(url, port, "http", "http", creds[0]['username'] if creds else "", creds[0].get('password') if creds else "", "error", error_msg, source_ip=source_ip or "")], None
        
        if verbose:
            logger.info(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Website is reachable (HTTP {test_resp.status_code})")
    except Exception as e:
        # If pre-flight check itself fails, continue anyway
        if verbose:
            logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Pre-flight check failed: {str(e)}, continuing anyway...")

    # Discover how to authenticate: Basic/Digest, HTML form, or a product API.
    if verbose:
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Discovering login mechanism...")

    plan = tester.discover_login(url, product=product_hint, vendor=vendor_hint)

    if not plan:
        detailed_reason = "No authentication mechanism detected (no Basic/Digest challenge, login form, or known login API)"
        logger.info(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {detailed_reason}")
        logger.info(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Skipping credential testing")

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
        logger.info(f"{Fore.GREEN}[✓]{Style.RESET_ALL} {plan.get('detail', plan.get('method'))}")

    # When discovery identifies a specific product, test that product's known
    # default credentials first - even if the port-probe never fingerprinted it.
    # This makes "just give the IP" auto-try the right defaults for the portal.
    if plan.get("product"):
        prod_key = plan["product"]
        try:
            all_prod, _ = get_credentials_for_service("http", fingerprint={"product": prod_key})
            prod_only = [c for c in all_prod if prod_key.lower() in (c.get("product") or "").lower()]
        except Exception:
            prod_only = []
        if prod_only:
            seen = set()
            merged = []
            for c in prod_only + list(creds):
                k = (c.get("username"), c.get("password"))
                if k in seen:
                    continue
                seen.add(k)
                merged.append(c)
            creds = merged
            if verbose:
                logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Prioritizing {Fore.GREEN}{len(prod_only)}{Style.RESET_ALL} {prod_key}-specific credential(s) for the identified portal")

    for i, cred in enumerate(creds, 1):
        if verbose:
            logger.info(f"  [{i}/{len(creds)}] Testing {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password'] or '(empty)'}{Style.RESET_ALL}")

        result = tester.test_auth(plan, url, port, cred["username"], cred["password"])
        if source_ip:
            result.source_ip = source_ip
        results.append(result)

        # Save to DB if scan_id provided
        if scan_id:
            save_result_to_db_sync(scan_id, result=result)

        if result.status == "success":
            logger.info(f"{Fore.GREEN}[✓ SUCCESS]{Style.RESET_ALL} {url} - {Fore.CYAN}{cred['username']}{Style.RESET_ALL}:{Fore.YELLOW}{cred['password']}{Style.RESET_ALL}")
            break  # Stop on first success

    return results, None

def _run_credential_loop(tester, ip: str, port: int, protocol: str, creds: List[Dict],
                         verbose: bool = True, scan_id: str = None,
                         max_attempts_per_user: int = 0, source_ip: str = None, **extra_kwargs) -> List[CredentialResult]:
    """Run the credential testing loop for a protocol tester.

    Handles: logging, DB save, success-break, per-user attempt tracking.
    Pass protocol-specific extra kwargs (e.g. use_ssl, domain) that get forwarded to tester.test().
    """
    results = []
    user_attempt_counts = defaultdict(int)

    for i, cred in enumerate(creds, 1):
        username = cred['username']

        # Per-user lockout protection
        if max_attempts_per_user > 0 and user_attempt_counts[username] >= max_attempts_per_user:
            if verbose:
                logger.info(f"  [{i}/{len(creds)}] Skipping {Fore.CYAN}{username}{Style.RESET_ALL} - max attempts ({max_attempts_per_user}) reached")
            continue
        user_attempt_counts[username] += 1

        if verbose:
            display_pass = cred.get('password') or '(empty)'
            logger.info(f"  [{i}/{len(creds)}] Testing {Fore.CYAN}{username}{Style.RESET_ALL}:{Fore.YELLOW}{display_pass}{Style.RESET_ALL}")

        result = tester.test(ip, port, username, cred.get("password", ""), **extra_kwargs)
        if source_ip:
            result.source_ip = source_ip
        results.append(result)

        if scan_id:
            save_result_to_db_sync(scan_id, result=result)

        if result.status == "success":
            logger.info(f"{Fore.GREEN}[✓ SUCCESS]{Style.RESET_ALL} {ip}:{port} - {Fore.CYAN}{username}{Style.RESET_ALL}:{Fore.YELLOW}{cred.get('password', '')}{Style.RESET_ALL}")
            break

    return results


def scan_target(ip: str, port: int, protocol: str, creds: List[Dict], timeout: int = 5,
                rate_limit: float = 0.1, verbose: bool = True, scan_id: str = None,
                ssh_key: str = None, ssh_key_passphrase: str = None, ssh_cert: str = None,
                jitter: float = 0.0, max_attempts_per_user: int = 0,
                source_ip: str = None, **kwargs) -> List[CredentialResult]:
    """Scan a single target with multiple credentials."""
    results = []

    # Pre-flight: Validate connection before testing credentials
    if verbose:
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Validating connection to {ip}:{port}...")

    is_connected, conn_error = validate_connection(ip, port, timeout, source_ip=source_ip)
    if not is_connected:
        error_msg = f"Cannot connect to {ip}:{port} - {conn_error}"
        logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {error_msg}")

        # Save error for all credentials
        if scan_id:
            for cred in creds:
                error_result = CredentialResult(ip, port, protocol, protocol, cred['username'], cred.get('password'), "error", error_msg, source_ip=source_ip or "")
                save_result_to_db_sync(scan_id, result=error_result)

        # Return error result for first credential as representative
        if creds:
            return [CredentialResult(ip, port, protocol, protocol, creds[0]['username'], creds[0].get('password'), "error", error_msg, source_ip=source_ip or "")]
        return [CredentialResult(ip, port, protocol, protocol, "", "", "error", error_msg, source_ip=source_ip or "")]

    if verbose:
        logger.info(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Connection successful")

    # Common kwargs for _run_credential_loop
    loop_kwargs = dict(verbose=verbose, scan_id=scan_id, max_attempts_per_user=max_attempts_per_user, source_ip=source_ip)

    # Select tester and run
    if protocol in ("http", "https"):
        tester = HTTPTester(timeout, rate_limit, jitter, source_ip=source_ip)

        scheme = "https" if protocol == "https" or port in (443, 8443, 9443) else "http"
        url = f"{scheme}://{ip}:{port}/"
        product_hint = next((c.get("product") for c in creds if c.get("product")), None)
        vendor_hint = next((c.get("vendor") for c in creds if c.get("vendor")), None)

        if verbose:
            logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Discovering login mechanism...")

        plan = tester.discover_login(url, product=product_hint, vendor=vendor_hint)

        if not plan:
            detection_info = "No authentication mechanism detected (no Basic/Digest challenge, login form, or known login API)"
            logger.info(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {detection_info}")
            logger.info(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Skipping credential testing")

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
            logger.info(f"{Fore.GREEN}[✓]{Style.RESET_ALL} {plan.get('detail', plan.get('method'))}")

        user_attempt_counts = defaultdict(int)
        for i, cred in enumerate(creds, 1):
            username = cred['username']
            if max_attempts_per_user > 0 and user_attempt_counts[username] >= max_attempts_per_user:
                if verbose:
                    logger.info(f"  [{i}/{len(creds)}] Skipping {Fore.CYAN}{username}{Style.RESET_ALL} - max attempts ({max_attempts_per_user}) reached")
                continue
            user_attempt_counts[username] += 1
            if verbose:
                display_pass = cred.get('password') or '(empty)'
                logger.info(f"  [{i}/{len(creds)}] Testing {Fore.CYAN}{username}{Style.RESET_ALL}:{Fore.YELLOW}{display_pass}{Style.RESET_ALL}")

            result = tester.test_auth(plan, ip, port, username, cred.get("password", ""))
            if source_ip:
                result.source_ip = source_ip
            results.append(result)
            if scan_id:
                save_result_to_db_sync(scan_id, result=result)
            if result.status == "success":
                logger.info(f"{Fore.GREEN}[✓ SUCCESS]{Style.RESET_ALL} {ip}:{port} - {Fore.CYAN}{username}{Style.RESET_ALL}:{Fore.YELLOW}{cred.get('password', '')}{Style.RESET_ALL}")
                break

    elif protocol == "ssh" and paramiko:
        tester = SSHTester(timeout, rate_limit, jitter, source_ip=source_ip)
        # Test SSH key authentication first if a key file is provided
        if ssh_key:
            key_display = Path(ssh_key).name
            cert_display = f" + cert:{Path(ssh_cert).name}" if ssh_cert else ""
            for i, cred in enumerate(creds, 1):
                username = cred['username']
                if max_attempts_per_user > 0:
                    # Per-user tracking for key auth
                    pass  # Key auth typically tests one key per user
                if verbose:
                    logger.info(f"  [{i}/{len(creds)}] Testing {Fore.CYAN}{username}{Style.RESET_ALL} with key {Fore.YELLOW}{key_display}{cert_display}{Style.RESET_ALL}")
                result = tester.test_key(ip, port, username, ssh_key, ssh_key_passphrase, cert_file=ssh_cert)
                if source_ip:
                    result.source_ip = source_ip
                results.append(result)

                if scan_id:
                    save_result_to_db_sync(scan_id, result=result)

                if result.status == "success":
                    logger.info(f"{Fore.GREEN}[✓ SUCCESS]{Style.RESET_ALL} {ip}:{port} - {Fore.CYAN}{username}{Style.RESET_ALL} (key: {key_display}{cert_display})")
                    logger.info(f"    {Fore.GREEN}→{Style.RESET_ALL} {result.details}")
                    break
                elif result.status == "failed":
                    logger.info(f"  {Fore.YELLOW}[✗ FAILED]{Style.RESET_ALL} {ip}:{port} - {Fore.CYAN}{username}{Style.RESET_ALL}: {result.details}")
                elif result.status == "error":
                    logger.info(f"  {Fore.RED}[! ERROR]{Style.RESET_ALL} {ip}:{port} - {Fore.CYAN}{username}{Style.RESET_ALL}: {result.details}")
        else:
            results = _run_credential_loop(tester, ip, port, protocol, creds, **loop_kwargs)

        # Test known-compromised SSH bad keys
        badkeys_enabled = kwargs.get('badkeys', True)
        if badkeys_enabled and paramiko:
            try:
                from cygor.credrecon.badkeys import load_badkeys
                bad_keys = load_badkeys()
                if bad_keys:
                    if verbose:
                        logger.info(f"  {Fore.CYAN}[*]{Style.RESET_ALL} Testing {len(bad_keys)} known-compromised SSH keys...")
                    for bk in bad_keys:
                        key_path = bk.get("path", "")
                        if not key_path or not Path(key_path).exists():
                            continue
                        bk_username = bk.get("default_username", "root")
                        result = tester.test_key(ip, port, bk_username, key_path)
                        if source_ip:
                            result.source_ip = source_ip
                        if result.status == "success":
                            cve_info = f" ({bk['cve']})" if bk.get('cve') else ""
                            result.details = f"COMPROMISED KEY: {bk.get('vendor', 'Unknown')} {bk.get('product', '')}{cve_info} - {result.details}"
                            results.append(result)
                            if scan_id:
                                save_result_to_db_sync(scan_id, result=result)
                            logger.info(f"{Fore.RED}[!! BADKEY]{Style.RESET_ALL} {ip}:{port} - {bk.get('vendor', '')} {bk.get('product', '')} key accepted for {Fore.CYAN}{bk_username}{Style.RESET_ALL}{cve_info}")
                            break
            except ImportError:
                pass

    elif protocol == "ftp" and FTP:
        results = _run_credential_loop(FTPTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "smb" and SMBConnection:
        smb_hash = kwargs.get('smb_hash', '')
        domain = kwargs.get('domain', '')
        results = _run_credential_loop(SMBTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds,
                                       domain=domain, nthash=smb_hash, **loop_kwargs)

    elif protocol == "mysql" and pymysql:
        results = _run_credential_loop(MySQLTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "postgres" and psycopg2:
        results = _run_credential_loop(PostgreSQLTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "rdp":
        domain = kwargs.get('domain', '')
        results = _run_credential_loop(RDPTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds,
                                       domain=domain, **loop_kwargs)

    elif protocol == "vnc":
        results = _run_credential_loop(VNCTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "mssql":
        results = _run_credential_loop(MSSQLTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "mongodb":
        results = _run_credential_loop(MongoDBTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "redis":
        results = _run_credential_loop(RedisTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "snmp":
        results = _run_credential_loop(SNMPTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "telnet":
        results = _run_credential_loop(TelnetTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol in ("ldap", "ldaps"):
        use_ssl = (protocol == "ldaps" or port == 636)
        domain = kwargs.get('domain', '')
        results = _run_credential_loop(LDAPTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds,
                                       use_ssl=use_ssl, domain=domain, **loop_kwargs)

    elif protocol in ("winrm", "winrm-ssl"):
        use_ssl = (protocol == "winrm-ssl" or port == 5986)
        domain = kwargs.get('domain', '')
        results = _run_credential_loop(WinRMTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds,
                                       use_ssl=use_ssl, domain=domain, **loop_kwargs)

    elif protocol == "ipmi":
        results = _run_credential_loop(IPMITester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol in ("mqtt", "mqtts"):
        use_tls = (protocol == "mqtts" or port == 8883)
        results = _run_credential_loop(MQTTTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds,
                                       use_tls=use_tls, **loop_kwargs)

    elif protocol in ("smtp", "smtps"):
        results = _run_credential_loop(SMTPTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol in ("imap", "imaps"):
        use_ssl = (protocol == "imaps" or port == 993)
        results = _run_credential_loop(IMAPTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds,
                                       use_ssl=use_ssl, **loop_kwargs)

    elif protocol in ("pop3", "pop3s"):
        use_ssl = (protocol == "pop3s" or port == 995)
        results = _run_credential_loop(POP3Tester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds,
                                       use_ssl=use_ssl, **loop_kwargs)

    elif protocol == "elasticsearch":
        results = _run_credential_loop(ElasticsearchTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "couchdb":
        results = _run_credential_loop(CouchDBTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "influxdb":
        results = _run_credential_loop(InfluxDBTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "cassandra":
        results = _run_credential_loop(CassandraTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "neo4j":
        results = _run_credential_loop(Neo4jTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "memcached":
        results = _run_credential_loop(MemcachedTester(timeout, rate_limit, jitter, source_ip=source_ip), ip, port, protocol, creds, **loop_kwargs)

    elif protocol == "unknown":
        error_msg = f"Unknown protocol for port {port} - cannot determine service type. Specify protocol manually with --protocol"
        logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {error_msg}")

        if scan_id:
            for cred in creds:
                error_result = CredentialResult(ip, port, protocol, protocol, cred['username'], cred.get('password'), "error", error_msg, source_ip=source_ip or "")
                save_result_to_db_sync(scan_id, result=error_result)

        if creds:
            results.append(CredentialResult(ip, port, protocol, protocol, creds[0]['username'], creds[0].get('password'), "error", error_msg, source_ip=source_ip or ""))
        else:
            results.append(CredentialResult(ip, port, protocol, protocol, "", "", "error", error_msg, source_ip=source_ip or ""))

    else:
        # Protocol not supported or library missing
        _MISSING_LIB_MAP = {
            "ssh": ("paramiko", paramiko),
            "ftp": ("ftplib", FTP),
            "mysql": ("pymysql", pymysql),
            "postgres": ("psycopg2", psycopg2),
            "mssql": ("pymssql", pymssql),
            "mongodb": ("pymongo", pymongo),
            "redis": ("redis", redis),
            "ldap": ("ldap3", ldap3),
            "ldaps": ("ldap3", ldap3),
            "winrm": ("pywinrm", winrm),
            "winrm-ssl": ("pywinrm", winrm),
            "ipmi": ("pyghmi", ipmi_command),
            "mqtt": ("paho-mqtt", mqtt),
            "mqtts": ("paho-mqtt", mqtt),
            "smb": ("impacket", SMBConnection),
            "cassandra": ("cassandra-driver", CassandraCluster),
        }
        missing_lib_msg = ""
        if protocol in _MISSING_LIB_MAP:
            lib_name, lib_ref = _MISSING_LIB_MAP[protocol]
            if not lib_ref:
                missing_lib_msg = f" - {lib_name} library not installed"

        error_msg = f"Protocol {protocol} not supported{missing_lib_msg}. Install required library or use a different protocol."
        logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {error_msg}")

        if scan_id:
            for cred in creds:
                error_result = CredentialResult(ip, port, protocol, protocol, cred['username'], cred.get('password'), "error", error_msg, source_ip=source_ip or "")
                save_result_to_db_sync(scan_id, result=error_result)

        if creds:
            results.append(CredentialResult(ip, port, protocol, protocol, creds[0]['username'], creds[0].get('password'), "error", error_msg, source_ip=source_ip or ""))
        else:
            results.append(CredentialResult(ip, port, protocol, protocol, "", "", "error", error_msg, source_ip=source_ip or ""))

    return results

# ----------------------------------------------------------------------
# Save results
# ----------------------------------------------------------------------
def save_results(results: List[CredentialResult], output_dir: Path, formats: str = "json,csv,xml"):
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

    # XML
    if "xml" in formats_list and results_dicts:
        import xml.etree.ElementTree as ET
        root = ET.Element("credrecon_results")
        root.set("generated", datetime.now().strftime("%Y-%m-%dT%H:%M:%S"))
        root.set("total", str(len(results_dicts)))
        for result_dict in results_dicts:
            result_el = ET.SubElement(root, "result")
            for key, value in result_dict.items():
                child = ET.SubElement(result_el, key)
                child.text = str(value) if value is not None else ""
        tree = ET.ElementTree(root)
        xml_file = output_dir / "credrecon_results.xml"
        ET.indent(tree, space="  ")
        tree.write(xml_file, encoding="unicode", xml_declaration=True)
        saved_files.append(xml_file)

    return saved_files

# Module-level singleton for DB engine reuse (avoids creating engine per result)
_sync_engine = None
_sync_engine_lock = threading.Lock()
_scan_id_cache = {}  # Cache scan_id -> db primary key lookups
_db_write_buffer = []  # Buffer for batched writes
_db_write_buffer_lock = threading.Lock()
_DB_BATCH_SIZE = 100  # Flush every N results


def _get_sync_engine():
    """Get or create a singleton synchronous DB engine with connection pooling."""
    global _sync_engine
    if _sync_engine is not None:
        return _sync_engine
    with _sync_engine_lock:
        if _sync_engine is not None:
            return _sync_engine
        try:
            from sqlmodel import create_engine
            from cygor.webapp.config import settings
            db_url = settings.DATABASE_URL
            if db_url.startswith("postgresql+psycopg://"):
                db_url = db_url.replace("postgresql+psycopg://", "postgresql://")
            _sync_engine = create_engine(
                db_url, echo=False,
                pool_size=5, max_overflow=10, pool_pre_ping=True, pool_recycle=300
            )
        except ImportError:
            return None
    return _sync_engine


def _get_scan_db_id(session, scan_id: str):
    """Get scan DB primary key with caching to avoid repeated lookups."""
    if scan_id in _scan_id_cache:
        return _scan_id_cache[scan_id]
    from sqlmodel import select
    from cygor.webapp.models import CredReconScan
    statement = (
        select(CredReconScan.id, CredReconScan.scan_id)
        .where(CredReconScan.scan_id == scan_id)
    )
    scan_row = session.exec(statement).first()
    if scan_row:
        _scan_id_cache[scan_id] = scan_row.id
        return scan_row.id
    return None


def _flush_db_write_buffer():
    """Flush buffered results to database in a single transaction.

    On commit failure: requeue the batch instead of silently losing it.
    The previous behaviour ate every result row when the commit failed
    (FK violation, dead connection, anything) -- a credrecon scan
    finding 100 valid credentials on a flaky DB would lose all 100 with
    no log message.
    """
    global _db_write_buffer
    with _db_write_buffer_lock:
        if not _db_write_buffer:
            return
        batch = _db_write_buffer[:]
        _db_write_buffer = []

    engine = _get_sync_engine()
    if not engine:
        # No engine available -- put the batch back so a later flush
        # (e.g. once the engine reconnects) can retry. Without this the
        # batch was already removed from the buffer above and lost.
        with _db_write_buffer_lock:
            _db_write_buffer = batch + _db_write_buffer
        return

    try:
        from sqlmodel import Session
        with Session(engine) as session:
            for db_result in batch:
                session.add(db_result)
            session.commit()
    except Exception as e:
        # Loud log so the failure isn't invisible. Don't requeue the
        # entire batch automatically because the same failure mode will
        # likely repeat -- write a warning to a dead-letter file alongside
        # cygor's app data so the user can investigate and recover.
        try:
            import logging as _logging
            _logging.getLogger("cygor.credrecon").error(
                f"DB write batch dropped: {len(batch)} result(s); commit failed "
                f"({type(e).__name__}: {e}). See app log for recovery."
            )
            # Best-effort dead-letter dump so the data isn't gone forever.
            try:
                from cygor.workspace import app_log_dir
                import json as _json
                dl = app_log_dir() / "credrecon-dropped.jsonl"
                dl.parent.mkdir(parents=True, exist_ok=True)
                with open(dl, "a", encoding="utf-8") as fh:
                    for r in batch:
                        try:
                            fh.write(_json.dumps({
                                "scan_id":  getattr(r, "scan_id", None),
                                "target":   getattr(r, "target", None),
                                "port":     getattr(r, "port", None),
                                "protocol": getattr(r, "protocol", None),
                                "status":   getattr(r, "status", None),
                                "error":    str(e)[:200],
                            }, default=str) + "\n")
                        except Exception:
                            continue
            except Exception:
                pass  # dead-letter is best-effort
        except Exception:
            pass


def save_result_to_db_sync(scan_id: str, result: CredentialResult = None, skip_info: Dict = None):
    """Save a credential test result to database using batched writes with a singleton engine."""
    try:
        from sqlmodel import Session
        from cygor.webapp.models import CredReconResult
        from datetime import datetime

        engine = _get_sync_engine()
        if not engine:
            return

        # Resolve scan DB primary key (cached after first lookup)
        with Session(engine) as session:
            db_scan_id = _get_scan_db_id(session, scan_id)
        if not db_scan_id:
            return

        db_result = None
        if result:
            db_result = CredReconResult(
                scan_id=db_scan_id,
                target=result.ip,
                port=result.port,
                protocol=result.protocol,
                service=result.service,
                username=result.username,
                password=result.password,
                status=result.status,
                reason=result.details,
                tested_at=datetime.utcnow().isoformat(),
                fingerprint_product=result.fingerprint_product if result.fingerprint_product else None,
                fingerprint_version=result.fingerprint_version if result.fingerprint_version else None,
                fingerprint_confidence=result.fingerprint_confidence if result.fingerprint_confidence else None,
                fingerprint_raw=result.fingerprint_raw if result.fingerprint_raw else None,
                credential_selection=result.credential_selection if result.credential_selection else None,
                source_ip=result.source_ip if result.source_ip else None,
            )
        elif skip_info:
            db_result = CredReconResult(
                scan_id=db_scan_id,
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

        if db_result:
            with _db_write_buffer_lock:
                _db_write_buffer.append(db_result)
                should_flush = len(_db_write_buffer) >= _DB_BATCH_SIZE
            if should_flush:
                _flush_db_write_buffer()

    except ImportError:
        pass
    except Exception:
        pass  # Silently fail to not interrupt scanning

# ----------------------------------------------------------------------
# Main function
# ----------------------------------------------------------------------
def credrecon(input_file: str = None, target: str = None, output_dir: str = None,
              protocol: str = "auto", port: int = None, threads: int = 10,
              timeout: int = 5, creds_file: str = None,
              usernames_file: str = None, passwords_file: str = None,
              max_attempts: int = 3, scan_id: str = None,
              attack_mode: str = "default", spray_password: str = None, stuff_username: str = None,
              single_username: str = None, single_password: str = None,
              credfile_path: str = None,
              probe_services: bool = True,
              ssh_key: str = None, ssh_key_passphrase: str = None,
              ssh_cert: str = None,
              jitter: float = 0.0, max_attempts_per_user: int = 0,
              smb_hash: str = None, domain: str = None,
              badkeys: bool = True, snmp_tier: str = "default",
              jsonl: bool = False, stdin_mode: bool = False,
              protocols: list = None,
              **kwargs):
    """Main credential reconnaissance function.

    Args:
        input_file: File containing targets (one per line, format: IP:PORT or URL)
        target: Single target (IP:PORT or URL)
        output_dir: Directory to save results
        protocol: Protocol to test ('auto' for auto-detection)
        port: Default port if not specified in target
        threads: Number of concurrent threads
        timeout: Connection timeout in seconds
        creds_file: Custom credentials YAML/JSON file
        usernames_file: File with usernames (one per line)
        passwords_file: File with passwords (one per line)
        max_attempts: Maximum credential attempts per target
        scan_id: Optional scan ID for web UI integration
        attack_mode: 'default', 'spray', 'stuff', or 'single'
        spray_password: Password to use in spray mode
        stuff_username: Username to use in stuff mode
        single_username: Username for single credential mode
        single_password: Password for single credential mode
        credfile_path: Path to credential file (CSV/text/JSON) for credfile mode
        probe_services: Whether to probe services before testing credentials (default: True)
        ssh_key: Path to SSH private key file for key-based authentication
        ssh_key_passphrase: Passphrase for encrypted SSH private key
        ssh_cert: Path to SSH certificate file (-cert.pub) for CA-signed auth
        jitter: Random delay variance (0 to N seconds) between tests for evasion
        max_attempts_per_user: Max password attempts per username (0 = unlimited)
        smb_hash: NTLM hash for SMB pass-the-hash (LMHASH:NTHASH or just NTHASH)
        domain: Domain for SMB/LDAP/WinRM authentication
        badkeys: Test known-compromised SSH keys (default: True)
        snmp_tier: SNMP community string tier (default, extended, full)
        jsonl: Output results as JSONL to stdout
        stdin_mode: Read targets from stdin as JSONL
        protocols: List of protocols to test in parallel (e.g. ['ssh', 'smb', 'winrm'])
    """
    # Internal defaults (not exposed to CLI)
    rate_limit = 0.1  # Rate limit between credential tests (seconds)

    # Normalize protocol input: build protocol_list for multi-protocol support
    # Priority: explicit protocols list > single protocol > auto-detect
    protocol_list = None
    if protocols and len(protocols) > 0:
        # Filter out 'auto' from the list
        filtered = [p for p in protocols if p != "auto"]
        if filtered:
            protocol_list = filtered
    elif protocol and protocol != "auto":
        protocol_list = [protocol]
    output_format = "json,csv,xml"  # Always output all formats

    # If JSONL mode, redirect logger to stderr so stdout is clean for JSONL
    if jsonl:
        for handler in logger.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and handler.stream == sys.stdout:
                handler.stream = sys.stderr

    start_time = time.time()

    # Log SSH key info if provided
    if ssh_key:
        if Path(ssh_key).exists():
            logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} SSH key authentication enabled: {Fore.GREEN}{ssh_key}{Style.RESET_ALL}")
            if ssh_key_passphrase:
                logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} SSH key passphrase: provided")
            if ssh_cert:
                if Path(ssh_cert).exists():
                    logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} SSH certificate: {Fore.GREEN}{ssh_cert}{Style.RESET_ALL}")
                else:
                    logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} SSH certificate file not found: {ssh_cert}")
                    return
        else:
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} SSH key file not found: {ssh_key}")
            return

    # Warn if jumpbox is active - most credential testing uses raw sockets
    if is_jumpbox_routing_active():
        logger.info(f"{Fore.CYAN}[i] Jumpbox active - credential testing needs proxychains wrapper{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}[i] Run: proxychains4 cygor credrecon ...{Style.RESET_ALL}")

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

        # Determine the fallback port:
        # - explicit --port flag always wins
        # - multi-protocol: use None (port assigned per-protocol during expansion)
        # - single protocol: use that protocol's default port
        # - auto-detect: fall back to 22
        if default_port:
            fallback_port = default_port
        elif protocol_list and len(protocol_list) > 1:
            # Multi-protocol: defer port assignment to expansion loop
            fallback_port = None
        elif protocol_list and len(protocol_list) == 1:
            fallback_port = get_default_port(protocol_list[0]) or 22
        elif protocol != "auto":
            fallback_port = get_default_port(protocol) or 22
        else:
            fallback_port = None  # Auto-detect: defer to expansion or use 22

        # Otherwise treat as IP:PORT format
        if ':' in target_str:
            try:
                host, port_str = target_str.rsplit(':', 1)
                port_val = int(port_str)
                return (host.strip(), port_val, None, None)
            except ValueError:
                # If port parsing fails, treat entire string as host
                return (target_str, fallback_port, None, None)
        else:
            return (target_str, fallback_port, None, None)

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
    elif stdin_mode or (not target and not input_file and not sys.stdin.isatty()):
        # Read targets from stdin (JSONL or IP:PORT format)
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Reading targets from stdin...")
        for line in sys.stdin:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                entry = json.loads(line)
                stdin_ip = entry.get("ip", entry.get("host", ""))
                stdin_port = int(entry.get("port", 0))
                stdin_service = entry.get("service", None)
                if stdin_ip and stdin_port:
                    targets.append((stdin_ip, stdin_port, stdin_service, None))
            except (json.JSONDecodeError, ValueError):
                # Fall back to IP:PORT format
                targets.append(parse_target(line, port))

    if not targets:
        logger.error("No targets specified. Use -t, -i, or --stdin")
        return

    logger.info(f"Loaded {len(targets)} targets")

    # Multi-protocol expansion: expand each target into one entry per protocol
    # so all protocol×target combinations run in parallel via the thread pool
    if protocol_list and len(protocol_list) > 1:
        expanded = []
        for target_data in targets:
            if len(target_data) == 4:
                ip, target_port, force_proto, scheme = target_data
            else:
                ip, target_port = target_data
                force_proto, scheme = None, None

            if force_proto:
                # URL target — protocol already determined, keep as-is
                expanded.append((ip, target_port, force_proto, scheme))
            else:
                # Expand: one entry per selected protocol with correct default port
                for proto in protocol_list:
                    if target_port:
                        # Target has explicit port — use it for all protocols
                        effective_port = target_port
                    else:
                        # Bare IP — assign protocol's default port
                        effective_port = get_default_port(proto) or 22
                    expanded.append((ip, effective_port, proto, None))

        logger.info(f"Multi-protocol expansion: {len(targets)} targets x {len(protocol_list)} protocols = {len(expanded)} test entries ({', '.join(p.upper() for p in protocol_list)})")
        targets = expanded
    elif protocol_list and len(protocol_list) == 1:
        # Single protocol selected — ensure bare targets get the right port
        single_proto = protocol_list[0]
        fixed = []
        for target_data in targets:
            if len(target_data) == 4:
                ip, target_port, force_proto, scheme = target_data
            else:
                ip, target_port = target_data
                force_proto, scheme = None, None

            if force_proto:
                fixed.append((ip, target_port, force_proto, scheme))
            elif not target_port:
                fixed.append((ip, get_default_port(single_proto) or 22, single_proto, None))
            else:
                fixed.append((ip, target_port, single_proto, None))
        targets = fixed
    else:
        # Auto-detect mode: ensure bare targets without ports get 22 as default
        fixed = []
        for target_data in targets:
            if len(target_data) == 4:
                ip, target_port, force_proto, scheme = target_data
            else:
                ip, target_port = target_data
                force_proto, scheme = None, None
            fixed.append((ip, target_port or 22, force_proto, scheme))
        targets = fixed

    # Load credentials based on attack mode
    custom_creds = None

    if attack_mode == "spray":
        # Password Spraying: one password against many usernames
        if not spray_password:
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} Password spraying requires --spray-password")
            return
        if not usernames_file or not Path(usernames_file).exists():
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} Password spraying requires --usernames-file")
            return

        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Attack mode: {Fore.YELLOW}PASSWORD SPRAYING{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Password: {Fore.GREEN}{spray_password}{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Loading usernames from: {usernames_file}")

        with open(usernames_file, "r") as f:
            usernames = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        if not usernames:
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} No usernames found in {usernames_file}")
            return

        # Create credentials: one password, many usernames
        combined_creds = []
        for username in usernames:
            combined_creds.append({"username": username, "password": spray_password, "service": "spray"})

        # Build custom_creds dict for all protocols
        custom_creds = {proto: combined_creds for proto in [
            "http", "ssh", "ftp", "mysql", "postgres", "mssql", "mongodb",
            "redis", "snmp", "rdp", "vnc", "telnet", "ldap", "ldaps", "ipmi", "mqtt", "mqtts",
            "smb", "winrm", "winrm-ssl", "smtp", "smtps", "imap", "imaps", "pop3", "pop3s",
            "elasticsearch", "couchdb", "influxdb", "cassandra", "neo4j", "memcached"
        ]}
        logger.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} Spraying password against {len(usernames)} usernames")

    elif attack_mode == "stuff":
        # Credential Stuffing: one username against many passwords
        if not stuff_username:
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} Credential stuffing requires --stuff-username")
            return
        if not passwords_file or not Path(passwords_file).exists():
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} Credential stuffing requires --passwords-file")
            return

        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Attack mode: {Fore.YELLOW}CREDENTIAL STUFFING{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Username: {Fore.GREEN}{stuff_username}{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Loading passwords from: {passwords_file}")

        with open(passwords_file, "r") as f:
            passwords = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        if not passwords:
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} No passwords found in {passwords_file}")
            return

        # Create credentials: one username, many passwords
        combined_creds = []
        for password in passwords:
            combined_creds.append({"username": stuff_username, "password": password, "service": "stuff"})

        # Build custom_creds dict for all protocols
        custom_creds = {proto: combined_creds for proto in [
            "http", "ssh", "ftp", "mysql", "postgres", "mssql", "mongodb",
            "redis", "snmp", "rdp", "vnc", "telnet", "ldap", "ldaps", "ipmi", "mqtt", "mqtts",
            "smb", "winrm", "winrm-ssl", "smtp", "smtps", "imap", "imaps", "pop3", "pop3s",
            "elasticsearch", "couchdb", "influxdb", "cassandra", "neo4j", "memcached"
        ]}
        logger.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} Testing {len(passwords)} passwords against username '{stuff_username}'")

    elif attack_mode == "single":
        # Single Credential: test one specific username/password pair
        if not single_username:
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} Single credential mode requires --single-username")
            return
        if not single_password and not ssh_key:
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} Single credential mode requires --single-password (or --ssh-key for key-based auth)")
            return

        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Attack mode: {Fore.YELLOW}SINGLE CREDENTIAL{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Username: {Fore.GREEN}{single_username}{Style.RESET_ALL}")
        if single_password:
            logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Password: {Fore.GREEN}{'*' * len(single_password)}{Style.RESET_ALL}")
        elif ssh_key:
            logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Authentication: SSH key ({ssh_key})")

        # Create single credential entry
        combined_creds = [{"username": single_username, "password": single_password or "", "service": "single"}]

        # Build custom_creds dict for all protocols
        custom_creds = {proto: combined_creds for proto in [
            "http", "ssh", "ftp", "mysql", "postgres", "mssql", "mongodb",
            "redis", "snmp", "rdp", "vnc", "telnet", "ldap", "ldaps", "ipmi", "mqtt", "mqtts",
            "smb", "winrm", "winrm-ssl", "smtp", "smtps", "imap", "imaps", "pop3", "pop3s",
            "elasticsearch", "couchdb", "influxdb", "cassandra", "neo4j", "memcached"
        ]}
        logger.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} Testing single credential against targets")

    elif attack_mode == "key":
        # Key Authentication: test SSH key (and optional certificate) against targets
        if not ssh_key:
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} Key authentication mode requires --ssh-key")
            return

        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Attack mode: {Fore.YELLOW}KEY AUTHENTICATION{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} SSH key: {Fore.GREEN}{ssh_key}{Style.RESET_ALL}")
        if ssh_cert:
            logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} SSH certificate: {Fore.GREEN}{ssh_cert}{Style.RESET_ALL}")

        # Load usernames to test the key against
        if usernames_file and Path(usernames_file).exists():
            usernames = [line.strip() for line in Path(usernames_file).read_text().splitlines() if line.strip()]
            logger.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} Loaded {len(usernames)} usernames from {usernames_file}")
        elif single_username:
            usernames = [single_username]
            logger.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} Testing key against username: {single_username}")
        else:
            # Default SSH usernames to try with the key
            usernames = ["root", "admin", "ubuntu", "ec2-user", "centos", "deploy", "git", "ansible", "vagrant"]
            logger.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} No usernames specified, using {len(usernames)} common SSH usernames")

        # Build credential list from usernames (password not used for key auth)
        combined_creds = [{"username": u, "password": "", "service": "ssh"} for u in usernames]
        custom_creds = {proto: combined_creds for proto in [
            "http", "ssh", "ftp", "mysql", "postgres", "mssql", "mongodb",
            "redis", "snmp", "rdp", "vnc", "telnet", "ldap", "ldaps", "ipmi", "mqtt", "mqtts",
            "smb", "winrm", "winrm-ssl", "smtp", "smtps", "imap", "imaps", "pop3", "pop3s",
            "elasticsearch", "couchdb", "influxdb", "cassandra", "neo4j", "memcached"
        ]}
        logger.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} Testing SSH key against {len(usernames)} usernames")

    elif attack_mode == "credfile":
        # Credential File mode: parse a structured file with per-target credentials
        if not credfile_path or not Path(credfile_path).exists():
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} Credential file mode requires --credfile-path pointing to a valid file")
            return

        from .credfile_parser import parse as parse_credfile

        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Attack mode: {Fore.YELLOW}CREDENTIAL FILE{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Parsing credential file: {credfile_path}")

        parse_result = parse_credfile(credfile_path)

        if parse_result.warnings:
            for w in parse_result.warnings[:10]:
                logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {w}")
            if len(parse_result.warnings) > 10:
                logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} ... and {len(parse_result.warnings) - 10} more warnings")

        if not parse_result.entries:
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} No valid credential entries found in file")
            return

        logger.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} Loaded {len(parse_result.entries)} credential entries ({parse_result.skipped} skipped)")

        # Group entries by (ip, port, service) for batched testing
        from collections import defaultdict as _defaultdict
        credfile_groups = _defaultdict(list)
        skipped_no_service = 0

        for entry in parse_result.entries:
            # Resolve service: per-row > global --protocol > port-based auto-detect
            resolved_service = entry.service
            if not resolved_service and protocol != "auto":
                resolved_service = protocol
            if not resolved_service and entry.port:
                resolved_service = detect_protocol(entry.port)
                if resolved_service == "unknown":
                    resolved_service = None
            if not resolved_service:
                skipped_no_service += 1
                logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Cannot determine service for {entry.ip} — skipped (specify service column or --protocol)")
                continue

            resolved_port = entry.port
            if not resolved_port and port:
                resolved_port = port
            if not resolved_port:
                # Use default port for service
                resolved_port = get_default_port(resolved_service)

            if not resolved_port:
                skipped_no_service += 1
                logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Cannot determine port for {entry.ip}/{resolved_service} — skipped")
                continue

            key = (entry.ip, resolved_port, resolved_service)
            credfile_groups[key].append({"username": entry.username, "password": entry.password, "service": "credfile"})

        if skipped_no_service:
            logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {skipped_no_service} entries skipped (no service resolved)")

        if not credfile_groups:
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} No testable credential groups after service resolution")
            return

        logger.info(f"{Fore.GREEN}[+]{Style.RESET_ALL} Testing {sum(len(v) for v in credfile_groups.values())} credentials across {len(credfile_groups)} target/service groups")

    elif creds_file and Path(creds_file).exists():
        # Default mode with custom credentials file
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Attack mode: {Fore.YELLOW}DEFAULT CREDENTIALS{Style.RESET_ALL}")
        logger.info(f"Loading credentials from {creds_file}")
        with open(creds_file, "r") as f:
            if creds_file.endswith(".yaml") or creds_file.endswith(".yml"):
                custom_creds = yaml.safe_load(f)
            else:
                custom_creds = json.load(f)

    elif usernames_file and passwords_file:
        # Default mode with separate username/password files (all combinations)
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Attack mode: {Fore.YELLOW}DEFAULT CREDENTIALS{Style.RESET_ALL}")
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
            # Build credentials lazily - only materialize the list once
            # For large wordlists this avoids O(n*m) memory before scanning starts
            total_combos = len(usernames) * len(passwords)
            if total_combos > 500_000:
                logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Large credential set: {total_combos:,} combinations. Consider reducing with --max-attempts")
            combined_creds = [
                {"username": u, "password": p, "service": "custom"}
                for u in usernames for p in passwords
            ]

            # Build custom_creds dict with same structure as default
            custom_creds = {proto: combined_creds for proto in [
                "http", "ssh", "ftp", "mysql", "postgres", "mssql", "mongodb",
                "redis", "snmp", "rdp", "vnc", "telnet", "ldap", "ldaps", "ipmi", "mqtt", "mqtts",
            "smb", "winrm", "winrm-ssl", "smtp", "smtps", "imap", "imaps", "pop3", "pop3s",
            "elasticsearch", "couchdb", "influxdb", "cassandra", "neo4j", "memcached"
            ]}
            logger.info(f"Generated {len(combined_creds):,} credential combinations ({len(usernames):,} users x {len(passwords):,} passwords)")
        else:
            logger.warning("Username or password file is empty or not found")
    else:
        # Default mode with built-in credentials
        logger.info(f"{Fore.CYAN}[*]{Style.RESET_ALL} Attack mode: {Fore.YELLOW}DEFAULT CREDENTIALS{Style.RESET_ALL} (built-in database)")

    # ---- CREDFILE MODE: override the standard target loop ----
    if attack_mode == "credfile" and credfile_groups:
        all_results = []
        success_count = 0
        fail_count = 0
        error_count = 0
        max_pending = threads * 3

        with ThreadPoolExecutor(max_workers=threads) as executor:
            pending_futures = set()

            for (target_ip, target_port, target_service), creds in credfile_groups.items():
                logger.info(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Testing {Fore.WHITE}{target_ip}:{target_port}{Style.RESET_ALL} ({Fore.MAGENTA}{target_service.upper()}{Style.RESET_ALL}) with {Fore.GREEN}{len(creds)}{Style.RESET_ALL} credential(s) from file")

                # Backpressure: wait for a slot if too many futures are pending
                while len(pending_futures) >= max_pending:
                    done, pending_futures = wait(pending_futures, return_when=FIRST_COMPLETED)
                    for fut in done:
                        try:
                            results = fut.result()
                            if isinstance(results, tuple):
                                results, _ = results
                            all_results.extend(results)
                            for r in results:
                                if r.status == "success":
                                    success_count += 1
                                elif r.status == "failed":
                                    fail_count += 1
                                else:
                                    error_count += 1
                        except Exception as e:
                            logger.debug(f"Future error: {e}")
                            error_count += 1

                # Build extra kwargs for protocol-specific options
                extra_scan_kwargs = dict(
                    jitter=jitter, max_attempts_per_user=max_attempts_per_user,
                    smb_hash=smb_hash or '', domain=domain or '', badkeys=badkeys,
                )

                _src_ip = None  # IP rotation not available in this build

                # Submit scan_target per group (one target/service combo, multiple creds)
                if target_service in ('http', 'https'):
                    cf_scheme = 'https' if target_service == 'https' else 'http'
                    future = executor.submit(scan_target_http, target_ip, target_port, creds, timeout, rate_limit, cf_scheme, True, scan_id, source_ip=_src_ip)
                else:
                    future = executor.submit(scan_target, target_ip, target_port, target_service, creds, timeout, rate_limit, True, scan_id, ssh_key, ssh_key_passphrase, ssh_cert, source_ip=_src_ip, **extra_scan_kwargs)
                pending_futures.add(future)

            # Drain remaining futures
            for future in as_completed(pending_futures):
                try:
                    results = future.result()
                    if isinstance(results, tuple):
                        results, _ = results
                    all_results.extend(results)
                    for r in results:
                        if r.status == "success":
                            success_count += 1
                        elif r.status == "failed":
                            fail_count += 1
                        else:
                            error_count += 1
                except Exception as e:
                    logger.debug(f"Future error: {e}")
                    error_count += 1

    else:
        # Scan all targets with backpressure - limit pending futures to avoid unbounded queue growth
        all_results = []
        success_count = 0
        fail_count = 0
        error_count = 0
        max_pending = threads * 3  # Allow 3x thread count pending futures for pipeline overlap

        with ThreadPoolExecutor(max_workers=threads) as executor:
            pending_futures = set()

            for target_data in targets:
                # Unpack target data (could be 2-tuple for legacy or 4-tuple for URL)
                if len(target_data) == 4:
                    ip, target_port, force_proto, scheme = target_data
                else:
                    ip, target_port = target_data
                    force_proto, scheme = None, None

                # Determine protocol
                service_info = None
                probe_confidence = 0.0

                if force_proto:
                    # Protocol already determined (URL detection or multi-protocol expansion)
                    detected_proto = force_proto
                    # Still probe (when enabled) to obtain a product/vendor
                    # fingerprint so credential selection prioritizes the right
                    # defaults instead of generic creds.
                    if probe_services and not service_info:
                        service_info = probe_fingerprint_for_protocol(ip, target_port, detected_proto, timeout=timeout)
                elif protocol == "auto":
                    # Auto-detect protocol - try probing first if enabled
                    if probe_services:
                        logger.info(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Auto-detecting service on {Fore.WHITE}{ip}:{target_port}{Style.RESET_ALL}...")
                        detected_proto, probe_confidence, service_info = detect_protocol_with_probe(
                            ip, target_port, timeout=timeout, verbose=True
                        )
                    else:
                        # Just use port-based detection
                        detected_proto = detect_protocol(target_port)
                        if detected_proto == "unknown":
                            logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Unknown port {target_port} - specify --protocol or enable --probe")
                            continue
                else:
                    # User specified protocol explicitly. Honor it, but still probe
                    # (when enabled) for a fingerprint to prioritize proper defaults.
                    detected_proto = protocol
                    if probe_services and not service_info:
                        logger.info(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Probing {Fore.WHITE}{ip}:{target_port}{Style.RESET_ALL} for {detected_proto.upper()} fingerprint...")
                        service_info = probe_fingerprint_for_protocol(ip, target_port, detected_proto, timeout=timeout)
                        if service_info and service_info.get("product") and verbose:
                            logger.info(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Fingerprint: {Fore.WHITE}{service_info.get('product')}{Style.RESET_ALL}")

                # Warn if protocol is unknown
                if detected_proto == "unknown":
                    logger.warning(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Could not detect service on {ip}:{target_port} - skipping (specify --protocol manually)")
                    continue

                # Get credentials for this protocol
                selection_rationale = None
                if custom_creds and detected_proto in custom_creds:
                    creds = custom_creds[detected_proto]
                    selection_rationale = f"Using {len(creds)} custom credentials"
                elif probe_services and service_info:
                    # Use smart credential selection based on probe results
                    creds, selection_rationale = get_credentials_for_service(
                        detected_proto,
                        fingerprint=service_info,
                        max_credentials=max_attempts if max_attempts > 0 else None
                    )
                else:
                    creds = DEFAULT_CREDENTIALS_DB.get(detected_proto, [])
                    selection_rationale = f"Selected {len(creds)} generic {detected_proto} credentials"

                # SNMP tier override: use tiered community string wordlists
                if detected_proto == "snmp" and attack_mode == "default" and not custom_creds:
                    tier_creds = _load_snmp_communities(snmp_tier)
                    if tier_creds:
                        creds = tier_creds
                        selection_rationale = f"Using {len(creds)} SNMP communities (tier: {snmp_tier})"

                if not creds:
                    logger.warning(f"No credentials defined for {detected_proto}")
                    continue

                # Limit credentials to max_attempts (if not already limited by smart selection)
                # Key auth mode: always test all usernames (no brute-force risk)
                if attack_mode == "key":
                    limited_creds = creds
                elif not (probe_services and service_info):
                    limited_creds = creds[:max_attempts] if max_attempts > 0 else creds
                else:
                    limited_creds = creds  # Already limited by get_credentials_for_service

                # Build info string for logging
                info_suffix = ""
                if service_info and (service_info.get("product") or service_info.get("version")):
                    info_parts = []
                    if service_info.get("product"):
                        info_parts.append(service_info["product"])
                    if service_info.get("version"):
                        info_parts.append(f"v{service_info['version']}")
                    info_suffix = f" - {' '.join(info_parts)}"

                logger.info(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Testing {Fore.WHITE}{ip}:{target_port}{Style.RESET_ALL} ({Fore.MAGENTA}{detected_proto.upper()}{Style.RESET_ALL}{info_suffix}) with {Fore.GREEN}{len(limited_creds)}{Style.RESET_ALL} credential(s)")
                if selection_rationale:
                    logger.info(f"    {Fore.CYAN}→{Style.RESET_ALL} {selection_rationale}")

                # Backpressure: wait for a slot if too many futures are pending
                while len(pending_futures) >= max_pending:
                    done, pending_futures = wait(pending_futures, return_when=FIRST_COMPLETED)
                    for future in done:
                        try:
                            results = future.result()
                            if isinstance(results, tuple):
                                results, skip_info = results
                            all_results.extend(results)
                            for r in results:
                                if r.status == "success":
                                    success_count += 1
                                elif r.status == "failed":
                                    fail_count += 1
                                else:
                                    error_count += 1
                                # JSONL streaming output
                                if jsonl and r.status == "success":
                                    print(json.dumps(asdict(r)), flush=True)
                        except Exception as e:
                            logger.error(f"Error scanning target: {e}")

                # Extra kwargs for protocol-specific options
                extra_scan_kwargs = dict(
                    jitter=jitter, max_attempts_per_user=max_attempts_per_user,
                    smb_hash=smb_hash or '', domain=domain or '', badkeys=badkeys,
                )

                _src_ip = None  # IP rotation not available in this build

                # HTTP and HTTPS both run through the HTTP tester; carry the scheme
                # so TLS endpoints (443/8443/...) are tested over https.
                if detected_proto in ('http', 'https'):
                    eff_scheme = scheme or ('https' if detected_proto == 'https' else 'http')
                    future = executor.submit(scan_target_http, ip, target_port, limited_creds, timeout, rate_limit, eff_scheme, True, scan_id, source_ip=_src_ip)
                else:
                    future = executor.submit(scan_target, ip, target_port, detected_proto, limited_creds, timeout, rate_limit, True, scan_id, ssh_key, ssh_key_passphrase, ssh_cert, source_ip=_src_ip, **extra_scan_kwargs)
                pending_futures.add(future)

            # Drain remaining futures
            for future in as_completed(pending_futures):
                try:
                    results = future.result()
                    if isinstance(results, tuple):
                        results, skip_info = results
                    all_results.extend(results)
                    for r in results:
                        if r.status == "success":
                            success_count += 1
                        elif r.status == "failed":
                            fail_count += 1
                        else:
                            error_count += 1
                        # JSONL streaming output
                        if jsonl and r.status == "success":
                            print(json.dumps(asdict(r)), flush=True)
                except Exception as e:
                    logger.error(f"Error scanning target: {e}")

    # Flush any remaining buffered DB writes
    _flush_db_write_buffer()

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

    # Display all results with details
    if all_results:
        logger.info(f"\n{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}")
        logger.info(f"{Fore.CYAN}Results:{Style.RESET_ALL}\n")
        for i, result in enumerate(all_results, 1):
            # Determine status indicator
            if result.status == "success":
                status_icon = f"{Fore.GREEN}✓ SUCCESS{Style.RESET_ALL}"
            elif result.status == "failed":
                status_icon = f"{Fore.YELLOW}✗ FAILED{Style.RESET_ALL}"
            else:
                status_icon = f"{Fore.RED}! ERROR{Style.RESET_ALL}"

            # Format credential display - handle key-based vs password-based
            is_key_auth = result.password and result.password.startswith("key:")
            if is_key_auth:
                # Key-based auth: show key file and cert info
                cred_display = f"({Fore.YELLOW}{result.password}{Style.RESET_ALL})"
            elif result.password:
                cred_display = f":{Fore.YELLOW}{result.password}{Style.RESET_ALL}"
            else:
                cred_display = f":{Fore.YELLOW}(empty){Style.RESET_ALL}"

            target_info = f"{Fore.CYAN}{result.ip}:{result.port}{Style.RESET_ALL} ({Fore.MAGENTA}{result.protocol.upper()}{Style.RESET_ALL})"
            if is_key_auth:
                logger.info(f"  [{status_icon}] {target_info} → {Fore.CYAN}{result.username}{Style.RESET_ALL} {cred_display}")
            else:
                logger.info(f"  [{status_icon}] {target_info} → {Fore.CYAN}{result.username}{Style.RESET_ALL}{cred_display}")

            # Always show details for context
            if result.details:
                logger.info(f"           {Fore.WHITE}{result.details}{Style.RESET_ALL}")

        logger.info(f"\n{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}")

    # Highlight successful credentials at the end
    if successful_results:
        logger.info(f"\n{Fore.GREEN}✓ SUCCESSFUL CREDENTIALS:{Style.RESET_ALL}\n")
        for i, result in enumerate(successful_results, 1):
            is_key_auth = result.password and result.password.startswith("key:")
            prefix = f"{Fore.GREEN}[{i}]{Style.RESET_ALL} " if len(successful_results) > 1 else "    "
            if is_key_auth:
                logger.info(f"{prefix}{Fore.CYAN}{result.ip}:{result.port}{Style.RESET_ALL} ({Fore.MAGENTA}{result.protocol.upper()}{Style.RESET_ALL}) → {Fore.CYAN}{result.username}{Style.RESET_ALL} ({Fore.YELLOW}{result.password}{Style.RESET_ALL})")
            else:
                logger.info(f"{prefix}{Fore.CYAN}{result.ip}:{result.port}{Style.RESET_ALL} ({Fore.MAGENTA}{result.protocol.upper()}{Style.RESET_ALL}) → {Fore.CYAN}{result.username}{Style.RESET_ALL}:{Fore.YELLOW}{result.password or '(empty)'}{Style.RESET_ALL}")
            if result.details:
                logger.info(f"    {Fore.GREEN}→{Style.RESET_ALL} {result.details}")
    else:
        logger.info(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} No successful credentials found")

# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def add_scan_arguments(parser):
    """Add common scan arguments to a parser."""
    # Target options
    parser.add_argument("-t", "--target", help="Single target (IP:PORT)")
    parser.add_argument("-i", "--input-file", help="File with targets (one per line, format IP:PORT)")
    parser.add_argument("-o", "--output-dir", nargs="?", const="", help="Output directory")
    parser.add_argument("--protocol", default="auto", help="Protocol to test (default: auto-detect)")
    parser.add_argument("--protocols", help="Comma-separated list of protocols to test in parallel (e.g. ssh,smb,winrm)")
    parser.add_argument("--port", type=int, help="Default port if not specified in target")

    # Scanning options
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--timeout", type=int, default=5, help="Connection timeout in seconds")
    parser.add_argument("--max-attempts", type=int, default=3, help="Maximum credential attempts per target (default: 3)")

    # Attack mode options
    parser.add_argument("--attack-mode", choices=["default", "spray", "stuff", "single", "key", "credfile"], default="default",
                        help="Attack mode: default (test known creds), spray (one password, many users), stuff (one user, many passwords), single (test one credential pair), key (SSH key/cert authentication), credfile (parse credential file with per-target creds)")
    parser.add_argument("--spray-password", help="Password to spray (for spray mode)")
    parser.add_argument("--stuff-username", help="Username to test (for stuff mode)")
    parser.add_argument("--single-username", help="Username for single credential mode")
    parser.add_argument("--single-password", help="Password for single credential mode")

    # Credential options
    parser.add_argument("--creds-file", help="Custom credentials YAML/JSON file")
    parser.add_argument("--usernames-file", help="File with usernames (one per line) - used with spray mode")
    parser.add_argument("--passwords-file", help="File with passwords (one per line) - used with stuff mode")
    parser.add_argument("--credfile-path", help="Path to credential file (CSV/text/JSON) for credfile attack mode")

    # Credential database options
    parser.add_argument("--sync", action="store_true", help="Sync credentials from external sources before scanning")
    parser.add_argument("--offline", action="store_true", help="Use only cached/builtin credentials (no external fetching)")

    # SSH key authentication options
    parser.add_argument("--ssh-key", help="SSH private key file for key-based authentication")
    parser.add_argument("--ssh-key-passphrase", help="Passphrase for encrypted SSH private key")
    parser.add_argument("--ssh-cert", help="SSH certificate file (-cert.pub) for CA-signed certificate authentication (used with --ssh-key)")

    # Service probing options
    parser.add_argument("--probe", action="store_true", default=True, help="Probe services to confirm protocol before testing (default: on)")
    parser.add_argument("--no-probe", action="store_true", help="Disable service probing, use port-based detection only")

    # Evasion / safety options
    parser.add_argument("--jitter", type=float, default=0.0,
                        help="Random jitter (0 to N seconds) added between tests for evasion (default: 0)")
    parser.add_argument("--max-attempts-per-user", type=int, default=0,
                        help="Max password attempts per username to avoid lockouts (0 = unlimited)")

    # SMB-specific options
    parser.add_argument("--smb-hash", help="NTLM hash for SMB pass-the-hash (format: LMHASH:NTHASH or just NTHASH)")
    parser.add_argument("--domain", help="Domain for SMB/LDAP/WinRM authentication")

    # SSH bad keys options
    parser.add_argument("--badkeys", action="store_true", default=True,
                        help="Test known-compromised SSH keys against targets (default: enabled)")
    parser.add_argument("--no-badkeys", dest="badkeys", action="store_false",
                        help="Disable known-compromised SSH key testing")

    # SNMP tier option
    parser.add_argument("--snmp-tier", choices=["default", "extended", "full"], default="default",
                        help="SNMP community string wordlist tier: default (25), extended (75), full (200+)")

    # Output options
    parser.add_argument("--jsonl", action="store_true",
                        help="Output results as JSON Lines to stdout (one JSON object per line)")

    # Pipeline input
    parser.add_argument("--stdin", action="store_true",
                        help="Read targets from stdin as JSONL (fields: ip, port, service) or IP:PORT lines")

    # Output options (internal)
    parser.add_argument("--scan-id", help="Scan ID for web UI integration (internal use)")


def parse_args():
    """Parse command-line arguments with subcommand support."""
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

{Fore.YELLOW}# Show credential database statistics{Style.RESET_ALL}
cygor credrecon stats

{Fore.YELLOW}# Sync external credential sources{Style.RESET_ALL}
cygor credrecon --sync -i targets.txt

{Fore.CYAN}Supported Protocols ({Fore.WHITE}27{Fore.CYAN}):{Style.RESET_ALL}
  {Fore.WHITE}Web/Shell:{Style.RESET_ALL}    http, ssh, ftp, telnet, rdp, vnc
  {Fore.WHITE}Email:{Style.RESET_ALL}        smtp, smtps, imap, imaps, pop3, pop3s
  {Fore.WHITE}Windows:{Style.RESET_ALL}      smb (pass-the-hash), winrm, winrm-ssl
  {Fore.WHITE}Directory:{Style.RESET_ALL}    ldap, ldaps
  {Fore.WHITE}Databases:{Style.RESET_ALL}    mysql, postgres, mssql, mongodb, redis,
                elasticsearch, couchdb, influxdb, cassandra, neo4j, memcached
  {Fore.WHITE}IoT/ICS:{Style.RESET_ALL}      snmp (tiered wordlists), ipmi, mqtt, mqtts

{Fore.CYAN}Notes:{Style.RESET_ALL}
  - SMB supports pass-the-hash via --smb-hash and domain auth via --domain
  - RDP detects service availability (full NLA/CredSSP auth with aardwolf library)
  - VNC supports password authentication and detects unauthenticated instances
  - LDAP supports both simple bind and NTLM authentication
  - IPMI probes BMC/iLO/iDRAC management interfaces (port 623/UDP)
  - MQTT tests broker authentication including anonymous access detection
  - SSH bad keys: auto-tests known-compromised vendor keys (--no-badkeys to disable)
  - SNMP: --snmp-tier selects community string wordlist depth (default/extended/full)
  - Pipeline: supports JSONL output (--jsonl) and stdin input (--stdin)
"""
    )

    # Create subparsers for subcommands
    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommands")

    # Stats subcommand
    stats_parser = subparsers.add_parser("stats", help="Show credential database statistics")
    stats_parser.add_argument("--json", action="store_true", help="Output stats as JSON")

    # Sync subcommand (alternative to --sync flag)
    sync_parser = subparsers.add_parser("sync", help="Sync credentials from external sources")
    sync_parser.add_argument("--sources", default="all", help="Comma-separated list of sources to sync (default: all)")

    # Add scan arguments to main parser (for direct scanning without subcommand)
    add_scan_arguments(parser)

    return parser.parse_args()

# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def show_credential_stats():
    """Display credential database statistics."""
    try:
        stats = get_credential_stats()
        if "error" in stats:
            logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} {stats['error']}")
            return

        print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════════════{Style.RESET_ALL}")
        print(f"{Fore.CYAN}               CredRecon Credential Database Statistics{Style.RESET_ALL}")
        print(f"{Fore.CYAN}═══════════════════════════════════════════════════════════════{Style.RESET_ALL}\n")

        print(f"{Fore.GREEN}Total Credentials:{Style.RESET_ALL} {stats.get('total', 0)}")
        print(f"{Fore.GREEN}Unique Credentials:{Style.RESET_ALL} {stats.get('unique', 0)}")

        # By category
        by_category = stats.get('by_category', {})
        if by_category:
            print(f"\n{Fore.YELLOW}By Category:{Style.RESET_ALL}")
            for cat, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
                print(f"  {cat}: {count}")

        # By protocol
        by_protocol = stats.get('by_protocol', {})
        if by_protocol:
            print(f"\n{Fore.YELLOW}By Protocol:{Style.RESET_ALL}")
            for proto, count in sorted(by_protocol.items(), key=lambda x: x[1], reverse=True)[:15]:
                print(f"  {proto}: {count}")

        # By source
        by_source = stats.get('by_source', {})
        if by_source:
            print(f"\n{Fore.YELLOW}By Source:{Style.RESET_ALL}")
            for src, count in sorted(by_source.items(), key=lambda x: x[1], reverse=True):
                print(f"  {src}: {count}")

        # By vendor
        by_vendor = stats.get('by_vendor', {})
        if by_vendor:
            print(f"\n{Fore.YELLOW}Top Vendors:{Style.RESET_ALL}")
            for vendor, count in sorted(by_vendor.items(), key=lambda x: x[1], reverse=True)[:10]:
                if vendor:  # Skip empty vendor
                    print(f"  {vendor}: {count}")

        print()

    except Exception as e:
        logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} Failed to get credential stats: {e}")


def sync_credentials(sources: str = "all"):
    """Sync credentials from external sources."""
    try:
        from .sources.sync import CredentialSyncEngine

        print(f"\n{Fore.CYAN}[*]{Style.RESET_ALL} Syncing credentials from external sources...")

        engine = CredentialSyncEngine()

        if sources == "all":
            result = engine.sync_all(force=True)
        else:
            source_list = [s.strip() for s in sources.split(',')]
            result = engine.sync_sources(source_list, force=True)

        if result.success:
            print(f"{Fore.GREEN}[✓]{Style.RESET_ALL} Sync completed successfully!")
            print(f"    Sources synced: {', '.join(result.sources_synced)}")
            print(f"    Total credentials: {result.total_credentials}")
        else:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} Sync completed with errors")
            for src, err in result.errors.items():
                print(f"    {src}: {err}")

        print()
        return result.success

    except ImportError:
        logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} External sources module not available")
        return False
    except Exception as e:
        logger.error(f"{Fore.RED}[!]{Style.RESET_ALL} Sync failed: {e}")
        return False


if __name__ == "__main__":
    args = parse_args()

    # Handle subcommands
    if args.subcommand == "stats":
        # Stats subcommand
        if getattr(args, 'json', False):
            stats = get_credential_stats()
            print(json.dumps(stats, indent=2, default=str))
        else:
            show_credential_stats()
        sys.exit(0)

    elif args.subcommand == "sync":
        # Sync subcommand
        sources = getattr(args, 'sources', 'all')
        success = sync_credentials(sources)
        sys.exit(0 if success else 1)

    # Default: run scan
    # Handle credential sync flag
    if getattr(args, 'sync', False):
        sync_credentials("all")

    # Determine if service probing should be enabled
    probe_services = getattr(args, 'probe', True) and not getattr(args, 'no_probe', False)

    # Run main scan
    # Parse --protocols flag (comma-separated string → list)
    protocols_raw = getattr(args, 'protocols', None)
    protocols_list = [p.strip() for p in protocols_raw.split(',') if p.strip()] if protocols_raw else None

    credrecon(
        input_file=getattr(args, 'input_file', None),
        target=getattr(args, 'target', None),
        output_dir=getattr(args, 'output_dir', None),
        protocol=getattr(args, 'protocol', 'auto'),
        port=getattr(args, 'port', None),
        protocols=protocols_list,
        threads=getattr(args, 'threads', 10),
        timeout=getattr(args, 'timeout', 5),
        creds_file=getattr(args, 'creds_file', None),
        usernames_file=getattr(args, 'usernames_file', None),
        passwords_file=getattr(args, 'passwords_file', None),
        max_attempts=getattr(args, 'max_attempts', 3),
        scan_id=getattr(args, 'scan_id', None),
        attack_mode=getattr(args, 'attack_mode', 'default'),
        credfile_path=getattr(args, 'credfile_path', None),
        spray_password=getattr(args, 'spray_password', None),
        stuff_username=getattr(args, 'stuff_username', None),
        single_username=getattr(args, 'single_username', None),
        single_password=getattr(args, 'single_password', None),
        probe_services=probe_services,
        ssh_key=getattr(args, 'ssh_key', None),
        ssh_key_passphrase=getattr(args, 'ssh_key_passphrase', None),
        ssh_cert=getattr(args, 'ssh_cert', None),
        jitter=getattr(args, 'jitter', 0.0),
        max_attempts_per_user=getattr(args, 'max_attempts_per_user', 0),
        smb_hash=getattr(args, 'smb_hash', None),
        domain=getattr(args, 'domain', None),
        badkeys=getattr(args, 'badkeys', True),
        snmp_tier=getattr(args, 'snmp_tier', 'default'),
        jsonl=getattr(args, 'jsonl', False),
        stdin_mode=getattr(args, 'stdin', False),
    )
