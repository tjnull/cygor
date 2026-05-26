#!/usr/bin/env python3
"""
Lockon - Unified Screenshot Capture Module for Cygor

Captures screenshots from various services:
- HTTP/HTTPS (web services via Playwright)
- RDP (Remote Desktop Protocol)
- VNC (Virtual Network Computing)
- X11 (X Window System)

Usage:
    cygor enum lockon http -f urls.txt        # Web screenshots (HTTP only)
    cygor enum lockon https -f urls.txt       # Web screenshots (HTTPS only)
    cygor enum lockon web -f urls.txt         # Web screenshots (HTTP + HTTPS)
    cygor enum lockon rdp -f targets.txt      # RDP screenshots
    cygor enum lockon vnc -f targets.txt      # VNC screenshots
    cygor enum lockon x11 -f targets.txt      # X11 screenshots
    cygor enum lockon all -f targets.txt      # All protocols
"""

import argparse
import asyncio
import csv
import json
import os
import re
import shutil
import socket
import ssl
import struct
import sys
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from subprocess import DEVNULL, PIPE, TimeoutExpired, run
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from colorama import Fore, Style, init
from requests.exceptions import ConnectionError, HTTPError, RequestException

# Import proxy configuration
from cygor.proxy_config import get_playwright_proxy, get_requests_proxies, is_jumpbox_routing_active

# IP rotation support
# IP rotation is not available in this build; provide a no-op shim.
def get_next_ip(*args, **kwargs):
    return None

# Try to import playwright (optional for web screenshots)
try:
    from playwright.async_api import async_playwright
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


# ----------------------------------------------------------------------
# Module Info for Cygor Module Loader
# ----------------------------------------------------------------------
module_info = {
    "name": "Lockon - Screenshot Capture",
    "slug": "lockon",
    "description": "Unified screenshot capture for HTTP/HTTPS, RDP, VNC, and X11 services.",
    "author": "Cygor Team",
    "version": "2.0.0",
    "module_type": "enumeration",
    "view": "gallery",
    "template": "modules_unified.html",
    "category": "screenshots",
}

# ----------------------------------------------------------------------
# Init
# ----------------------------------------------------------------------
init(autoreset=True, strip=False)
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

MAX_RETRIES = 3
RETRY_DELAY = 2

# Global print lock for thread-safe output
_print_lock = threading.Lock()


def _print_status(tag: str, target: str, status: str, color=None):
    """Pretty-print status lines aligned across threads, thread-safe."""
    if color is None:
        if status in ("SUCCESS", "LIVE"):
            color = Fore.GREEN
        elif status in ("FAILED", "ERROR"):
            color = Fore.RED
        else:
            color = Fore.YELLOW
    tag_fmt = f"[{tag}]".ljust(10)
    target_fmt = target.ljust(55)
    status_fmt = f"({status})".ljust(14)
    line = f"{tag_fmt} {target_fmt} {status_fmt}"
    with _print_lock:
        print(color + line + Style.RESET_ALL, flush=True)


def _color_for_status(code: int) -> str:
    """Get color for HTTP status code."""
    if code is None or code < 0:
        return Fore.MAGENTA
    if 200 <= code < 300:
        return Fore.GREEN
    elif 300 <= code < 400:
        return Fore.CYAN
    elif 400 <= code < 500:
        return Fore.YELLOW
    elif 500 <= code < 600:
        return Fore.RED
    return Fore.MAGENTA


# ----------------------------------------------------------------------
# Utility Functions
# ----------------------------------------------------------------------
def _sanitize_filename(s: str) -> str:
    """Sanitize string for use as filename."""
    s = s.replace("://", "_").replace("/", "_").replace(":", "_").replace("?", "_").replace("&", "_")
    return re.sub(r'[^A-Za-z0-9._-]', '_', s)[:200]


def _fmt_secs(sec: float) -> str:
    """Format seconds to human-readable string."""
    if sec < 1:
        return f"{sec*1000:.0f} ms"
    if sec < 60:
        return f"{sec:.2f} s"
    m, s = divmod(sec, 60)
    if m < 60:
        return f"{int(m)}m {s:.1f}s"
    h, m = divmod(m, 60)
    return f"{int(h)}h {int(m)}m {s:.0f}s"


def _check_port_open(host: str, port: int, timeout: float = 3.0, source_ip: str = None) -> bool:
    """Check if a TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if source_ip:
            sock.bind((source_ip, 0))
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def _parse_host_port(entry: str, default_port: int) -> Tuple[str, int]:
    """Parse host[:port] entry."""
    entry = entry.strip()
    if not entry:
        return "", 0

    # Handle IPv6
    if entry.startswith("["):
        match = re.match(r'\[([^\]]+)\]:?(\d+)?', entry)
        if match:
            host = match.group(1)
            port = int(match.group(2)) if match.group(2) else default_port
            return host, port

    # Handle host:port
    if ":" in entry:
        parts = entry.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return entry, default_port

    return entry, default_port


def _parse_rdp_file(path: str) -> Optional[Dict[str, Any]]:
    """Parse a Windows ``.rdp`` connection file into an RDP target.

    ``.rdp`` files are line-based ``key:type:value`` entries (type ``s``
    string, ``i`` int, ``b`` binary).  We pull out the connection target
    plus any stored username/domain.  The stored password
    (``password 51:b:...``) is DPAPI-encrypted and unusable off-Windows, so
    the actual password must still be supplied via ``--rdp-pass``.

    Returns a dict ``{host, port, user, domain, source}`` or ``None`` if the
    file can't be read or has no usable target.
    """
    p = Path(path)
    if not p.is_file():
        return None

    # .rdp files written on Windows are commonly UTF-16-LE with a BOM; files
    # created elsewhere are usually UTF-8. Detect the BOM so we don't garble a
    # UTF-8 file by force-decoding it as UTF-16.
    text = None
    try:
        raw = p.read_bytes()
    except Exception:
        return None
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        encodings = ("utf-16", "utf-8-sig", "utf-8", "latin-1")
    else:
        encodings = ("utf-8-sig", "utf-8", "latin-1")
    for enc in encodings:
        try:
            text = raw.decode(enc)
            break
        except Exception:
            continue
    if text is None:
        return None

    full_address = ""
    server_port: Optional[int] = None
    user = ""
    domain = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        key = parts[0].strip().lower()
        value = parts[2].strip()
        if key == "full address":
            full_address = value
        elif key == "alternate full address" and not full_address:
            full_address = value
        elif key == "server port":
            try:
                server_port = int(value)
            except ValueError:
                pass
        elif key == "username":
            user = value
        elif key == "domain":
            domain = value

    if not full_address:
        return None

    host, addr_port = _parse_host_port(full_address, server_port or 3389)
    if not host:
        return None
    # An explicit port in "full address" wins; otherwise honour "server port".
    port = addr_port

    # username is sometimes stored as DOMAIN\\user.
    if user and "\\" in user and not domain:
        domain, user = user.split("\\", 1)

    return {
        "host": host,
        "port": port,
        "user": user or "",
        "domain": domain or "",
        "source": str(p),
    }


def _read_targets_file(file_path: str) -> List[str]:
    """Read targets from file (one per line)."""
    path = Path(file_path)
    if not path.is_file():
        print(Fore.RED + f"File not found: {file_path}")
        return []

    targets = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
    return targets


# ----------------------------------------------------------------------
# Output Directory Management
# ----------------------------------------------------------------------
def _get_output_dir(custom_output: Optional[str] = None) -> Path:
    """Get the output directory, respecting workspace settings (no ./results)."""
    if custom_output:
        out_dir = Path(custom_output)
    else:
        from cygor.workspace import require_workspace
        out_dir = require_workspace() / "cygor-enumeration-modules" / "lockon"

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "screenshots").mkdir(exist_ok=True)
    return out_dir


def _archive_current_results(out_dir: Path) -> Optional[Path]:
    """Archive current screenshots + results before a new scan overwrites them.

    Copies cygor-result.json and all screenshot PNGs into a timestamped
    subfolder under screenshots/archive/.  The timestamp is derived from
    the previous scan's metadata.started_at field.
    """
    json_path = out_dir / "cygor-result.json"
    if not json_path.exists():
        return None

    # Determine timestamp for the archive folder name
    try:
        raw = json.loads(json_path.read_text(encoding="utf-8"))
        started_at_str = raw.get("metadata", {}).get("started_at", "")
        if started_at_str:
            ts = datetime.fromisoformat(started_at_str)
            folder_name = ts.strftime("%Y-%m-%d_%H-%M-%S")
        else:
            mtime = json_path.stat().st_mtime
            folder_name = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d_%H-%M-%S")
    except Exception:
        mtime = json_path.stat().st_mtime
        folder_name = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d_%H-%M-%S")

    archive_dir = out_dir / "screenshots" / "archive" / folder_name
    if archive_dir.exists():
        # Already archived (e.g. interrupted re-run)
        return archive_dir

    archive_dir.mkdir(parents=True, exist_ok=True)

    # Copy cygor-result.json
    shutil.copy2(str(json_path), str(archive_dir / "cygor-result.json"))

    # Copy all screenshot PNGs (non-recursive — only the root screenshots/ dir)
    shots_dir = out_dir / "screenshots"
    for png in shots_dir.glob("*.png"):
        shutil.copy2(str(png), str(archive_dir / png.name))

    print(Fore.YELLOW + f"[*] Archived previous scan -> {archive_dir}" + Style.RESET_ALL)
    return archive_dir


# ======================================================================
# WEB SCREENSHOTS (HTTP/HTTPS)
# ======================================================================
def _is_full_url(s: str) -> bool:
    return s.lower().startswith("http://") or s.lower().startswith("https://")


def _expand_to_urls(entries: List[str], scheme: str) -> List[str]:
    """Expand host entries to URLs with specified scheme(s)."""
    urls = []
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        if _is_full_url(entry):
            urls.append(entry)
        elif scheme == "both":
            urls.append(f"http://{entry}")
            urls.append(f"https://{entry}")
        else:
            urls.append(f"{scheme}://{entry}")
    return urls


class _SourceIPAdapter(requests.adapters.HTTPAdapter):
    """HTTPAdapter that binds to a specific source IP address."""
    def __init__(self, source_address, **kwargs):
        self._source_address = source_address
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["source_address"] = (self._source_address, 0)
        super().init_poolmanager(*args, **kwargs)


def _test_url_reachability(url: str, timeout: float, source_ip: str = None) -> Tuple[str, int]:
    """Test if URL is reachable, return (url, status_code)."""
    proxies = get_requests_proxies()
    session = requests.Session()
    if source_ip:
        adapter = _SourceIPAdapter(source_ip)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
    retries = 0
    while retries < MAX_RETRIES:
        try:
            r = session.get(url, timeout=timeout, verify=False, proxies=proxies)
            return url, r.status_code
        except (RequestException, ConnectionError):
            retries += 1
            if retries < MAX_RETRIES:
                time.sleep(RETRY_DELAY)
        except HTTPError as e:
            return url, getattr(e.response, "status_code", 0)
        except Exception:
            return url, -1
    return url, -1


def _pw_install_browser(engine: str) -> bool:
    """Download a Playwright browser binary. No root required."""
    print(Fore.CYAN + f"[*] Installing Playwright {engine} browser (one-time, no sudo needed)..." + Style.RESET_ALL)
    try:
        r = run([sys.executable, "-m", "playwright", "install", engine],
                stdout=PIPE, stderr=PIPE, timeout=900)
        return r.returncode == 0
    except Exception as e:
        print(Fore.YELLOW + f"[!] Browser download failed: {str(e)[:120]}" + Style.RESET_ALL)
        return False


def _pw_install_deps(engine: str) -> bool:
    """Install the browser's OS dependencies, but only non-interactively so we
    never prompt or hang: directly when root, else via passwordless/cached sudo."""
    base = [sys.executable, "-m", "playwright", "install-deps", engine]
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            cmd = base
        elif shutil.which("sudo") and run(["sudo", "-n", "true"],
                                          stdout=DEVNULL, stderr=DEVNULL).returncode == 0:
            cmd = ["sudo", "-n"] + base
        else:
            return False  # needs an interactive sudo password; caller will guide
        print(Fore.CYAN + f"[*] Installing {engine} system dependencies..." + Style.RESET_ALL)
        return run(cmd, stdout=PIPE, stderr=PIPE, timeout=600).returncode == 0
    except Exception:
        return False


async def _try_launch_engine(engine: str) -> str:
    """Try launching a browser. Returns ok | missing_browser | missing_deps | error."""
    try:
        async with async_playwright() as p:
            eng = getattr(p, engine, None)
            if eng is None:
                return "error"
            launch_args = {"headless": True}
            if engine == "chromium":
                launch_args["args"] = ["--no-sandbox", "--disable-setuid-sandbox", "--ignore-certificate-errors"]
            browser = await eng.launch(**launch_args)
            await browser.close()
        return "ok"
    except Exception as e:
        msg = str(e).lower()
        # Check deps first: the missing-deps error text also contains the string
        # "install-deps" (which would falsely match a generic "install" check).
        if ("missing dependencies" in msg or "host system is missing" in msg
                or "error while loading shared libraries" in msg or "install-deps" in msg):
            return "missing_deps"
        if "executable doesn't exist" in msg or "looks like playwright" in msg:
            return "missing_browser"
        return "error"


async def _ensure_playwright_browser(requested: str = "chromium", auto_install: bool = True) -> Optional[str]:
    """Return a launchable Playwright browser engine name, or None.

    Precheck so web screenshots "just work" on first run: auto-downloads the
    browser binary (no sudo), resolves missing OS deps non-interactively when
    possible, and falls back to chromium (most portable on Linux) if the
    requested engine can't run. Never prompts or hangs; prints the exact one-line
    fix if something genuinely needs manual action.
    """
    if not HAS_PLAYWRIGHT:
        print(Fore.YELLOW + "[!] The 'playwright' Python package is not installed. "
              f"Run: {sys.executable} -m pip install playwright" + Style.RESET_ALL)
        return None

    order, seen = [], set()
    for e in (requested, "chromium", "webkit", "firefox"):
        if e and e not in seen:
            seen.add(e)
            order.append(e)

    needs_deps = []
    for engine in order:
        status = await _try_launch_engine(engine)
        if status == "missing_browser" and auto_install:
            if _pw_install_browser(engine):
                status = await _try_launch_engine(engine)
                if status == "missing_deps" and _pw_install_deps(engine):
                    status = await _try_launch_engine(engine)
        elif status == "missing_deps" and auto_install:
            if _pw_install_deps(engine):
                status = await _try_launch_engine(engine)
        if status == "ok":
            if engine != requested:
                print(Fore.CYAN + f"[i] Using {engine} (requested '{requested}' isn't "
                      f"usable on this host)" + Style.RESET_ALL)
            return engine
        if status == "missing_deps":
            needs_deps.append(engine)

    if needs_deps:
        eng = needs_deps[0]
        print(Fore.YELLOW + f"[!] {eng} is installed but needs OS libraries. Run once: "
              f"sudo {sys.executable} -m playwright install-deps {eng}" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "[!] No usable Playwright browser could be prepared. Run: "
              f"{sys.executable} -m playwright install chromium" + Style.RESET_ALL)
    return None


def _fingerprint_web(headers: Dict[str, str]) -> str:
    """Light tech fingerprint from response headers (no extra requests)."""
    bits: List[str] = []
    for key, label in (("server", None), ("x-powered-by", None),
                       ("x-aspnet-version", "ASP.NET"), ("x-generator", None)):
        val = (headers.get(key) or "").strip()
        if val:
            bits.append(f"{label} {val}" if label else val)
    cookie = (headers.get("set-cookie") or "").lower()
    if "phpsessid" in cookie:
        bits.append("PHP")
    if "jsessionid" in cookie:
        bits.append("Java")
    if "asp.net_sessionid" in cookie or "aspsessionid" in cookie:
        bits.append("ASP.NET")
    seen, out = set(), []
    for b in bits:
        if b and b not in seen:
            seen.add(b)
            out.append(b)
    return ", ".join(out)


def _tls_cert_info(host: str, port: int, timeout: float = 5) -> str:
    """Best-effort TLS cert summary (CN + expiry), tolerating invalid certs.

    Uses cryptography (a guaranteed transitive dep via paramiko) and CERT_NONE
    so self-signed/expired lab certs still parse.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception:
        return ""
    if not der:
        return ""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        cert = x509.load_der_x509_certificate(der)
        cn = ""
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            cn = attrs[0].value
        try:
            exp = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        except AttributeError:
            exp = cert.not_valid_after.strftime("%Y-%m-%d")
        return f"CN={cn}; exp={exp}" if cn else f"exp={exp}"
    except Exception:
        return ""


# Web-data keys recorded alongside each screenshot; defaulted empty so rows stay
# uniform across success/failure/skip and non-web protocols.
_WEB_DATA_KEYS = {
    "http_status": "", "title": "", "server": "", "content_type": "",
    "tech": "", "tls": "", "redirect": "",
}


async def _extract_web_data(page, response, requested_url: str,
                            host: str, port: str, protocol: str) -> Dict[str, str]:
    """Harvest structured web facts from a page already loaded for screenshotting.

    This is data the browser produced during navigation and we'd otherwise throw
    away -- status, title, server, tech fingerprint, redirect, TLS cert -- so the
    inventory is queryable (e.g. "all nginx hosts with a cert expiring soon"),
    which a screenshot alone can't answer.
    """
    data = dict(_WEB_DATA_KEYS)
    try:
        if response is not None:
            data["http_status"] = str(response.status)
            headers = response.headers or {}
            data["server"] = (headers.get("server") or "").strip()
            data["content_type"] = (headers.get("content-type") or "").split(";")[0].strip()
            data["tech"] = _fingerprint_web(headers)
            final = response.url or ""
            if final and final.rstrip("/") != (requested_url or "").rstrip("/"):
                data["redirect"] = final
    except Exception:
        pass
    try:
        data["title"] = (await page.title() or "").strip()[:120]
    except Exception:
        pass
    if protocol == "https":
        try:
            loop = asyncio.get_event_loop()
            data["tls"] = await loop.run_in_executor(
                None, _tls_cert_info, host, int(port), 5)
        except Exception:
            pass
    return data


async def _capture_web_screenshots(
    urls: List[str],
    out_dir: Path,
    workers: int,
    nav_timeout: int,
    viewport: str,
    extra_wait: int,
    install_browsers: bool = False,
    browser_engine: str = "chromium",
) -> List[Dict[str, Any]]:
    """Capture web screenshots using Playwright (webkit, chromium, or firefox)."""
    shots_dir = out_dir / "screenshots"
    results = []

    resolved_engine = await _ensure_playwright_browser(requested=browser_engine, auto_install=True)
    if not resolved_engine:
        print(Fore.YELLOW + f"[!] No Playwright browser available, skipping web screenshots" + Style.RESET_ALL)
        for url in urls:
            results.append({
                "host": urlparse(url).hostname or "",
                "port": str(urlparse(url).port or (443 if url.startswith("https") else 80)),
                "protocol": "https" if url.startswith("https") else "http",
                "url": url,
                "status": "SKIPPED",
                "screenshot_file": "",
                "screenshot_failed": True,
                **dict(_WEB_DATA_KEYS),
            })
        return results

    w, h = viewport.split("x") if "x" in viewport else (1366, 768)
    w, h = int(w), int(h)

    sem = asyncio.Semaphore(workers)
    playwright_proxy = get_playwright_proxy()

    print(Fore.CYAN + f"[*] Browser engine: {resolved_engine}" + Style.RESET_ALL)

    async with async_playwright() as p:
        engine = getattr(p, resolved_engine, p.chromium)
        launch_args = {"headless": True}
        if resolved_engine == "chromium":
            launch_args["args"] = ["--ignore-certificate-errors", "--no-sandbox", "--disable-setuid-sandbox"]
        if playwright_proxy:
            launch_args["proxy"] = playwright_proxy

        browser = await engine.launch(**launch_args)
        ctx = await browser.new_context(
            viewport={"width": w, "height": h},
            ignore_https_errors=True,
        )

        async def capture_one(url: str):
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
            protocol = parsed.scheme

            filename = f"{protocol}_{_sanitize_filename(url)}.png"
            filepath = shots_dir / filename

            async with sem:
                page = await ctx.new_page()
                try:
                    page.set_default_navigation_timeout(nav_timeout)
                    response = await page.goto(url, wait_until="load")
                    if extra_wait > 0:
                        await page.wait_for_timeout(extra_wait)
                    await page.screenshot(path=str(filepath), full_page=True)
                    web = await _extract_web_data(page, response, url, host, port, protocol)
                    _print_status("WEB", url[:50], "SUCCESS", Fore.GREEN)
                    return {
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "url": url,
                        "status": "SUCCESS",
                        "screenshot_file": filename,
                        "screenshot_url": f"/modules/lockon/screenshots/{filename}",
                        "screenshot_failed": False,
                        **web,
                    }
                except Exception as e:
                    _print_status("WEB", url[:50], "FAILED", Fore.RED)
                    return {
                        "host": host,
                        "port": port,
                        "protocol": protocol,
                        "url": url,
                        "status": "FAILED",
                        "screenshot_file": "",
                        "screenshot_failed": True,
                        "error": str(e)[:100],
                        **dict(_WEB_DATA_KEYS),
                    }
                finally:
                    await page.close()

        results = await asyncio.gather(*(capture_one(url) for url in urls))
        await ctx.close()
        await browser.close()

    return list(results)


# ======================================================================
# Native (pure-Python) capture backends for RDP / VNC / X11
# ----------------------------------------------------------------------
# These speak the protocol directly -- no external tools (xfreerdp/vncsnapshot)
# and no local display/Xvfb -- and are auto-installed on first use, like the
# Playwright browser. Each capture function tries the native backend first and
# falls back to the external tool path if the library is unavailable or fails.
# ======================================================================
_PIP_PKGS = {  # import name -> pip distribution name
    "asyncvnc": "asyncvnc",
    "Xlib": "python-xlib",
    "aardwolf": "aardwolf",
}


def _ensure_pip_package(import_name: str) -> bool:
    """Import a capture backend, pip-installing it once if missing (no sudo)."""
    import importlib
    try:
        importlib.import_module(import_name)
        return True
    except Exception:
        pass
    pip_name = _PIP_PKGS.get(import_name, import_name)
    print(Fore.CYAN + f"[*] Installing {pip_name} (one-time, no sudo needed)..." + Style.RESET_ALL)
    try:
        run([sys.executable, "-m", "pip", "install", pip_name], stdout=PIPE, stderr=PIPE, timeout=600)
        importlib.import_module(import_name)
        return True
    except Exception as e:
        print(Fore.YELLOW + f"[!] Could not install {pip_name}: {str(e)[:100]}" + Style.RESET_ALL)
        return False


def _save_image(obj, filepath: Path) -> bool:
    """Save a PIL image or a numpy array to PNG; True if a non-empty file results."""
    try:
        if hasattr(obj, "save"):
            obj.save(str(filepath))
        else:
            from PIL import Image
            Image.fromarray(obj).save(str(filepath))
        return filepath.exists() and filepath.stat().st_size > 0
    except Exception:
        return False


def _vnc_capture_native(host: str, port: int, password, filepath: Path, timeout: int) -> Tuple[bool, str]:
    """Capture a VNC framebuffer with asyncvnc. Returns (ok, info)."""
    if not _ensure_pip_package("asyncvnc"):
        return False, "asyncvnc unavailable"
    import asyncvnc

    async def _go():
        async with asyncvnc.connect(host, port, password=password) as client:
            return await asyncio.wait_for(client.screenshot(), timeout=timeout)
    try:
        px = asyncio.run(_go())
    except Exception as e:
        return False, str(e)[:120]
    return (_save_image(px, filepath), "asyncvnc")


def _x11_capture_native(host: str, display: int, filepath: Path) -> Tuple[bool, str]:
    """Capture an open X11 root window with python-xlib. Returns (ok, info)."""
    if not _ensure_pip_package("Xlib"):
        return False, "python-xlib unavailable"
    try:
        from Xlib import display as xdisplay, X
        from PIL import Image
        d = xdisplay.Display(f"{host}:{display}")
        root = d.screen().root
        g = root.get_geometry()
        raw = root.get_image(0, 0, g.width, g.height, X.ZPixmap, 0xffffffff)
        img = Image.frombytes("RGB", (g.width, g.height), raw.data, "raw", "BGRX")
        ok = _save_image(img, filepath)
        d.close()
        return ok, "python-xlib"
    except Exception as e:
        return False, str(e)[:120]


def _rdp_capture_native(host: str, port: int, user, password, domain, filepath: Path,
                        timeout: int, width: int = 1024, height: int = 768) -> Tuple[bool, str]:
    """Capture an RDP desktop with aardwolf. Returns (ok, info)."""
    if not _ensure_pip_package("aardwolf"):
        return False, "aardwolf unavailable"
    try:
        from aardwolf.commons.factory import RDPConnectionFactory
        from aardwolf.commons.iosettings import RDPIOSettings
        from aardwolf.commons.queuedata.constants import VIDEO_FORMAT
    except Exception as e:
        return False, f"aardwolf import: {str(e)[:80]}"

    if user:
        prefix = f"{domain}\\{user}" if domain else user
        url = f"rdp+ntlm-password://{prefix}:{password or ''}@{host}:{port}"
    else:
        url = f"rdp+plain://{host}:{port}"  # login-screen capture when NLA isn't enforced

    async def _go():
        ios = RDPIOSettings()
        ios.channels = []
        ios.video_width = width
        ios.video_height = height
        ios.video_bpp_min = 15
        ios.video_bpp_max = 32
        ios.video_out_format = VIDEO_FORMAT.PIL
        ios.clipboard_use_pyperclip = False
        factory = RDPConnectionFactory.from_url(url, ios)
        conn = factory.get_connection(ios)
        _, err = await asyncio.wait_for(conn.connect(), timeout=timeout)
        if err is not None:
            raise err
        await asyncio.sleep(min(5, max(2, timeout - 2)))
        ok = False
        try:
            if getattr(conn, "desktop_buffer_has_data", False):
                img = conn.get_desktop_buffer(VIDEO_FORMAT.PIL)
                ok = _save_image(img, filepath)
        finally:
            await conn.terminate()
        return ok
    try:
        return asyncio.run(_go()), "aardwolf"
    except Exception as e:
        return False, str(e)[:120]


# ======================================================================
# RDP SCREENSHOTS
# ======================================================================
def _find_rdp_tool() -> Tuple[Optional[str], str]:
    """Find available RDP screenshot tool."""
    for tool_name in ["rdpy-rdpscreenshot", "xfreerdp", "xfreerdp3", "rdesktop"]:
        path = shutil.which(tool_name)
        if path:
            return path, tool_name.replace("-", "_")
    return None, "none"


def _capture_rdp_screenshot(
    host: str, port: int, shots_dir: Path, tool: Optional[str], tool_path: Optional[str],
    timeout: int, viewport: str,
    rdp_user: Optional[str] = None, rdp_pass: Optional[str] = None,
    rdp_domain: Optional[str] = None,
) -> Dict[str, Any]:
    """Capture a single RDP screenshot."""
    target_str = f"{host}:{port}"

    if not _check_port_open(host, port, 5.0):
        _print_status("RDP", target_str, "PORT_CLOSED", Fore.YELLOW)
        return {
            "host": host,
            "port": str(port),
            "protocol": "rdp",
            "status": "PORT_CLOSED",
            "screenshot_file": "",
            "screenshot_failed": True,
        }

    _print_status("RDP", target_str, "CONNECTING", Fore.CYAN)

    filename = f"rdp_{host.replace('.', '_')}_{port}.png"
    filepath = shots_dir / filename
    success = False
    ext_info = ""  # error from the external-tool fallback (kept apart from native)

    # Native capture first (aardwolf): no external tool or display required.
    try:
        vw, vh = (int(x) for x in viewport.split("x")) if "x" in viewport else (1024, 768)
    except Exception:
        vw, vh = 1024, 768
    nat_ok, nat_info = _rdp_capture_native(host, port, rdp_user, rdp_pass, rdp_domain,
                                           filepath, max(8, min(timeout, 30)), vw, vh)
    if nat_ok:
        _print_status("RDP", target_str, "SUCCESS", Fore.GREEN)
        return {
            "host": host,
            "port": str(port),
            "protocol": "rdp",
            "status": "SUCCESS",
            "screenshot_file": filename,
            "screenshot_url": f"/modules/lockon/screenshots/{filename}",
            "screenshot_failed": False,
        }
    try:
        if not tool_path:
            pass  # no external tool; native attempt above is all we have
        elif tool in ("xfreerdp", "xfreerdp3"):
            w, h = viewport.split("x") if "x" in viewport else (1024, 768)
            cmd = [
                tool_path,
                f"/v:{host}:{port}",
                f"/size:{w}x{h}",
                "/cert:ignore",
                "/cert-tofu",
                "/sec:any",
                "/log-level:OFF",
                f"/screenshot:{filepath}",
                "/timeout:5000",
            ]
            if rdp_user:
                cmd.append(f"/u:{rdp_user}")
            if rdp_pass:
                cmd.append(f"/p:{rdp_pass}")
            if rdp_domain:
                cmd.append(f"/d:{rdp_domain}")
            if not rdp_user:
                # No creds: disable NLA so the login screen can be captured.
                # "-sec-nla" is the correct flag for FreeRDP 2.x/3.x ("-nla"
                # is rejected by the command-line parser).
                cmd.append("-sec-nla")
            proc = run(cmd, stdout=DEVNULL, stderr=PIPE, timeout=timeout, text=True)
            success = filepath.exists()
            ext_info = proc.stderr[:100] if proc.stderr else ""
        elif tool == "rdpy_rdpscreenshot":
            cmd = [tool_path, f"{host}:{port}", str(shots_dir)]
            proc = run(cmd, stdout=PIPE, stderr=PIPE, timeout=timeout, text=True)
            # rdpy creates different filenames, check for them
            for candidate in [filepath, shots_dir / f"{host}_{port}.png", shots_dir / f"{host}.png"]:
                if candidate.exists() and candidate != filepath:
                    candidate.rename(filepath)
                    success = True
                    break
            else:
                success = filepath.exists()
            ext_info = proc.stderr[:100] if proc.stderr else ""
        elif tool == "rdesktop":
            w, h = viewport.split("x") if "x" in viewport else (1024, 768)
            cmd = [tool_path, "-g", f"{w}x{h}", f"{host}:{port}"]
            if rdp_user:
                cmd.extend(["-u", rdp_user])
            if rdp_pass:
                cmd.extend(["-p", rdp_pass])
            # rdesktop doesn't have a native screenshot flag, use with
            # import (ImageMagick) to grab the window after a brief delay
            import_tool = shutil.which("import")
            if import_tool:
                # Start rdesktop in background, capture after delay, then kill
                import signal
                proc = __import__("subprocess").Popen(
                    cmd, stdout=DEVNULL, stderr=PIPE, env={**os.environ, "DISPLAY": os.environ.get("DISPLAY", ":0")},
                )
                time.sleep(min(8, timeout // 2))
                try:
                    run([import_tool, "-window", "root", str(filepath)],
                        stdout=PIPE, stderr=PIPE, timeout=10, text=True,
                        env={**os.environ, "DISPLAY": os.environ.get("DISPLAY", ":0")})
                    success = filepath.exists()
                finally:
                    proc.send_signal(signal.SIGTERM)
                    proc.wait(timeout=5)
            else:
                ext_info = "rdesktop requires ImageMagick 'import' for screenshots"
    except TimeoutExpired:
        ext_info = "Timeout"
    except Exception as e:
        ext_info = str(e)[:100]

    if success:
        _print_status("RDP", target_str, "SUCCESS", Fore.GREEN)
        return {
            "host": host,
            "port": str(port),
            "protocol": "rdp",
            "status": "SUCCESS",
            "screenshot_file": filename,
            "screenshot_url": f"/modules/lockon/screenshots/{filename}",
            "screenshot_failed": False,
        }
    else:
        # Prefer the native backend's error -- aardwolf speaks CredSSP/NLA
        # directly so it reports the real auth/protocol failure (e.g. a
        # logon-failure code). Fall back to the external tool's error only
        # when the native backend couldn't run at all.
        native_unusable = (not nat_info) or ("unavailable" in nat_info) or ("aardwolf import" in nat_info)
        if native_unusable:
            error = ext_info or nat_info or "capture failed"
        elif ext_info and ext_info[:60] != nat_info[:60]:
            error = f"native: {nat_info}"
        else:
            error = nat_info
        _print_status("RDP", target_str, "FAILED", Fore.RED)
        return {
            "host": host,
            "port": str(port),
            "protocol": "rdp",
            "status": "FAILED",
            "screenshot_file": "",
            "screenshot_failed": True,
            "error": error,
        }


def _normalize_rdp_target(
    target: Any, default_user: Optional[str], default_domain: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Normalize an RDP target into ``{host, port, user, domain}``.

    Accepts a ``(host, port)`` tuple or a dict (e.g. parsed from a ``.rdp``
    file).  Per-target ``user``/``domain`` take precedence; the CLI-supplied
    ``--rdp-user``/``--domain`` act as fallbacks.
    """
    if isinstance(target, dict):
        host = target.get("host", "")
        port = target.get("port", 3389)
        user = target.get("user") or default_user
        domain = target.get("domain") or default_domain
    else:
        host, port = target
        user, domain = default_user, default_domain
    if not host:
        return None
    return {"host": host, "port": int(port), "user": user or None, "domain": domain or None}


def capture_rdp_screenshots(
    targets: List[Any], out_dir: Path, workers: int, timeout: int, viewport: str,
    rdp_user: Optional[str] = None, rdp_pass: Optional[str] = None,
    rdp_domain: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Capture RDP screenshots for multiple targets.

    ``targets`` may be ``(host, port)`` tuples or dicts carrying per-target
    ``user``/``domain`` (as produced by :func:`_parse_rdp_file`).
    """
    shots_dir = out_dir / "screenshots"

    # Warn if jumpbox is active - RDP tools need proxychains for SOCKS routing
    if is_jumpbox_routing_active():
        print(Fore.CYAN + "[i] Jumpbox active - RDP screenshots may need proxychains wrapper" + Style.RESET_ALL)

    norm = [
        t for t in (_normalize_rdp_target(t, rdp_user, rdp_domain) for t in targets) if t
    ]

    # Native aardwolf backend needs no external tool; only inform the user.
    tool_path, tool = _find_rdp_tool()
    if tool_path:
        print(Fore.GREEN + f"[+] RDP tool: {tool} ({tool_path}); native backend tried first" + Style.RESET_ALL)
    else:
        print(Fore.CYAN + "[i] No external RDP tool; using native backend (aardwolf)" + Style.RESET_ALL)

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                _capture_rdp_screenshot, t["host"], t["port"], shots_dir, tool, tool_path,
                timeout, viewport, t["user"], rdp_pass, t["domain"],
            ): t
            for t in norm
        }
        for fut in as_completed(futures):
            t = futures[fut]
            try:
                results.append(fut.result())
            except Exception as e:
                results.append({
                    "host": t["host"],
                    "port": str(t["port"]),
                    "protocol": "rdp",
                    "status": "ERROR",
                    "screenshot_file": "",
                    "screenshot_failed": True,
                    "error": str(e)[:100],
                })
    return results


# ======================================================================
# VNC SCREENSHOTS
# ======================================================================
def _find_vnc_tool() -> Tuple[Optional[str], str]:
    """Find available VNC screenshot tool."""
    for tool_name in ["vncsnapshot", "vncdotool", "vncdo"]:
        path = shutil.which(tool_name)
        if path:
            return path, tool_name
    return None, "none"


def _get_vnc_auth_type(host: str, port: int, timeout: float = 5.0) -> Tuple[str, str]:
    """Get VNC server info and auth type."""
    vnc_version = ""
    auth_type = "unknown"

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        version_data = sock.recv(12)
        if version_data:
            vnc_version = version_data.decode('latin-1', errors='ignore').strip()
            sock.send(version_data)

            if vnc_version.startswith("RFB"):
                try:
                    num_types_data = sock.recv(1)
                    if num_types_data:
                        num_types = struct.unpack('B', num_types_data)[0]
                        if num_types > 0:
                            sec_types = sock.recv(num_types)
                            types = list(sec_types)
                            if 1 in types:
                                auth_type = "None"
                            elif 2 in types:
                                auth_type = "VNC_Auth"
                            else:
                                auth_type = f"Type_{types[0]}" if types else "unknown"
                except Exception:
                    pass
        sock.close()
    except Exception:
        pass

    return vnc_version, auth_type


def _capture_vnc_screenshot(
    host: str, port: int, shots_dir: Path, tool: str, tool_path: str, timeout: int, password: Optional[str]
) -> Dict[str, Any]:
    """Capture a single VNC screenshot."""
    target_str = f"{host}:{port}"

    if not _check_port_open(host, port, 5.0):
        _print_status("VNC", target_str, "PORT_CLOSED", Fore.YELLOW)
        return {
            "host": host,
            "port": str(port),
            "protocol": "vnc",
            "status": "PORT_CLOSED",
            "screenshot_file": "",
            "screenshot_failed": True,
        }

    vnc_version, auth_type = _get_vnc_auth_type(host, port)
    _print_status("VNC", target_str, f"AUTH:{auth_type[:8]}", Fore.CYAN)

    # Only bail on confirmed auth requirement without a password.
    # If the probe failed ("unknown"), still attempt the screenshot — it may work.
    if auth_type not in ("None", "unknown") and not password:
        return {
            "host": host,
            "port": str(port),
            "protocol": "vnc",
            "status": "AUTH_REQUIRED",
            "screenshot_file": "",
            "screenshot_failed": True,
            "auth_type": auth_type,
        }

    filename = f"vnc_{host.replace('.', '_')}_{port}.png"
    filepath = shots_dir / filename
    success = False
    info = ""
    passwd_file = None

    # Native capture first (asyncvnc): no external VNC tool required.
    nat_ok, nat_info = _vnc_capture_native(host, port, password, filepath, max(8, min(timeout, 30)))
    if nat_ok:
        _print_status("VNC", target_str, "SUCCESS", Fore.GREEN)
        return {
            "host": host,
            "port": str(port),
            "protocol": "vnc",
            "status": "SUCCESS",
            "screenshot_file": filename,
            "screenshot_url": f"/modules/lockon/screenshots/{filename}",
            "screenshot_failed": False,
            "auth_type": auth_type,
        }
    info = nat_info

    try:
        if tool == "vncsnapshot":
            display = port - 5900 if port >= 5900 else 0
            cmd = [tool_path, f"{host}:{display}", str(filepath)]
            if password:
                # vncsnapshot -passwd expects a path to a VNC passwd file, not plaintext.
                # Write the password to a temp file in the shots directory.
                import tempfile
                fd, passwd_file = tempfile.mkstemp(prefix="vnc_pw_", dir=str(shots_dir))
                os.write(fd, password.encode("utf-8"))
                os.close(fd)
                cmd = [tool_path, "-passwd", passwd_file, f"{host}:{display}", str(filepath)]
            proc = run(cmd, stdout=PIPE, stderr=PIPE, timeout=timeout, text=True)
            success = filepath.exists()
            info = proc.stderr[:100] if proc.stderr else ""
        elif tool in ("vncdotool", "vncdo"):
            cmd = [tool_path, "-s", f"{host}::{port}"]
            if password:
                cmd.extend(["-p", password])
            cmd.extend(["capture", str(filepath)])
            proc = run(cmd, stdout=PIPE, stderr=PIPE, timeout=timeout, text=True)
            success = filepath.exists()
            info = proc.stderr[:100] if proc.stderr else ""
    except TimeoutExpired:
        info = "Timeout"
    except Exception as e:
        info = str(e)[:100]
    finally:
        # Clean up temp passwd file
        if passwd_file:
            try:
                os.unlink(passwd_file)
            except OSError:
                pass

    if success:
        _print_status("VNC", target_str, "SUCCESS", Fore.GREEN)
        return {
            "host": host,
            "port": str(port),
            "protocol": "vnc",
            "status": "SUCCESS",
            "screenshot_file": filename,
            "screenshot_url": f"/modules/lockon/screenshots/{filename}",
            "screenshot_failed": False,
            "auth_type": auth_type,
        }
    else:
        _print_status("VNC", target_str, "FAILED", Fore.RED)
        return {
            "host": host,
            "port": str(port),
            "protocol": "vnc",
            "status": "FAILED",
            "screenshot_file": "",
            "screenshot_failed": True,
            "auth_type": auth_type,
            "error": info,
        }


def capture_vnc_screenshots(
    targets: List[Tuple[str, int]], out_dir: Path, workers: int, timeout: int, password: Optional[str]
) -> List[Dict[str, Any]]:
    """Capture VNC screenshots for multiple targets."""
    shots_dir = out_dir / "screenshots"

    # Warn if jumpbox is active - VNC tools need proxychains for SOCKS routing
    if is_jumpbox_routing_active():
        print(Fore.CYAN + "[i] Jumpbox active - VNC screenshots may need proxychains wrapper" + Style.RESET_ALL)

    tool_path, tool = _find_vnc_tool()

    if not tool_path:
        print(Fore.CYAN + "[i] No external VNC tool; using the native asyncvnc backend." + Style.RESET_ALL)
        tool, tool_path = None, None
    else:
        print(Fore.GREEN + f"[+] VNC tool available: {tool} ({tool_path}); native asyncvnc tried first." + Style.RESET_ALL)

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_capture_vnc_screenshot, host, port, shots_dir, tool, tool_path, timeout, password): (host, port)
            for host, port in targets
        }
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                host, port = futures[fut]
                results.append({
                    "host": host,
                    "port": str(port),
                    "protocol": "vnc",
                    "status": "ERROR",
                    "screenshot_file": "",
                    "screenshot_failed": True,
                    "error": str(e)[:100],
                })
    return results


# ======================================================================
# X11 SCREENSHOTS
# ======================================================================
def _find_x11_tools() -> Dict[str, Optional[str]]:
    """Find available X11 screenshot tools."""
    tools = {}
    for name in ["xwd", "xwdtopnm", "pnmtopng", "import", "xdpyinfo"]:
        tools[name] = shutil.which(name)
    return tools


def _check_x11_access(host: str, port: int, display: int, timeout: float = 5.0) -> Tuple[str, bool]:
    """Check X11 server access."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        conn_request = struct.pack('<cxHHHH', b'l', 11, 0, 0, 0) + b'\x00\x00'
        sock.send(conn_request)

        response = sock.recv(8)
        sock.close()

        if len(response) >= 1:
            status = response[0]
            if status == 1:
                return "Access allowed", True
            elif status == 0:
                return "Access denied", False
            elif status == 2:
                return "Auth required", False
        return "Unknown", False
    except Exception as e:
        return str(e)[:50], False


def _capture_x11_screenshot(
    host: str, port: int, display: int, shots_dir: Path, tools: Dict, timeout: int
) -> Dict[str, Any]:
    """Capture a single X11 screenshot."""
    target_str = f"{host}:{port} (:{display})"

    if not _check_port_open(host, port, 5.0):
        _print_status("X11", target_str, "PORT_CLOSED", Fore.YELLOW)
        return {
            "host": host,
            "port": str(port),
            "display": display,
            "protocol": "x11",
            "status": "PORT_CLOSED",
            "screenshot_file": "",
            "screenshot_failed": True,
        }

    info, access_allowed = _check_x11_access(host, port, display)

    if not access_allowed:
        _print_status("X11", target_str, "DENIED", Fore.YELLOW)
        return {
            "host": host,
            "port": str(port),
            "display": display,
            "protocol": "x11",
            "status": "ACCESS_DENIED",
            "screenshot_file": "",
            "screenshot_failed": True,
            "auth_type": info,
        }

    _print_status("X11", target_str, "ACCESS_OK", Fore.GREEN)

    filename = f"x11_{host.replace('.', '_')}_{port}_d{display}.png"
    filepath = shots_dir / filename
    success = False
    capture_info = ""

    # Native capture first (python-xlib): no external X11 tools required.
    nat_ok, nat_info = _x11_capture_native(host, display, filepath)
    if nat_ok:
        _print_status("X11", target_str, "SUCCESS", Fore.GREEN)
        return {
            "host": host,
            "port": str(port),
            "display": display,
            "protocol": "x11",
            "status": "SUCCESS",
            "screenshot_file": filename,
            "screenshot_url": f"/modules/lockon/screenshots/{filename}",
            "screenshot_failed": False,
            "auth_type": "open_access",
        }
    capture_info = nat_info

    env = os.environ.copy()
    env["DISPLAY"] = f"{host}:{display}"

    try:
        if tools.get("xwd"):
            xwd_file = filepath.with_suffix('.xwd')
            cmd = [tools["xwd"], "-root", "-display", f"{host}:{display}", "-out", str(xwd_file)]
            proc = run(cmd, stdout=PIPE, stderr=PIPE, timeout=timeout, text=True, env=env)

            if xwd_file.exists():
                if tools.get("xwdtopnm") and tools.get("pnmtopng"):
                    pnm_file = filepath.with_suffix('.pnm')
                    run([tools["xwdtopnm"], str(xwd_file)], stdout=open(pnm_file, 'wb'), stderr=PIPE, timeout=timeout)
                    if pnm_file.exists():
                        run([tools["pnmtopng"], str(pnm_file)], stdout=open(filepath, 'wb'), stderr=PIPE, timeout=timeout)
                        pnm_file.unlink(missing_ok=True)
                        xwd_file.unlink(missing_ok=True)
                        success = filepath.exists()
                elif shutil.which("convert"):
                    # Use ImageMagick convert to turn XWD into real PNG
                    run([shutil.which("convert"), str(xwd_file), str(filepath)],
                        stdout=PIPE, stderr=PIPE, timeout=timeout)
                    xwd_file.unlink(missing_ok=True)
                    success = filepath.exists()
                else:
                    # Keep the .xwd extension so the file isn't misrepresented as PNG
                    xwd_filename = f"x11_{host.replace('.', '_')}_{port}_d{display}.xwd"
                    xwd_dest = shots_dir / xwd_filename
                    xwd_file.rename(xwd_dest)
                    filename = xwd_filename
                    filepath = xwd_dest
                    success = True
                    capture_info = "XWD format (install netpbm or imagemagick for PNG conversion)"
            if not capture_info:
                capture_info = proc.stderr[:100] if proc.stderr else ""

        if not success and tools.get("import"):
            # Reset to PNG path in case it was changed by the XWD fallback
            filename = f"x11_{host.replace('.', '_')}_{port}_d{display}.png"
            filepath = shots_dir / filename
            cmd = [tools["import"], "-window", "root", "-display", f"{host}:{display}", str(filepath)]
            proc = run(cmd, stdout=PIPE, stderr=PIPE, timeout=timeout, text=True, env=env)
            success = filepath.exists()
            capture_info = proc.stderr[:100] if proc.stderr else ""
    except TimeoutExpired:
        capture_info = "Timeout"
    except Exception as e:
        capture_info = str(e)[:100]

    if success:
        _print_status("X11", target_str, "SUCCESS", Fore.GREEN)
        return {
            "host": host,
            "port": str(port),
            "display": display,
            "protocol": "x11",
            "status": "SUCCESS",
            "screenshot_file": filename,
            "screenshot_url": f"/modules/lockon/screenshots/{filename}",
            "screenshot_failed": False,
            "auth_type": "open_access",
        }
    else:
        _print_status("X11", target_str, "FAILED", Fore.RED)
        return {
            "host": host,
            "port": str(port),
            "display": display,
            "protocol": "x11",
            "status": "SCREENSHOT_FAILED",
            "screenshot_file": "",
            "screenshot_failed": True,
            "auth_type": "open_access",
            "error": capture_info,
        }


def capture_x11_screenshots(
    targets: List[Tuple[str, int]], out_dir: Path, workers: int, timeout: int, displays: List[int]
) -> List[Dict[str, Any]]:
    """Capture X11 screenshots for multiple targets."""
    shots_dir = out_dir / "screenshots"

    # Warn if jumpbox is active - X11 tools need proxychains for SOCKS routing
    if is_jumpbox_routing_active():
        print(Fore.CYAN + "[i] Jumpbox active - X11 screenshots may need proxychains wrapper" + Style.RESET_ALL)

    tools = _find_x11_tools()

    if not (tools.get("xwd") or tools.get("import")):
        print(Fore.CYAN + "[i] No external X11 tools; using the native python-xlib backend." + Style.RESET_ALL)
    else:
        tool_names = [k for k, v in tools.items() if v]
        print(Fore.GREEN + f"[+] X11 tools available: {', '.join(tool_names)}; native python-xlib tried first." + Style.RESET_ALL)

    # Expand targets with displays
    expanded_targets = []
    for host, base_port in targets:
        for display in displays:
            expanded_targets.append((host, base_port + display, display))

    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_capture_x11_screenshot, host, port, display, shots_dir, tools, timeout): (host, port, display)
            for host, port, display in expanded_targets
        }
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except Exception as e:
                host, port, display = futures[fut]
                results.append({
                    "host": host,
                    "port": str(port),
                    "display": display,
                    "protocol": "x11",
                    "status": "ERROR",
                    "screenshot_file": "",
                    "screenshot_failed": True,
                    "error": str(e)[:100],
                })
    return results


# ======================================================================
# RESULT SAVING
# ======================================================================
def save_cygor_result(results: List[Dict], out_dir: Path, started_at: datetime) -> Path:
    """Save results in the new cygor-result.json format."""
    completed_at = datetime.now()

    # Merge with any prior lockon results, refreshing only the protocol(s) this
    # run captured -- so auto-dispatch (which runs lockon once per http/https/
    # rdp/vnc bucket) accumulates into one file instead of overwriting.
    from cygor.modules.base import merge_prior_results
    json_path = out_dir / "cygor-result.json"
    protocols_this_run = {r.get("protocol") for r in results}
    results = merge_prior_results(json_path, results, "protocol", protocols_this_run)

    # Count success/fail
    success_count = sum(1 for r in results if r.get("status") == "SUCCESS")
    screenshot_files = [r["screenshot_file"] for r in results if r.get("screenshot_file")]

    cygor_result = {
        "module": {
            "name": "Lockon",
            "slug": "lockon",
            "version": "2.0.0",
            "author": "Cygor Team",
            "description": "Unified screenshot capture for HTTP/HTTPS, RDP, VNC, and X11 services.",
            "category": "screenshots"
        },
        "metadata": {
            "started_at": started_at.isoformat(),
            "completed_at": completed_at.isoformat(),
            "target_count": len(results),
            "success_count": success_count,
            "error_count": len(results) - success_count,
            "exported_formats": ["json", "csv", "xml", "txt"],
        },
        "schema": {
            "view": "gallery",
            "columns": [
                {"key": "host", "label": "Host", "type": "ip"},
                {"key": "port", "label": "Port", "type": "string"},
                {"key": "protocol", "label": "Protocol", "type": "badge"},
                {"key": "status", "label": "Status", "type": "badge"},
                {"key": "http_status", "label": "HTTP", "type": "badge"},
                {"key": "title", "label": "Title", "type": "string"},
                {"key": "server", "label": "Server", "type": "string"},
                {"key": "tech", "label": "Tech", "type": "string"},
                {"key": "tls", "label": "TLS Cert", "type": "string"},
                {"key": "screenshot_url", "label": "Screenshot", "type": "screenshot"},
            ],
            "thumbnail_key": "screenshot_url",
            "caption_keys": ["host", "port", "protocol"],
            "group_by": "protocol",
        },
        "results": results,
        "assets": {
            "screenshots": [f"screenshots/{f}" for f in screenshot_files],
            "files": [],
        }
    }

    json_path = out_dir / "cygor-result.json"
    json_path.write_text(json.dumps(cygor_result, indent=2), encoding="utf-8")
    return json_path


def save_legacy_results(results: List[Dict], out_dir: Path, output_format: str):
    """Save results in legacy formats for compatibility."""
    # CSV
    if output_format in ("csv", "all"):
        csv_path = out_dir / "lockon-results.csv"
        if results:
            # Union of keys across rows (web/rdp/vnc/x11 rows differ); ignore
            # extras so heterogeneous rows never raise.
            keys = []
            for r in results:
                for k in r:
                    if k not in keys:
                        keys.append(k)
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=keys, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(results)
            print(Fore.CYAN + f"[+] CSV saved -> {csv_path}" + Style.RESET_ALL)

    # TXT
    if output_format in ("txt", "all"):
        txt_path = out_dir / "lockon-results.txt"
        with open(txt_path, "w", encoding="utf-8") as f:
            for r in results:
                f.write(f"{r.get('host')}:{r.get('port')} ({r.get('protocol')}) [{r.get('status')}] -> {r.get('screenshot_file', '')}\n")
        print(Fore.CYAN + f"[+] TXT saved -> {txt_path}" + Style.RESET_ALL)

    # XML
    if output_format in ("xml", "all"):
        xml_path = out_dir / "lockon-results.xml"
        root = ET.Element("LockonResults")
        for r in results:
            entry = ET.SubElement(root, "Result")
            for k, v in r.items():
                ET.SubElement(entry, k.replace("_", "")).text = str(v) if v is not None else ""
        ET.ElementTree(root).write(xml_path, encoding="utf-8", xml_declaration=True)
        print(Fore.CYAN + f"[+] XML saved -> {xml_path}" + Style.RESET_ALL)


# ======================================================================
# CLI
# ======================================================================
def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        prog="cygor enum lockon",
        description="Lockon - Unified Screenshot Capture",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Subcommands:
  http      Capture HTTP web screenshots
  https     Capture HTTPS web screenshots
  web       Capture HTTP and HTTPS web screenshots
  rdp       Capture RDP screenshots
  vnc       Capture VNC screenshots
  x11       Capture X11 screenshots
  all       Capture from all protocols

Examples:
  cygor enum lockon web -f urls.txt
  cygor enum lockon rdp -f rdp_hosts.txt
  cygor enum lockon rdp --rdp-file server.rdp --rdp-pass 'Passw0rd!'
  cygor enum lockon rdp -t server.rdp --rdp-pass 'Passw0rd!'
  cygor enum lockon all -f targets.txt --workers 16
""",
    )

    parser.add_argument("protocol", choices=["http", "https", "web", "rdp", "vnc", "x11", "all"],
                        help="Protocol to screenshot")
    parser.add_argument("-f", "--file", help="File with targets (one per line)")
    parser.add_argument("-t", "--targets", nargs="+", help="Targets directly on command line")
    parser.add_argument("-o", "--output", help="Custom output directory")
    parser.add_argument("--output-format", choices=["json", "csv", "xml", "txt", "all"], default="all")
    parser.add_argument("--workers", type=int, default=min(16, (os.cpu_count() or 4) * 2))
    parser.add_argument("--timeout", type=int, default=30, help="Capture timeout (seconds)")
    parser.add_argument("--viewport", default="1366x768", help="Screenshot viewport WxH")

    # Web-specific
    parser.add_argument("--nav-timeout", type=int, default=45000, help="Playwright navigation timeout (ms)")
    parser.add_argument("--extra-wait", type=int, default=2000, help="Extra wait after page load (ms)")
    parser.add_argument("--source", default="",
                        help="Tag each result with the module that triggered the capture "
                             "(e.g. 'webenum'); shown in the Screenshots gallery")
    parser.add_argument("--status-filter", nargs="+", type=int, default=[200, 301, 302, 307, 308],
                        help="HTTP status codes to screenshot (0 = all)")
    parser.add_argument("--install-browsers", action="store_true", help="Install Playwright browsers")
    parser.add_argument("--browser", choices=["webkit", "chromium", "firefox"], default="chromium",
                        help="Browser engine for web screenshots (default: chromium -- most "
                             "reliable; webkit often lacks system libs and silently fails)")

    # RDP-specific
    parser.add_argument("--rdp-user", help="RDP username for authentication")
    parser.add_argument("--rdp-pass", help="RDP password for authentication")
    parser.add_argument("--domain", help="RDP/NTLM domain for authentication")
    parser.add_argument("--rdp-file", nargs="+",
                        help="One or more .rdp files; target host/port/username/domain are "
                             "read from each (password still comes from --rdp-pass)")

    # VNC-specific
    parser.add_argument("--password", help="VNC password")

    # X11-specific
    parser.add_argument("--displays", default="0", help="X11 displays to scan (e.g., '0', '0-5', '0,1,2')")

    args = parser.parse_args()

    # Validate input
    if not args.file and not args.targets and not args.rdp_file:
        parser.error("Specify -f/--file, -t/--targets, or --rdp-file")

    # Read targets
    raw_targets = []
    if args.file:
        raw_targets.extend(_read_targets_file(args.file))
    if args.targets:
        raw_targets.extend(args.targets)

    # Any target that is an existing .rdp file is parsed for RDP, not treated
    # as a literal host string for the other protocols.
    rdp_file_paths = list(args.rdp_file or [])
    leftover_targets = []
    for entry in raw_targets:
        if entry.lower().endswith(".rdp") and Path(entry).is_file():
            rdp_file_paths.append(entry)
        else:
            leftover_targets.append(entry)
    raw_targets = leftover_targets

    if not raw_targets and not rdp_file_paths:
        print(Fore.RED + "No valid targets found." + Style.RESET_ALL)
        return

    # Setup
    out_dir = _get_output_dir(args.output)
    _archive_current_results(out_dir)
    print(Fore.CYAN + f"[*] Output directory: {out_dir}" + Style.RESET_ALL)
    print(Fore.CYAN + f"[*] Protocol: {args.protocol}" + Style.RESET_ALL)
    print(Fore.CYAN + f"[*] Targets: {len(raw_targets) + len(rdp_file_paths)}" + Style.RESET_ALL)

    started_at = datetime.now()
    all_results = []

    # IP rotation: get source IP for this session
    rotation_entry = get_next_ip(context="scan")
    source_ip = rotation_entry["address"] if rotation_entry else None
    if source_ip:
        print(Fore.CYAN + f"[i] Source IP (rotation): {source_ip}" + Style.RESET_ALL)

    # Run based on protocol
    protocol = args.protocol

    # Web (HTTP/HTTPS)
    if protocol in ("http", "https", "web", "all"):
        if protocol == "http":
            scheme = "http"
        elif protocol == "https":
            scheme = "https"
        else:
            scheme = "both"

        urls = _expand_to_urls(raw_targets, scheme)

        # Filter by status code
        if args.status_filter != [0]:
            print(Fore.YELLOW + f"[*] Testing URL reachability..." + Style.RESET_ALL)
            reachable = []
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures = {pool.submit(_test_url_reachability, url, 5.0, source_ip): url for url in urls}
                for fut in as_completed(futures):
                    url, code = fut.result()
                    _print_status("PROBE", url[:50], str(code), _color_for_status(code))
                    if code in args.status_filter or args.status_filter == [0]:
                        reachable.append(url)
            urls = reachable

        if urls:
            print(Fore.BLUE + f"\n[*] Capturing {len(urls)} web screenshots\n" + Style.RESET_ALL)
            browser_engine = os.environ.get("CYGOR_BROWSER_ENGINE", args.browser)
            web_results = asyncio.run(_capture_web_screenshots(
                urls, out_dir, args.workers, args.nav_timeout, args.viewport, args.extra_wait,
                install_browsers=args.install_browsers,
                browser_engine=browser_engine,
            ))
            all_results.extend(web_results)

    # RDP
    if protocol in ("rdp", "all"):
        rdp_targets: List[Any] = []
        # Plain host[:port] entries -> use CLI creds (if any).
        for t in raw_targets:
            host, port = _parse_host_port(t, 3389)
            if host:
                rdp_targets.append({"host": host, "port": port})
        # .rdp files -> per-target host/port/username/domain.
        for rpath in rdp_file_paths:
            parsed = _parse_rdp_file(rpath)
            if parsed:
                creds = f" as {parsed['domain']}\\{parsed['user']}" if parsed.get("user") else ""
                print(Fore.CYAN + f"[i] {Path(rpath).name} -> {parsed['host']}:{parsed['port']}{creds}" + Style.RESET_ALL)
                rdp_targets.append(parsed)
            else:
                print(Fore.YELLOW + f"[!] Could not parse RDP file: {rpath}" + Style.RESET_ALL)
        if rdp_targets:
            print(Fore.BLUE + f"\n[*] Capturing {len(rdp_targets)} RDP screenshots\n" + Style.RESET_ALL)
            rdp_results = capture_rdp_screenshots(
                rdp_targets, out_dir, args.workers, args.timeout, args.viewport,
                rdp_user=args.rdp_user, rdp_pass=args.rdp_pass, rdp_domain=args.domain,
            )
            all_results.extend(rdp_results)

    # VNC
    if protocol in ("vnc", "all"):
        vnc_targets = [_parse_host_port(t, 5900) for t in raw_targets]
        vnc_targets = [(h, p) for h, p in vnc_targets if h]
        if vnc_targets:
            print(Fore.BLUE + f"\n[*] Capturing {len(vnc_targets)} VNC screenshots\n" + Style.RESET_ALL)
            vnc_results = capture_vnc_screenshots(vnc_targets, out_dir, args.workers, args.timeout, args.password)
            all_results.extend(vnc_results)

    # X11
    if protocol in ("x11", "all"):
        x11_targets = [_parse_host_port(t, 6000) for t in raw_targets]
        x11_targets = [(h, p) for h, p in x11_targets if h]

        # Parse displays
        displays = []
        for part in args.displays.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-', 1)
                displays.extend(range(int(start), int(end) + 1))
            else:
                displays.append(int(part))
        displays = sorted(set(displays)) or [0]

        if x11_targets:
            print(Fore.BLUE + f"\n[*] Capturing X11 screenshots for {len(x11_targets)} hosts, displays {displays}\n" + Style.RESET_ALL)
            x11_results = capture_x11_screenshots(x11_targets, out_dir, args.workers, args.timeout, displays)
            all_results.extend(x11_results)

    # Tag rows with who triggered the capture (e.g. webenum), so the
    # Screenshots gallery can label where each screenshot came from.
    if getattr(args, "source", ""):
        for r in all_results:
            r["source"] = args.source

    # Save results
    if all_results:
        print(Fore.CYAN + "\n[*] Saving results..." + Style.RESET_ALL)
        json_path = save_cygor_result(all_results, out_dir, started_at)
        print(Fore.CYAN + f"[+] cygor-result.json saved -> {json_path}" + Style.RESET_ALL)
        save_legacy_results(all_results, out_dir, args.output_format)

        # Summary
        success_count = sum(1 for r in all_results if r.get("status") == "SUCCESS")
        failed_count = len(all_results) - success_count

        print(Style.BRIGHT + Fore.CYAN + "\n========== Lockon Summary ==========" + Style.RESET_ALL)
        print(f"Total targets   : {len(all_results)}")
        print(Fore.GREEN + f"Successful      : {success_count}" + Style.RESET_ALL)
        print(Fore.RED + f"Failed          : {failed_count}" + Style.RESET_ALL)

        # Per-protocol breakdown
        protocols = set(r.get("protocol", "unknown") for r in all_results)
        for proto in sorted(protocols):
            proto_results = [r for r in all_results if r.get("protocol") == proto]
            proto_success = sum(1 for r in proto_results if r.get("status") == "SUCCESS")
            print(f"  {proto.upper():8}: {proto_success}/{len(proto_results)} successful")

        print(f"Output          : {out_dir}")
        print(Style.BRIGHT + Fore.CYAN + "====================================" + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + "[!] No results to save." + Style.RESET_ALL)


if __name__ == "__main__":
    main()
