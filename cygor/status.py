"""'cygor status' — quick diagnostic of the running install.

Reports workspace, external tools, Playwright browser, DB target,
fingerprint sync state, plugin count, and version. Aims to answer
"what's working, what's missing, what do I do next" without making
any network calls or running anything slow.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Iterable, Tuple

from colorama import Fore, Style

from . import __version__
from . import workspace as ws


# ── External tools each module actually invokes (slug → list of (binary, role)) ──
# Only list binaries that the code shells out to. Python libraries that ship
# with cygor (impacket, smbmap, pyNfsClient, aardwolf, …) don't belong here —
# they're tracked by the installer, not by status. Order chosen for output
# readability, not importance.
TOOL_GROUPS: list[Tuple[str, list[Tuple[str, str]]]] = [
    ("Scanning", [
        ("nmap",            "cygor scan (Nmap engine)"),
        ("masscan",         "cygor scan --discover masscan"),
        ("naabu",           "cygor scan --discover naabu"),
    ]),
    ("Web content discovery", [
        ("ffuf",            "webenum (default tool)"),
        ("feroxbuster",     "webenum (default tool)"),
        ("gobuster",        "webenum (default tool)"),
        ("dirsearch",       "webenum --tools all"),
    ]),
    ("Enumeration modules", [
        ("rpcclient",       "rpcexplorer (MSRPC enumeration)"),
        # Password policy now comes from native impacket SAMR -- no external
        # polenum binary required.
        ("ldapsearch",      "ldapexplorer (anonymous / authenticated queries)"),
        ("ldapdomaindump",  "ldapexplorer (authenticated dump)"),
        ("snmpwalk",        "snmpexplorer (MIB walk)"),
        ("snmpget",         "snmpexplorer (single OID fetch)"),
        ("onesixtyone",     "snmpexplorer (community brute)"),
        ("dig",             "dnsexplorer"),
        ("dnsrecon",        "dnsexplorer (zone transfer / brute)"),
        ("psql",            "dbprobe (Postgres unauth probe)"),
    ]),
    ("Lockon optional helpers", [
        # All optional — lockon's native backends (aardwolf for RDP, the
        # built-in VNC client, Playwright for web) handle the work when these
        # aren't present. They're listed so users know what to install if
        # the native path is unavailable on their box.
        ("xfreerdp",        "lockon (RDP fallback when aardwolf is unusable)"),
        ("vncsnapshot",     "lockon (VNC fallback)"),
        ("xwd",             "lockon (X11 screenshot capture)"),
    ]),
]


# ── Helpers ─────────────────────────────────────────────────────────────────

def _ok(text: str) -> str:  return f"{Fore.GREEN}✓{Style.RESET_ALL} {text}"
def _miss(text: str) -> str: return f"{Fore.YELLOW}✗{Style.RESET_ALL} {text}"
def _warn(text: str) -> str: return f"{Fore.YELLOW}!{Style.RESET_ALL} {text}"
def _info(text: str) -> str: return f"{Fore.CYAN}i{Style.RESET_ALL} {text}"
def _header(text: str) -> str: return f"\n{Fore.MAGENTA}{text}{Style.RESET_ALL}"


def _playwright_chromium_installed() -> bool:
    """True iff Playwright has Chromium downloaded under ms-playwright/."""
    # Honours $PLAYWRIGHT_BROWSERS_PATH if set, else falls back to the standard
    # ~/.cache/ms-playwright on Linux.
    cache = os.environ.get("PLAYWRIGHT_BROWSERS_PATH") or str(Path.home() / ".cache" / "ms-playwright")
    p = Path(cache)
    if not p.is_dir():
        return False
    # Playwright stores chromium under chromium_headless_shell-<rev>/ and/or chromium-<rev>/
    for child in p.iterdir():
        name = child.name.lower()
        if name.startswith("chromium-") or name.startswith("chromium_headless_shell-"):
            return True
    return False


def _fingerprint_sync_state() -> Tuple[int, int, str]:
    """Return (synced_count, total_sources, cache_dir_str)."""
    cache_dir = Path.home() / ".cache" / "cygor" / "fingerprints"
    if not cache_dir.is_dir():
        return (0, 0, str(cache_dir))
    # The fingerprint cache writes one JSON per source; count what's there.
    try:
        from .fingerprinting.cache import FingerprintCache
        c = FingerprintCache(str(cache_dir))
        sources = list(c.CACHE_FILES.keys())
        synced = sum(1 for s in sources if (cache_dir / c.CACHE_FILES[s]).is_file())
        return (synced, len(sources), str(cache_dir))
    except Exception:
        # Best-effort fallback: just count JSON files under the cache dir.
        synced = sum(1 for _ in cache_dir.glob("*.json"))
        return (synced, max(synced, 1), str(cache_dir))


def _plugin_count() -> int:
    try:
        from .plugin_loader import discover_plugins
        return len(discover_plugins())
    except Exception:
        return 0


def _mask_db_url(url: str) -> str:
    """Strip the password from a libpq-style URL so it's safe to print."""
    if "@" in url and "://" in url:
        scheme, rest = url.split("://", 1)
        if "@" in rest:
            creds, host = rest.split("@", 1)
            if ":" in creds:
                user, _ = creds.split(":", 1)
                return f"{scheme}://{user}:***@{host}"
    return url


def _detect_postgres() -> tuple[bool, list, bool]:
    """Probe what cygor's autodetect would find for Postgres.

    Returns (psql_present, running_instances, adapter_import_ok). The instances
    list is whatever PostgreSQLAdapter.detect_running_instances() returns:
    list of (port, version) tuples, latest first. Best-effort; never raises.
    """
    try:
        from .webapp.db_adapters import PostgreSQLAdapter
    except Exception:
        return (bool(shutil.which("psql")), [], False)
    try:
        adapter = PostgreSQLAdapter()
        return (adapter.is_available(), adapter.detect_running_instances(), True)
    except Exception:
        return (bool(shutil.which("psql")), [], True)


def _db_target() -> tuple[str, str]:
    """Mirror cygor's real DB autodetect.

    Returns (backend, descriptor):
      - backend ∈ {"explicit", "postgres", "sqlite-workspace", "sqlite-default"}
      - descriptor is a one-line, password-masked description suitable for
        printing.

    Order of resolution follows webapp/db.py:get_database_url():
      1. $CYGOR_DB_URL — explicit override wins.
      2. Postgres autodetect (psql installed AND a server is running on
         5430-5440). Picks the latest version.
      3. SQLite under the active workspace.
      4. SQLite in the app data dir (last-resort).
    """
    url = os.environ.get("CYGOR_DB_URL")
    if url:
        return ("explicit", _mask_db_url(url))

    psql_present, instances, _ = _detect_postgres()
    if psql_present and instances:
        port, version = instances[0]
        # Match the default credentials the adapter uses when none are set,
        # so what we print is what `cygor web start` will actually connect to.
        user = os.environ.get("CYGOR_DB_USER", "cygor")
        db   = os.environ.get("CYGOR_DB_NAME", "cygor")
        host = os.environ.get("CYGOR_DB_HOST", "localhost")
        ver_label = f"v{version}" if version and version != "detected" else "detected"
        return ("postgres",
                f"postgresql://{user}:***@{host}:{port}/{db}  ({ver_label})")

    active = ws.active_workspace_path()
    if active:
        return ("sqlite-workspace", f"sqlite:///{active}/cygor.db")
    return ("sqlite-default", "sqlite (workspace-aware default; no workspace active)")


# ── Sections ────────────────────────────────────────────────────────────────

def _section_version(lines: list[str]) -> None:
    lines.append(_header("Cygor"))
    lines.append(f"  Version: {Style.BRIGHT}{__version__}{Style.RESET_ALL}")
    lines.append(f"  Python:  {sys.version.split()[0]}  ({sys.executable})")


def _section_workspace(lines: list[str], issues: list[str]) -> None:
    lines.append(_header("Workspace"))
    active = ws.active_workspace_path()
    if active is None:
        lines.append("  " + _warn("no active workspace"))
        issues.append("Set a workspace so scan/module output gets saved to a known place:")
        issues.append(f"      {Fore.CYAN}cygor workspace init <path>{Style.RESET_ALL}")
        return
    exists = active.exists()
    if exists:
        lines.append("  " + _ok(f"active: {active}"))
    else:
        lines.append("  " + _miss(f"active path does not exist: {active}"))
        issues.append(f"Active workspace points at a missing directory: {active}")
        issues.append(f"      {Fore.CYAN}cygor workspace init \"{active}\"{Style.RESET_ALL}  (re-create)")
        issues.append(f"      {Fore.CYAN}cygor workspace switch <name|path>{Style.RESET_ALL}  (pick another)")


def _section_db(lines: list[str]) -> None:
    lines.append(_header("Database"))
    backend, descriptor = _db_target()

    if backend == "explicit":
        lines.append("  " + _ok(descriptor))
        lines.append("  " + _info("Source: $CYGOR_DB_URL (overrides autodetect)"))
        return

    if backend == "postgres":
        lines.append("  " + _ok(descriptor))
        lines.append("  " + _info("Postgres is cygor's primary backend; autodetected on the listed port."))
        return

    # SQLite path — explain why Postgres wasn't picked so the user can fix it
    # if they meant to be on Postgres.
    psql_present, instances, _ = _detect_postgres()
    if backend == "sqlite-workspace":
        lines.append("  " + _ok(descriptor))
    else:
        lines.append("  " + _warn(descriptor))

    if not psql_present:
        lines.append("  " + _info("Postgres not detected (psql missing); falling back to SQLite."))
        lines.append(f"      Install with: {Fore.CYAN}sudo apt install postgresql-client{Style.RESET_ALL}")
    elif not instances:
        lines.append("  " + _info("Postgres client found but no server is running on 5430-5440."))
        lines.append(f"      Start one with: {Fore.CYAN}sudo systemctl start postgresql{Style.RESET_ALL}"
                     f"   (or `cygor web start --auto-start-postgres`)")
    if backend == "sqlite-default":
        lines.append("  " + _info("Web UI will create a per-workspace SQLite file when one is set."))


def _section_tools(lines: list[str], issues: list[str]) -> None:
    lines.append(_header("External tools (per-module dependencies)"))
    any_missing_default = False
    for group, tools in TOOL_GROUPS:
        lines.append(f"  {Style.BRIGHT}{group}{Style.RESET_ALL}")
        # Groups whose tools are nice-to-have rather than required: a missing
        # entry shouldn't render as a red ✗ that nags the user. The Lockon
        # native backends already cover these protocols without the helper
        # binaries.
        optional_group = group.endswith("optional helpers")
        for binary, role in tools:
            present = bool(shutil.which(binary))
            label = f"{binary:<16}  {Style.DIM}{role}{Style.RESET_ALL}"
            if present:
                marker = _ok
            elif optional_group:
                marker = _info  # cyan "i" — informational, not an issue
            else:
                marker = _miss
            lines.append("    " + marker(label))
            if not present and binary in {"nmap", "ffuf", "feroxbuster", "gobuster"}:
                any_missing_default = True
    if any_missing_default:
        issues.append("One or more *default* tools are missing (nmap / ffuf / feroxbuster / gobuster).")
        issues.append("    Debian/Ubuntu:  sudo apt install nmap ffuf feroxbuster gobuster")
        issues.append("    macOS:          brew install nmap ffuf feroxbuster gobuster")


def _section_playwright(lines: list[str], issues: list[str]) -> None:
    lines.append(_header("Lockon screenshot capture (Playwright)"))
    if _playwright_chromium_installed():
        lines.append("  " + _ok("Chromium browser installed"))
    else:
        lines.append("  " + _miss("Chromium browser not installed"))
        issues.append("Install the Playwright browser used by lockon for screenshots:")
        issues.append(f"      {Fore.CYAN}python -m playwright install chromium{Style.RESET_ALL}")


def _section_data_sources(lines: list[str], issues: list[str]) -> None:
    synced, total, cache_dir = _fingerprint_sync_state()
    lines.append(_header("Data sources"))
    if total == 0 or synced == 0:
        lines.append("  " + _miss(f"Fingerprint databases not synced  ({cache_dir})"))
        issues.append("Sync the fingerprint databases (powers device classification + cloud-IP enrichment):")
        issues.append(f"      {Fore.CYAN}cygor sync fingerprints{Style.RESET_ALL}")
    else:
        marker = _ok if synced == total else _warn
        lines.append("  " + marker(f"Fingerprints: {synced}/{total} sources synced  ({cache_dir})"))
        if synced != total:
            issues.append(f"Fingerprint sync is partial ({synced}/{total}). Re-run to top up:")
            issues.append(f"      {Fore.CYAN}cygor sync fingerprints{Style.RESET_ALL}")

    plug_count = _plugin_count()
    lines.append(f"  " + _info(f"Plugins: {plug_count} installed under ~/.cygor/plugins/"))


# ── Entry point ─────────────────────────────────────────────────────────────

def run() -> int:
    """Render the status report. Returns a process exit code (0 = healthy,
    1 = at least one actionable issue was surfaced)."""
    lines: list[str] = []
    issues: list[str] = []

    _section_version(lines)
    _section_workspace(lines, issues)
    _section_db(lines)
    _section_tools(lines, issues)
    _section_playwright(lines, issues)
    _section_data_sources(lines, issues)

    for line in lines:
        print(line)

    if issues:
        print()
        print(f"{Fore.YELLOW}Next steps{Style.RESET_ALL}")
        for issue in issues:
            # Plain bullet for the first line of each issue; indented continuation
            # lines start with whitespace.
            if issue.startswith(" "):
                print(f"  {issue}")
            else:
                print(f"  • {issue}")
        return 1

    print()
    print(f"{Fore.GREEN}Everything looks good.{Style.RESET_ALL}")
    return 0
