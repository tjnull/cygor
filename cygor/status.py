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


# ── External tools each module wraps (slug → list of (binary, role)) ────────
# Order chosen for output readability, not importance.
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
        ("smbclient",       "smbexplorer"),
        ("showmount",       "nfsexplorer"),
        ("rpcclient",       "rpcexplorer"),
        ("polenum",         "rpcexplorer (password policy)"),
        ("ldapsearch",      "ldapexplorer"),
        ("ldapdomaindump",  "ldapexplorer (authenticated dump)"),
        ("snmpwalk",        "snmpexplorer"),
        ("onesixtyone",     "snmpexplorer (community brute)"),
        ("dig",             "dnsexplorer"),
        ("dnsrecon",        "dnsexplorer (zone transfer / brute)"),
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


def _db_target() -> str:
    """Where would cygor web start write its DB by default? Best-effort."""
    url = os.environ.get("CYGOR_DB_URL")
    if url:
        # Mask password if present.
        masked = url
        if "@" in url and "://" in url:
            scheme, rest = url.split("://", 1)
            if "@" in rest:
                creds, host = rest.split("@", 1)
                if ":" in creds:
                    user, _ = creds.split(":", 1)
                    masked = f"{scheme}://{user}:***@{host}"
        return masked
    # Fall back to the workspace-aware SQLite path.
    active = ws.active_workspace_path()
    if active:
        return f"sqlite:///{active}/cygor.db"
    return "sqlite (workspace-aware default; no workspace active)"


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
    target = _db_target()
    lines.append(f"  {target}")
    if target.startswith("sqlite") and "no workspace active" in target:
        lines.append("  " + _info("Web UI will create a per-workspace SQLite file when one is set."))


def _section_tools(lines: list[str], issues: list[str]) -> None:
    lines.append(_header("External tools (per-module dependencies)"))
    any_missing_default = False
    for group, tools in TOOL_GROUPS:
        lines.append(f"  {Style.BRIGHT}{group}{Style.RESET_ALL}")
        for binary, role in tools:
            present = bool(shutil.which(binary))
            label = f"{binary:<16}  {Style.DIM}{role}{Style.RESET_ALL}"
            lines.append("    " + (_ok(label) if present else _miss(label)))
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
