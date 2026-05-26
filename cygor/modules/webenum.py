#!/usr/bin/env python3
"""
Web Content Discovery - Cygor Enumeration Module (webenum)
==========================================================

Multi-tool web content/directory discovery that runs several best-in-class
fuzzers **in parallel**, then **dedupes and correlates** their findings into a
single high-signal result set.

Why multiple tools?  Each engine (ffuf, feroxbuster, gobuster, dirsearch) has
different request handling, filtering, and heuristics, so they catch slightly
different paths.  Running them together and cross-referencing the results gives
a confidence signal (a path found by 3/4 tools is almost certainly real) and
reduces the blind spots of any single tool.  nikto is deliberately excluded --
it is noisy and prone to false positives for content discovery.

False-positive reduction:
  * ffuf auto-calibration (-ac); feroxbuster's built-in wildcard filtering.
  * A per-target baseline request to a random path: 200-responses whose status
    and body size match the baseline (catch-all / soft-404) are dropped.
  * Cross-tool correlation: a "confidence" = how many tools agreed on a path.

Optional --screenshot hands the discovered URLs to the lockon module so each
live page is captured and the thumbnail is correlated back onto its result row
(and shows up in the Screenshots gallery).

Wordlists: ships sensible bug-bounty-grade presets (raft / SecLists, with
fallbacks) selectable by size, or supply your own with --wordlist.

Output format: cygor-result.json (universal schema) -> web UI table.
"""
import json
import os
import random
import re
import shutil
import socket
import string
import subprocess
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from cygor.modules.base import CygorModule

try:  # silence self-signed cert noise against internal targets
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )
except Exception:
    pass


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------
ALL_TOOLS = ["ffuf", "feroxbuster", "gobuster", "dirsearch"]

# Default set: the fast engines.  Benchmarked against a 30k-word list on a real
# target, ffuf/feroxbuster/gobuster finish in ~5s while dirsearch takes ~80s
# (14-17x slower) for marginal extra coverage -- so dirsearch is opt-in
# (--tools all, or include it explicitly) rather than slowing every run.
DEFAULT_TOOLS = ["ffuf", "feroxbuster", "gobuster"]

# Interesting HTTP status codes (applied to every tool for a consistent view).
DEFAULT_STATUS = "200,204,301,302,307,308,401,403,405,500"

# Statuses worth a screenshot when --screenshot is set.
_SHOT_STATUS = {200, 204, 301, 302, 307, 308, 401, 403}

# Non-HTML assets aren't worth screenshotting (an image/CSS/JSON renders as junk)
# and, worse, navigating them in a headless browser can hang on download/stream
# handling -- so they're excluded from the screenshot set.
_NO_SHOT_EXT = (
    ".css", ".js", ".mjs", ".map", ".json", ".xml", ".rss", ".txt", ".csv",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".zip", ".gz", ".tar", ".rar", ".7z", ".bin", ".exe", ".dmg",
    ".mp4", ".mp3", ".wav", ".avi", ".mov", ".wasm",
)

# Statuses worth fetching a <title> for (live/interesting pages).
_TITLE_STATUS = {200, 401, 403, 500}

# High-signal paths worth flagging for the analyst (secrets, admin, API docs,
# VCS metadata, backups). Pure string match on the path -- no extra requests.
_NOTABLE_RE = re.compile(
    r"(?i)("
    r"\.git|\.svn|\.hg|\.env|\.htpasswd|\.htaccess|\.ds_store|web\.config|"
    r"\.bak|\.old|\.swp|\.save|\.orig|\.backup|backup|\.sql|\.db|dump|"
    r"phpmyadmin|adminer|wp-admin|wp-login|wp-config|"
    r"swagger|openapi|graphql|actuator|server-status|server-info|metrics|"
    r"\.well-known|jenkins|/console|phpinfo|"
    r"id_rsa|\.pem|\.key|credential|secret|passwd|password"
    r")"
)

_TITLE_RE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _resolve_tool_request(spec: str) -> List[str]:
    """Map a --tools value to a concrete tool list.

    'all' -> every supported tool (incl. the slow dirsearch);
    'default'/'' -> the fast trio; otherwise a comma-separated list.
    """
    spec = (spec or "default").strip().lower()
    if spec == "all":
        return list(ALL_TOOLS)
    if spec in ("", "default", "fast"):
        return list(DEFAULT_TOOLS)
    return [t.strip() for t in spec.split(",") if t.strip()]


def _available_tools(requested: List[str]) -> List[str]:
    """Intersection of requested tools and what's installed on PATH."""
    return [t for t in requested if shutil.which(t)]


# Per-tool wall-clock cap by wordlist size, used when --max-time is left at 0
# (auto). A responsive host finishes well under these; the cap stops a slow or
# rate-limiting host from stalling the scan (each tool flushes partial results).
_AUTO_MAX_TIME = {"quick": 90, "common": 90, "api": 90, "medium": 180, "large": 360}


def _auto_max_time(size: str, custom: Optional[str]) -> int:
    if custom:
        return 240
    return _AUTO_MAX_TIME.get(size, 180)


# ---------------------------------------------------------------------------
# Wordlists -- bug-bounty-grade presets with graceful fallbacks.
# Each preset is a list of "slots"; for each slot the first existing path wins,
# and the chosen files are merged+deduped into one wordlist for the run.
# ---------------------------------------------------------------------------
_SECLISTS = "/usr/share/seclists/Discovery/Web-Content"
_DIRB = "/usr/share/wordlists/dirb"
_DIRBUSTER = "/usr/share/dirbuster/wordlists"

WORDLIST_PRESETS: Dict[str, List[List[str]]] = {
    # Curated, high-signal, fast first pass.
    "quick": [
        [f"{_SECLISTS}/quickhits.txt"],
        [f"{_SECLISTS}/common.txt", f"{_DIRB}/common.txt"],
    ],
    # Classic small list -- fast and reliable.
    "common": [
        [f"{_SECLISTS}/common.txt", f"{_DIRB}/common.txt"],
    ],
    # Default. raft-* are derived from real-world data; the bug-bounty sweet spot.
    "medium": [
        [f"{_SECLISTS}/raft-medium-directories.txt"],
        [f"{_SECLISTS}/raft-medium-files.txt"],
    ],
    # Deep crawl.
    "large": [
        [f"{_SECLISTS}/raft-large-directories.txt", f"{_DIRBUSTER}/directory-list-2.3-medium.txt"],
        [f"{_SECLISTS}/raft-large-files.txt"],
    ],
    # API endpoint discovery.
    "api": [
        [f"{_SECLISTS}/api/api-endpoints.txt"],
        [f"{_SECLISTS}/api/objects.txt"],
    ],
}


def _resolve_wordlist(custom: Optional[str], size: str, workdir: Path) -> Tuple[Optional[str], str]:
    """Resolve the wordlist to use.

    A custom path (if it exists) always wins.  Otherwise pick files from the
    named preset and merge+dedupe them into one file under ``workdir``.
    Returns (path, human_description) or (None, reason) if nothing usable.
    """
    if custom:
        p = Path(custom).expanduser()
        if p.is_file():
            return str(p), f"custom: {p}"
        return None, f"custom wordlist not found: {custom}"

    slots = WORDLIST_PRESETS.get(size) or WORDLIST_PRESETS["medium"]
    chosen: List[str] = []
    for slot in slots:
        for cand in slot:
            if Path(cand).is_file():
                chosen.append(cand)
                break
    if not chosen:
        return None, f"no wordlist found for preset '{size}' (install seclists?)"

    if len(chosen) == 1:
        return chosen[0], f"{size}: {Path(chosen[0]).name}"

    # Merge + dedupe, preserving first-seen order.
    merged = workdir / f"wordlist-{size}.txt"
    seen: set = set()
    with merged.open("w", encoding="utf-8", errors="ignore") as out:
        for f in chosen:
            try:
                for line in Path(f).read_text(encoding="utf-8", errors="ignore").splitlines():
                    w = line.strip()
                    if w and not w.startswith("#") and w not in seen:
                        seen.add(w)
                        out.write(w + "\n")
            except Exception:
                continue
    names = " + ".join(Path(f).name for f in chosen)
    return str(merged), f"{size}: {names} ({len(seen)} words)"


# ---------------------------------------------------------------------------
# Target normalization
# ---------------------------------------------------------------------------
def _normalize_base_url(target: str, scheme: str) -> Optional[str]:
    """Turn a target (host, host:port, or URL) into a base URL with no path.

    scheme: 'http', 'https', or 'auto' (https for 443/8443, else http).
    """
    t = (target or "").strip()
    if not t or t.startswith("#"):
        return None
    if "://" in t:
        u = urlparse(t)
        if not u.hostname:
            return None
        netloc = u.netloc
        return f"{u.scheme}://{netloc}"

    # bare host[:port]
    host = t
    port = None
    if t.count(":") == 1:
        host, _, p = t.partition(":")
        port = p if p.isdigit() else None

    if scheme == "http":
        sch = "http"
    elif scheme == "https":
        sch = "https"
    else:  # auto
        sch = "https" if port in ("443", "8443") else "http"

    return f"{sch}://{host}:{port}" if port else f"{sch}://{host}"


def _rand_path() -> str:
    return "cygor_" + "".join(random.choices(string.ascii_lowercase + string.digits, k=18))


def _reachable(base_url: str, timeout: float) -> bool:
    """Liveness check so we skip only *definitively dead* hosts.

    Uses a raw TCP connect rather than a full HTTP request: a slow/rate-limiting
    host (which an HTTP GET might time out on, wrongly skipping a productive
    target) still completes the TCP handshake instantly. Only a refused
    connection or DNS failure counts as dead; a connect timeout is treated as
    'maybe filtered/slow' and we let the tools try (bounded by --max-time)."""
    pr = urlparse(base_url)
    host = pr.hostname
    if not host:
        return False
    port = pr.port or (443 if pr.scheme == "https" else 80)
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (ConnectionRefusedError, socket.gaierror):
        return False
    except (socket.timeout, OSError):
        return True  # filtered/slow -> proceed; tools time-box themselves


def _baseline(base_url: str, timeout: float) -> Optional[Tuple[int, int]]:
    """Probe a random non-existent path to detect catch-all/soft-404 behavior.
    Returns (status, body_len) or None."""
    url = base_url.rstrip("/") + "/" + _rand_path()
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
        return (r.status_code, len(r.content or b""))
    except Exception:
        return None


def _fetch_title(url: str, timeout: float) -> str:
    """Fetch and extract the HTML <title> of a discovered page (first 64KB)."""
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True, stream=True)
        chunk = r.raw.read(65536, decode_content=True) or b""
        r.close()
    except Exception:
        return ""
    m = _TITLE_RE.search(chunk)
    if not m:
        return ""
    title = re.sub(r"\s+", " ", m.group(1).decode("utf-8", "ignore")).strip()
    return title[:120]


def _timed_run(tool: str, fn, *args) -> Tuple[str, List[Dict[str, Any]], float]:
    """Run a tool runner, returning (tool, findings, elapsed_seconds)."""
    import time
    t0 = time.monotonic()
    res = fn(*args)
    return tool, res, time.monotonic() - t0


# ---------------------------------------------------------------------------
# Per-tool runners.  Each returns normalized findings:
#   {"path","url","status","size","content_type","redirect","tool"}
# ---------------------------------------------------------------------------
def _dotted_exts(exts: str) -> str:
    """ffuf appends -e values verbatim to FUZZ, so they must carry a leading
    dot ('.php'), unlike gobuster/feroxbuster/dirsearch which add it."""
    return ",".join("." + e.strip().lstrip(".") for e in exts.split(",") if e.strip())


def _finding(tool, url, status, size, ct="", redirect="") -> Dict[str, Any]:
    path = urlparse(url).path or "/"
    return {"tool": tool, "url": url, "path": path, "status": int(status or 0),
            "size": int(size or 0), "content_type": (ct or "").split(";")[0].strip(),
            "redirect": redirect or ""}


def _run_ffuf(base, wordlist, exts, threads, status, depth, max_time, td) -> List[Dict[str, Any]]:
    out = td / "ffuf.json"
    cmd = ["ffuf", "-w", wordlist, "-u", base.rstrip("/") + "/FUZZ",
           "-o", str(out), "-of", "json", "-mc", status, "-ac",
           "-t", str(threads), "-timeout", "7", "-maxtime", str(max_time),
           "-noninteractive", "-s"]
    if exts:
        cmd += ["-e", _dotted_exts(exts)]  # ffuf needs leading dots
    if depth and depth > 1:
        cmd += ["-recursion", "-recursion-depth", str(depth)]
    _exec(cmd, max_time + _EXEC_GRACE)
    findings = []
    if out.is_file():
        try:
            data = json.loads(out.read_text(encoding="utf-8", errors="ignore"))
            for r in data.get("results", []):
                findings.append(_finding("ffuf", r.get("url", ""), r.get("status"),
                                         r.get("length"), r.get("content-type", ""),
                                         r.get("redirectlocation", "")))
        except Exception:
            pass
    return findings


def _run_feroxbuster(base, wordlist, exts, threads, status, depth, max_time, td) -> List[Dict[str, Any]]:
    out = td / "ferox.json"
    cmd = ["feroxbuster", "-u", base, "-w", wordlist, "-t", str(threads),
           "--json", "-o", str(out), "-k", "-q", "--time-limit", f"{max_time}s",
           "--no-state", "-s", *status.split(",")]
    if exts:
        cmd += ["-x", *exts.split(",")]
    if depth and depth > 1:
        cmd += ["-d", str(depth)]
    else:
        cmd += ["-n"]  # no recursion
    _exec(cmd, max_time + _EXEC_GRACE)
    findings = []
    if out.is_file():
        for line in out.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
            except Exception:
                continue
            if o.get("type") != "response":
                continue
            findings.append(_finding("feroxbuster", o.get("url", ""), o.get("status"),
                                     o.get("content_length"), o.get("content_type", "")))
    return findings


_GOBUSTER_RE = re.compile(
    r"^(?P<url>\S+)\s+\(Status:\s*(?P<status>\d+)\)\s*\[Size:\s*(?P<size>\d+)\]"
    r"(?:\s*\[-->\s*(?P<redir>[^\]]+)\])?"
)


def _run_gobuster(base, wordlist, exts, threads, status, depth, max_time, td) -> List[Dict[str, Any]]:
    out = td / "gobuster.txt"
    cmd = ["gobuster", "dir", "-u", base, "-w", wordlist, "-t", str(threads),
           "-q", "--no-error", "-e", "-k", "-o", str(out),
           "-s", status, "-b", ""]
    if exts:
        cmd += ["-x", exts]
    # gobuster has no total-time flag; it streams to the file, so a hard kill at
    # max_time still leaves partial results to parse.
    _exec(cmd, max_time)
    findings = []
    if out.is_file():
        for line in out.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = _GOBUSTER_RE.match(line.strip())
            if not m:
                continue
            findings.append(_finding("gobuster", m.group("url"), m.group("status"),
                                     m.group("size"), "", (m.group("redir") or "")))
    return findings


def _run_dirsearch(base, wordlist, exts, threads, status, depth, max_time, td) -> List[Dict[str, Any]]:
    out = td / "dirsearch.json"
    cmd = ["dirsearch", "-u", base, "-w", wordlist, "-t", str(threads),
           "-q", "--format=json", "-o", str(out), "-i", status, "--random-agent",
           "--max-time", str(max_time)]
    if exts:
        # -f forces extensions onto every plain wordlist entry; without it
        # dirsearch only applies them to words containing a %EXT% placeholder.
        cmd += ["-e", exts, "-f"]
    if depth and depth > 1:
        cmd += ["-r", "--max-recursion-depth", str(depth)]
    _exec(cmd, max_time + _EXEC_GRACE)
    findings = []
    if out.is_file():
        try:
            data = json.loads(out.read_text(encoding="utf-8", errors="ignore"))
            results = data.get("results", data if isinstance(data, list) else [])
            for r in results:
                findings.append(_finding("dirsearch", r.get("url", ""), r.get("status"),
                                         r.get("content-length"), r.get("content-type", ""),
                                         r.get("redirect", "")))
        except Exception:
            pass
    return findings


RUNNERS = {
    "ffuf": _run_ffuf,
    "feroxbuster": _run_feroxbuster,
    "gobuster": _run_gobuster,
    "dirsearch": _run_dirsearch,
}


# Subprocess timeout is a backstop above each tool's own time limit: ffuf
# (-maxtime), feroxbuster (--time-limit) and dirsearch (--max-time) self-stop
# and flush their output files, so we kill only if they overshoot this grace.
_EXEC_GRACE = 30


def _exec(cmd: List[str], timeout: int) -> None:
    """Run a tool, capping wall-clock time.  Output files are parsed by the
    caller; ffuf/dirsearch write at exit (so they're given native time limits
    to flush partial results), while feroxbuster/gobuster stream to disk."""
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        pass
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Dedup + correlate
# ---------------------------------------------------------------------------
def _mode(values: List[Any]) -> Any:
    vals = [v for v in values if v is not None]
    return Counter(vals).most_common(1)[0][0] if vals else None


def _correlate(findings: List[Dict[str, Any]], base: str,
               baseline: Optional[Tuple[int, int]]) -> List[Dict[str, Any]]:
    """Group findings by normalized path, drop catch-all noise, and emit one
    correlated row per unique path with a cross-tool confidence count."""
    groups: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        key = (f["path"].rstrip("/") or "/")
        g = groups.setdefault(key, {"statuses": [], "sizes": [], "cts": [],
                                    "redirects": [], "tools": set()})
        g["statuses"].append(f["status"])
        g["sizes"].append(f["size"])
        if f["content_type"]:
            g["cts"].append(f["content_type"])
        if f["redirect"]:
            g["redirects"].append(f["redirect"])
        g["tools"].add(f["tool"])

    rows = []
    for key, g in groups.items():
        status = _mode(g["statuses"]) or 0
        size = _mode(g["sizes"]) or 0
        tools = sorted(g["tools"])
        url = base.rstrip("/") + key
        rows.append({
            "target": base,
            "path": key,
            "url": url,
            "status": str(status),
            "size": str(size),
            "content_type": _mode(g["cts"]) or "",
            "title": "",
            "notable": "yes" if _NOTABLE_RE.search(key) else "",
            "found_by": ", ".join(tools),
            "confidence": str(len(tools)),
            "redirect": _mode(g["redirects"]) or "",
            "screenshot_url": "",
        })

    kept, dropped = _drop_wildcards(rows, baseline)
    # Notable first, then highest confidence, then by path.
    kept.sort(key=lambda r: (r["notable"] != "yes", -int(r["confidence"]), r["path"]))
    return kept, dropped


_REDIRECT_CODES = {301, 302, 303, 307, 308}
# Bulk identical responses with these codes are catch-all/error templates.
_ERROR_TEMPLATE_CODES = {400, 500, 502, 503, 504}
# A non-empty response repeated byte-for-byte across this many distinct paths is
# a template (soft-200 / SPA shell / prefix catch-all), even if it doesn't
# dominate the whole result set (e.g. 28 '/login*' paths all serving the shell).
_REPEAT_LIMIT = 10


def _drop_wildcards(rows: List[Dict[str, Any]],
                    baseline: Optional[Tuple[int, int]]) -> Tuple[List[Dict[str, Any]], int]:
    """Remove wildcard/catch-all rows that survived per-tool calibration.

    Messy servers emit several catch-all signatures a single random-path
    baseline can't capture, so we treat any (status, size) signature shared by
    many distinct paths as a template:
      * exact match to the random-path baseline -> drop (any status);
      * server-error/400 templates with 4+ identical hits -> drop;
      * a non-redirect signature dominating the result set -> drop.

    Redirects need care: a real directory redirect (/admin -> /admin/) has an
    empty body, so many dirs legitimately share (30x, 0) -- kept. But a catch-all
    that bounces every path to a login/SSO page returns a 30x with a *non-empty*
    body; those repeat (exactly, or near-exactly since the body echoes the path),
    so non-empty redirects that repeat or dominate are dropped.
    Returns (kept_rows, dropped_count).
    """
    if not rows:
        return rows, 0
    counts = Counter((r["status"], r["size"]) for r in rows)
    total = len(rows)
    base_sig = (str(baseline[0]), str(baseline[1])) if baseline else None
    dominant = max(8, int(0.7 * total))

    def _is_redirect(sig):
        return (int(sig[0]) if sig[0].isdigit() else 0) in _REDIRECT_CODES

    def _sized(sig):
        return sig[1] not in ("0", "", "-")

    # Total non-empty redirect rows: a login/SSO catch-all makes these dominate.
    nz_redirect = sum(c for sig, c in counts.items() if _is_redirect(sig) and _sized(sig))

    wildcard: set = set()
    for sig, c in counts.items():
        st = int(sig[0]) if sig[0].isdigit() else 0
        if base_sig and sig == base_sig:
            wildcard.add(sig)
        elif st in _REDIRECT_CODES:
            # empty-body redirects (real dirs) are fine; non-empty ones that
            # repeat or dominate are a fixed catch-all redirect.
            if _sized(sig) and (c >= 4 or nz_redirect >= dominant):
                wildcard.add(sig)
        elif st in _ERROR_TEMPLATE_CODES and c >= 4:
            wildcard.add(sig)
        elif c >= dominant:
            wildcard.add(sig)
        elif _sized(sig) and c >= _REPEAT_LIMIT:
            wildcard.add(sig)  # bulk byte-identical non-redirect (SPA/prefix shell)

    if not wildcard:
        return rows, 0
    kept = [r for r in rows if (r["status"], r["size"]) not in wildcard]
    return kept, total - len(kept)


class WebEnum(CygorModule):
    name = "Web Content Discovery"
    slug = "webenum"
    version = "1.0.0"
    author = "cygor"
    description = ("Parallel multi-tool web content discovery (ffuf, feroxbuster, "
                   "gobuster, dirsearch) with cross-tool dedup/correlation and "
                   "optional lockon screenshots")
    category = "enumeration"
    view = "table"
    columns = [
        {"key": "path", "label": "Path", "type": "string"},
        {"key": "notable", "label": "Notable", "type": "badge"},
        {"key": "status", "label": "Status", "type": "badge"},
        {"key": "title", "label": "Title", "type": "string"},
        {"key": "size", "label": "Size", "type": "string"},
        {"key": "content_type", "label": "Type", "type": "string"},
        {"key": "found_by", "label": "Found By", "type": "string"},
        {"key": "confidence", "label": "Tools", "type": "badge"},
        {"key": "redirect", "label": "Redirect", "type": "string"},
        {"key": "url", "label": "URL", "type": "url"},
        {"key": "target", "label": "Target", "type": "url", "hidden": True},
        {"key": "screenshot_url", "label": "Shot", "type": "screenshot"},
    ]

    def setup_argparser(self, parser):
        parser.add_argument("--tools", default="default",
                            help="Tools to use: 'default' (ffuf,feroxbuster,gobuster - fast), "
                                 "'all' (adds dirsearch, much slower), or a comma-separated "
                                 "list. Only installed tools run.")
        parser.add_argument("--wordlist", default=None,
                            help="Custom wordlist path (overrides --wordlist-size)")
        parser.add_argument("--wordlist-size", default="medium",
                            choices=list(WORDLIST_PRESETS.keys()),
                            help="Built-in wordlist preset (default: medium = raft-medium)")
        parser.add_argument("--extensions", default="",
                            help="Comma-separated extensions, e.g. php,txt,html (default: none)")
        parser.add_argument("--threads", type=int, default=40,
                            help="Threads per tool (default: 40)")
        parser.add_argument("--target-workers", type=int, default=3,
                            help="How many targets to scan in parallel (default: 3)")
        parser.add_argument("--status-codes", default=DEFAULT_STATUS,
                            help=f"Match these HTTP codes (default: {DEFAULT_STATUS})")
        parser.add_argument("--recursion-depth", type=int, default=1,
                            help="Recursion depth; >1 enables recursive discovery (default: 1)")
        parser.add_argument("--max-time", type=int, default=0,
                            help="Per-tool wall-clock limit in seconds (0 = auto by "
                                 "wordlist size: 90s quick/common, 180s medium, 360s large)")
        parser.add_argument("--scheme", default="auto", choices=["auto", "http", "https"],
                            help="Scheme for bare host targets (default: auto)")
        parser.add_argument("--no-titles", action="store_true",
                            help="Skip fetching page <title> for discovered pages")
        parser.add_argument("--screenshot", action="store_true",
                            help="Screenshot discovered pages via lockon and link them on rows")
        parser.add_argument("--max-screenshots", type=int, default=75,
                            help="Cap screenshots when --screenshot is set (default: 75)")

    def run(self, targets: List[str], **kwargs) -> None:
        requested = _resolve_tool_request(kwargs.get("tools"))
        tools = _available_tools(requested)
        if not tools:
            print("[!] No content-discovery tools found. Install: ffuf, feroxbuster, "
                  "gobuster, dirsearch")
            return

        exts = (kwargs.get("extensions") or "").strip().strip(",")
        threads = kwargs.get("threads") or 40
        status = kwargs.get("status_codes") or DEFAULT_STATUS
        depth = kwargs.get("recursion_depth") or 1
        wl_size = kwargs.get("wordlist_size") or "medium"
        # 0/unset -> auto cap by wordlist size; otherwise honour the user's value.
        max_time = kwargs.get("max_time") or _auto_max_time(wl_size, kwargs.get("wordlist"))
        scheme = kwargs.get("scheme") or "auto"
        do_shots = bool(kwargs.get("screenshot"))
        max_shots = kwargs.get("max_screenshots") or 75
        do_titles = not kwargs.get("no_titles")

        bases = []
        for t in targets:
            b = _normalize_base_url(t, scheme)
            if b and b not in bases:
                bases.append(b)
        if not bases:
            print("[!] No valid targets after normalization")
            return

        # Scan several hosts at once (each still runs its tools in parallel).
        # Bounded so we don't melt the box: target_workers x tools processes.
        target_workers = max(1, min(kwargs.get("target_workers") or 3, len(bases)))
        print(f"[*] Tools: {', '.join(tools)}  |  targets: {len(bases)}  |  "
              f"{target_workers} target(s) in parallel")

        with tempfile.TemporaryDirectory(prefix="cygor-webenum-") as tmp:
            tmpdir = Path(tmp)
            wordlist, wl_desc = _resolve_wordlist(kwargs.get("wordlist"),
                                                  kwargs.get("wordlist_size") or "medium", tmpdir)
            if not wordlist:
                print(f"[!] {wl_desc}")
                return
            print(f"[*] Wordlist {wl_desc}" + (f"  exts: {exts}" if exts else "")
                  + f"  max-time: {max_time}s/tool")

            cfg = dict(wordlist=wordlist, exts=exts, threads=threads, status=status,
                       depth=depth, max_time=max_time, tools=tools, do_titles=do_titles,
                       tmpdir=tmpdir)
            with ThreadPoolExecutor(max_workers=target_workers) as tpool:
                futs = {tpool.submit(self._scan_target, base, cfg): base for base in bases}
                for fut in as_completed(futs):
                    base = futs[fut]
                    try:
                        rows, logs = fut.result()
                    except Exception as e:
                        print(f"\n[>] {base}\n    [!] scan failed: {str(e)[:100]}")
                        self.increment_errors()
                        continue
                    print("\n".join(logs))  # print each target's lines as one block
                    self.add_results(rows)

        if do_shots and self.results:
            self._attach_screenshots(max_shots)

    def _scan_target(self, base: str, cfg: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Discover content on a single base URL. Returns (rows, log_lines).

        Log lines are buffered and returned (not printed) so concurrent target
        scans don't interleave their output."""
        logs = [f"\n[>] {base}"]
        if not _reachable(base, 6):
            logs.append("    [-] not responding to HTTP; skipping")
            return [], logs

        baseline = _baseline(base, 7)
        if baseline and baseline[0] == 200:
            logs.append(f"    [i] catch-all baseline detected (200, {baseline[1]} bytes) - "
                        f"matching 200s will be filtered")

        run_dir = cfg["tmpdir"] / re.sub(r"[^A-Za-z0-9]+", "_", base)
        run_dir.mkdir(parents=True, exist_ok=True)
        tools = cfg["tools"]

        findings: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=len(tools)) as pool:
            futs = {
                pool.submit(_timed_run, t, RUNNERS[t], base, cfg["wordlist"], cfg["exts"],
                            cfg["threads"], cfg["status"], cfg["depth"], cfg["max_time"], run_dir): t
                for t in tools
            }
            for fut in as_completed(futs):
                t = futs[fut]
                try:
                    _, got, secs = fut.result()
                    logs.append(f"    [+] {t}: {len(got)} hits in {secs:.1f}s")
                    findings += got
                except Exception as e:
                    logs.append(f"    [!] {t} failed: {str(e)[:80]}")
                    self.increment_errors()

        rows, dropped = _correlate(findings, base, baseline)
        if cfg["do_titles"]:
            self._enrich_titles(rows)
        multi = sum(1 for r in rows if int(r["confidence"]) > 1)
        notable = sum(1 for r in rows if r["notable"] == "yes")
        extra = f", {notable} notable" if notable else ""
        extra += f", {dropped} wildcard/template filtered" if dropped else ""
        logs.append(f"    => {len(rows)} unique paths ({multi} confirmed by 2+ tools{extra})")
        return rows, logs

    # -- enrichment ---------------------------------------------------------
    def _enrich_titles(self, rows: List[Dict[str, Any]], max_n: int = 150) -> None:
        """Fetch the <title> for live/interesting pages, concurrently and
        bounded, so each discovery row carries a human-readable label."""
        todo = [r for r in rows if int(r["status"] or 0) in _TITLE_STATUS][:max_n]
        if not todo:
            return
        with ThreadPoolExecutor(max_workers=min(20, len(todo))) as pool:
            futs = {pool.submit(_fetch_title, r["url"], 6): r for r in todo}
            for fut in as_completed(futs):
                try:
                    futs[fut]["title"] = fut.result()
                except Exception:
                    pass

    # -- lockon integration -------------------------------------------------
    def _attach_screenshots(self, max_shots: int) -> None:
        """Feed discovered URLs to lockon, then map screenshots back to rows."""
        from cygor.workspace import resolve_workspace
        ws = resolve_workspace()
        if ws is None:
            print("[!] --screenshot needs a workspace; skipping")
            return

        # Interesting, deduped, highest-confidence-first; skip non-HTML assets
        # (useless as screenshots and prone to hang a headless browser).
        seen, urls = set(), []
        for r in self.results:
            url = r["url"]
            if int(r["status"] or 0) not in _SHOT_STATUS or url in seen:
                continue
            if urlparse(url).path.lower().rstrip("/").endswith(_NO_SHOT_EXT):
                continue
            seen.add(url)
            urls.append(url)
        urls = urls[:max_shots]
        if not urls:
            return

        url_file = self.output_dir / "discovered-urls.txt"
        url_file.write_text("\n".join(urls), encoding="utf-8")
        print(f"\n[*] Screenshotting {len(urls)} discovered URLs via lockon ...")

        # Faster per-page nav so 30+ URLs finish well inside the cap; tag the
        # capture's source so the gallery can label these as webenum-sourced.
        cmd = [sys.executable, "-m", "cygor.enumcli", "lockon", "web",
               "-f", str(url_file), "--status-filter", "0",
               "--nav-timeout", "20000", "--extra-wait", "800",
               "--source", "webenum"]
        env = dict(os.environ)
        env["CYGOR_WORKSPACE"] = str(ws)
        try:
            subprocess.run(cmd, env=env, timeout=max(300, len(urls) * 25), check=False)
        except Exception as e:
            # Even on timeout the PNGs already written to disk are usable -- we
            # link by deterministic filename below, so don't bail here.
            print(f"[i] lockon capture interrupted ({str(e)[:60]}); linking what was saved")

        # Link by lockon's deterministic screenshot filename + on-disk presence,
        # so linking never depends on lockon finishing/saving its result JSON.
        from cygor.modules.lockon import _sanitize_filename
        shots_dir = ws / "cygor-enumeration-modules" / "lockon" / "screenshots"
        hits = 0
        for row in self.results:
            url = row["url"]
            scheme = "https" if url.startswith("https") else "http"
            fn = f"{scheme}_{_sanitize_filename(url)}.png"
            if (shots_dir / fn).is_file():
                row["screenshot_url"] = f"/modules/lockon/screenshots/{fn}"
                row["source"] = "webenum"
                hits += 1
        print(f"[+] Linked {hits} screenshots to discovery rows")


# Web UI registration (see dbprobe/ftpexplorer for the rationale).
module_info = {
    "name": WebEnum.name,
    "slug": WebEnum.slug,
    "description": WebEnum.description,
    "author": WebEnum.author,
    "version": WebEnum.version,
    "module_type": "enumeration",
    "view": WebEnum.view,
    "table": {"columns": WebEnum.columns},
    "options": [
        {"name": "tools", "label": "Tools", "type": "select", "default": "default",
         "choices": [
             {"value": "default", "label": "Fast (ffuf + feroxbuster + gobuster)"},
             {"value": "all", "label": "All (adds dirsearch - much slower)"},
             {"value": "ffuf", "label": "ffuf only"},
             {"value": "feroxbuster", "label": "feroxbuster only"},
         ],
         "help": "Fast trio by default; dirsearch is ~15x slower so it's opt-in via 'All'."},
        {"name": "wordlist_size", "label": "Wordlist", "type": "select", "default": "medium",
         "choices": [
             {"value": "quick", "label": "Quick (quickhits/common)"},
             {"value": "common", "label": "Common (~4.7k)"},
             {"value": "medium", "label": "Medium - raft-medium (recommended)"},
             {"value": "large", "label": "Large - raft-large / dirbuster"},
             {"value": "api", "label": "API endpoints"},
         ],
         "help": "Built-in preset. Overridden by a custom wordlist path."},
        {"name": "wordlist", "label": "Custom wordlist", "type": "text", "default": "",
         "help": "Absolute path to your own wordlist (overrides the preset)."},
        {"name": "extensions", "label": "Extensions", "type": "text", "default": "",
         "help": "Comma-separated, e.g. php,txt,html (more extensions = more requests)."},
        {"name": "threads", "label": "Threads", "type": "number", "default": "40",
         "min": 1, "max": 200, "help": "Threads per tool."},
        {"name": "target_workers", "label": "Parallel targets", "type": "number", "default": "3",
         "min": 1, "max": 20, "help": "How many targets to scan at once."},
        {"name": "status_codes", "label": "Match codes", "type": "text", "default": DEFAULT_STATUS,
         "help": "HTTP status codes to treat as hits."},
        {"name": "recursion_depth", "label": "Recursion depth", "type": "number", "default": "1",
         "min": 1, "max": 5, "help": ">1 enables recursive discovery (slower)."},
        {"name": "max_time", "label": "Per-tool timeout (s)", "type": "number", "default": "0",
         "min": 0, "max": 7200, "help": "0 = auto by wordlist size (90/180/360s). Wall-clock cap per tool."},
        {"name": "scheme", "label": "Scheme", "type": "select", "default": "auto",
         "choices": [
             {"value": "auto", "label": "Auto (https on 443/8443)"},
             {"value": "http", "label": "HTTP"},
             {"value": "https", "label": "HTTPS"},
         ],
         "help": "Scheme to use for bare host targets."},
        {"name": "no_titles", "label": "Skip page titles", "type": "checkbox",
         "default": False, "help": "Don't fetch the <title> of discovered pages."},
        {"name": "screenshot", "label": "Screenshot pages (lockon)", "type": "checkbox",
         "default": False, "help": "Capture each discovered page and link the thumbnail."},
        {"name": "max_screenshots", "label": "Max screenshots", "type": "number", "default": "75",
         "min": 1, "max": 1000, "help": "Cap when screenshotting is enabled."},
    ],
}


def main(argv=None):
    WebEnum().cli(argv)


if __name__ == "__main__":
    main()
