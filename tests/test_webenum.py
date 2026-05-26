"""Tests for the webenum (Web Content Discovery) module.

Covers the pure logic -- target normalization, wordlist resolution, per-tool
output parsing, and the dedup/correlate + catch-all filtering -- without
invoking the external tools or the network.
"""
import json

import pytest

from cygor.modules import webenum as W


# ---- target normalization ------------------------------------------------
@pytest.mark.parametrize("target,scheme,expected", [
    ("example.com", "http", "http://example.com"),
    ("example.com", "https", "https://example.com"),
    ("example.com:8080", "auto", "http://example.com:8080"),
    ("example.com:443", "auto", "https://example.com:443"),
    ("example.com:8443", "auto", "https://example.com:8443"),
    ("https://example.com/admin", "auto", "https://example.com"),
    ("http://10.0.0.1:8000/x/y", "http", "http://10.0.0.1:8000"),
])
def test_normalize_base_url(target, scheme, expected):
    assert W._normalize_base_url(target, scheme) == expected


def test_normalize_base_url_rejects_blank_and_comments():
    assert W._normalize_base_url("", "auto") is None
    assert W._normalize_base_url("# a comment", "auto") is None


# ---- wordlist resolution -------------------------------------------------
def test_resolve_custom_wordlist(tmp_path):
    wl = tmp_path / "mine.txt"
    wl.write_text("admin\nlogin\n")
    path, desc = W._resolve_wordlist(str(wl), "medium", tmp_path)
    assert path == str(wl)
    assert "custom" in desc


def test_resolve_custom_wordlist_missing(tmp_path):
    path, desc = W._resolve_wordlist(str(tmp_path / "nope.txt"), "medium", tmp_path)
    assert path is None
    assert "not found" in desc


def test_resolve_preset_merges_and_dedupes(tmp_path, monkeypatch):
    a = tmp_path / "a.txt"; a.write_text("admin\nlogin\n# comment\n")
    b = tmp_path / "b.txt"; b.write_text("login\nbackup\n")
    monkeypatch.setitem(W.WORDLIST_PRESETS, "test", [[str(a)], [str(b)]])
    path, desc = W._resolve_wordlist(None, "test", tmp_path)
    words = [w for w in __import__("pathlib").Path(path).read_text().splitlines() if w]
    assert words == ["admin", "login", "backup"]  # deduped, order preserved, comment dropped
    assert "3 words" in desc


def test_resolve_preset_none_available(tmp_path, monkeypatch):
    monkeypatch.setitem(W.WORDLIST_PRESETS, "empty", [["/no/such/list.txt"]])
    path, desc = W._resolve_wordlist(None, "empty", tmp_path)
    assert path is None
    assert "no wordlist" in desc


# ---- per-tool output parsing --------------------------------------------
def test_parse_ffuf(tmp_path):
    out = tmp_path / "ffuf.json"
    out.write_text(json.dumps({"results": [
        {"url": "http://h/admin", "status": 301, "length": 0, "content-type": "",
         "redirectlocation": "/admin/"},
        {"url": "http://h/config.php", "status": 200, "length": 7,
         "content-type": "text/html;charset=utf-8", "redirectlocation": ""},
    ]}))
    monkey_no_exec(W)
    res = W._run_ffuf("http://h", "wl", "", 10, W.DEFAULT_STATUS, 1, 1, tmp_path)
    assert {r["path"] for r in res} == {"/admin", "/config.php"}
    cfg = next(r for r in res if r["path"] == "/config.php")
    assert cfg["status"] == 200 and cfg["content_type"] == "text/html" and cfg["tool"] == "ffuf"


def test_parse_feroxbuster(tmp_path):
    out = tmp_path / "ferox.json"
    out.write_text("\n".join([
        json.dumps({"type": "configuration"}),
        json.dumps({"type": "response", "url": "http://h/api", "status": 301, "content_length": 0}),
        json.dumps({"type": "response", "url": "http://h/index.html", "status": 200, "content_length": 14}),
        json.dumps({"type": "statistics"}),
    ]))
    monkey_no_exec(W)
    res = W._run_feroxbuster("http://h", "wl", "", 10, W.DEFAULT_STATUS, 1, 1, tmp_path)
    assert {r["path"] for r in res} == {"/api", "/index.html"}  # config/statistics skipped


def test_parse_gobuster(tmp_path):
    out = tmp_path / "gobuster.txt"
    out.write_text(
        "http://h/admin (Status: 301) [Size: 0] [--> /admin/]\n"
        "http://h/robots.txt (Status: 200) [Size: 7]\n"
        "garbage line that should be ignored\n"
    )
    monkey_no_exec(W)
    res = W._run_gobuster("http://h", "wl", "", 10, W.DEFAULT_STATUS, 1, 1, tmp_path)
    assert {r["path"] for r in res} == {"/admin", "/robots.txt"}
    admin = next(r for r in res if r["path"] == "/admin")
    assert admin["status"] == 301 and admin["redirect"] == "/admin/"


def test_parse_dirsearch(tmp_path):
    out = tmp_path / "dirsearch.json"
    out.write_text(json.dumps({"info": {}, "results": [
        {"url": "http://h/backup", "status": 301, "content-length": 0,
         "content-type": "unknown", "redirect": "/backup/"},
        {"url": "http://h/login.html", "status": 200, "content-length": 15,
         "content-type": "text/html", "redirect": ""},
    ]}))
    monkey_no_exec(W)
    res = W._run_dirsearch("http://h", "wl", "", 10, W.DEFAULT_STATUS, 1, 1, tmp_path)
    assert {r["path"] for r in res} == {"/backup", "/login.html"}


def monkey_no_exec(mod):
    """Replace the subprocess runner with a no-op so parsers read the file we
    pre-wrote (the tools themselves are not invoked)."""
    mod._exec = lambda cmd, max_time: None


# ---- dedup + correlate ---------------------------------------------------
def test_correlate_merges_tools_and_counts_confidence():
    findings = [
        W._finding("ffuf", "http://h/admin", 301, 0, redirect="/admin/"),
        W._finding("gobuster", "http://h/admin/", 301, 0, redirect="/admin/"),  # trailing slash -> same key
        W._finding("feroxbuster", "http://h/admin", 301, 0),
        W._finding("ffuf", "http://h/secret", 200, 123),
    ]
    rows, _dropped = W._correlate(findings, "http://h", baseline=None)
    by_path = {r["path"]: r for r in rows}
    assert by_path["/admin"]["confidence"] == "3"
    assert by_path["/admin"]["found_by"] == "feroxbuster, ffuf, gobuster"
    assert by_path["/secret"]["confidence"] == "1"
    # /secret matches the notable keyword list and so is flagged + sorted first,
    # ahead of the higher-confidence but non-notable /admin.
    assert by_path["/secret"]["notable"] == "yes"
    assert by_path["/admin"]["notable"] == ""
    assert rows[0]["path"] == "/secret"
    # among non-notable rows, highest confidence wins
    non_notable = [r for r in rows if r["notable"] != "yes"]
    assert non_notable[0]["path"] == "/admin"


def test_correlate_filters_catchall_baseline():
    # baseline = soft-404: every unknown 200 returns 1000 bytes
    findings = [
        W._finding("ffuf", "http://h/wildcard", 200, 1000),   # matches baseline -> dropped
        W._finding("ffuf", "http://h/real", 200, 50),         # different size -> kept
        W._finding("gobuster", "http://h/realdir", 301, 1000),  # redirect, not a 200 -> kept
    ]
    rows, _dropped = W._correlate(findings, "http://h", baseline=(200, 1000))
    paths = {r["path"] for r in rows}
    assert "/wildcard" not in paths
    assert {"/real", "/realdir"} <= paths


def _row(path, status, size, tools=("ffuf",)):
    return {"target": "http://h", "path": path, "url": "http://h" + path,
            "status": str(status), "size": str(size), "content_type": "", "title": "",
            "notable": "", "found_by": ", ".join(tools), "confidence": str(len(tools)),
            "redirect": "", "screenshot_url": ""}


def test_drop_wildcards_error_template():
    # 8 distinct paths all returning byte-identical 500s == catch-all template
    # (the real 192.168.1.254 case). All should be dropped.
    rows = [_row(f"/index.html{i}", 500, 170) for i in range(8)]
    kept, dropped = W._drop_wildcards(rows, baseline=(302, 138))
    assert kept == [] and dropped == 8


def test_drop_wildcards_keeps_redirect_dirs():
    # Many real directories share (301, 0); must NOT be dropped.
    rows = [_row(f"/dir{i}", 301, 0) for i in range(10)]
    kept, dropped = W._drop_wildcards(rows, baseline=None)
    assert len(kept) == 10 and dropped == 0


def test_drop_wildcards_sized_redirect_catchall():
    # The real 192.168.10.2 case: every path 302s to /login with a non-empty
    # body (size ~200). Many sized redirects = catch-all -> dropped; the genuine
    # 401/403 protected resources survive.
    rows = [_row(f"/p{i}", 302, 200) for i in range(30)]
    rows += [_row("/admin", 401, 229), _row("/secret-area", 403, 223)]
    kept, dropped = W._drop_wildcards(rows, baseline=None)
    paths = {r["path"] for r in kept}
    assert "/p0" not in paths and "/p29" not in paths   # sized-redirect catch-all gone
    assert {"/admin", "/secret-area"} <= paths          # real protected resources kept
    assert dropped == 30


def test_drop_wildcards_prefix_200_shell():
    # The real 192.168.20.203 case: 28 '/login*' paths all serving the identical
    # 807-byte login shell (a prefix catch-all). Bulk byte-identical 200s are a
    # template even when they don't dominate the whole result set.
    rows = [_row(f"/login{i}", 200, 807) for i in range(28)]
    rows += [_row(f"/realdir{i}", 301, 0) for i in range(15)]   # real dirs kept
    rows += [_row("/api/exp", 500, 0)]                          # real broken endpoint
    kept, dropped = W._drop_wildcards(rows, baseline=None)
    paths = {r["path"] for r in kept}
    assert dropped == 28
    assert not any(p.startswith("/login") for p in paths)        # shell cluster gone
    assert len([p for p in paths if p.startswith("/realdir")]) == 15  # dirs preserved


def test_drop_wildcards_keeps_below_repeat_limit():
    # A handful of same-size 200s (below the repeat limit) are kept.
    rows = [_row(f"/p{i}", 200, 500) for i in range(5)]
    kept, dropped = W._drop_wildcards(rows, baseline=None)
    assert dropped == 0 and len(kept) == 5


def test_drop_wildcards_keeps_few_sized_redirects():
    # A couple of legitimate sized redirects (below threshold) are kept.
    rows = [_row("/a", 302, 120), _row("/b", 301, 80), _row("/real", 200, 50)]
    kept, dropped = W._drop_wildcards(rows, baseline=None)
    assert dropped == 0 and len(kept) == 3


def test_drop_wildcards_baseline_any_status():
    rows = [_row("/a", 302, 138), _row("/b", 302, 138), _row("/real", 200, 50)]
    kept, dropped = W._drop_wildcards(rows, baseline=(302, 138))
    # baseline 302/138 dropped even though redirect-coded; real 200 kept
    assert {r["path"] for r in kept} == {"/real"} and dropped == 2


def test_drop_wildcards_keeps_small_error_groups():
    # Only 3 identical 500s -> below the template threshold, kept (could be real)
    rows = [_row(f"/x{i}", 500, 99) for i in range(3)]
    kept, dropped = W._drop_wildcards(rows, baseline=None)
    assert dropped == 0


def test_finding_strips_content_type_params_and_derives_path():
    f = W._finding("ffuf", "http://h/x/y.php?a=1", 200, 10, ct="text/html; charset=utf-8")
    assert f["path"] == "/x/y.php"
    assert f["content_type"] == "text/html"


# ---- module wiring -------------------------------------------------------
def test_module_info_options_and_columns_present():
    names = {o["name"] for o in W.module_info["options"]}
    assert {"tools", "wordlist_size", "wordlist", "extensions", "screenshot"} <= names
    keys = {c["key"] for c in W.module_info["table"]["columns"]}
    assert {"path", "status", "found_by", "confidence", "screenshot_url"} <= keys
    assert W.module_info["module_type"] == "enumeration"


def test_available_tools_filters_to_installed(monkeypatch):
    monkeypatch.setattr(W.shutil, "which", lambda t: "/usr/bin/" + t if t in ("ffuf", "gobuster") else None)
    assert W._available_tools(W.ALL_TOOLS) == ["ffuf", "gobuster"]


def test_resolve_tool_request():
    # default/empty -> fast trio (dirsearch excluded for performance)
    assert W._resolve_tool_request("default") == W.DEFAULT_TOOLS
    assert W._resolve_tool_request("") == W.DEFAULT_TOOLS
    assert W._resolve_tool_request(None) == W.DEFAULT_TOOLS
    assert "dirsearch" not in W._resolve_tool_request("default")
    # all -> every tool incl. dirsearch
    assert W._resolve_tool_request("all") == W.ALL_TOOLS
    assert "dirsearch" in W._resolve_tool_request("all")
    # explicit list
    assert W._resolve_tool_request("ffuf, dirsearch") == ["ffuf", "dirsearch"]


@pytest.mark.parametrize("path,notable", [
    ("/.git/config", True),
    ("/.env", True),
    ("/backup.zip", True),
    ("/openapi.json", True),
    ("/admin", False),          # 'admin' alone is common; not auto-flagged
    ("/wp-admin", True),
    ("/.well-known/security.txt", True),
    ("/images", False),
    ("/index.html", False),
])
def test_notable_flagging(path, notable):
    assert bool(W._NOTABLE_RE.search(path)) is notable


def test_title_regex_extracts_title():
    body = b"<html><head><title> Swagger UI </title></head><body>x</body></html>"
    m = W._TITLE_RE.search(body)
    assert m and m.group(1).decode().strip() == "Swagger UI"


def test_dotted_exts_for_ffuf():
    # ffuf appends -e verbatim, so extensions must carry a leading dot.
    assert W._dotted_exts("php,html,txt") == ".php,.html,.txt"
    assert W._dotted_exts(".php, html ,.bak") == ".php,.html,.bak"  # tolerate dots/spaces
    assert W._dotted_exts("") == ""


def test_ffuf_cmd_uses_dotted_extensions(tmp_path, monkeypatch):
    """Regression: ffuf needs '.php' not 'php' or it appends 'php' to FUZZ and
    finds nothing. Capture the command to assert dotted extensions are passed."""
    captured = {}
    monkeypatch.setattr(W, "_exec", lambda cmd, mt: captured.setdefault("cmd", cmd))
    W._run_ffuf("http://h", "wl", "php,html", 10, W.DEFAULT_STATUS, 1, 1, tmp_path)
    cmd = captured["cmd"]
    assert "-e" in cmd and cmd[cmd.index("-e") + 1] == ".php,.html"


def test_dirsearch_cmd_forces_extensions(tmp_path, monkeypatch):
    """Regression: dirsearch needs -f to apply extensions to plain wordlists."""
    captured = {}
    monkeypatch.setattr(W, "_exec", lambda cmd, mt: captured.setdefault("cmd", cmd))
    W._run_dirsearch("http://h", "wl", "php", 10, W.DEFAULT_STATUS, 1, 1, tmp_path)
    assert "-f" in captured["cmd"]


def test_auto_max_time_scales_with_wordlist():
    assert W._auto_max_time("common", None) == 90
    assert W._auto_max_time("medium", None) == 180
    assert W._auto_max_time("large", None) == 360
    assert W._auto_max_time("medium", "/my/list.txt") == 240   # custom list
    assert W._auto_max_time("unknown", None) == 180             # safe fallback


def test_tools_pass_native_time_limits(tmp_path, monkeypatch):
    """ffuf/feroxbuster/dirsearch must self-limit (so they flush partial output)
    and the subprocess backstop must sit above the tool's own limit."""
    cap = {}

    def fake_exec(cmd, timeout):
        cap["cmd"] = cmd
        cap["timeout"] = timeout
    monkeypatch.setattr(W, "_exec", fake_exec)

    W._run_ffuf("http://h", "wl", "", 10, W.DEFAULT_STATUS, 1, 120, tmp_path)
    assert "-maxtime" in cap["cmd"] and cap["cmd"][cap["cmd"].index("-maxtime") + 1] == "120"
    assert cap["timeout"] == 120 + W._EXEC_GRACE

    W._run_feroxbuster("http://h", "wl", "", 10, W.DEFAULT_STATUS, 1, 120, tmp_path)
    assert "--time-limit" in cap["cmd"] and "120s" in cap["cmd"]
    assert "--no-state" in cap["cmd"]  # don't litter CWD with ferox-*.state files
    assert cap["timeout"] == 120 + W._EXEC_GRACE

    W._run_dirsearch("http://h", "wl", "", 10, W.DEFAULT_STATUS, 1, 120, tmp_path)
    assert "--max-time" in cap["cmd"] and cap["cmd"][cap["cmd"].index("--max-time") + 1] == "120"

    # gobuster has no native total-time flag: subprocess timeout == max_time
    W._run_gobuster("http://h", "wl", "", 10, W.DEFAULT_STATUS, 1, 120, tmp_path)
    assert cap["timeout"] == 120


def test_screenshot_url_selection_skips_assets(monkeypatch, tmp_path):
    """_attach_screenshots should only screenshot likely-HTML pages: assets
    (.css/.js/.json/images) are excluded, and the subprocess isn't even
    launched when nothing qualifies."""
    mod = W.WebEnum(output_dir=str(tmp_path))
    mod._results = [
        {"url": "https://h/login", "status": "200"},
        {"url": "https://h/admin", "status": "401"},
        {"url": "https://h/openapi.json", "status": "200"},   # asset -> skip
        {"url": "https://h/assets/app.css", "status": "200"},  # asset -> skip
        {"url": "https://h/logo.png", "status": "200"},        # asset -> skip
        {"url": "https://h/down", "status": "404"},            # status -> skip
    ]
    captured = {}
    import cygor.workspace as _ws
    monkeypatch.setattr(_ws, "resolve_workspace", lambda: tmp_path)
    # output_dir == tmp_path, so the URL file lands there
    monkeypatch.setattr(W.subprocess, "run",
                        lambda cmd, **kw: captured.setdefault("urls",
                            (tmp_path / "discovered-urls.txt").read_text().splitlines()))
    mod._attach_screenshots(75)
    assert set(captured.get("urls", [])) == {"https://h/login", "https://h/admin"}


def test_reachable_only_skips_definitively_dead(monkeypatch):
    import socket as _socket

    class _Conn:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    def make(behavior):
        def fake(addr, timeout=None):
            if behavior == "ok":
                return _Conn()
            raise behavior
        return fake

    # open port -> reachable
    monkeypatch.setattr(W.socket, "create_connection", make("ok"))
    assert W._reachable("http://h:80", 3) is True
    # refused / DNS failure -> dead
    monkeypatch.setattr(W.socket, "create_connection", make(ConnectionRefusedError()))
    assert W._reachable("http://h:80", 3) is False
    monkeypatch.setattr(W.socket, "create_connection", make(_socket.gaierror()))
    assert W._reachable("http://nope:80", 3) is False
    # connect timeout (slow/filtered) -> proceed anyway, tools time-box
    monkeypatch.setattr(W.socket, "create_connection", make(_socket.timeout()))
    assert W._reachable("http://slow:80", 3) is True


def test_scan_target_skips_unreachable(monkeypatch, tmp_path):
    monkeypatch.setattr(W, "_reachable", lambda base, t: False)
    mod = W.WebEnum(output_dir=str(tmp_path))
    rows, logs = mod._scan_target("http://dead", {
        "wordlist": "wl", "exts": "", "threads": 10, "status": W.DEFAULT_STATUS,
        "depth": 1, "max_time": 60, "tools": ["ffuf"], "do_titles": False, "tmpdir": tmp_path,
    })
    assert rows == []
    assert any("not responding" in l for l in logs)
