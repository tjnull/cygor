"""Regression tests for two issues that hid collected enum-module data in the
web UI:

1. The sidebar's "Enumeration Results" section was hardcoded to Screenshots +
   Network Shares, so the newer modules (dnsexplorer, rpcexplorer, ...) had no
   nav link even though their pages and data existed. The sidebar now lists
   every discovered enumeration module.
2. The UI workspace switch only rewrote the config file; the running process
   kept reading the startup workspace because the env vars / settings were
   frozen. The switch route now applies the workspace to the live process, and
   the lockon screenshot routes resolve the workspace at request time.
"""
import os
import types
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "cygor" / "webapp" / "templates"


def _fake_module(slug, name, module_type="enumeration"):
    return types.SimpleNamespace(slug=slug, name=name, module_type=module_type)


def _render_sidebar(show_screenshots=False, show_network_shares=False, sidebar_modules=None):
    """Render the data-gated Enumeration Results region of base.html.

    The sidebar is driven by server-computed state (set in main.py): only
    modules with results in the active workspace are shown."""
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)),
                      autoescape=select_autoescape(["html"]))
    src = (TEMPLATES_DIR / "base.html").read_text()
    # From the Enumeration section comment to the next sidebar section title
    # (Reports/Settings differ by branch -> anchor on the generic marker).
    start = src.index("<!-- Enumeration Section")
    enum_title = src.index('<div class="sidebar-section-title"', start)
    end = src.index('<div class="sidebar-section-title"', enum_title + 1)
    snippet = "<ul>" + src[start:end] + "</ul>"
    req = types.SimpleNamespace(
        state=types.SimpleNamespace(
            modules=[], auth_enabled=False, current_user=None,
            show_screenshots=show_screenshots,
            show_network_shares=show_network_shares,
            sidebar_modules=sidebar_modules or [],
        ),
        url=types.SimpleNamespace(path="/", scheme="http"),
    )
    return env.from_string(snippet).render(request=req)


def test_sidebar_shows_only_modules_with_data():
    mods = [_fake_module("dnsexplorer", "DNS Explorer"),
            _fake_module("webenum", "Web Content Discovery")]
    html = _render_sidebar(show_screenshots=True, show_network_shares=True, sidebar_modules=mods)
    assert "Enumeration Results" in html
    assert 'href="/modules/screenshots"' in html        # lockon has data
    assert 'href="/modules/network-shares"' in html     # smb/nfs has data
    assert 'href="/modules/dnsexplorer"' in html
    assert 'href="/modules/webenum"' in html
    # modules without data are NOT shown
    assert 'href="/modules/ftpexplorer"' not in html
    assert 'href="/modules/smtpexplorer"' not in html


def test_sidebar_combined_views_are_gated():
    # Only an explorer has data -> the two combined views are hidden.
    html = _render_sidebar(show_screenshots=False, show_network_shares=False,
                           sidebar_modules=[_fake_module("dnsexplorer", "DNS Explorer")])
    assert 'href="/modules/screenshots"' not in html
    assert 'href="/modules/network-shares"' not in html
    assert 'href="/modules/dnsexplorer"' in html


def test_sidebar_section_hidden_when_no_data():
    html = _render_sidebar(show_screenshots=False, show_network_shares=False, sidebar_modules=[])
    assert 'href="/modules/' not in html      # no enumeration links
    assert "Enumeration Results" not in html  # whole section header hidden


def test_enum_modules_with_data_detects_results(tmp_path, monkeypatch):
    """The middleware helper flags only modules whose cygor-result.json has
    non-empty results in the active workspace."""
    import json
    from cygor.webapp import main as webmain
    base = tmp_path / "cygor-enumeration-modules"
    (base / "dnsexplorer").mkdir(parents=True)
    (base / "dnsexplorer" / "cygor-result.json").write_text(json.dumps({"results": [{"x": 1}]}))
    (base / "ftpexplorer").mkdir(parents=True)
    (base / "ftpexplorer" / "cygor-result.json").write_text(json.dumps({"results": []}))  # empty
    (base / "smbexplorer").mkdir(parents=True)  # no result file at all
    monkeypatch.setenv("CYGOR_LOAD_DIR", str(tmp_path))
    mods = [_fake_module(s, s) for s in ("dnsexplorer", "ftpexplorer", "smbexplorer")]
    assert webmain._enum_modules_with_data(mods) == {"dnsexplorer"}


def test_apply_workspace_updates_live_process(tmp_path):
    """_apply_workspace_to_process touches process-global state (os.environ and
    the settings singleton) that monkeypatch can't reliably restore, so save and
    restore it by hand to keep the test hermetic."""
    from cygor.webapp.routes.settings import workspaces
    from cygor.webapp.config import settings

    saved_env = {k: os.environ.get(k) for k in ("CYGOR_WORKSPACE", "CYGOR_LOAD_DIR")}
    saved_results_dir = settings.RESULTS_DIR
    saved_configured = settings.WORKSPACE_CONFIGURED
    try:
        ws = tmp_path / "ws-b"
        ws.mkdir()
        workspaces._apply_workspace_to_process(ws)

        assert os.environ["CYGOR_WORKSPACE"] == str(ws)
        assert os.environ["CYGOR_LOAD_DIR"] == str(ws)
        assert str(settings.RESULTS_DIR) == str(ws)
        assert settings.WORKSPACE_CONFIGURED is True
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        settings.RESULTS_DIR = saved_results_dir
        settings.WORKSPACE_CONFIGURED = saved_configured


def test_lockon_load_dir_resolution_precedence():
    from cygor.webapp.routes import modules as module_routes

    saved_env = {k: os.environ.get(k) for k in ("CYGOR_WORKSPACE", "CYGOR_LOAD_DIR")}
    try:
        os.environ["CYGOR_LOAD_DIR"] = "/ld"
        os.environ["CYGOR_WORKSPACE"] = "/ws"
        assert module_routes._resolve_load_dir() == "/ld"  # load-dir wins

        os.environ.pop("CYGOR_LOAD_DIR", None)
        assert module_routes._resolve_load_dir() == "/ws"  # falls back to workspace

        os.environ.pop("CYGOR_WORKSPACE", None)
        # Falls back to settings.RESULTS_DIR (whatever it is) -- must be non-empty.
        assert module_routes._resolve_load_dir()
    finally:
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
