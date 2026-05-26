"""Tests for the /tasks/{task_id} detail handler.

Several templates link/redirect to ``/tasks/<uuid>`` after task creation. The
handler:
- redirects credrecon tasks to ``/credrecon/scans/<id>``
- renders the generic ``task_detail.html`` page (with live output console)
  for everything else, including tasks not yet known to any store.
"""
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from httpx import ASGITransport, AsyncClient

from cygor.webapp.routes import tasks as tasks_routes


def _fake_task(task_type: str):
    """Minimal duck-typed Task with the attributes our handler reads."""
    return type("T", (), {"task_type": task_type})()


@pytest_asyncio.fixture
async def client():
    app = FastAPI()
    # Wire a real Jinja2 templates instance pointing at the package's templates
    # dir so the generic-task code path can render task_detail.html.
    templates_dir = Path(__file__).resolve().parent.parent / "cygor" / "webapp" / "templates"
    tasks_routes.set_templates(Jinja2Templates(directory=str(templates_dir)))
    app.include_router(tasks_routes.router)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_redirects_credrecon_to_credrecon_page(client):
    with patch.object(tasks_routes.task_manager, 'get_task',
                      new=AsyncMock(return_value=_fake_task("credrecon"))):
        r = await client.get("/tasks/cred-789", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/credrecon/scans/cred-789"


@pytest.mark.asyncio
async def test_redirects_credential_test_to_credrecon_page(client):
    with patch.object(tasks_routes.task_manager, 'get_task',
                      new=AsyncMock(return_value=_fake_task("credential_test"))):
        r = await client.get("/tasks/cred-x", follow_redirects=False)
    assert r.status_code == 303
    assert r.headers["location"] == "/credrecon/scans/cred-x"


@pytest.mark.asyncio
async def test_generic_task_renders_detail_page(client):
    """Verifies the redesigned task_detail.html renders for generic tasks.
    The page extracts task_id from window.location.pathname client-side, so
    no Jinja context to assert — just the structural hallmarks."""
    with patch.object(tasks_routes.task_manager, 'get_task',
                      new=AsyncMock(return_value=_fake_task("port_scan"))):
        r = await client.get("/tasks/scan-uuid-1")
    assert r.status_code == 200
    body = r.text
    # Compact-layout hallmarks
    assert "td-page" in body                 # page wrapper
    assert "td-header" in body               # compact header strip
    assert "td-cmd-bar" in body              # command bar
    assert "td-console" in body              # console container
    # JS hooks the polling logic depends on
    assert 'id="taskInfoCollapse"' in body
    assert 'id="outputContent"' in body
    assert "/api/tasks/${taskId}" in body


@pytest.mark.asyncio
async def test_unknown_task_renders_detail_page(client):
    """Task not found in any store still renders (no 404) — the page polls
    /api/tasks/<id> and surfaces a not-found message client-side."""
    with patch.object(tasks_routes.task_manager, 'get_task',
                      new=AsyncMock(return_value=None)), \
         patch.object(tasks_routes, 'get_task_from_schedule_history',
                      new=AsyncMock(return_value=None)):
        r = await client.get("/tasks/3a454c56-7fd2-4209-b9ba-6caee7716ef1")
    assert r.status_code == 200
    body = r.text
    assert "td-page" in body
    assert 'id="outputContent"' in body


@pytest.mark.asyncio
async def test_info_card_collapsed_by_default(client):
    """The 'enterprise grade' redesign defaults the metadata card to
    collapsed (was ``collapse show`` before, now bare ``collapse``) so the
    live console sits above the fold instead of being pushed below ~700px
    of redundant metadata."""
    with patch.object(tasks_routes.task_manager, 'get_task',
                      new=AsyncMock(return_value=_fake_task("port_scan"))):
        r = await client.get("/tasks/x")
    assert r.status_code == 200
    body = r.text
    # Bare ``collapse`` (closed). The substring ``collapse show`` should
    # NOT appear on the taskInfoCollapse element.
    assert 'class="collapse" id="taskInfoCollapse"' in body
    assert 'class="collapse show" id="taskInfoCollapse"' not in body


@pytest.mark.asyncio
async def test_literal_subroutes_not_stolen_by_parameterized_route(client):
    """``/tasks/scan/new`` etc. are two-segment paths so the single-segment
    ``/tasks/{task_id}`` route cannot match them, regardless of registration
    order. Verified by inspecting the matched route, not by invoking the
    handler (the template engine isn't wired in tests)."""
    from starlette.routing import Match
    scope = {"type": "http", "path": "/tasks/scan/new", "method": "GET",
             "headers": [], "query_string": b""}
    matched_routes = []
    for route in tasks_routes.router.routes:
        match, _ = route.matches(scope)
        if match == Match.FULL:
            matched_routes.append(route.path)
    assert "/tasks/scan/new" in matched_routes
    assert "/tasks/{task_id}" not in matched_routes
