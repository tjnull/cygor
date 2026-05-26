"""Tests for the task output streaming fix.

Long-running scans (parallel ``nmap -p-`` across many hosts) generate more
than ``MAX_OUTPUT_LINES`` lines. The bounded ``deque`` rotates old lines
out and ``len()`` stops growing, which previously made the UI think output
had stopped flowing. ``CountingDeque.total_appended`` is the absolute
counter that fixes this; the API surface honors ``?since=N`` so the UI
can poll incrementally.
"""
from collections import deque
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from cygor.webapp.tasks import CountingDeque
from cygor.webapp.routes import tasks as tasks_routes


# ---------------- CountingDeque ----------------

def test_counting_deque_increments_on_append():
    cd = CountingDeque(maxlen=3)
    cd.append("a")
    cd.append("b")
    cd.append("c")
    assert list(cd) == ["a", "b", "c"]
    assert cd.total_appended == 3


def test_counting_deque_counter_keeps_growing_after_rotation():
    """The whole point: ``len()`` caps at ``maxlen`` but ``total_appended``
    keeps growing even when the deque rotates old entries out."""
    cd = CountingDeque(maxlen=3)
    for i in range(10):
        cd.append(f"line-{i}")
    assert len(cd) == 3                  # capped
    assert list(cd) == ["line-7", "line-8", "line-9"]
    assert cd.total_appended == 10       # absolute counter unaffected


def test_counting_deque_extend_increments_in_bulk():
    cd = CountingDeque(maxlen=100)
    cd.extend(["x", "y", "z"])
    assert cd.total_appended == 3
    cd.extend(iter(["q", "r"]))         # one-shot iterator works too
    assert cd.total_appended == 5


def test_counting_deque_appendleft_counts():
    cd = CountingDeque(maxlen=10)
    cd.appendleft("first")
    assert cd.total_appended == 1


# ---------------- /api/tasks/{id}/output streaming ----------------

class _FakeTask:
    """Minimal stand-in for ``cygor.webapp.tasks.Task`` — only the
    attributes the output endpoint reads."""
    def __init__(self, output_lines, error_lines=(), status_value="running",
                 user_id=None, username=None):
        self.output_lines = output_lines
        self.error_lines  = error_lines
        # Mock TaskStatus.value access
        self.status = type("S", (), {"value": status_value})()
        self.user_id = user_id
        self.username = username


@pytest_asyncio.fixture
async def client():
    app = FastAPI()
    app.include_router(tasks_routes.router)
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_output_endpoint_reports_total_counter(client):
    cd = CountingDeque(maxlen=100)
    for i in range(7):
        cd.append(f"line-{i}")
    fake = _FakeTask(cd, CountingDeque(maxlen=100))
    with patch.object(tasks_routes.task_manager, "get_task",
                      new=AsyncMock(return_value=fake)):
        r = await client.get("/api/tasks/abc/output")
    assert r.status_code == 200
    body = r.json()
    assert body["total_output_lines"] == 7
    assert body["total_error_lines"] == 0
    assert body["dropped_output_lines"] == 0
    assert len(body["output"]) == 7


@pytest.mark.asyncio
async def test_output_endpoint_honors_since(client):
    cd = CountingDeque(maxlen=100)
    for i in range(10):
        cd.append(f"line-{i}")
    fake = _FakeTask(cd, CountingDeque(maxlen=100))
    with patch.object(tasks_routes.task_manager, "get_task",
                      new=AsyncMock(return_value=fake)):
        r = await client.get("/api/tasks/abc/output?since=7")
    body = r.json()
    assert body["output_offset"] == 7
    assert body["output"] == ["line-7", "line-8", "line-9"]


@pytest.mark.asyncio
async def test_output_endpoint_handles_dropped_lines(client):
    """The user's actual scenario: deque rotated, ``len()`` capped at
    maxlen, but the absolute counter says many more lines were produced.
    The endpoint reports both ``total_output_lines`` and
    ``dropped_output_lines`` so the UI can detect the gap."""
    cd = CountingDeque(maxlen=5)
    for i in range(20):
        cd.append(f"line-{i}")
    assert len(cd) == 5  # rotated
    assert cd.total_appended == 20
    fake = _FakeTask(cd, CountingDeque(maxlen=5))
    with patch.object(tasks_routes.task_manager, "get_task",
                      new=AsyncMock(return_value=fake)):
        # Client thinks it has 18 lines; server says 20 produced, 15 dropped
        r = await client.get("/api/tasks/abc/output?since=18")
    body = r.json()
    assert body["total_output_lines"] == 20
    assert body["dropped_output_lines"] == 15
    # since=18 falls within the dropped range, so the response starts
    # at the first available line in the buffer (offset 15).
    assert body["output_offset"] == 18
    assert body["output"] == ["line-18", "line-19"]


@pytest.mark.asyncio
async def test_output_endpoint_when_since_below_dropped_window(client):
    """If the client falls farther behind than the buffer holds, the
    endpoint serves whatever's still in the buffer and reports
    ``dropped_output_lines`` so the UI can surface a 'lines lost' notice."""
    cd = CountingDeque(maxlen=5)
    for i in range(50):
        cd.append(f"line-{i}")
    fake = _FakeTask(cd, CountingDeque(maxlen=5))
    with patch.object(tasks_routes.task_manager, "get_task",
                      new=AsyncMock(return_value=fake)):
        r = await client.get("/api/tasks/abc/output?since=10")
    body = r.json()
    assert body["dropped_output_lines"] == 45
    # Returned tail starts at the oldest available line (offset 45)
    assert body["output_offset"] == 45
    assert body["output"][0] == "line-45"
    assert body["output"][-1] == "line-49"
    assert len(body["output"]) == 5


@pytest.mark.asyncio
async def test_output_endpoint_with_real_task_class():
    """Smoke test that the actual ``Task`` class uses ``CountingDeque`` so
    the endpoint contract holds end-to-end."""
    from cygor.webapp.tasks import Task
    t = Task(task_id="t1", task_type="test", command=["echo", "hi"], output_dir="/tmp")
    for i in range(15):
        t.output_lines.append(f"line-{i}")
    assert t.output_lines.total_appended == 15
    assert isinstance(t.output_lines, CountingDeque)
