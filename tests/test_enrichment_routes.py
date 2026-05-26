"""
Tests for the enrichment route module — verifies registration and the
core query behaviors of the dashboard / drill-down / per-host APIs.

These are smoke-level: they exercise the routes against an in-memory
sqlite DB seeded with EnrichmentRun + EnrichmentFinding rows, no real
external service calls.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel

from cygor.webapp.models import EnrichmentFinding, EnrichmentRun, Host
from cygor.webapp.routes import enrichment as enrichment_routes


@pytest_asyncio.fixture
async def app_and_session(tmp_path):
    """Build a minimal FastAPI app wiring just the enrichment router."""
    db_path = tmp_path / "routes_test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    # Seed two runs + a host with linked findings
    async with Session() as s:
        h = Host(address="10.0.0.5", hostname="web-01")
        s.add(h)
        await s.flush()

        run1 = EnrichmentRun(
            output_path="/tmp/r1.json",
            sources=["shodan", "virustotal"],
            ioc_count=1,
            finding_count=2,
            started_at=datetime.utcnow() - timedelta(hours=2),
            completed_at=datetime.utcnow() - timedelta(hours=1),
        )
        run2 = EnrichmentRun(
            output_path="/tmp/r2.json",
            sources=["crt_sh"],
            ioc_count=1,
            finding_count=1,
            started_at=datetime.utcnow() - timedelta(minutes=30),
            completed_at=datetime.utcnow() - timedelta(minutes=29),
        )
        s.add_all([run1, run2])
        await s.flush()

        s.add_all([
            EnrichmentFinding(
                run_id=run1.id, ioc_value="10.0.0.5", ioc_type="ip",
                source="shodan", finding_kind="observation",
                summary="3 ports indexed", signals=["shodan-record"],
                raw={"ports": [22, 80, 443]}, host_id=h.id,
            ),
            EnrichmentFinding(
                run_id=run1.id, ioc_value="10.0.0.5", ioc_type="ip",
                source="ai_service", finding_kind="ai_indicator",
                summary="ollama on :11434", signals=["ai-suspected", "ai-ollama"],
                raw={"protocol": "ollama", "port": 11434}, host_id=h.id,
            ),
            EnrichmentFinding(
                run_id=run2.id, ioc_value="example.com", ioc_type="domain",
                source="crt_sh", finding_kind="observation",
                summary="2 cert(s) in CT logs", signals=["crt-sh-record"],
                raw={"certs": []}, host_id=None,
            ),
        ])
        await s.commit()

    # Build app, set templates to a stub (we only test API endpoints below)
    app = FastAPI()
    app.include_router(enrichment_routes.router)

    async def _override_get_session():
        async with Session() as ss:
            yield ss

    from cygor.webapp.db import get_session
    app.dependency_overrides[get_session] = _override_get_session

    yield app, Session
    await engine.dispose()


@pytest.mark.asyncio
async def test_api_list_runs(app_and_session):
    app, _ = app_and_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/enrichment/runs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 2
    assert len(data["runs"]) == 2
    # Most recent first
    assert data["runs"][0]["sources"] == ["crt_sh"]


@pytest.mark.asyncio
async def test_api_get_run(app_and_session):
    app, _ = app_and_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/enrichment/runs/1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == 1
    assert data["by_source"].get("shodan") == 1
    assert data["by_source"].get("ai_service") == 1
    assert data["by_finding_kind"].get("ai_indicator") == 1


@pytest.mark.asyncio
async def test_api_get_run_not_found(app_and_session):
    app, _ = app_and_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/enrichment/runs/999")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_api_run_findings_filtered(app_and_session):
    app, _ = app_and_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/enrichment/runs/1/findings", params={"source": "ai_service"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["findings"]) == 1
    assert data["findings"][0]["source"] == "ai_service"


@pytest.mark.asyncio
async def test_api_run_findings_signal_filter(app_and_session):
    app, _ = app_and_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/enrichment/runs/1/findings", params={"signal": "ai-ollama"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["findings"]) == 1
    assert "ai-ollama" in data["findings"][0]["signals"]


@pytest.mark.asyncio
async def test_api_host_findings(app_and_session):
    app, _ = app_and_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/enrichment/host/1")
    assert resp.status_code == 200
    data = resp.json()
    assert data["host_id"] == 1
    assert data["address"] == "10.0.0.5"
    assert data["total_findings"] == 2
    assert len(data["buckets"]["observation"]) == 1
    assert len(data["buckets"]["ai_indicator"]) == 1
    assert len(data["buckets"]["cert"]) == 0


@pytest.mark.asyncio
async def test_api_host_findings_not_found(app_and_session):
    app, _ = app_and_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/enrichment/host/9999")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_api_delete_run(app_and_session):
    app, _ = app_and_session
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.delete("/api/enrichment/runs/2")
        assert resp.status_code == 200
        # And gone now
        resp2 = await ac.get("/api/enrichment/runs/2")
        assert resp2.status_code == 404


def test_router_paths_present():
    """Defensive: register-time path list must include all the documented endpoints."""
    paths = sorted(r.path for r in enrichment_routes.router.routes)
    expected = [
        "/api/enrichment/host/{host_id}",
        "/api/enrichment/runs",
        "/api/enrichment/runs/{run_id}",
        "/api/enrichment/runs/{run_id}/findings",
        "/enrichment",
        "/enrichment/{run_id}",
    ]
    for ep in expected:
        assert ep in paths, f"Missing route: {ep}"
