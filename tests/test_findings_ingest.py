"""Tests for Finding ingestion (cygor/webapp/findings.py): module results ->
finding table, host linkage, idempotent full replace."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel, select

from cygor.webapp.findings import ingest_findings
from cygor.webapp.models import Finding, Host


@pytest_asyncio.fixture
async def session(tmp_path):
    db_path = tmp_path / "findings_test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as s:
        yield s
    await engine.dispose()


def _write_module(ws: Path, slug: str, results: list):
    d = ws / "cygor-enumeration-modules" / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / "cygor-result.json").write_text(
        json.dumps({"module": {"slug": slug}, "results": results}), encoding="utf-8")


@pytest.mark.asyncio
async def test_ingest_creates_findings_and_links_host(session, tmp_path):
    ws = tmp_path / "ws"
    session.add(Host(address="10.0.0.5"))
    await session.commit()

    _write_module(ws, "dbprobe", [
        {"ip": "10.0.0.5", "service": "redis", "port": "6379", "auth_required": "no", "version": "7"},
    ])
    _write_module(ws, "smbexplorer", [
        {"ip": "10.0.0.9", "share": "data", "permissions": "READ, WRITE"},  # host not in DB
    ])

    n = await ingest_findings(session, str(ws))
    assert n == 2

    findings = (await session.execute(select(Finding))).scalars().all()
    by_type = {f.finding_type: f for f in findings}

    redis = by_type["unauth_database"]
    assert redis.target_host == "10.0.0.5"
    assert redis.severity == "high"
    assert redis.port == 6379
    # linked to the Host record by address
    host = (await session.execute(select(Host).where(Host.address == "10.0.0.5"))).scalar_one()
    assert redis.host_id == host.id

    smb = by_type["smb_writable_share"]
    assert smb.target_host == "10.0.0.9"
    assert smb.host_id is None  # no matching Host -> still recorded by target_host


@pytest.mark.asyncio
async def test_ingest_is_idempotent_full_replace(session, tmp_path):
    ws = tmp_path / "ws"
    _write_module(ws, "dnsexplorer", [{"ip": "10.0.0.1", "axfr": "SUCCESS", "recursion": "open"}])

    first = await ingest_findings(session, str(ws))
    second = await ingest_findings(session, str(ws))
    assert first == second  # no duplication on re-ingest

    total = len((await session.execute(select(Finding))).scalars().all())
    assert total == first


@pytest.mark.asyncio
async def test_ingest_empty_workspace(session, tmp_path):
    n = await ingest_findings(session, str(tmp_path / "empty"))
    assert n == 0
    assert (await session.execute(select(Finding))).scalars().all() == []
