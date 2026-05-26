"""
Enrichment dashboard, run drill-down, and per-host enrichment APIs.

These routes read from the EnrichmentRun + EnrichmentFinding tables that
the post-task ingest hook populates. They never trigger network calls
themselves — display-only, in keeping with the architectural rule that
enrich-side traffic is owned by the ``cygor enrich`` CLI / async pipeline.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_session
from ..models import EnrichmentFinding, EnrichmentRun, Host

router = APIRouter(tags=["enrichment"])

templates = None


def set_templates(tmpl):
    global templates
    templates = tmpl


# ---------------------------------------------------------------------------
# Dashboard page
# ---------------------------------------------------------------------------


@router.get("/enrichment", response_class=HTMLResponse)
async def enrichment_dashboard(request: Request, session: AsyncSession = Depends(get_session)):
    """Coverage-oriented dashboard listing recent runs + workspace stats."""
    if templates is None:
        raise HTTPException(status_code=500, detail="Templates not configured")

    # Recent runs (latest 50)
    runs_stmt = (
        select(EnrichmentRun)
        .order_by(EnrichmentRun.started_at.desc())
        .limit(50)
    )
    runs = (await session.execute(runs_stmt)).scalars().all()

    # Coverage stats — count hosts with at least one finding of each kind.
    total_hosts = (await session.execute(select(func.count(Host.id)))).scalar_one() or 0

    async def _hosts_with_kind(kind: str) -> int:
        stmt = select(func.count(func.distinct(EnrichmentFinding.host_id))).where(
            EnrichmentFinding.host_id.is_not(None),
            EnrichmentFinding.finding_kind == kind,
        )
        return (await session.execute(stmt)).scalar_one() or 0

    async def _hosts_with_source(source: str) -> int:
        stmt = select(func.count(func.distinct(EnrichmentFinding.host_id))).where(
            EnrichmentFinding.host_id.is_not(None),
            EnrichmentFinding.source == source,
        )
        return (await session.execute(stmt)).scalar_one() or 0

    coverage = {
        "total_hosts": total_hosts,
        "with_shodan": await _hosts_with_source("shodan"),
        "with_cert": await _hosts_with_kind("cert"),
        "with_ai": await _hosts_with_kind("ai_indicator"),
        "with_mcp": await _hosts_with_kind("mcp_indicator"),
        "with_vt": await _hosts_with_source("virustotal"),
    }

    return templates.TemplateResponse(
        request,
        "enrichment_dashboard.html",
        {
            "runs": runs,
            "coverage": coverage,
        },
    )


# ---------------------------------------------------------------------------
# Run drill-down page
# ---------------------------------------------------------------------------


@router.get("/enrichment/{run_id}", response_class=HTMLResponse)
async def enrichment_run_view(
    run_id: int, request: Request, session: AsyncSession = Depends(get_session)
):
    if templates is None:
        raise HTTPException(status_code=500, detail="Templates not configured")

    run = (await session.execute(
        select(EnrichmentRun).where(EnrichmentRun.id == run_id)
    )).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Enrichment run not found")

    findings = (await session.execute(
        select(EnrichmentFinding)
        .where(EnrichmentFinding.run_id == run_id)
        .order_by(EnrichmentFinding.ioc_value, EnrichmentFinding.source)
    )).scalars().all()

    # Group findings by IOC for the drill-down view.
    by_ioc: Dict[str, List[EnrichmentFinding]] = {}
    for f in findings:
        by_ioc.setdefault(f.ioc_value, []).append(f)

    # Per-IOC quick-counts the template uses for the "signals at a glance" row.
    ioc_summaries: List[Dict[str, Any]] = []
    for ioc, rows in by_ioc.items():
        sources = sorted({r.source for r in rows})
        signal_counts: Dict[str, int] = {}
        for r in rows:
            for sig in r.signals or []:
                signal_counts[sig] = signal_counts.get(sig, 0) + 1
        ioc_summaries.append({
            "ioc": ioc,
            "ioc_type": rows[0].ioc_type,
            "host_id": rows[0].host_id,
            "rows": rows,
            "sources": sources,
            "signal_counts": signal_counts,
        })

    return templates.TemplateResponse(
        request,
        "enrichment_run.html",
        {
            "run": run,
            "iocs": ioc_summaries,
        },
    )


# ---------------------------------------------------------------------------
# JSON APIs
# ---------------------------------------------------------------------------


@router.get("/api/enrichment/runs")
async def api_list_runs(
    session: AsyncSession = Depends(get_session),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    stmt = (
        select(EnrichmentRun)
        .order_by(EnrichmentRun.started_at.desc())
        .offset(offset)
        .limit(limit)
    )
    runs = (await session.execute(stmt)).scalars().all()
    total = (await session.execute(select(func.count(EnrichmentRun.id)))).scalar_one() or 0
    return JSONResponse({
        "runs": [
            {
                "id": r.id,
                "task_id": r.task_id,
                "started_at": r.started_at.isoformat() if r.started_at else None,
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "output_path": r.output_path,
                "sources": r.sources,
                "ioc_count": r.ioc_count,
                "finding_count": r.finding_count,
                "notes": r.notes,
            }
            for r in runs
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    })


@router.get("/api/enrichment/runs/{run_id}")
async def api_get_run(run_id: int, session: AsyncSession = Depends(get_session)):
    run = (await session.execute(
        select(EnrichmentRun).where(EnrichmentRun.id == run_id)
    )).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")

    by_source = (await session.execute(
        select(EnrichmentFinding.source, func.count(EnrichmentFinding.id))
        .where(EnrichmentFinding.run_id == run_id)
        .group_by(EnrichmentFinding.source)
    )).all()
    by_kind = (await session.execute(
        select(EnrichmentFinding.finding_kind, func.count(EnrichmentFinding.id))
        .where(EnrichmentFinding.run_id == run_id)
        .group_by(EnrichmentFinding.finding_kind)
    )).all()

    return JSONResponse({
        "id": run.id,
        "task_id": run.task_id,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        "output_path": run.output_path,
        "sources": run.sources,
        "ioc_count": run.ioc_count,
        "finding_count": run.finding_count,
        "by_source": {s: c for (s, c) in by_source},
        "by_finding_kind": {k: c for (k, c) in by_kind},
    })


@router.get("/api/enrichment/runs/{run_id}/findings")
async def api_run_findings(
    run_id: int,
    session: AsyncSession = Depends(get_session),
    source: Optional[str] = Query(None),
    kind: Optional[str] = Query(None, alias="finding_kind"),
    signal: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    stmt = select(EnrichmentFinding).where(EnrichmentFinding.run_id == run_id)
    if source:
        stmt = stmt.where(EnrichmentFinding.source == source)
    if kind:
        stmt = stmt.where(EnrichmentFinding.finding_kind == kind)
    if search:
        like = f"%{search}%"
        stmt = stmt.where(
            (EnrichmentFinding.ioc_value.ilike(like))
            | (EnrichmentFinding.summary.ilike(like))
        )
    stmt = stmt.order_by(EnrichmentFinding.ioc_value).offset(offset).limit(limit)

    findings = (await session.execute(stmt)).scalars().all()
    if signal:
        findings = [f for f in findings if signal in (f.signals or [])]

    return JSONResponse({
        "findings": [
            {
                "id": f.id,
                "ioc_value": f.ioc_value,
                "ioc_type": f.ioc_type,
                "source": f.source,
                "finding_kind": f.finding_kind,
                "summary": f.summary,
                "signals": f.signals,
                "host_id": f.host_id,
                "enriched_at": f.enriched_at.isoformat() if f.enriched_at else None,
            }
            for f in findings
        ],
        "limit": limit,
        "offset": offset,
    })


@router.get("/api/enrichment/host/{host_id}")
async def api_host_findings(host_id: int, session: AsyncSession = Depends(get_session)):
    """Return all enrichment findings for a single host, bucketed by kind."""
    host = (await session.execute(
        select(Host).where(Host.id == host_id)
    )).scalar_one_or_none()
    if host is None:
        raise HTTPException(status_code=404, detail="Host not found")

    findings = (await session.execute(
        select(EnrichmentFinding)
        .where(EnrichmentFinding.host_id == host_id)
        .order_by(EnrichmentFinding.enriched_at.desc())
    )).scalars().all()

    buckets: Dict[str, List[Dict[str, Any]]] = {
        "cert": [], "ai_indicator": [], "mcp_indicator": [], "observation": [],
    }
    for f in findings:
        kind = f.finding_kind or "observation"
        buckets.setdefault(kind, []).append({
            "id": f.id,
            "run_id": f.run_id,
            "ioc_value": f.ioc_value,
            "source": f.source,
            "summary": f.summary,
            "signals": f.signals,
            "raw": f.raw,
            "enriched_at": f.enriched_at.isoformat() if f.enriched_at else None,
        })

    return JSONResponse({
        "host_id": host.id,
        "address": host.address,
        "buckets": buckets,
        "total_findings": len(findings),
    })


@router.delete("/api/enrichment/runs/{run_id}")
async def api_delete_run(run_id: int, session: AsyncSession = Depends(get_session)):
    """Drop a run and its findings (re-ingestable from the JSON file on disk)."""
    run = (await session.execute(
        select(EnrichmentRun).where(EnrichmentRun.id == run_id)
    )).scalar_one_or_none()
    if run is None:
        raise HTTPException(status_code=404, detail="Run not found")
    # Delete findings first (no FK cascade configured in the model).
    await session.execute(
        EnrichmentFinding.__table__.delete().where(EnrichmentFinding.run_id == run_id)
    )
    await session.delete(run)
    await session.commit()
    return JSONResponse({"deleted": run_id})
