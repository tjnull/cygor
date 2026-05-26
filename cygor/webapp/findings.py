"""
Finding ingestion
=================

Distil the high-signal observations from enumeration module output into the
queryable ``finding`` table, so per-host next steps and (later) cross-host triage
don't have to re-read every cygor-result.json on each request.

The per-module JSON files remain the source of truth. Ingestion is a full
replace: it reads the current state of all module results and rewrites the table,
so it is idempotent and never accumulates stale rows. The derivation itself lives
in :mod:`cygor.nextsteps` (pure logic), shared with the per-host panel.
"""
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import delete, select

from cygor.nextsteps import module_findings
from cygor.webapp.models import Finding, Host


def _load_module_results(workspace: str) -> List[Dict[str, Any]]:
    """Read every cygor-enumeration-modules/<slug>/cygor-result.json."""
    base = Path(workspace) / "cygor-enumeration-modules"
    out: List[Dict[str, Any]] = []
    if not base.is_dir():
        return out
    for slug_dir in sorted(base.iterdir()):
        if not slug_dir.is_dir():
            continue
        jf = slug_dir / "cygor-result.json"
        if not jf.is_file():
            continue
        try:
            data = json.loads(jf.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            continue
        if isinstance(data, dict):
            out.append({
                "module": data.get("module") or {"slug": slug_dir.name},
                "results": data.get("results") or [],
            })
    return out


async def ingest_findings(session, workspace: str) -> int:
    """Re-derive findings from module results and replace the finding table.

    Returns the number of findings written. Files are the source of truth, so we
    fully replace the table each run (idempotent, no stale rows).
    """
    module_results = _load_module_results(workspace)
    findings = module_findings(module_results)

    rows = (await session.execute(select(Host.id, Host.address))).all()
    addr_to_id = {(addr or "").lower(): hid for hid, addr in rows}

    await session.execute(delete(Finding))

    count = 0
    for f in findings:
        host = (f.get("host") or "").strip()
        port = f.get("port")
        session.add(Finding(
            host_id=addr_to_id.get(host.lower()),
            target_host=host,
            port=int(port) if str(port).isdigit() else None,
            service=f.get("service") or None,
            module=f.get("module") or None,
            finding_type=f.get("finding_type") or "finding",
            severity=f.get("severity") or "info",
            title=f.get("title") or "",
            evidence=f.get("evidence") or None,
            command=f.get("command") or None,
        ))
        count += 1

    await session.commit()
    return count


async def ingest_findings_safe(workspace: str) -> int:
    """Best-effort ingest with its own session (for background task hooks).

    Never raises -- a findings-index hiccup must not fail the enumeration task
    that triggered it.
    """
    try:
        from cygor.webapp.db import SessionLocal
        if SessionLocal is None:
            return 0
        async with SessionLocal() as session:
            return await ingest_findings(session, workspace)
    except Exception:
        return 0
