"""
Tests for the enrichment ingest pipeline (Phase 1 substrate).

Covers:
- The schema is created and the two tables are linked correctly.
- A canonical enrich JSON file is parsed into one run + N findings.
- Per-source extractors produce neutral summaries and signal lists
  (no severity language, ever).
- IP IOCs that match a Host record get linked via host_id.
- Source-specific failures (an enrichment dict with "error") are recorded
  rather than dropped.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel, select

from cygor.webapp.enrichment_ingest import (
    _abuseipdb_extractor,
    _greynoise_extractor,
    _otx_extractor,
    _shodan_extractor,
    _virustotal_extractor,
    ingest_enrichment_file,
)
from cygor.webapp.models import EnrichmentFinding, EnrichmentRun, Host


# ---------------------------------------------------------------------------
# Async DB fixture
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def session(tmp_path):
    db_path = tmp_path / "enrich_test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}", future=True)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as s:
        yield s
    await engine.dispose()


def _write_enrichment(path: Path, results: list) -> Path:
    path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# Extractors — tested standalone (no DB needed)
# ---------------------------------------------------------------------------


class TestExtractors:
    """Per-source summary + signals must be neutral and informative."""

    def test_shodan(self):
        s, sig = _shodan_extractor({"ports": [22, 80], "org": "Acme", "country": "US"})
        assert "2 port(s)" in s
        assert "Acme" in s
        assert sig == ["shodan-record"]

    def test_shodan_with_cves_and_ssl(self):
        _, sig = _shodan_extractor({"ports": [22], "vulns": ["CVE-1"], "ssl": {}})
        assert "shodan-cves" in sig
        assert "has-tls" in sig

    def test_vt_string_ratio(self):
        s, sig = _virustotal_extractor({"detection_ratio": "5/89"})
        assert "5/89" in s
        assert "vt-detections" in sig

    def test_vt_zero_detections(self):
        s, sig = _virustotal_extractor({"detection_ratio": "0/89"})
        assert "0/89" in s
        assert "vt-detections" not in sig

    def test_vt_dict_stats(self):
        s, _ = _virustotal_extractor(
            {"last_analysis_stats": {"malicious": 3, "suspicious": 1}}
        )
        assert "3 malicious" in s
        assert "1 suspicious" in s

    def test_abuseipdb(self):
        s, sig = _abuseipdb_extractor(
            {"abuse_confidence_score": 87, "total_reports": 142, "country_code": "RU"}
        )
        assert "87%" in s
        assert "142" in s
        assert "abuseipdb-reported" in sig

    def test_abuseipdb_clean(self):
        _, sig = _abuseipdb_extractor({"abuse_confidence_score": 0})
        assert "abuseipdb-reported" not in sig

    def test_greynoise(self):
        s, sig = _greynoise_extractor(
            {"classification": "malicious", "name": "Mirai", "last_seen": "2026-04-30"}
        )
        assert "malicious" in s
        assert "Mirai" in s
        assert "greynoise-malicious" in sig

    def test_otx(self):
        _, sig = _otx_extractor({"pulse_count": 4})
        assert "otx-pulses" in sig

    def test_otx_empty(self):
        _, sig = _otx_extractor({"pulse_count": 0})
        assert "otx-pulses" not in sig

    def test_no_severity_language(self):
        # No extractor should produce summaries or signals containing
        # severity vocabulary. The product convention is signals-only.
        forbidden = {"critical", "high", "medium", "low", "severity", "malicious_score"}
        for ext, sample in [
            (_shodan_extractor, {"ports": [22], "vulns": ["CVE-1"]}),
            (_virustotal_extractor, {"detection_ratio": "5/89"}),
            (_abuseipdb_extractor, {"abuse_confidence_score": 87}),
            (_greynoise_extractor, {"classification": "malicious"}),
            (_otx_extractor, {"pulse_count": 4}),
        ]:
            summary, signals = ext(sample)
            blob = (summary + " " + " ".join(signals)).lower()
            for word in forbidden:
                # "malicious" is allowed when it's the GreyNoise classification
                # (descriptive, not a verdict). We're checking that nothing
                # else applies severity vocabulary to the data.
                if word == "malicious" and ext is _greynoise_extractor:
                    continue
                assert word not in blob, (
                    f"{ext.__name__} leaked severity word '{word}' into output"
                )


# ---------------------------------------------------------------------------
# Schema sanity
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tables_exist_and_link(session: AsyncSession):
    run = EnrichmentRun(output_path="/tmp/x.json", sources=["shodan"])
    session.add(run)
    await session.flush()
    finding = EnrichmentFinding(
        run_id=run.id,
        ioc_value="1.2.3.4",
        ioc_type="ip",
        source="shodan",
        signals=["shodan-record"],
        raw={"ports": [22]},
    )
    session.add(finding)
    await session.commit()

    res = await session.execute(select(EnrichmentFinding))
    rows = res.scalars().all()
    assert len(rows) == 1
    assert rows[0].run_id == run.id
    assert rows[0].signals == ["shodan-record"]


# ---------------------------------------------------------------------------
# Full ingest path
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_ingest_canonical_file(session: AsyncSession, tmp_path):
    json_path = _write_enrichment(tmp_path / "enrichment-test.json", [
        {
            "ioc": "1.2.3.4",
            "type": "ip",
            "enrichments": [
                {"source": "shodan", "ports": [22, 80], "org": "Acme"},
                {"source": "virustotal", "detection_ratio": "5/89"},
                {"source": "abuseipdb", "abuse_confidence_score": 87, "total_reports": 12},
            ],
        },
        {
            "ioc": "evil.com",
            "type": "domain",
            "enrichments": [
                {"source": "virustotal", "detection_ratio": "0/89", "categories": ["phishing"]},
            ],
        },
    ])

    run = await ingest_enrichment_file(
        session, json_path, task_id="task-abc",
    )
    await session.commit()

    assert run.id is not None
    assert run.task_id == "task-abc"
    assert run.ioc_count == 2
    assert run.finding_count == 4
    assert run.completed_at is not None
    assert set(run.sources) == {"shodan", "virustotal", "abuseipdb"}

    findings = (await session.execute(
        select(EnrichmentFinding).where(EnrichmentFinding.run_id == run.id)
    )).scalars().all()
    assert len(findings) == 4
    by_source = {}
    for f in findings:
        by_source.setdefault(f.source, []).append(f)
    assert "shodan" in by_source
    assert by_source["virustotal"][0].summary  # non-empty


@pytest.mark.asyncio
async def test_ingest_links_known_host(session: AsyncSession, tmp_path):
    # Pre-create a Host record. The ingest should link the IP finding to it.
    h = Host(address="10.0.0.5", hostname="web-01")
    session.add(h)
    await session.commit()

    json_path = _write_enrichment(tmp_path / "enrichment.json", [
        {
            "ioc": "10.0.0.5",
            "type": "ip",
            "enrichments": [{"source": "shodan", "ports": [22]}],
        },
        {
            "ioc": "8.8.8.8",
            "type": "ip",
            "enrichments": [{"source": "shodan", "ports": [53]}],
        },
    ])

    await ingest_enrichment_file(session, json_path)
    await session.commit()

    findings = (await session.execute(select(EnrichmentFinding))).scalars().all()
    by_ioc = {f.ioc_value: f for f in findings}
    assert by_ioc["10.0.0.5"].host_id == h.id
    assert by_ioc["8.8.8.8"].host_id is None


@pytest.mark.asyncio
async def test_source_error_is_recorded_not_dropped(session: AsyncSession, tmp_path):
    json_path = _write_enrichment(tmp_path / "errs.json", [
        {
            "ioc": "1.1.1.1",
            "type": "ip",
            "enrichments": [
                {"source": "shodan", "error": "rate limited"},
                {"source": "virustotal", "detection_ratio": "0/89"},
            ],
        },
    ])

    run = await ingest_enrichment_file(session, json_path)
    await session.commit()

    findings = (await session.execute(
        select(EnrichmentFinding).where(EnrichmentFinding.run_id == run.id)
    )).scalars().all()
    sources = {f.source for f in findings}
    assert sources == {"shodan", "virustotal"}
    shodan_finding = next(f for f in findings if f.source == "shodan")
    assert "rate limited" in shodan_finding.summary
    assert "shodan-error" in shodan_finding.signals


@pytest.mark.asyncio
async def test_ingest_unknown_source_falls_through(session: AsyncSession, tmp_path):
    # Sources we don't have an extractor for should still produce a row with
    # a generic summary — important for forward-compat as new enrichers ship.
    json_path = _write_enrichment(tmp_path / "future.json", [
        {
            "ioc": "1.2.3.4",
            "type": "ip",
            "enrichments": [
                {"source": "future_intel_co", "weird_field": "hello", "another": 42},
            ],
        },
    ])
    await ingest_enrichment_file(session, json_path)
    await session.commit()
    f = (await session.execute(select(EnrichmentFinding))).scalars().one()
    assert f.source == "future_intel_co"
    assert f.summary  # not empty


@pytest.mark.asyncio
async def test_ingest_rejects_non_list_json(session: AsyncSession, tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"not": "a list"}), encoding="utf-8")
    with pytest.raises(ValueError):
        await ingest_enrichment_file(session, bad)


@pytest.mark.asyncio
async def test_ingest_missing_file(session: AsyncSession, tmp_path):
    with pytest.raises(FileNotFoundError):
        await ingest_enrichment_file(session, tmp_path / "nope.json")


@pytest.mark.asyncio
async def test_ingest_skips_blank_iocs(session: AsyncSession, tmp_path):
    json_path = _write_enrichment(tmp_path / "blanks.json", [
        {"ioc": "", "type": "ip", "enrichments": [{"source": "shodan"}]},
        {"ioc": "1.2.3.4", "type": "ip", "enrichments": [{"source": "shodan"}]},
        {"not_a_dict": True},
    ])
    run = await ingest_enrichment_file(session, json_path)
    await session.commit()
    assert run.ioc_count == 1
    assert run.finding_count == 1


# ---------------------------------------------------------------------------
# Phase 2: Shodan ssl block → cert finding (derived at ingest time)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shodan_ssl_emits_separate_cert_finding(session: AsyncSession, tmp_path):
    """When Shodan returns an ssl block, ingest emits an extra cert-flavored row."""
    json_path = _write_enrichment(tmp_path / "ssl.json", [
        {
            "ioc": "1.2.3.4",
            "type": "ip",
            "enrichments": [
                {
                    "source": "shodan",
                    "ports": [443],
                    "ssl": {
                        "cert": {
                            "subject": {"CN": "example.com"},
                            "issuer": {"CN": "Let's Encrypt"},
                            "expires": "20251231120000Z",
                            "subject_alt_names": ["example.com", "*.example.com"],
                            "pubkey": {"type": "rsa", "bits": 2048},
                            "fingerprint": {"sha256": "a" * 64},
                        },
                        "versions": ["TLSv1.2", "TLSv1.3"],
                    },
                },
            ],
        },
    ])
    run = await ingest_enrichment_file(session, json_path)
    await session.commit()

    findings = (await session.execute(
        select(EnrichmentFinding).where(EnrichmentFinding.run_id == run.id)
    )).scalars().all()
    sources = {f.source for f in findings}
    kinds = {f.finding_kind for f in findings}
    assert "shodan" in sources           # the regular observation row
    assert "shodan_ssl" in sources       # the derived cert row
    assert "cert" in kinds
    cert_row = next(f for f in findings if f.finding_kind == "cert")
    assert "CN=example.com" in cert_row.summary
    assert "has-sans" in cert_row.signals


@pytest.mark.asyncio
async def test_shodan_no_ssl_no_cert_finding(session: AsyncSession, tmp_path):
    json_path = _write_enrichment(tmp_path / "no_ssl.json", [
        {
            "ioc": "1.2.3.4", "type": "ip",
            "enrichments": [{"source": "shodan", "ports": [80]}],
        },
    ])
    await ingest_enrichment_file(session, json_path)
    await session.commit()
    kinds = (await session.execute(
        select(EnrichmentFinding.finding_kind).distinct()
    )).scalars().all()
    assert "cert" not in set(kinds)


# ---------------------------------------------------------------------------
# Phase 2b: crt.sh extractor
# ---------------------------------------------------------------------------


def test_crtsh_extractor():
    from cygor.webapp.enrichment_ingest import _crtsh_extractor
    s, sig = _crtsh_extractor({
        "certs": [
            {"common_name": "example.com", "issuer_name": "Lets Encrypt R3"},
            {"common_name": "example.com", "issuer_name": "Lets Encrypt R3"},
        ]
    })
    assert "2 cert(s)" in s
    assert "ct-history-available" in sig
    assert "crt-sh-record" in sig


def test_crtsh_extractor_empty():
    from cygor.webapp.enrichment_ingest import _crtsh_extractor
    s, sig = _crtsh_extractor({"certs": []})
    assert "ct-history-available" not in sig
    assert "crt-sh-record" in sig


# ---------------------------------------------------------------------------
# Phase 3: AI service indicator emission
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shodan_with_ollama_banner_emits_ai_indicator(session: AsyncSession, tmp_path):
    json_path = _write_enrichment(tmp_path / "ai.json", [
        {
            "ioc": "10.0.0.50",
            "type": "ip",
            "enrichments": [
                {
                    "source": "shodan",
                    "port": 11434,
                    "data": "HTTP/1.1 200 OK\nServer: Werkzeug\n\nOllama is running",
                },
            ],
        },
    ])
    run = await ingest_enrichment_file(session, json_path)
    await session.commit()

    findings = (await session.execute(
        select(EnrichmentFinding).where(EnrichmentFinding.run_id == run.id)
    )).scalars().all()
    kinds = {f.finding_kind for f in findings}
    assert "ai_indicator" in kinds
    ai_row = next(f for f in findings if f.finding_kind == "ai_indicator")
    assert ai_row.signals  # has signals
    assert "ai-suspected" in ai_row.signals
    assert "ai-ollama" in ai_row.signals
    assert "mcp-confirmed" not in ai_row.signals  # never use confirmed language


# ---------------------------------------------------------------------------
# Phase 4: MCP indicator emission
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_shodan_with_mcp_signals_emits_mcp_indicator(session: AsyncSession, tmp_path):
    json_path = _write_enrichment(tmp_path / "mcp.json", [
        {
            "ioc": "10.0.0.51",
            "type": "ip",
            "enrichments": [
                {
                    "source": "shodan",
                    "port": 9000,
                    "data": "Some banner mentioning Model Context Protocol",
                    "http": {
                        "html": "Model Context Protocol jsonrpc tools",
                        "title": "MCP",
                    },
                },
            ],
        },
    ])
    run = await ingest_enrichment_file(session, json_path)
    await session.commit()

    findings = (await session.execute(
        select(EnrichmentFinding).where(EnrichmentFinding.run_id == run.id)
    )).scalars().all()
    kinds = {f.finding_kind for f in findings}
    assert "mcp_indicator" in kinds
    mcp_row = next(f for f in findings if f.finding_kind == "mcp_indicator")
    assert "mcp-suspected" in mcp_row.signals
    # Confirmation vocabulary is forbidden in enrich:
    assert not any("confirmed" in s for s in mcp_row.signals)
    assert "suspected" in mcp_row.summary.lower()


@pytest.mark.asyncio
async def test_shodan_without_mcp_signals_emits_nothing(session: AsyncSession, tmp_path):
    json_path = _write_enrichment(tmp_path / "no_mcp.json", [
        {
            "ioc": "10.0.0.52",
            "type": "ip",
            "enrichments": [{"source": "shodan", "port": 80, "data": "nginx 1.20"}],
        },
    ])
    run = await ingest_enrichment_file(session, json_path)
    await session.commit()
    kinds = (await session.execute(
        select(EnrichmentFinding.finding_kind).distinct()
    )).scalars().all()
    assert "mcp_indicator" not in set(kinds)
