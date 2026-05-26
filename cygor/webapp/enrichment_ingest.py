"""
Enrichment file ingest.

Parses the JSON produced by ``cygor enrich`` (a list of result dicts of the
shape ``{"ioc", "type", "enrichments": [...]}``) and writes one
``EnrichmentRun`` row plus N ``EnrichmentFinding`` rows. The JSON file on
disk remains the source of truth — this layer is the searchable index.

The ingest is deliberately tolerant of source-specific shapes: each
``enrichments[i]`` dict is stored verbatim in ``EnrichmentFinding.raw`` and
a neutral one-line ``summary`` is derived per source via small extractor
functions. New enrichers can be added without touching the schema.

This module follows the project's architectural rule for enrich: it never
sends a packet to an asset. It only reads what the enrich pipeline already
saved on disk and persists it to the database.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import EnrichmentFinding, EnrichmentRun, Host

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-source summary + signal extractors
# ---------------------------------------------------------------------------
#
# Each extractor takes the enrichment dict and returns (summary, signals).
# Both fields are neutral — no severity language. Signals are searchable
# tags consumers (UI filters, search, reports) can match against.
#
# Sources we don't recognize fall through to ``_default_extractor``, which
# still records the row but produces a generic summary. That keeps ingest
# forward-compatible with new sources we add later.


def _shodan_extractor(e: Dict[str, Any]) -> Tuple[str, List[str]]:
    ports = e.get("ports") or []
    org = e.get("org") or e.get("organization") or ""
    country = e.get("country") or e.get("country_code") or ""
    last_update = e.get("last_update") or e.get("timestamp") or ""

    bits: List[str] = []
    if ports:
        bits.append(f"{len(ports)} port(s) indexed")
    if org:
        bits.append(f"org: {org}")
    if country:
        bits.append(f"country: {country}")
    summary = " · ".join(bits) if bits else "Shodan record present"
    if last_update:
        summary += f" · last seen {last_update}"

    signals: List[str] = ["shodan-record"]
    if e.get("vulns") or e.get("cves"):
        signals.append("shodan-cves")
    # Shodan often returns an empty {} ssl block to indicate "TLS observed
    # but no cert details parsed"; key presence is the right test.
    if "ssl" in e or "certificate" in e:
        signals.append("has-tls")
    return summary, signals


def _virustotal_extractor(e: Dict[str, Any]) -> Tuple[str, List[str]]:
    # VT shapes vary across IOC type (domain vs ip vs hash). Keep the
    # extractor wide.
    detection_ratio = e.get("detection_ratio") or e.get("last_analysis_stats")
    summary_bits: List[str] = []
    signals: List[str] = ["vt-record"]

    if isinstance(detection_ratio, str) and "/" in detection_ratio:
        # "7/89"
        try:
            hits, _, total = detection_ratio.partition("/")
            n = int(hits)
            if n > 0:
                signals.append("vt-detections")
            summary_bits.append(f"{detection_ratio} engines flagged")
        except ValueError:
            pass
    elif isinstance(detection_ratio, dict):
        # last_analysis_stats: {"malicious": N, "suspicious": M, ...}
        mal = detection_ratio.get("malicious") or 0
        susp = detection_ratio.get("suspicious") or 0
        summary_bits.append(f"{mal} malicious · {susp} suspicious")
        if mal:
            signals.append("vt-detections")

    cats = e.get("categories")
    if cats:
        if isinstance(cats, dict):
            cats = list(cats.values())
        if isinstance(cats, list) and cats:
            summary_bits.append("categories: " + ", ".join(str(c) for c in cats[:3]))

    if not summary_bits:
        summary_bits.append("VirusTotal record present")
    return " · ".join(summary_bits), signals


def _abuseipdb_extractor(e: Dict[str, Any]) -> Tuple[str, List[str]]:
    confidence = e.get("abuse_confidence_score")
    if confidence is None:
        confidence = e.get("confidence_score")
    reports = e.get("total_reports") or 0
    bits: List[str] = []
    if confidence is not None:
        bits.append(f"confidence: {confidence}%")
    if reports:
        bits.append(f"{reports} report(s)")
    if e.get("country_code"):
        bits.append(f"country: {e['country_code']}")

    summary = " · ".join(bits) if bits else "AbuseIPDB record present"
    signals = ["abuseipdb-record"]
    try:
        if confidence is not None and int(confidence) > 0:
            signals.append("abuseipdb-reported")
    except (TypeError, ValueError):
        pass
    return summary, signals


def _greynoise_extractor(e: Dict[str, Any]) -> Tuple[str, List[str]]:
    classification = e.get("classification") or e.get("noise") or ""
    name = e.get("name") or ""
    last_seen = e.get("last_seen") or ""
    bits: List[str] = []
    if classification:
        bits.append(f"classification: {classification}")
    if name:
        bits.append(f"actor: {name}")
    if last_seen:
        bits.append(f"last seen {last_seen}")
    summary = " · ".join(bits) if bits else "GreyNoise record present"

    signals = ["greynoise-record"]
    if classification:
        signals.append(f"greynoise-{classification}")
    return summary, signals


def _otx_extractor(e: Dict[str, Any]) -> Tuple[str, List[str]]:
    pulses = e.get("pulse_count") or e.get("pulses") or 0
    if isinstance(pulses, list):
        pulses = len(pulses)
    summary = f"{pulses} pulse(s)" if pulses else "OTX record present"

    signals = ["otx-record"]
    if pulses:
        signals.append("otx-pulses")
    return summary, signals


def _default_extractor(e: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Catch-all summary so unknown sources still produce a row."""
    keys = sorted(k for k in e.keys() if k != "source" and not k.startswith("_"))
    if not keys:
        return "record present", []
    return f"fields: {', '.join(keys[:5])}", []


def _crtsh_extractor(e: Dict[str, Any]) -> Tuple[str, List[str]]:
    """crt.sh CT-log finding produced by the dedicated enricher."""
    certs = e.get("certs") or []
    bits: List[str] = []
    if certs:
        bits.append(f"{len(certs)} cert(s) in CT logs")
        latest = certs[0] if isinstance(certs[0], dict) else None
        if latest:
            cn = latest.get("common_name") or latest.get("subject_cn") or ""
            if cn:
                bits.append(f"latest CN: {cn}")
            issuer = latest.get("issuer_name") or latest.get("issuer_cn") or ""
            if issuer:
                bits.append(f"issuer: {issuer}")
    summary = " · ".join(bits) if bits else "crt.sh record present"
    signals = ["crt-sh-record"]
    if certs:
        signals.append("ct-history-available")
    return summary, signals


# Map source name -> extractor. Unknown sources go through _default_extractor.
# Defined after every extractor so name resolution works at import.
_EXTRACTORS = {
    "shodan": _shodan_extractor,
    "virustotal": _virustotal_extractor,
    "abuseipdb": _abuseipdb_extractor,
    "greynoise": _greynoise_extractor,
    "otx": _otx_extractor,
    "crt_sh": _crtsh_extractor,
}


# ---------------------------------------------------------------------------
# Derived findings: read existing source data and emit additional findings
# ---------------------------------------------------------------------------
#
# Some sources carry data that's worth a separate EnrichmentFinding row even
# though it came from the same enricher. Example: Shodan returns a full SSL
# block embedded in its main response. Surfacing it as its own finding lets
# the host-detail "Certificate" card pull a clean record without parsing the
# whole Shodan blob.


def _shodan_ssl_to_cert_finding(ioc_value: str, ioc_type: str, shodan_dict: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    If a Shodan enrichment dict carries an ``ssl`` block, return a cert-flavored
    finding payload (caller wraps it into an EnrichmentFinding). Returns None
    when there's no usable cert data.
    """
    ssl = shodan_dict.get("ssl") or {}
    if not isinstance(ssl, dict) or not ssl:
        return None
    cert = ssl.get("cert") or {}
    if not isinstance(cert, dict):
        cert = {}

    # crawl through the various ways subject CN can appear
    subject = cert.get("subject") or {}
    if isinstance(subject, dict):
        cn = subject.get("CN") or subject.get("commonName") or ""
    else:
        cn = ""
    issuer = cert.get("issuer") or {}
    issuer_cn = ""
    if isinstance(issuer, dict):
        issuer_cn = issuer.get("CN") or issuer.get("commonName") or ""

    sans = cert.get("subject_alt_names") or cert.get("sans") or []
    if not isinstance(sans, list):
        sans = []

    expires = cert.get("expires") or cert.get("not_after") or ""
    issued = cert.get("issued") or cert.get("not_before") or ""

    pubkey = cert.get("pubkey") or {}
    key_alg = pubkey.get("type") if isinstance(pubkey, dict) else ""
    key_bits = pubkey.get("bits") if isinstance(pubkey, dict) else None

    fp_obj = cert.get("fingerprint") or {}
    sha256_fp = ""
    if isinstance(fp_obj, dict):
        sha256_fp = fp_obj.get("sha256") or fp_obj.get("SHA256") or ""

    sig_alg = cert.get("sig_alg") or cert.get("signature_algorithm") or ""

    bits: List[str] = []
    if cn:
        bits.append(f"CN={cn}")
    if issuer_cn:
        bits.append(f"issuer: {issuer_cn}")
    if expires:
        bits.append(f"expires {expires}")
    summary = " · ".join(bits) if bits else "Shodan-observed certificate"

    signals: List[str] = ["cert-from-shodan"]
    if sans:
        signals.append("has-sans")
    if not issuer_cn or (cn and issuer_cn == cn):
        signals.append("self-signed-suspect")
    if sig_alg and "sha1" in sig_alg.lower():
        signals.append("weak-sig")
    if isinstance(key_bits, int) and key_bits and key_bits < 2048:
        signals.append("weak-key")

    raw = {
        "subject_cn": cn,
        "issuer_cn": issuer_cn,
        "sans": sans,
        "issued": issued,
        "expires": expires,
        "key_alg": key_alg,
        "key_bits": key_bits,
        "sig_alg": sig_alg,
        "sha256_fingerprint": sha256_fp,
        "tls_versions": ssl.get("versions"),
        "raw_ssl": ssl,
    }
    return {
        "source": "shodan_ssl",
        "finding_kind": "cert",
        "summary": summary,
        "signals": signals,
        "raw": raw,
    }


# ---------------------------------------------------------------------------
# Ingest
# ---------------------------------------------------------------------------


async def ingest_enrichment_file(
    session: AsyncSession,
    json_path: Path | str,
    *,
    task_id: Optional[str] = None,
    sources: Optional[List[str]] = None,
    notes: Optional[str] = None,
) -> EnrichmentRun:
    """
    Parse a cygor enrich output file and write a run + findings to the DB.

    Parameters
    ----------
    session
        Async SQLAlchemy session. The caller is responsible for committing.
    json_path
        Path to the ``enrichment-*.json`` file written by ``cygor enrich``.
    task_id
        Optional cygor task ID this run came from. Used to correlate the run
        with the live console output.
    sources
        The list of sources the user requested. When omitted, we infer the
        set from the source names present in the file.
    notes
        Free-form description (e.g., "AI scope sweep on 10.10.0.0/16").

    Returns
    -------
    EnrichmentRun
        The persisted run record (with all its findings flushed). Caller
        should ``await session.commit()`` after.

    Raises
    ------
    FileNotFoundError
        If ``json_path`` doesn't exist.
    ValueError
        If the file isn't a JSON list of result dicts.
    """
    path = Path(json_path)
    if not path.exists():
        raise FileNotFoundError(f"Enrichment file not found: {path}")

    try:
        results = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Failed to parse enrichment JSON {path}: {e}") from e

    if not isinstance(results, list):
        raise ValueError(
            f"Enrichment file {path} did not contain a list of results "
            f"(got {type(results).__name__})"
        )

    # Build a lookup for IP -> host_id so we can link findings.
    host_lookup: Dict[str, int] = {}
    if results:
        ips = sorted({
            str(r.get("ioc")).strip()
            for r in results
            if isinstance(r, dict) and r.get("type") == "ip" and r.get("ioc")
        })
        if ips:
            stmt = select(Host.id, Host.address).where(Host.address.in_(ips))
            rows = (await session.execute(stmt)).all()
            host_lookup = {addr: hid for (hid, addr) in rows if addr}

    # Infer sources if caller didn't provide them.
    if sources is None:
        seen: List[str] = []
        for r in results:
            if not isinstance(r, dict):
                continue
            for e in r.get("enrichments") or []:
                if isinstance(e, dict):
                    s = e.get("source")
                    if s and s not in seen:
                        seen.append(s)
        sources = seen

    run = EnrichmentRun(
        task_id=task_id,
        started_at=datetime.utcnow(),
        completed_at=None,
        output_path=str(path.resolve()),
        sources=list(sources or []),
        notes=notes,
        ioc_count=0,
        finding_count=0,
    )
    session.add(run)
    await session.flush()  # populate run.id

    finding_count = 0
    ioc_count = 0

    for entry in results:
        if not isinstance(entry, dict):
            continue
        ioc_value = str(entry.get("ioc") or "").strip()
        if not ioc_value:
            continue
        ioc_type = str(entry.get("type") or "").strip().lower() or "unknown"
        ioc_count += 1
        host_id = host_lookup.get(ioc_value) if ioc_type == "ip" else None

        enrichments = entry.get("enrichments") or []
        if not isinstance(enrichments, list):
            continue

        for enrichment in enrichments:
            if not isinstance(enrichment, dict):
                continue
            source = str(enrichment.get("source") or "unknown").strip().lower()
            # Errors from a single source shouldn't drop the row — record them
            # so the UI can surface "shodan failed for 1.2.3.4" cleanly.
            if "error" in enrichment:
                summary = f"{source} failed: {enrichment['error']}"
                signals = [f"{source}-error"]
            else:
                extractor = _EXTRACTORS.get(source, _default_extractor)
                try:
                    summary, signals = extractor(enrichment)
                except Exception as exc:  # extractor bugs shouldn't kill ingest
                    logger.warning(
                        "Extractor for source=%s raised %s; falling back",
                        source, exc,
                    )
                    summary, signals = _default_extractor(enrichment)

            finding = EnrichmentFinding(
                run_id=run.id,
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                source=source,
                finding_kind="observation",
                summary=summary,
                signals=list(signals or []),
                raw=enrichment,
                host_id=host_id,
                enriched_at=datetime.utcnow(),
            )
            session.add(finding)
            finding_count += 1

            # Derived findings: surface cert data embedded in the Shodan
            # response as a separate cert-flavored finding so the UI's
            # Certificate card can pull a clean record.
            if source == "shodan":
                cert_payload = _shodan_ssl_to_cert_finding(ioc_value, ioc_type, enrichment)
                if cert_payload:
                    derived = EnrichmentFinding(
                        run_id=run.id,
                        ioc_value=ioc_value,
                        ioc_type=ioc_type,
                        source=cert_payload["source"],
                        finding_kind=cert_payload["finding_kind"],
                        summary=cert_payload["summary"],
                        signals=cert_payload["signals"],
                        raw=cert_payload["raw"],
                        host_id=host_id,
                        enriched_at=datetime.utcnow(),
                    )
                    session.add(derived)
                    finding_count += 1

                # Walk the Shodan response for AI/MCP indicators (Phase 3+4
                # passive matching). Multiple services on a host can each
                # produce a separate indicator finding.
                from .enrichment_ai import shodan_to_ai_findings
                from .enrichment_mcp import shodan_to_mcp_findings
                for payload in shodan_to_ai_findings(ioc_value, ioc_type, enrichment):
                    session.add(EnrichmentFinding(
                        run_id=run.id,
                        ioc_value=ioc_value,
                        ioc_type=ioc_type,
                        source=payload["source"],
                        finding_kind=payload["finding_kind"],
                        summary=payload["summary"],
                        signals=payload["signals"],
                        raw=payload["raw"],
                        host_id=host_id,
                        enriched_at=datetime.utcnow(),
                    ))
                    finding_count += 1
                for payload in shodan_to_mcp_findings(ioc_value, ioc_type, enrichment):
                    session.add(EnrichmentFinding(
                        run_id=run.id,
                        ioc_value=ioc_value,
                        ioc_type=ioc_type,
                        source=payload["source"],
                        finding_kind=payload["finding_kind"],
                        summary=payload["summary"],
                        signals=payload["signals"],
                        raw=payload["raw"],
                        host_id=host_id,
                        enriched_at=datetime.utcnow(),
                    ))
                    finding_count += 1

    run.ioc_count = ioc_count
    run.finding_count = finding_count
    run.completed_at = datetime.utcnow()
    await session.flush()

    logger.info(
        "Ingested enrichment file %s: run=%d iocs=%d findings=%d sources=%s",
        path.name, run.id, ioc_count, finding_count, sources,
    )
    return run


async def reingest_enrichment_file(
    session: AsyncSession,
    json_path: Path | str,
    **kwargs,
) -> EnrichmentRun:
    """
    Re-ingest a file (e.g., after the extractor logic changed).

    Currently this just creates a new run rather than updating in place.
    History of past runs is preserved deliberately so the UI can show drift
    in how many findings a given file produced over time.
    """
    return await ingest_enrichment_file(session, json_path, **kwargs)
