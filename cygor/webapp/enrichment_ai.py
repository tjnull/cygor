"""
Pattern matcher for AI / agent-service indicators in already-fetched
external source data (Mode A from the design).

This module reads what Shodan / Censys / VirusTotal returned and emits
``ai_indicator`` and ``mcp_indicator`` finding payloads. It never sends a
packet to the asset — that's deliberate, per the enrich architectural rule.

The matcher is intentionally conservative about what fields it inspects —
each pattern says exactly what it requires. False positives are worse here
than false negatives because the `ai-suspected` signal will direct user
attention.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from .enrichment_ai_patterns import AI_DEFAULT_PORTS, get_active_patterns


# ---------------------------------------------------------------------------
# Field extraction helpers — tolerate the various shapes Shodan returns
# ---------------------------------------------------------------------------


def _shodan_iter_services(shodan_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    A Shodan host record can be either:
      - a single service dict (ip + port + http + ...), or
      - a host-document with a ``data`` array containing per-service dicts.

    Normalize both shapes to a list of service dicts.
    """
    if not isinstance(shodan_dict, dict):
        return []
    data = shodan_dict.get("data")
    if isinstance(data, list) and data:
        return [d for d in data if isinstance(d, dict)]
    return [shodan_dict]


def _http_field(service: Dict[str, Any], key: str) -> str:
    """Pull HTTP fields tolerating both nested and flat layouts."""
    http = service.get("http")
    if isinstance(http, dict):
        v = http.get(key)
        if v:
            return str(v)
    # Flat fallback — some Shodan responses inline these
    flat = service.get(f"http_{key}") or service.get(f"http.{key}")
    return str(flat) if flat else ""


def _content_type(service: Dict[str, Any]) -> str:
    http = service.get("http")
    if isinstance(http, dict):
        headers = http.get("headers")
        if isinstance(headers, dict):
            return str(headers.get("Content-Type") or headers.get("content-type") or "")
    return ""


def _favicon_hash(service: Dict[str, Any]) -> Optional[int]:
    http = service.get("http")
    if isinstance(http, dict):
        fav = http.get("favicon")
        if isinstance(fav, dict):
            try:
                return int(fav.get("hash"))
            except (TypeError, ValueError):
                return None
    return None


def _banner(service: Dict[str, Any]) -> str:
    """Concatenate the service's banner-ish strings for substring search."""
    parts: List[str] = []
    for key in ("data", "banner", "product", "title", "_shodan_module"):
        v = service.get(key)
        if isinstance(v, str):
            parts.append(v)
    # http.html / http.title also commonly contain banner content
    parts.append(_http_field(service, "html"))
    parts.append(_http_field(service, "title"))
    return "\n".join(parts).lower()


# ---------------------------------------------------------------------------
# Pattern matching
# ---------------------------------------------------------------------------


def _match_condition(service: Dict[str, Any], match: Dict[str, Any]) -> bool:
    """Evaluate a single pattern's match block against one service dict."""
    if "port" in match:
        if int(service.get("port") or 0) != int(match["port"]):
            return False

    if "banner_contains" in match:
        needles = match["banner_contains"]
        if isinstance(needles, str):
            needles = [needles]
        banner = _banner(service)
        if not all(n.lower() in banner for n in needles):
            return False

    if "http.html_contains" in match:
        needles = match["http.html_contains"]
        if isinstance(needles, str):
            needles = [needles]
        html = _http_field(service, "html").lower()
        if not all(n.lower() in html for n in needles):
            return False

    if "http.title_contains" in match:
        needle = str(match["http.title_contains"]).lower()
        title = _http_field(service, "title").lower()
        if needle not in title:
            return False

    if "content_type" in match:
        needle = str(match["content_type"]).lower()
        if needle not in _content_type(service).lower():
            return False

    if "favicon_hash" in match:
        if _favicon_hash(service) != int(match["favicon_hash"]):
            return False

    return True


def find_ai_indicators(shodan_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Walk a Shodan response (single-service or multi-service shape) and
    return a list of indicator payloads suitable for wrapping into
    ``EnrichmentFinding`` rows.

    Each payload:
      ``{"protocol", "port", "evidence", "matched_pattern_index"}``

    Per pattern + service we emit at most one payload (the first match wins).
    Multiple services on the same host CAN each produce indicators.
    """
    if not isinstance(shodan_dict, dict):
        return []
    services = _shodan_iter_services(shodan_dict)
    if not services:
        return []

    patterns = get_active_patterns()
    out: List[Dict[str, Any]] = []
    seen_keys: set = set()

    for svc in services:
        port = int(svc.get("port") or 0)

        # Pattern matches first
        matched_protocol_for_service: Optional[str] = None
        for i, pat in enumerate(patterns):
            if _match_condition(svc, pat["match"]):
                proto = pat["protocol"]
                key = (proto, port)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                evidence = _summarize_evidence(svc, pat["match"])
                out.append({
                    "protocol": proto,
                    "port": port,
                    "evidence": evidence,
                    "matched_pattern_index": i,
                })
                matched_protocol_for_service = proto
                # First definitive match per service wins; default-port
                # heuristics only fire when nothing else matched.
                break

        # Default-port heuristic (soft signal). Only emit when no pattern
        # matched for this service and the port is in the AI defaults table.
        if matched_protocol_for_service is None and port in AI_DEFAULT_PORTS:
            proto = AI_DEFAULT_PORTS[port]
            key = (f"{proto}-default-port", port)
            if key not in seen_keys:
                seen_keys.add(key)
                out.append({
                    "protocol": proto,
                    "port": port,
                    "evidence": f"port {port} is the default for {proto} (no banner match)",
                    "matched_pattern_index": -1,  # heuristic, not a pattern
                })

    return out


def _summarize_evidence(service: Dict[str, Any], match: Dict[str, Any]) -> str:
    """Build a one-liner that explains what triggered the match."""
    bits: List[str] = []
    if "port" in match:
        bits.append(f"port {match['port']}")
    if "banner_contains" in match:
        needles = match["banner_contains"]
        needles = [needles] if isinstance(needles, str) else needles
        bits.append(f"banner: {', '.join(repr(n) for n in needles)}")
    if "http.html_contains" in match:
        needles = match["http.html_contains"]
        needles = [needles] if isinstance(needles, str) else needles
        bits.append(f"http.html: {', '.join(repr(n) for n in needles)}")
    if "http.title_contains" in match:
        bits.append(f"http.title: {match['http.title_contains']!r}")
    if "content_type" in match:
        bits.append(f"content-type: {match['content_type']!r}")
    if "favicon_hash" in match:
        bits.append(f"favicon hash: {match['favicon_hash']}")
    return " · ".join(bits) if bits else "match"


# ---------------------------------------------------------------------------
# AI indicator → finding payload
# ---------------------------------------------------------------------------


def shodan_to_ai_findings(
    ioc_value: str,
    ioc_type: str,
    shodan_dict: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Run the AI matcher over a Shodan enrichment response and return one
    finding payload per detected service. Each payload is a dict with the
    same shape the ingest path uses for derived findings:

        {"source", "finding_kind", "summary", "signals", "raw"}
    """
    indicators = find_ai_indicators(shodan_dict)
    payloads: List[Dict[str, Any]] = []
    last_seen = (
        shodan_dict.get("last_update")
        or shodan_dict.get("timestamp")
        or ""
    )
    for ind in indicators:
        proto = ind["protocol"]
        port = ind["port"]
        evidence = ind["evidence"]
        is_heuristic = ind["matched_pattern_index"] == -1

        bits = [f"{proto} on :{port}"]
        if last_seen:
            bits.append(f"last seen {last_seen}")
        if is_heuristic:
            bits.append("(heuristic)")
        else:
            bits.append("(banner-confirmed externally)")
        summary = " · ".join(bits)

        signals = ["ai-suspected", f"ai-{proto}", "shodan-banner-match"]
        if port in AI_DEFAULT_PORTS:
            signals.append("ai-port-default")
        if is_heuristic:
            signals.append("ai-heuristic-only")

        payloads.append({
            "source": "ai_service",
            "finding_kind": "ai_indicator",
            "summary": summary,
            "signals": signals,
            "raw": {
                "protocol": proto,
                "port": port,
                "evidence": evidence,
                "external_sources": ["shodan"],
                "shodan_last_seen": last_seen,
                "model": None,                 # only enum module can confirm
                "framework_version": None,     # same
                "matched_pattern_index": ind["matched_pattern_index"],
            },
        })
    return payloads
