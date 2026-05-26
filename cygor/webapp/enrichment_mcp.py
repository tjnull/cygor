"""
MCP (Model Context Protocol) indicator detection from external source data.

Per the enrich architectural rule, this module **does not** send a JSON-RPC
``initialize`` to the asset. The only definitive way to confirm an MCP
server is to send that handshake — which is the job of the future
``cygor enum aimcp`` module. Here we identify *suspects* from external
observations only:

- Shodan banner / HTTP fields containing MCP markers
  ("Model Context Protocol", `/mcp/sse`, JSON-RPC + tools/capabilities
  language paired with text/event-stream content type)
- Censys cert SANs containing MCP-suggestive prefixes (``mcp.``, ``agent.``)
- crt.sh CT-log SAN scan for the same prefixes (handled by the cert
  source's own findings; this module is Shodan-focused)

The vocabulary is honest: ``finding_kind = "mcp_indicator"`` and
``signals = ["mcp-suspected", ...]`` — never ``mcp-confirmed``. That's
reserved for the future enum module.
"""
from __future__ import annotations

from typing import Any, Dict, List

from .enrichment_ai import _http_field, _banner, _content_type, _shodan_iter_services


# MCP-suggestive substrings to scan for in HTTP responses Shodan captured.
# Casing-insensitive substring match.
_MCP_HTML_NEEDLES = [
    "model context protocol",
    "/mcp/sse",
    "/mcp",            # weak on its own; combined with jsonrpc below
]
_MCP_BANNER_NEEDLES = [
    "model context protocol",
    "mcp/sse",
]


def _service_has_mcp_signal(svc: Dict[str, Any]) -> List[str]:
    """
    Return a list of evidence strings if this service shows MCP indicators.
    Empty list = no indicators.
    """
    evidence: List[str] = []

    banner = _banner(svc)
    for needle in _MCP_BANNER_NEEDLES:
        if needle in banner:
            evidence.append(f"banner contains {needle!r}")

    html = _http_field(svc, "html").lower()
    for needle in _MCP_HTML_NEEDLES:
        if needle in html:
            # /mcp on its own is weak; require corroborating jsonrpc/tools text
            if needle == "/mcp" and not any(w in html for w in ("jsonrpc", "tools", "capabilities")):
                continue
            evidence.append(f"http.html contains {needle!r}")

    # Server-Sent Events + MCP path is a classic combo
    ct = _content_type(svc).lower()
    if "text/event-stream" in ct and ("mcp" in html or "mcp" in banner):
        evidence.append("content-type=text/event-stream + mcp marker")

    return evidence


def shodan_to_mcp_findings(
    ioc_value: str,
    ioc_type: str,
    shodan_dict: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Walk a Shodan response and return one MCP indicator payload per
    service that shows MCP markers. Each payload is a dict with the same
    shape the ingest path uses for derived findings.

    Returns an empty list when nothing matches.
    """
    if not isinstance(shodan_dict, dict):
        return []
    services = _shodan_iter_services(shodan_dict)
    if not services:
        return []

    last_seen = (
        shodan_dict.get("last_update")
        or shodan_dict.get("timestamp")
        or ""
    )

    payloads: List[Dict[str, Any]] = []
    seen_ports: set = set()

    for svc in services:
        evidence = _service_has_mcp_signal(svc)
        if not evidence:
            continue
        port = int(svc.get("port") or 0)
        if port in seen_ports:
            continue
        seen_ports.add(port)

        bits = [f"MCP indicator on :{port}"]
        if last_seen:
            bits.append(f"last seen {last_seen}")
        bits.append("(suspected — confirmation requires cygor enum aimcp)")
        summary = " · ".join(bits)

        signals = ["mcp-suspected", "shodan-banner-match"]

        payloads.append({
            "source": "mcp",
            "finding_kind": "mcp_indicator",
            "summary": summary,
            "signals": signals,
            "raw": {
                "protocol": "mcp",
                "port": port,
                "evidence": "; ".join(evidence),
                "external_sources": ["shodan"],
                "shodan_last_seen": last_seen,
                "matched_signals": evidence,
            },
        })
    return payloads
