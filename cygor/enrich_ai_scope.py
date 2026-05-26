"""
Mode B for AI service detection: scoped Shodan dork sweep.

Given a CIDR (or comma-separated list of CIDRs), runs a curated set of
AI/MCP-targeted Shodan queries with ``net:<cidr>`` prefixed. Returns a
list of normalized result dicts that the caller can persist into the
enrichment pipeline.

This module talks **only to Shodan** — never to the assets in scope.
That keeps it inside the architectural rule for ``cygor enrich``.

Layout mirrors the BaseAsyncEnricher convention so the result shape
remains consistent with what the existing enrich pipeline produces.
"""
from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# Curated Shodan dorks for AI/agent infrastructure. Each entry maps a short
# key to the dork string. ``net:<cidr>`` is prepended at query time.
AI_SCOPE_DORKS: Dict[str, str] = {
    # MCP signals
    "mcp_protocol":         '"Model Context Protocol"',
    "mcp_sse_path":         'http.html:"/mcp/sse"',
    "mcp_jsonrpc":          'http.html:"/mcp" "jsonrpc"',

    # Ollama
    "ollama_default":       'port:11434 "Ollama is running"',
    "ollama_anywhere":      '"Ollama is running"',
    "ollama_product":       'product:"Ollama"',

    # OpenAI-compatible
    "vllm":                 'http.html:"/v1/models" port:8000',
    "openai_chat":          'http.html:"/v1/chat/completions"',
    "litellm":              '"LiteLLM" port:4000',
    "litellm_dashboard":    'http.title:"LiteLLM"',
    "localai":              '"LocalAI" port:8080',

    # LangServe / LangChain
    "langserve":            'http.html:"langserve" "playground"',
    "langchain_playground": 'http.html:"/playground" "langchain"',

    # Chat / image UIs
    "open_webui":           'http.title:"Open WebUI"',
    "librechat":            'http.title:"LibreChat"',
    "comfyui":              'http.title:"ComfyUI"',
    "comfyui_default":      '"comfyui" port:8188',
    "stable_diffusion":     'http.title:"Stable Diffusion"',
    "automatic1111":        'http.html:"stable-diffusion-webui" port:7860',
    "textgen_webui":        'http.title:"Text generation web UI" port:7860',

    # Generic frameworks commonly used to expose AI demos
    "gradio_title":         'http.title:"Gradio"',
    "gradio_footer":        'http.html:"Built with Gradio"',
    "streamlit_title":      'http.title:"Streamlit"',
    "huggingface_tgi":      'http.html:"huggingface" http.html:"model"',

    # Agent/orchestration
    "openclaw_dashboard":   'http.title:"Clawdbot Control"',
    "openclaw_default":     'port:18789 "clawdbot"',
}


def _query_shodan(api_key: str, query: str, max_results: int = 100) -> List[Dict[str, Any]]:
    """
    Run a single Shodan search. Returns the matching documents (Shodan's
    ``matches`` array). Empty list on any error so the caller can carry on.

    Uses the synchronous ``shodan`` SDK because the existing enrich pipeline
    does the same. The 1-second sleep between pages respects the basic-tier
    rate limit.
    """
    try:
        import shodan
    except ImportError:
        logger.warning("shodan library not installed; --ai-scope unavailable")
        return []

    client = shodan.Shodan(api_key)
    out: List[Dict[str, Any]] = []
    page = 1
    while len(out) < max_results:
        try:
            result = client.search(query, page=page)
        except Exception as e:
            # APIError on credit exhaustion / invalid query is normal here.
            logger.info("Shodan query failed (%s): %s", query[:60], e)
            break
        matches = result.get("matches") or []
        if not matches:
            break
        out.extend(matches)
        if len(matches) < 100:
            break  # last page
        page += 1
        time.sleep(1.0)  # respect rate limit
    return out[:max_results]


def run_ai_scope_sweep(
    api_key: str,
    cidrs: List[str],
    *,
    max_results_per_query: int = 100,
    only_dorks: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Run the curated AI dorks scoped to ``net:<cidr>`` for each CIDR.

    Returns a flat list of result dicts in the standard cygor enrich shape:

        {"ioc": "<ip>", "type": "ip", "enrichments": [{"source": "shodan",
         "ai_scope_dork": "<key>", ...}, ...]}

    Each Shodan match becomes one entry; if the same IP is hit by multiple
    dorks we return one entry with multiple enrichment dicts.
    """
    if not cidrs:
        return []
    dorks = AI_SCOPE_DORKS
    if only_dorks:
        dorks = {k: v for k, v in AI_SCOPE_DORKS.items() if k in set(only_dorks)}
        if not dorks:
            return []

    # Aggregate per IP across all dorks/CIDRs.
    by_ip: Dict[str, Dict[str, Any]] = {}

    for cidr in cidrs:
        for dork_key, dork in dorks.items():
            full_query = f"net:{cidr} {dork}"
            matches = _query_shodan(api_key, full_query, max_results=max_results_per_query)
            for m in matches:
                ip = m.get("ip_str") or m.get("ip")
                if not ip:
                    continue
                ip = str(ip)
                entry = by_ip.setdefault(ip, {
                    "ioc": ip,
                    "type": "ip",
                    "enrichments": [],
                })
                # Attach the raw match as a Shodan enrichment, tagged with
                # which dork found it. The matcher in enrichment_ai.py picks
                # the protocol back out from the banner content.
                shodan_record = dict(m)
                shodan_record["source"] = "shodan"
                shodan_record["ai_scope_dork"] = dork_key
                shodan_record["ai_scope_cidr"] = cidr
                entry["enrichments"].append(shodan_record)

    return list(by_ip.values())
