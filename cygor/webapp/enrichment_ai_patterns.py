"""
Curated patterns for identifying AI / agent services in already-fetched
external source data (Shodan, Censys, etc.).

Each pattern is a dict with a ``protocol`` and a ``match`` block. The match
block describes structural conditions that, when all true against a single
external source's response, indicate the asset is exposing the named
protocol. This is purely **passive identification** — no traffic is sent
to the asset.

Conditions supported in a ``match`` block:

- ``port``: int — port the service must be on
- ``banner_contains``: str | list[str] — substring(s) in any banner /
  ``data`` string field. List = all-of.
- ``http.html_contains``: str | list[str] — substring(s) in ``http.html``
- ``http.title_contains``: str — substring in ``http.title``
- ``content_type``: str — substring in HTTP Content-Type header
- ``favicon_hash``: int — Shodan-style mmh3 favicon hash

The list is data, not code. New services can be added by appending an entry.
The pattern set lives in code rather than a JSON file because keeping it
versioned with the code makes refactors safer; users wanting to override or
extend can drop ``~/.cygor/ai_patterns.json`` (loaded at runtime if present).
"""
from __future__ import annotations

from typing import Any, Dict, List


# Each entry: protocol (display name), match dict, and optional notes for ops.
AI_PATTERNS: List[Dict[str, Any]] = [
    # ── Ollama ─────────────────────────────────────────────────────────────
    {"protocol": "ollama",        "match": {"port": 11434, "banner_contains": "Ollama is running"}},
    {"protocol": "ollama",        "match": {"banner_contains": "Ollama is running"}},
    {"protocol": "ollama",        "match": {"http.html_contains": "/api/tags"}},
    {"protocol": "ollama",        "match": {"http.html_contains": "/api/generate"}},

    # ── OpenAI-compatible APIs ────────────────────────────────────────────
    {"protocol": "vllm",          "match": {"http.html_contains": "/v1/models", "port": 8000}},
    {"protocol": "openai_compat", "match": {"http.html_contains": "/v1/chat/completions"}},
    {"protocol": "openai_compat", "match": {"http.html_contains": "/v1/models"}},
    {"protocol": "litellm",       "match": {"http.title_contains": "LiteLLM"}},
    {"protocol": "litellm",       "match": {"banner_contains": "LiteLLM", "port": 4000}},
    {"protocol": "localai",       "match": {"banner_contains": "LocalAI", "port": 8080}},

    # ── LangChain / LangServe ─────────────────────────────────────────────
    {"protocol": "langserve",     "match": {"http.html_contains": ["langserve", "playground"]}},
    {"protocol": "langchain",     "match": {"http.html_contains": ["/playground", "langchain"]}},

    # ── Chat UIs ──────────────────────────────────────────────────────────
    {"protocol": "open_webui",    "match": {"http.title_contains": "Open WebUI"}},
    {"protocol": "librechat",     "match": {"http.title_contains": "LibreChat"}},

    # ── Image generation UIs ──────────────────────────────────────────────
    {"protocol": "comfyui",       "match": {"http.title_contains": "ComfyUI"}},
    {"protocol": "comfyui",       "match": {"banner_contains": "comfyui", "port": 8188}},
    {"protocol": "stable_diffusion", "match": {"http.title_contains": "Stable Diffusion"}},
    {"protocol": "automatic1111", "match": {"http.html_contains": "stable-diffusion-webui", "port": 7860}},

    # ── Text generation ───────────────────────────────────────────────────
    {"protocol": "textgen_webui", "match": {"http.title_contains": "Text generation web UI", "port": 7860}},

    # ── Generic UI frameworks commonly used to expose AI demos ────────────
    {"protocol": "gradio",        "match": {"http.title_contains": "Gradio"}},
    {"protocol": "gradio",        "match": {"http.html_contains": "Built with Gradio"}},
    {"protocol": "gradio",        "match": {"favicon_hash": 945408572}},
    {"protocol": "streamlit",     "match": {"http.title_contains": "Streamlit"}},
    {"protocol": "streamlit",     "match": {"favicon_hash": -335242539}},

    # ── Hugging Face TGI ──────────────────────────────────────────────────
    {"protocol": "huggingface_tgi", "match": {"http.html_contains": ["huggingface", "model"]}},

    # ── Agent / orchestration platforms ───────────────────────────────────
    {"protocol": "openclaw",      "match": {"http.title_contains": "Clawdbot Control"}},
    {"protocol": "openclaw",      "match": {"banner_contains": "clawdbot", "port": 18789}},
]


# Default port → protocol fallback. Used to add a soft signal when the host
# is on an AI-default port but no banner pattern matched.
AI_DEFAULT_PORTS: Dict[int, str] = {
    11434: "ollama",
    8000: "vllm",
    4000: "litellm",
    8188: "comfyui",
    7860: "gradio",
    18789: "openclaw",
}


# ---------------------------------------------------------------------------
# Optional user override loader
# ---------------------------------------------------------------------------


def _load_user_overrides() -> List[Dict[str, Any]]:
    """
    Load optional user-supplied pattern additions from
    ``~/.cygor/ai_patterns.json``. The file should be a JSON list with the
    same shape as ``AI_PATTERNS``. Entries with the same (protocol, match)
    pair as a built-in are added; cygor never silently rewrites built-ins.
    """
    import json
    from pathlib import Path

    path = Path.home() / ".cygor" / "ai_patterns.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def get_active_patterns() -> List[Dict[str, Any]]:
    """Return the merged built-in + user-override pattern list."""
    return AI_PATTERNS + _load_user_overrides()
