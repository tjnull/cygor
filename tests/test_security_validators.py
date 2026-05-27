"""Security-focused tests for the validators added in Pass 3.

Covers:
  - PostgreSQLAdapter._validate_identifier rejects SQL-injection patterns
    in CYGOR_DB_USER / CYGOR_DB_NAME env values.
  - PostgreSQLAdapter._quote_sql_literal escapes embedded single quotes.
  - plugin_loader._allowlist_pre_exec_check refuses unsigned files when
    the allowlist is enforcing.
  - SOCKS proxy env vars no longer leak into HTTPS_PROXY/HTTP_PROXY.
"""
import pytest


# ---------------------------------------------------------------------------
# Postgres identifier validation
# ---------------------------------------------------------------------------
from cygor.webapp.db_adapters import PostgreSQLAdapter


@pytest.mark.parametrize("evil", [
    "cygor; DROP DATABASE postgres; --",
    "a'b",
    "a;\nDROP TABLE x",
    "name with spaces",
    "name-with-dashes",
    "a\x00b",                    # null byte
    "1starts_with_digit",        # postgres rejects this
    "",                          # empty
    "a" * 100,                   # over 63 chars
    '";SELECT 1--',
])
def test_validate_identifier_rejects_injection_patterns(evil):
    with pytest.raises(ValueError):
        PostgreSQLAdapter._validate_identifier("test_field", evil)


@pytest.mark.parametrize("ok", [
    "cygor",
    "cygor_user",
    "_underscore_start",
    "Mixed_Case_123",
    "x",
    "a" * 63,  # max length
])
def test_validate_identifier_accepts_normal_names(ok):
    PostgreSQLAdapter._validate_identifier("test_field", ok)  # no raise


# ---------------------------------------------------------------------------
# SQL literal escaping
# ---------------------------------------------------------------------------
def test_quote_sql_literal_escapes_single_quotes():
    """An embedded ' must double itself so it can't terminate the literal."""
    assert PostgreSQLAdapter._quote_sql_literal("ab'cd") == "'ab''cd'"


def test_quote_sql_literal_handles_empty_string():
    assert PostgreSQLAdapter._quote_sql_literal("") == "''"


def test_quote_sql_literal_handles_none():
    assert PostgreSQLAdapter._quote_sql_literal(None) == "''"


def test_quote_sql_literal_rejects_null_bytes():
    with pytest.raises(ValueError):
        PostgreSQLAdapter._quote_sql_literal("a\x00b")


def test_quote_sql_literal_preserves_other_special_chars():
    # Backslashes and newlines are NOT SQL-escape characters in standard
    # mode; only ' matters. Verify the function doesn't over-escape.
    assert PostgreSQLAdapter._quote_sql_literal(r"a\nb;c") == r"'a\nb;c'"


# ---------------------------------------------------------------------------
# Plugin loader: pre-exec allowlist gate
# ---------------------------------------------------------------------------
from cygor.plugin_loader import _allowlist_pre_exec_check


def test_pre_exec_gate_passes_when_allowlist_disabled():
    """No allowlist file / enforce=False: gate is a no-op."""
    assert _allowlist_pre_exec_check("anyhash", {}) is None
    assert _allowlist_pre_exec_check("anyhash", {"enforce": False}) is None


def test_pre_exec_gate_passes_when_fingerprint_pinned():
    allowlist = {"enforce": True, "plugins": {"good_slug": "abc123"}}
    assert _allowlist_pre_exec_check("abc123", allowlist) is None
    # case-insensitive
    assert _allowlist_pre_exec_check("ABC123", allowlist) is None


def test_pre_exec_gate_rejects_unpinned_fingerprint():
    """The whole point of the gate: refuse to import unsigned files."""
    allowlist = {"enforce": True, "plugins": {"good_slug": "abc123"}}
    err = _allowlist_pre_exec_check("DEADBEEF", allowlist)
    assert err is not None
    assert "not pinned" in err.lower()


def test_pre_exec_gate_rejects_empty_fingerprint():
    allowlist = {"enforce": True, "plugins": {"good_slug": "abc123"}}
    err = _allowlist_pre_exec_check("", allowlist)
    assert err is not None


# ---------------------------------------------------------------------------
# SOCKS proxy: no longer leaks into HTTPS_PROXY/HTTP_PROXY
# ---------------------------------------------------------------------------
def test_socks_proxy_does_not_export_https_proxy(monkeypatch):
    """HTTPS_PROXY=socks5://... is a silent traffic-leak vector (plain
    urllib + many tools treat it as HTTP CONNECT). ALL_PROXY only."""
    from cygor import proxy_config
    # Fake an active jumpbox so the function actually returns vars.
    monkeypatch.setattr(proxy_config, "is_jumpbox_routing_active", lambda: True)
    monkeypatch.setattr(proxy_config, "_get_jumpbox_socks_url",
                        lambda: "socks5://127.0.0.1:1080")
    env = proxy_config.format_socks_proxy_for_subprocess()
    # ALL_PROXY (both cases) MUST be set.
    assert env.get("ALL_PROXY") == "socks5://127.0.0.1:1080"
    assert env.get("all_proxy") == "socks5://127.0.0.1:1080"
    # HTTPS_PROXY / HTTP_PROXY MUST NOT be set (was the bug).
    assert "HTTPS_PROXY" not in env
    assert "https_proxy" not in env
    assert "HTTP_PROXY" not in env
    assert "http_proxy" not in env


def test_socks_proxy_empty_when_jumpbox_inactive(monkeypatch):
    from cygor import proxy_config
    monkeypatch.setattr(proxy_config, "is_jumpbox_routing_active", lambda: False)
    assert proxy_config.format_socks_proxy_for_subprocess() == {}
