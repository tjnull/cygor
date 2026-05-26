"""Tests for rpcexplorer: rpcclient output parsing, null-session/auth row
assembly, password-policy surfacing (getdompwinfo + native impacket SAMR),
RID-range parsing and RID cycling via lookupsids. External tools and the
SAMR transport are mocked -- no network/samba.
Also covers the nextsteps weak-password-policy findings driven by these fields.
"""
import types

import pytest

from cygor.modules import rpcexplorer as rpc
from cygor import nextsteps as N


def _fake_proc(stdout="", stderr="", rc=0):
    return types.SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


# ---- _parse_rpcclient -----------------------------------------------------
def test_parse_rpcclient():
    out = ("\tOS Version\t:\t10.0\n"
           "\tServer Type\t:\t0x809a03\n"
           "Domain Name: CORP\n"
           "Domain Sid: S-1-5-21-1-2-3\n"
           "user:[Administrator] rid:[0x1f4]\n"
           "user:[Guest] rid:[0x1f5]\n"
           "group:[Domain Admins] rid:[0x200]\n"
           "min_password_length: 7\n"
           "password_properties: 0x00000001\n")
    p = rpc._parse_rpcclient(out)
    assert p["os"] == "10.0"
    assert p["domain"] == "CORP"
    assert p["domain_sid"].startswith("S-1-5-21")
    assert p["users"] == "2"
    assert p["groups"] == "1"
    assert p["pw_min_length"] == "7"
    assert p["pw_complexity"] == "yes"     # bit 0 (DOMAIN_PASSWORD_COMPLEX) set


def test_parse_rpcclient_complexity_off_when_bit_clear():
    p = rpc._parse_rpcclient("min_password_length: 0\npassword_properties: 0x00000000\n")
    assert p["pw_min_length"] == "0"
    assert p["pw_complexity"] == "no"


def test_parse_rpcclient_empty_on_no_data():
    p = rpc._parse_rpcclient("NT_STATUS_ACCESS_DENIED\n")
    assert p["pw_min_length"] == "" and p["pw_complexity"] == "" and p["users"] == ""


# ---- run() row assembly ---------------------------------------------------
def test_run_null_session(monkeypatch, tmp_path):
    monkeypatch.setattr(rpc.shutil, "which", lambda x: "/usr/bin/rpcclient")
    monkeypatch.setattr(rpc, "_rpcclient",
                        lambda *a, **k: "Domain Name: CORP\nuser:[a] rid:[0x1]\n")
    monkeypatch.setattr(rpc, "_samr_password_policy", lambda *a, **k: {})
    m = rpc.RPCExplorer(output_dir=str(tmp_path / "o"))
    m.run(["10.0.0.1"], timeout=2)
    r = m.results[0]
    assert r["null_session"] == "yes"
    assert r["domain"] == "CORP"
    assert r["users"] == "1"


def test_run_access_denied(monkeypatch, tmp_path):
    monkeypatch.setattr(rpc.shutil, "which", lambda x: "/usr/bin/rpcclient")
    monkeypatch.setattr(rpc, "_rpcclient",
                        lambda *a, **k: "Cannot connect. Error was NT_STATUS_ACCESS_DENIED\n")
    m = rpc.RPCExplorer(output_dir=str(tmp_path / "o"))
    m.run(["10.0.0.1"], timeout=2)
    r = m.results[0]
    assert r["null_session"] == "no"
    assert "ACCESS_DENIED" in r["info"]


def test_run_authenticated_label(monkeypatch, tmp_path):
    monkeypatch.setattr(rpc.shutil, "which", lambda x: "/usr/bin/rpcclient")
    monkeypatch.setattr(rpc, "_rpcclient", lambda *a, **k: "Domain Name: CORP\n")
    monkeypatch.setattr(rpc, "_samr_password_policy", lambda *a, **k: {})
    m = rpc.RPCExplorer(output_dir=str(tmp_path / "o"))
    m.run(["10.0.0.1"], username="CORP\\user", password="pw", timeout=2)
    assert m.results[0]["null_session"] == "n/a (auth)"


def test_run_surfaces_policy_and_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(rpc.shutil, "which", lambda x: "/usr/bin/rpcclient")
    monkeypatch.setattr(
        rpc, "_rpcclient",
        lambda *a, **k: ("Domain Name: CORP\nuser:[a] rid:[0x1]\n"
                         "min_password_length: 7\npassword_properties: 0x00000000\n"))
    monkeypatch.setattr(
        rpc, "_samr_password_policy",
        lambda *a, **k: {"lockout": "none", "max_age": "42 days"})
    m = rpc.RPCExplorer(output_dir=str(tmp_path / "o"))
    m.run(["10.0.0.1"], timeout=2)
    r = m.results[0]
    assert r["pw_lockout"] == "none"
    assert r["pw_max_age"] == "42 days"
    assert "minlen=7" in r["pw_policy"] and "complex=no" in r["pw_policy"]
    assert "lockout=none" in r["pw_policy"]


def test_run_rid_cycles_when_user_enum_blocked(monkeypatch, tmp_path):
    # SAMR enumdomusers returns nothing, but we have a domain SID -> RID cycle.
    monkeypatch.setattr(rpc.shutil, "which", lambda x: "/usr/bin/rpcclient")
    monkeypatch.setattr(
        rpc, "_rpcclient",
        lambda *a, **k: "Domain Name: CORP\nDomain Sid: S-1-5-21-1-2-3\n")
    monkeypatch.setattr(rpc, "_samr_password_policy", lambda *a, **k: {})
    monkeypatch.setattr(rpc, "_rid_cycle", lambda *a, **k: ["jsmith", "admin"])
    m = rpc.RPCExplorer(output_dir=str(tmp_path / "o"))
    m.run(["10.0.0.1"], timeout=2)
    r = m.results[0]
    assert r["users"] == "2"
    assert "RID-cycled" in r["info"] and "jsmith" in r["info"]


# ---- LARGE_INTEGER + formatter helpers -----------------------------------
class _LI:
    """Stand-in for an impacket OLD_LARGE_INTEGER / LARGE_INTEGER struct."""
    def __init__(self, ticks: int):
        # Pack a signed 64-bit value into LowPart/HighPart the way impacket does.
        unsigned = ticks & 0xFFFFFFFFFFFFFFFF
        self._d = {"LowPart": unsigned & 0xFFFFFFFF,
                   "HighPart": (unsigned >> 32) & 0xFFFFFFFF}
    def __getitem__(self, k): return self._d[k]


def _days_to_ticks(days: int) -> int:
    return days * 86400 * 10_000_000


def test_largeint_decodes_negative_duration():
    # Windows stores durations as negative 100-ns deltas.
    li = _LI(-_days_to_ticks(42))
    assert rpc._largeint_to_int(li) == -_days_to_ticks(42)


def test_fmt_days_renders_duration_or_never():
    assert rpc._fmt_days(-_days_to_ticks(42)) == "42 days"
    assert rpc._fmt_days(_days_to_ticks(7)) == "7 days"     # positive too
    assert rpc._fmt_days(0x8000000000000000) == "never"     # MIN_VALUE sentinel
    assert rpc._fmt_days(0) == "never"
    # Sub-day duration: fall back to minutes.
    assert rpc._fmt_days(-(15 * 60 * 10_000_000)) == "15 min"


def test_fmt_lockout_threshold():
    assert rpc._fmt_lockout_threshold(0) == "none"
    assert rpc._fmt_lockout_threshold(5) == "5 attempts"


# ---- _samr_password_policy (native impacket SAMR) ------------------------

def _stub_samr_query(level_to_struct):
    """Return a callable that mimics impacket.samr.hSamrQueryInformationDomain
    by looking up the requested DOMAIN_INFORMATION_CLASS level."""
    def _impl(dce, domainHandle, domainInformationClass):
        try:
            level = int(domainInformationClass)
        except (TypeError, ValueError):
            level = int(getattr(domainInformationClass, "Data", domainInformationClass))
        if level not in level_to_struct:
            raise RuntimeError(f"unexpected info class {level}")
        return level_to_struct[level]
    return _impl


@pytest.fixture
def _fake_samr(monkeypatch):
    """Patch the impacket modules the helper imports so we never touch the
    network. Yields a dict the test can mutate to control the response."""
    from impacket.dcerpc.v5 import samr as real_samr
    from impacket.dcerpc.v5 import transport as real_transport

    # The fake dce just needs to look like an object; impacket calls
    # connect/bind/disconnect on it which we make no-ops.
    class _DCE:
        def connect(self): pass
        def bind(self, *a, **k): pass
        def disconnect(self): pass

    class _Trans:
        def __init__(self, *a, **k): pass
        def set_connect_timeout(self, t): pass
        def get_dce_rpc(self): return _DCE()

    # Default response: password level (1) + lockout level (12), matching
    # Win Server 2019 defaults except we make lockout=5 / maxage=42d / minlen=8.
    state = {
        "responses": {
            1:  {"Buffer": {"Password": {
                    "MinPasswordLength":     8,
                    "PasswordHistoryLength": 24,
                    "PasswordProperties":    1,                # complex
                    "MaxPasswordAge":        _LI(-_days_to_ticks(42)),
                    "MinPasswordAge":        _LI(-_days_to_ticks(1)),
                }}},
            12: {"Buffer": {"Lockout": {"LockoutThreshold": 5}}},
        },
    }

    def _fake_connect(dce):                  return {"ServerHandle": "S"}
    def _fake_enum(dce, h):                  return {"Buffer": {"Buffer": [
                                                    {"Name": "Builtin"},
                                                    {"Name": "CORP"}]}}
    def _fake_lookup(dce, h, name):          return {"DomainId": "SID"}
    def _fake_opendomain(dce, h, domainId):  return {"DomainHandle": "D"}

    monkeypatch.setattr(real_transport, "SMBTransport", _Trans)
    monkeypatch.setattr(real_samr, "hSamrConnect", _fake_connect)
    monkeypatch.setattr(real_samr, "hSamrEnumerateDomainsInSamServer", _fake_enum)
    monkeypatch.setattr(real_samr, "hSamrLookupDomainInSamServer", _fake_lookup)
    monkeypatch.setattr(real_samr, "hSamrOpenDomain", _fake_opendomain)
    monkeypatch.setattr(real_samr, "hSamrQueryInformationDomain",
                        _stub_samr_query(state["responses"]))
    return state


def test_samr_password_policy_happy_path(_fake_samr):
    pol = rpc._samr_password_policy("10.0.0.1", "", "", timeout=2)
    assert pol["min_length"] == "8"
    assert pol["history"]    == "24"
    assert pol["complexity"] == "yes"
    assert pol["max_age"]    == "42 days"
    assert pol["min_age"]    == "1 days"
    assert pol["lockout"]    == "5 attempts"


def test_samr_password_policy_no_lockout(_fake_samr):
    # Threshold 0 → "none" (matches the nextsteps weak-policy detector)
    _fake_samr["responses"][12]["Buffer"]["Lockout"]["LockoutThreshold"] = 0
    pol = rpc._samr_password_policy("10.0.0.1", "", "", timeout=2)
    assert pol["lockout"] == "none"


def test_samr_password_policy_complexity_off(_fake_samr):
    _fake_samr["responses"][1]["Buffer"]["Password"]["PasswordProperties"] = 0
    pol = rpc._samr_password_policy("10.0.0.1", "", "", timeout=2)
    assert pol["complexity"] == "no"


def test_samr_password_policy_lockout_query_failure_still_returns_password(_fake_samr, monkeypatch):
    """When the lockout info class is rejected (NT4-era / Samba quirks), the
    password-policy fields should still come back."""
    from impacket.dcerpc.v5 import samr as real_samr

    def _raises_on_lockout(dce, domainHandle, domainInformationClass):
        try:
            level = int(domainInformationClass)
        except (TypeError, ValueError):
            level = int(getattr(domainInformationClass, "Data", domainInformationClass))
        if level == 12:
            raise RuntimeError("ERROR_INVALID_INFO_CLASS")
        return _fake_samr["responses"][level]

    monkeypatch.setattr(real_samr, "hSamrQueryInformationDomain", _raises_on_lockout)
    pol = rpc._samr_password_policy("10.0.0.1", "", "", timeout=2)
    assert pol["min_length"] == "8"
    assert "lockout" not in pol


def test_samr_password_policy_returns_empty_on_network_error(monkeypatch):
    """Unreachable host / closed pipe → empty dict (treated the same way the
    old code treated 'polenum not installed')."""
    from impacket.dcerpc.v5 import transport as real_transport

    class _Boom:
        def __init__(self, *a, **k): pass
        def set_connect_timeout(self, t): pass
        def get_dce_rpc(self):
            class _D:
                def connect(self): raise OSError("conn refused")
            return _D()

    monkeypatch.setattr(real_transport, "SMBTransport", _Boom)
    assert rpc._samr_password_policy("10.0.0.1", "", "", timeout=2) == {}


# ---- _parse_rid_ranges ----------------------------------------------------
def test_parse_rid_ranges_expands_ranges_and_singletons():
    assert rpc._parse_rid_ranges("500-502,1000,1010-1011") == [500, 501, 502, 1000, 1010, 1011]


def test_parse_rid_ranges_defaults_when_blank():
    rids = rpc._parse_rid_ranges("")
    assert 500 in rids and 550 in rids and 1000 in rids and 1050 in rids


def test_parse_rid_ranges_respects_cap():
    assert len(rpc._parse_rid_ranges(f"0-{rpc._MAX_RIDS + 5000}")) == rpc._MAX_RIDS


# ---- _rid_cycle -----------------------------------------------------------
def test_rid_cycle_parses_user_sids_and_dedupes(monkeypatch):
    out = ("S-1-5-21-1-2-3-1000 CORP\\jsmith (1)\n"
           "S-1-5-21-1-2-3-1001 CORP\\admin (1)\n"
           "S-1-5-21-1-2-3-1002 *unknown*\\*unknown* (8)\n"
           "S-1-5-21-1-2-3-1003 CORP\\Domain Admins (2)\n"   # group (type 2) -- skipped
           "S-1-5-21-1-2-3-1000 CORP\\jsmith (1)\n")          # dup -- skipped
    monkeypatch.setattr(rpc, "wrap_external", lambda *a, **k: _fake_proc(out))
    names = rpc._rid_cycle("h", "", "", "S-1-5-21-1-2-3", [1000, 1001, 1002, 1003], 10)
    assert names == ["jsmith", "admin"]


def test_rid_cycle_no_sid_returns_empty():
    assert rpc._rid_cycle("h", "", "", "", [1000], 10) == []


def test_rid_cycle_handles_exception(monkeypatch):
    def boom(*a, **k):
        raise OSError("nope")

    monkeypatch.setattr(rpc, "wrap_external", boom)
    assert rpc._rid_cycle("h", "", "", "S-1-5-21-1", [1000], 10) == []


# ---- _summarize_policy ----------------------------------------------------
def test_summarize_policy_joins_present_fields():
    row = {"pw_min_length": "7", "pw_complexity": "no",
           "pw_lockout": "0", "pw_max_age": "42 days"}
    assert rpc._summarize_policy(row) == "minlen=7, complex=no, lockout=0, maxage=42 days"


def test_summarize_policy_skips_blanks():
    assert rpc._summarize_policy({"pw_min_length": "8"}) == "minlen=8"


# ---- module_info ----------------------------------------------------------
def test_module_info_columns_include_pw_policy():
    keys = {c["key"] for c in rpc.module_info["table"]["columns"]}
    assert "pw_policy" in keys


def test_module_info_options_include_rid_controls():
    names = {o["name"] for o in rpc.module_info["options"]}
    assert {"rid_cycle", "rid_ranges"} <= names


# ---- nextsteps weak-policy findings ---------------------------------------
def test_x_rpc_no_lockout_high_finding():
    fs = N._x_rpc("10.0.0.1", {"pw_lockout": "None"})
    f = next(f for f in fs if f["title"] == "No account lockout policy")
    assert f["severity"] == "high"


def test_x_rpc_no_complexity_medium_finding():
    fs = N._x_rpc("10.0.0.1", {"pw_complexity": "no", "pw_min_length": "6"})
    f = next(f for f in fs if f["title"] == "Password complexity not enforced")
    assert f["severity"] == "medium"


def test_x_rpc_weak_minlen_low_finding():
    fs = N._x_rpc("10.0.0.1", {"pw_min_length": "5"})
    f = next(f for f in fs if "Weak minimum password length" in f["title"])
    assert f["severity"] == "low"


def test_x_rpc_strong_policy_no_findings():
    fs = N._x_rpc("10.0.0.1",
                  {"pw_lockout": "5", "pw_complexity": "yes", "pw_min_length": "14"})
    assert fs == []


def test_x_rpc_null_session_still_fires():
    fs = N._x_rpc("10.0.0.1", {"null_session": "yes", "domain": "CORP", "users": "12"})
    assert any(f["finding_type"] == "rpc_null_session" for f in fs)
