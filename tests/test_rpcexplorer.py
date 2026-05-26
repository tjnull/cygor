"""Tests for rpcexplorer: rpcclient output parsing, null-session/auth row
assembly, password-policy surfacing (getdompwinfo + polenum), RID-range parsing
and RID cycling via lookupsids. External tools are mocked -- no network/samba.
Also covers the nextsteps weak-password-policy findings driven by these fields.
"""
import types

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
    monkeypatch.setattr(rpc, "_polenum", lambda *a, **k: {})
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
    monkeypatch.setattr(rpc, "_polenum", lambda *a, **k: {})
    m = rpc.RPCExplorer(output_dir=str(tmp_path / "o"))
    m.run(["10.0.0.1"], username="CORP\\user", password="pw", timeout=2)
    assert m.results[0]["null_session"] == "n/a (auth)"


def test_run_surfaces_policy_and_summary(monkeypatch, tmp_path):
    monkeypatch.setattr(rpc.shutil, "which", lambda x: "/usr/bin/rpcclient")
    monkeypatch.setattr(
        rpc, "_rpcclient",
        lambda *a, **k: ("Domain Name: CORP\nuser:[a] rid:[0x1]\n"
                         "min_password_length: 7\npassword_properties: 0x00000000\n"))
    monkeypatch.setattr(rpc, "_polenum",
                        lambda *a, **k: {"lockout": "None", "max_age": "42 days"})
    m = rpc.RPCExplorer(output_dir=str(tmp_path / "o"))
    m.run(["10.0.0.1"], timeout=2)
    r = m.results[0]
    assert r["pw_lockout"] == "None"
    assert r["pw_max_age"] == "42 days"
    assert "minlen=7" in r["pw_policy"] and "complex=no" in r["pw_policy"]
    assert "lockout=None" in r["pw_policy"]


def test_run_rid_cycles_when_user_enum_blocked(monkeypatch, tmp_path):
    # SAMR enumdomusers returns nothing, but we have a domain SID -> RID cycle.
    monkeypatch.setattr(rpc.shutil, "which", lambda x: "/usr/bin/rpcclient")
    monkeypatch.setattr(
        rpc, "_rpcclient",
        lambda *a, **k: "Domain Name: CORP\nDomain Sid: S-1-5-21-1-2-3\n")
    monkeypatch.setattr(rpc, "_polenum", lambda *a, **k: {})
    monkeypatch.setattr(rpc, "_rid_cycle", lambda *a, **k: ["jsmith", "admin"])
    m = rpc.RPCExplorer(output_dir=str(tmp_path / "o"))
    m.run(["10.0.0.1"], timeout=2)
    r = m.results[0]
    assert r["users"] == "2"
    assert "RID-cycled" in r["info"] and "jsmith" in r["info"]


# ---- _polenum -------------------------------------------------------------
def test_polenum_parses_full_policy(monkeypatch):
    monkeypatch.setattr(rpc.shutil, "which", lambda t: "/usr/bin/polenum")
    out = ("Minimum password length: 8\n"
           "Password history length: 24\n"
           "Maximum password age: 42 days\n"
           "Account Lockout Threshold: None\n"
           "Domain Password Complex: 1\n")
    monkeypatch.setattr(rpc, "wrap_external", lambda *a, **k: _fake_proc(out))
    pol = rpc._polenum("h", "", "", 10)
    assert pol["min_length"] == "8"
    assert pol["history"] == "24"
    assert pol["max_age"] == "42 days"
    assert pol["lockout"] == "None"
    assert pol["complexity"] == "yes"


def test_polenum_absent_tool_returns_empty(monkeypatch):
    monkeypatch.setattr(rpc.shutil, "which", lambda t: None)
    assert rpc._polenum("h", "", "", 10) == {}


def test_polenum_handles_exception(monkeypatch):
    monkeypatch.setattr(rpc.shutil, "which", lambda t: "/usr/bin/polenum")

    def boom(*a, **k):
        raise OSError("nope")

    monkeypatch.setattr(rpc, "wrap_external", boom)
    assert rpc._polenum("h", "", "", 10) == {}


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
