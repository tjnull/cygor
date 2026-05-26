"""Tests for the deepened SNMP Explorer: onesixtyone community brute fallback
and the snmpwalk MIB sweep (users/processes/software/ports/interfaces), parsed
into typed rows. External tools are mocked -- no network or net-snmp needed."""
import types

from cygor.modules import snmpexplorer as S


def _fake_run(stdout, rc=0):
    return types.SimpleNamespace(returncode=rc, stdout=stdout, stderr="")


# ---- snmpwalk parsing -----------------------------------------------------
def test_snmpwalk_parses_and_filters_noise(monkeypatch):
    monkeypatch.setattr(S.shutil, "which", lambda t: "/usr/bin/" + t)
    monkeypatch.setattr(S.subprocess, "run",
                        lambda *a, **k: _fake_run('"sshd"\n"nginx"\n"No Such Object available"\n"bash"\n'))
    assert S._snmpwalk("h", "public", "1.2.3", 2) == ["sshd", "nginx", "bash"]


def test_snmpwalk_absent_tool_returns_empty(monkeypatch):
    monkeypatch.setattr(S.shutil, "which", lambda t: None)
    assert S._snmpwalk("h", "public", "1.2.3", 2) == []


def test_snmpwalk_respects_cap(monkeypatch):
    monkeypatch.setattr(S.shutil, "which", lambda t: "/usr/bin/" + t)
    monkeypatch.setattr(S.subprocess, "run",
                        lambda *a, **k: _fake_run("\n".join(f'"p{i}"' for i in range(20))))
    assert len(S._snmpwalk("h", "public", "1.2.3", 2, cap=5)) == 5


# ---- onesixtyone parsing --------------------------------------------------
def test_onesixtyone_extracts_unique_communities(monkeypatch):
    monkeypatch.setattr(S.shutil, "which", lambda t: "/usr/bin/" + t)
    out = ("192.168.1.1 [public] Hardware: x86\n"
           "192.168.1.1 [private] Software\n"
           "192.168.1.1 [public] dup line\n")
    monkeypatch.setattr(S.subprocess, "run", lambda *a, **k: _fake_run(out))
    assert S._onesixtyone("192.168.1.1", ["public", "private"], 2) == ["public", "private"]


def test_onesixtyone_absent_returns_empty(monkeypatch):
    monkeypatch.setattr(S.shutil, "which", lambda t: None)
    assert S._onesixtyone("h", ["public"], 2) == []


# ---- full host enumeration ------------------------------------------------
def test_enumerate_host_walks_and_counts(monkeypatch):
    monkeypatch.setattr(S, "_snmpget", lambda h, c, oid, t: "val" if c == "public" else None)
    walks = {
        S.WALK_OIDS["users"]: ["admin", "guest"],
        S.WALK_OIDS["processes"]: ["sshd", "nginx", "cron"],
        S.WALK_OIDS["software"]: ["openssh", "nginx"],
        S.WALK_OIDS["tcp_ports"]: ["22", "80", "80", "443"],   # dupes + unsorted
        S.WALK_OIDS["interfaces"]: ["eth0", "lo"],
    }
    monkeypatch.setattr(S, "_snmpwalk", lambda h, c, oid, t, cap=300: walks.get(oid, []))
    row = S._enumerate_host("10.0.0.1", ["public", "private"], 2)
    assert row["community"] == "public"
    assert row["users"] == "admin, guest" and row["user_count"] == "2"
    assert row["process_count"] == "3"
    assert row["software_count"] == "2"
    assert row["tcp_ports"] == "22, 80, 443"          # deduped + numeric-sorted
    assert row["interfaces"] == "eth0, lo"


def test_enumerate_host_brute_fallback(monkeypatch):
    # configured communities fail; onesixtyone discovers a valid one
    monkeypatch.setattr(S, "_snmpget", lambda h, c, oid, t: "ok" if c == "community" else None)
    monkeypatch.setattr(S, "_onesixtyone", lambda h, comms, t: ["community"])
    monkeypatch.setattr(S, "_snmpwalk", lambda *a, **k: [])
    row = S._enumerate_host("10.0.0.2", ["public", "private"], 2)
    assert row and row["community"] == "community"


def test_enumerate_host_no_snmp_returns_none(monkeypatch):
    monkeypatch.setattr(S, "_snmpget", lambda *a, **k: None)
    monkeypatch.setattr(S, "_onesixtyone", lambda *a, **k: [])
    assert S._enumerate_host("10.0.0.3", ["public"], 2) is None


def test_module_info_columns_include_walk_fields():
    keys = {c["key"] for c in S.module_info["table"]["columns"]}
    assert {"users", "tcp_ports", "process_count", "software_count"} <= keys
