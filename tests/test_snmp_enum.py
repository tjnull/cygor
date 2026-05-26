"""Tests for the SNMP enum module's parsing/target logic and the
service->module auto-dispatch layer (cygor enum --auto)."""
import pytest

from cygor.modules import snmpexplorer as snmp


def test_read_targets_file_and_inline(tmp_path):
    f = tmp_path / "hosts.txt"
    f.write_text("# comment\n192.168.1.1\n192.168.1.2:161\n10.0.0.5 extra\n\n")
    hosts = snmp._read_targets("192.168.1.1, 9.9.9.9", str(f))
    # file entries normalized (port/extra stripped) + inline, deduped, order kept
    assert hosts == ["192.168.1.1", "192.168.1.2", "10.0.0.5", "9.9.9.9"]


def test_enumerate_host_parses_system_group(monkeypatch):
    # Simulate snmpget answers: 'public' works, returns values per OID.
    answers = {
        "1.3.6.1.2.1.1.1.0": "Linux fw01 5.15 x86_64",   # sysDescr
        "1.3.6.1.2.1.1.3.0": "12 days, 3:04:05.00",        # sysUpTime
        "1.3.6.1.2.1.1.4.0": "admin@corp",                 # sysContact
        "1.3.6.1.2.1.1.5.0": "fw01",                       # sysName
        "1.3.6.1.2.1.1.6.0": "ServerRoom",                 # sysLocation
    }

    def fake_snmpget(host, community, oid, timeout):
        if community != "public":
            return None
        return answers.get(oid)

    monkeypatch.setattr(snmp, "_snmpget", fake_snmpget)
    row = snmp._enumerate_host("192.168.1.1", ["private", "public"], 2)
    assert row is not None
    assert row["ip"] == "192.168.1.1"
    assert row["community"] == "public"      # detected the working community
    assert row["sysName"] == "fw01"
    assert row["sysDescr"].startswith("Linux fw01")
    assert row["sysLocation"] == "ServerRoom"


def test_enumerate_host_no_snmp(monkeypatch):
    monkeypatch.setattr(snmp, "_snmpget", lambda *a, **k: None)
    assert snmp._enumerate_host("10.0.0.9", ["public"], 1) is None


def test_auto_dispatch_runs_mapped_module(tmp_path, monkeypatch):
    import cygor.enumcli as enumcli

    # Fake workspace with an snmp hostlist (and an empty smb one that must be skipped).
    ws = tmp_path / "ws"
    (ws / "parsed-hostlists" / "snmp").mkdir(parents=True)
    (ws / "parsed-hostlists" / "snmp" / "snmp-hostlist.txt").write_text("192.168.1.1\n192.168.1.2\n")
    (ws / "parsed-hostlists" / "smb").mkdir(parents=True)
    (ws / "parsed-hostlists" / "smb" / "smb-hostlist.txt").write_text("")  # empty -> skip

    monkeypatch.setenv("CYGOR_WORKSPACE", str(ws))

    calls = []
    monkeypatch.setattr(enumcli.subprocess, "run", lambda cmd, **kw: calls.append(cmd))

    rc = enumcli._run_auto()
    assert rc == 0
    # exactly one dispatch: snmp -> snmpexplorer with the hostlist as final arg
    snmp_calls = [c for c in calls if "snmpexplorer" in c]
    assert len(snmp_calls) == 1
    cmd = snmp_calls[0]
    assert cmd[-1].endswith("snmp/snmp-hostlist.txt")
    assert "-f" in cmd
    # empty smb hostlist must NOT have been dispatched
    assert not any("smbexplorer" in c for c in calls)
