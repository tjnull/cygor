"""Tests for the dbprobe module: per-service probe parsing, row assembly,
closed-port skipping, and the merge-on-save that lets auto-dispatch accumulate
results across DB buckets without overwriting."""
import json

from cygor.modules import dbprobe
from cygor.modules.base import merge_prior_results


class _FakeSock:
    """Minimal context-manager socket returning a canned reply."""
    def __init__(self, reply: bytes):
        self._reply = reply

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, *a):
        pass

    def sendall(self, *a):
        pass

    def recv(self, n):
        return self._reply


def test_merge_prior_results_accumulates_and_refreshes(tmp_path):
    p = tmp_path / "cygor-result.json"
    p.write_text(json.dumps({"results": [
        {"ip": "1.1.1.1", "service": "redis", "auth_required": "no"},
        {"ip": "2.2.2.2", "service": "postgres", "auth_required": "yes"},
    ]}))
    new = [{"ip": "2.2.2.2", "service": "postgres", "auth_required": "no"}]
    merged = merge_prior_results(p, new, "service", {"postgres"})
    by = {(r["ip"], r["service"]): r for r in merged}
    assert by[("1.1.1.1", "redis")]["auth_required"] == "no"   # other group kept
    assert by[("2.2.2.2", "postgres")]["auth_required"] == "no"  # own group refreshed
    assert len(merged) == 2


def test_merge_prior_results_missing_file(tmp_path):
    out = merge_prior_results(tmp_path / "nope.json", [{"service": "redis"}], "service", {"redis"})
    assert out == [{"service": "redis"}]


def test_redis_unauth_parse(monkeypatch):
    reply = b"$80\r\n# Server\r\nredis_version:7.0.5\r\nrole:master\r\n"
    monkeypatch.setattr(dbprobe.socket, "create_connection", lambda *a, **k: _FakeSock(reply))
    row = dbprobe._probe_redis("h", 6379, 2)
    assert row["auth_required"] == "no"
    assert row["version"] == "7.0.5"
    assert "master" in row["info"]


def test_redis_noauth(monkeypatch):
    monkeypatch.setattr(dbprobe.socket, "create_connection",
                        lambda *a, **k: _FakeSock(b"-NOAUTH Authentication required.\r\n"))
    assert dbprobe._probe_redis("h", 6379, 2)["auth_required"] == "yes"


def test_mysql_handshake_version(monkeypatch):
    payload = b"\x0a" + b"5.7.42-log\x00" + b"\x00\x00\x00\x00"
    pkt = b"\x36\x00\x00\x00" + payload
    monkeypatch.setattr(dbprobe.socket, "create_connection", lambda *a, **k: _FakeSock(pkt))
    row = dbprobe._probe_mysql("h", 3306, 2)
    assert row["version"] == "5.7.42-log"
    assert row["auth_required"] == "yes"


def test_mysql_error_packet(monkeypatch):
    # 0xff after the 4-byte header => ERR packet (host not allowed)
    pkt = b"\x10\x00\x00\x00" + b"\xff\x6a\x04" + b"Host blocked"
    monkeypatch.setattr(dbprobe.socket, "create_connection", lambda *a, **k: _FakeSock(pkt))
    row = dbprobe._probe_mysql("h", 3306, 2)
    assert row["auth_required"] == "yes"
    assert "Host blocked" in row["info"]


def test_bson_cmd_roundtrip():
    doc = dbprobe._bson_cmd("buildInfo", "admin")
    assert dbprobe._bson_find_str(doc, "$db") == "admin"


def test_run_assembles_rows_and_skips_closed(tmp_path, monkeypatch):
    monkeypatch.setitem(dbprobe.PROBES, "redis",
                        lambda h, p, t: {"reachable": "yes", "auth_required": "no",
                                         "version": "7", "info": "UNAUTH"})
    monkeypatch.setitem(dbprobe.PROBES, "mysql", lambda h, p, t: None)  # closed -> skip

    m = dbprobe.DBProbe(output_dir=str(tmp_path / "o1"))
    m.run(["10.0.0.1"], service="redis")
    assert len(m.results) == 1
    r = m.results[0]
    assert r["ip"] == "10.0.0.1" and r["service"] == "redis" and r["port"] == "6379"
    assert r["auth_required"] == "no"

    m2 = dbprobe.DBProbe(output_dir=str(tmp_path / "o2"))
    m2.run(["10.0.0.1"], service="mysql")
    assert m2.results == []  # closed port produced no row
