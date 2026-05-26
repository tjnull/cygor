"""Tests for dnsexplorer parsing: version.bind, open-resolver detection, and
AXFR result classification (dig output is mocked, no network)."""
from cygor.modules import dnsexplorer as dns


def test_recursion_open(monkeypatch):
    def fake_dig(server, name, rtype, timeout, extra=None):
        return "93.184.216.34\n" if name == dns.RECURSION_PROBE else ""
    monkeypatch.setattr(dns, "_dig", fake_dig)
    assert dns._recursion_open("8.8.8.8", 2) == "open"


def test_recursion_closed(monkeypatch):
    monkeypatch.setattr(dns, "_dig", lambda *a, **k: "")
    assert dns._recursion_open("h", 2) == "closed"


def test_version_bind(monkeypatch):
    monkeypatch.setattr(dns, "_dig", lambda *a, **k: '"9.16.1-Debian"\n')
    assert dns._version_bind("h", 2) == "9.16.1-Debian"


def test_axfr_success(monkeypatch):
    out = ("example.com. 3600 IN SOA ns1.example.com. root.example.com. 1 2 3 4 5\n"
           "example.com. 3600 IN NS ns1.example.com.\n"
           "www.example.com. 3600 IN A 1.2.3.4\n")
    monkeypatch.setattr(dns, "_dig", lambda *a, **k: out)
    res = dns._axfr("h", "example.com", 2)
    assert res["axfr"] == "SUCCESS"
    assert int(res["records"]) >= 2


def test_axfr_refused(monkeypatch):
    monkeypatch.setattr(dns, "_dig", lambda *a, **k: "; Transfer failed.\n")
    assert dns._axfr("h", "example.com", 2)["axfr"] == "refused"


def test_run_per_server_row(monkeypatch, tmp_path):
    monkeypatch.setattr(dns.shutil, "which", lambda x: "/usr/bin/dig")
    monkeypatch.setattr(dns, "_version_bind", lambda s, t: "9.18")
    monkeypatch.setattr(dns, "_recursion_open", lambda s, t: "open")
    m = dns.DNSExplorer(output_dir=str(tmp_path / "o"))
    m.run(["192.168.1.53"], timeout=2)  # no domain -> no AXFR
    r = m.results[0]
    assert r["ip"] == "192.168.1.53"
    assert r["version"] == "9.18"
    assert r["recursion"] == "open"
    assert r["axfr"] == "not-tested"
