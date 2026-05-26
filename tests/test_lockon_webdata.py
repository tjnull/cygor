"""Tests for lockon's web-data harvesting (added so screenshots are paired with
queryable facts) and the protocol-keyed merge that keeps auto-dispatch from
overwriting one protocol's results with the next."""
import asyncio
import json

from cygor.modules import lockon as L
from cygor.modules.base import merge_prior_results


def test_fingerprint_web():
    tech = L._fingerprint_web({
        "server": "nginx/1.25",
        "x-powered-by": "PHP/8.2",
        "set-cookie": "JSESSIONID=abc; Path=/",
    })
    assert "nginx/1.25" in tech
    assert "PHP/8.2" in tech
    assert "Java" in tech  # from JSESSIONID cookie


def test_extract_web_data_basic():
    class FakeResp:
        status = 200
        url = "http://h/dashboard"
        headers = {"server": "Apache/2.4", "content-type": "text/html; charset=utf-8"}

    class FakePage:
        async def title(self):
            return "Admin Console"

    data = asyncio.run(
        L._extract_web_data(FakePage(), FakeResp(), "http://h/", "h", "80", "http")
    )
    assert data["http_status"] == "200"
    assert data["title"] == "Admin Console"
    assert data["server"] == "Apache/2.4"
    assert data["content_type"] == "text/html"
    assert data["redirect"] == "http://h/dashboard"   # final URL differs from requested
    assert data["tls"] == ""                            # http -> no cert probe


def test_extract_web_data_keys_uniform_on_no_response():
    class FakePage:
        async def title(self):
            return ""

    data = asyncio.run(
        L._extract_web_data(FakePage(), None, "http://h/", "h", "80", "http")
    )
    assert set(data.keys()) == set(L._WEB_DATA_KEYS.keys())


def test_lockon_merge_by_protocol(tmp_path):
    p = tmp_path / "cygor-result.json"
    p.write_text(json.dumps({"results": [
        {"protocol": "http", "url": "a"},
        {"protocol": "rdp", "url": "b"},
    ]}))
    new = [{"protocol": "http", "url": "c"}]
    merged = merge_prior_results(p, new, "protocol", {"http"})
    pairs = {(r["protocol"], r["url"]) for r in merged}
    assert ("rdp", "b") in pairs       # untouched protocol preserved
    assert ("http", "c") in pairs      # refreshed protocol present
    assert ("http", "a") not in pairs  # stale http row dropped


def test_native_capture_helpers_present_and_save(tmp_path):
    """Native RDP/VNC/X11 backends exist and the image saver round-trips."""
    from cygor.modules import lockon as L
    for fn in ("_vnc_capture_native", "_x11_capture_native", "_rdp_capture_native",
               "_ensure_pip_package", "_save_image"):
        assert hasattr(L, fn), f"missing {fn}"
    from PIL import Image
    out = tmp_path / "shot.png"
    assert L._save_image(Image.new("RGB", (8, 8), "blue"), out) is True
    assert out.exists() and out.stat().st_size > 0
    # numpy array path
    import numpy as np
    out2 = tmp_path / "shot2.png"
    assert L._save_image(np.zeros((8, 8, 3), dtype="uint8"), out2) is True


# ----------------------------------------------------------------------
# .rdp file parsing (lockon rdp --rdp-file / -t server.rdp)
# ----------------------------------------------------------------------
def _write(path, text, encoding="utf-8"):
    path.write_bytes(text.encode(encoding))
    return str(path)


def test_parse_rdp_file_utf8_with_domain(tmp_path):
    p = _write(tmp_path / "srv.rdp",
               "full address:s:192.168.1.251:3389\r\n"
               "username:s:Administrator\r\n"
               "domain:s:CORP\r\n"
               "screen mode id:i:2\r\n")
    info = L._parse_rdp_file(p)
    assert info["host"] == "192.168.1.251"
    assert info["port"] == 3389
    assert info["user"] == "Administrator"
    assert info["domain"] == "CORP"


def test_parse_rdp_file_utf16_and_domain_user_split(tmp_path):
    # Windows-written .rdp is UTF-16; server port is separate; user is DOMAIN\user.
    p = _write(tmp_path / "win.rdp",
               "full address:s:10.0.0.5\r\n"
               "server port:i:3390\r\n"
               "username:s:WORKGROUP\\bob\r\n",
               encoding="utf-16")
    info = L._parse_rdp_file(p)
    assert info["host"] == "10.0.0.5"
    assert info["port"] == 3390          # honoured "server port"
    assert info["user"] == "bob"
    assert info["domain"] == "WORKGROUP"  # split out of DOMAIN\user


def test_parse_rdp_file_embedded_port_wins(tmp_path):
    p = _write(tmp_path / "m.rdp", "full address:s:host.example.com:3399\r\n")
    info = L._parse_rdp_file(p)
    assert (info["host"], info["port"]) == ("host.example.com", 3399)
    assert info["user"] == "" and info["domain"] == ""


def test_parse_rdp_file_invalid_returns_none(tmp_path):
    assert L._parse_rdp_file(str(tmp_path / "nope.rdp")) is None          # missing
    p = _write(tmp_path / "bad.rdp", "username:s:nobody\r\n")              # no target
    assert L._parse_rdp_file(p) is None


def test_normalize_rdp_target_precedence():
    # per-target creds win over CLI fallbacks
    t = L._normalize_rdp_target({"host": "1.1.1.1", "port": 3389, "user": "bob", "domain": "CORP"},
                                "cli", "CLIDOM")
    assert (t["user"], t["domain"]) == ("bob", "CORP")
    # empty per-target creds fall back to CLI values
    t = L._normalize_rdp_target({"host": "1.1.1.1", "port": 3389, "user": "", "domain": ""},
                                "cli", "CLIDOM")
    assert (t["user"], t["domain"]) == ("cli", "CLIDOM")
    # tuple target uses CLI fallbacks
    t = L._normalize_rdp_target(("2.2.2.2", 3390), "cli", None)
    assert (t["host"], t["port"], t["user"], t["domain"]) == ("2.2.2.2", 3390, "cli", None)
    # no host -> dropped
    assert L._normalize_rdp_target({"host": "", "port": 3389}, None, None) is None
