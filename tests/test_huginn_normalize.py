"""
Tests for the Huginn-Muninn record normalizer.

These guard against the regression where lookup_huginn_device dumped the
raw Huginn ``name`` (a model string like "Apple iPhone") into the
``device_type`` field and the full hierarchy path into ``device_category``.
The post-fix expectation is that:

- device_type is a normalized bucket ("smartphone", "router", "switch", ...)
- device_category is a normalized category ("Mobile Device", "Network Device", ...)
- manufacturer is extracted from the hierarchy when implied
- os_family is inferred for vendor-specific mobile records (Apple → iOS, etc.)
- pure OS records ("Operating System > Windows OS") produce os_family + os_vendor
  with no spurious device_type
- vendor-only records ("Hardware Manufacturer > X") produce manufacturer only
"""
from __future__ import annotations

from cygor.fingerprinting.huginn_normalize import normalize_huginn_record, tokenize


def _entry(name, hierarchy, mobile=False, tablet=False):
    return {
        "name": name,
        "hierarchy": hierarchy,
        "hierarchy_str": " > ".join(hierarchy),
        "mobile": mobile,
        "tablet": tablet,
    }


# ---------------------------------------------------------------------------
# Mobile devices — the original failure mode
# ---------------------------------------------------------------------------


def test_apple_iphone_normalizes_correctly():
    rec = _entry(
        "Apple iPhone",
        ["Phone, Tablet or Wearable", "Apple Mobile Device", "Apple iPhone"],
        mobile=True,
    )
    out = normalize_huginn_record(rec)
    assert out["device_type"] == "smartphone"
    assert out["device_category"] == "Mobile Device"
    assert out["manufacturer"] == "Apple"
    assert out["os_family"] == "iOS"
    assert out["os_vendor"] == "Apple"
    assert out["model"] == "Apple iPhone"


def test_apple_ipad_is_tablet_not_smartphone():
    """Huginn marks iPads as mobile=True, tablet=False — the keyword wins."""
    rec = _entry(
        "Apple iPad",
        ["Phone, Tablet or Wearable", "Apple Mobile Device", "Apple iPad"],
        mobile=True, tablet=False,
    )
    out = normalize_huginn_record(rec)
    assert out["device_type"] == "tablet"
    assert out["manufacturer"] == "Apple"


def test_specific_iphone_model_keeps_apple_vendor():
    rec = _entry(
        "iPhone 14",
        ["Phone, Tablet or Wearable", "Apple Mobile Device", "Apple iPhone", "iPhone 14"],
        mobile=True,
    )
    out = normalize_huginn_record(rec)
    assert out["manufacturer"] == "Apple"
    assert out["os_family"] == "iOS"
    assert out["device_type"] == "smartphone"


def test_samsung_galaxy_implies_android():
    rec = _entry(
        "Samsung Galaxy S22",
        ["Phone, Tablet or Wearable", "Samsung Mobile Device", "Samsung Galaxy S22"],
        mobile=True,
    )
    out = normalize_huginn_record(rec)
    assert out["manufacturer"] == "Samsung"
    assert out["device_type"] == "smartphone"
    assert out["os_family"] == "Android"


# ---------------------------------------------------------------------------
# Network gear
# ---------------------------------------------------------------------------


def test_cisco_switch_extracts_vendor():
    rec = _entry(
        "Cisco Catalyst 2960",
        ["Switch and Wireless Controller", "Cisco Switches", "Cisco Catalyst 2960"],
    )
    out = normalize_huginn_record(rec)
    assert out["device_type"] == "switch"
    assert out["device_category"] == "Network Device"
    assert out["manufacturer"] == "Cisco"


def test_router_record():
    rec = _entry(
        "ASUS RT-AX86U",
        ["Router, Access Point or Femtocell", "ASUS Routers", "ASUS RT-AX86U"],
    )
    out = normalize_huginn_record(rec)
    assert out["device_type"] == "router"
    assert out["device_category"] == "Network Device"
    assert out["manufacturer"] == "ASUS"


# ---------------------------------------------------------------------------
# Peripherals / IoT
# ---------------------------------------------------------------------------


def test_hp_printer():
    rec = _entry(
        "HP LaserJet 4250",
        ["Printer or Scanner", "HP Printer", "HP LaserJet 4250"],
    )
    out = normalize_huginn_record(rec)
    assert out["device_type"] == "printer"
    assert out["device_category"] == "Peripheral"
    assert out["manufacturer"] == "HP"


def test_ip_camera():
    rec = _entry(
        "Hikvision DS-2CD",
        ["Internet of Things (IoT)", "IP Camera", "Hikvision DS-2CD"],
    )
    out = normalize_huginn_record(rec)
    assert out["device_type"] == "ip_camera"
    assert out["device_category"] == "IoT"


# ---------------------------------------------------------------------------
# OS-rooted records — these must NOT produce a device_type
# ---------------------------------------------------------------------------


def test_windows_os_record():
    rec = _entry("Windows OS", ["Operating System", "Windows OS"])
    out = normalize_huginn_record(rec)
    assert out["device_type"] is None
    assert out["device_category"] is None
    assert out["os_family"] == "Windows"
    assert out["os_vendor"] == "Microsoft"


def test_macos_record():
    rec = _entry(
        "Mac OS X or macOS",
        ["Operating System", "Apple OS", "Mac OS X or macOS"],
    )
    out = normalize_huginn_record(rec)
    assert out["device_type"] is None
    assert out["os_family"] == "macOS"
    assert out["os_vendor"] == "Apple"


def test_linux_distro_record():
    rec = _entry(
        "Ubuntu",
        ["Operating System", "Linux", "Ubuntu"],
    )
    out = normalize_huginn_record(rec)
    assert out["os_family"] == "Linux"
    # Vendor depends on whether the hint matched "ubuntu" (Canonical) or
    # bare "linux"; either is acceptable.
    assert out["os_vendor"] in {"Canonical", None}


# ---------------------------------------------------------------------------
# Vendor-only records — manufacturer only
# ---------------------------------------------------------------------------


def test_hardware_manufacturer_record():
    rec = _entry(
        "Acme Networks",
        ["Hardware Manufacturer", "Acme Networks"],
    )
    out = normalize_huginn_record(rec)
    assert out["manufacturer"] == "Acme Networks"
    assert out["device_type"] is None
    assert out["device_category"] is None


# ---------------------------------------------------------------------------
# Generic device records — no false-positive manufacturer
# ---------------------------------------------------------------------------


def test_generic_voip_device_no_fake_vendor():
    """The leaf 'VoIP Device' is generic — must NOT become manufacturer='VoIP'."""
    rec = _entry("VoIP Device", ["VoIP Device"])
    out = normalize_huginn_record(rec)
    assert out["device_type"] == "voip_phone"
    assert out["device_category"] == "Communication"
    # Generic device-type words must never leak into the vendor slot.
    assert out["manufacturer"] != "VoIP"


def test_empty_record_returns_all_none():
    out = normalize_huginn_record({})
    for k in ("device_type", "device_category", "manufacturer", "os_family"):
        assert out[k] is None


# ---------------------------------------------------------------------------
# Tokenizer (used by hostname fuzzy matching)
# ---------------------------------------------------------------------------


def test_tokenize_basic():
    assert tokenize("Apple iPhone") == ["apple", "iphone"]
    assert tokenize("iphone-bob") == ["iphone", "bob"]
    assert tokenize("DESKTOP-H1JK345") == ["desktop", "h1jk345"]
    assert tokenize("") == []
