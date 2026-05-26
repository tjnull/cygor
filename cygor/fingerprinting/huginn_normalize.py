"""
Normalize Huginn-Muninn device records into cygor's flat fingerprint shape.

A Huginn record looks like:

    {
      "name": "Apple iPhone",
      "hierarchy": ["Phone, Tablet or Wearable", "Apple Mobile Device", "Apple iPhone"],
      "hierarchy_str": "Phone, Tablet or Wearable > Apple Mobile Device > Apple iPhone",
      "mobile": true,
      "tablet": false,
      "simplified_name": "appleiphone"
    }

The cygor fingerprint pipeline expects flat normalized fields:

    {"device_type": "smartphone",
     "device_category": "Mobile Device",
     "manufacturer": "Apple",
     "model": "Apple iPhone",
     "os_family": "iOS",
     "os_vendor": "Apple"}

This module owns that translation. Keeping the heuristics in one place means
new Huginn record shapes can be supported by editing data tables here rather
than by patching lookup.py.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Hierarchy root → cygor device_category
# ---------------------------------------------------------------------------
# Based on the live distribution of 116K Huginn records — sorted by frequency.
# Roots not in this map fall through to "Unknown" / no category.
ROOT_TO_CATEGORY: Dict[str, str] = {
    "Phone, Tablet or Wearable":             "Mobile Device",
    "Hardware Manufacturer":                 None,  # vendor-only records, not a device
    "Printer or Scanner":                    "Peripheral",
    "Audio, Imaging or Video Equipment":     "Media",
    "Router, Access Point or Femtocell":     "Network Device",
    "Switch and Wireless Controller":        "Network Device",
    "Internet of Things (IoT)":              "IoT",
    "VoIP Device":                           "Communication",
    "Robotics and Industrial Automation":    "SCADA/ICS",
    "Storage Device":                        "Storage",
    "Automotive, Energy and Tools":          "Embedded",
    "Monitoring and Testing Device":         "Embedded",
    "Medical Device":                        "Medical",
    "Firewall and Security Appliance":       "Security",
    "Physical Security":                     "Security",
    "Datacenter Appliance":                  "Computing",
    "Projector":                             "Media",
    "Operating System":                      None,  # OS record, special-cased below
    "Video Conferencing":                    "Communication",
    "Point of Sale Device":                  "Embedded",
}


# ---------------------------------------------------------------------------
# Suffix words used to peel a vendor name out of an intermediate hierarchy
# entry like "HP Printer" → "HP" or "Cisco Switches" → "Cisco".
# Order matters — longer phrases first so we don't strip "Printer" before
# "Network Printer".
# ---------------------------------------------------------------------------
_VENDOR_TYPE_SUFFIXES: List[str] = [
    "Mobile Device", "Operating System", "Wireless Controller",
    "Wireless Access Point", "Access Point", "IP Camera",
    "Network Printer", "Network Switch", "Network Storage",
    "Printers", "Printer", "Switches", "Switch",
    "Routers", "Router", "Cameras", "Camera",
    "Phones", "Phone", "Tablets", "Tablet",
    "TVs", "TV", "Television", "Televisions",
    "Storage", "Servers", "Server",
    "Laptops", "Laptop", "Desktops", "Desktop",
    "Watches", "Watch", "Wearables", "Wearable",
    "Speakers", "Speaker", "Modems", "Modem",
    "Receivers", "Receiver", "Players", "Player",
    "Devices", "Device",
]


# ---------------------------------------------------------------------------
# Hierarchy keywords → normalized device_type bucket. Walked in order; first
# match wins. Add patterns by appending to the list (data, not code change).
# ---------------------------------------------------------------------------
_TYPE_PATTERNS: List[tuple] = [
    # (lowercase keyword that must appear in any hierarchy level, device_type)
    ("smartphone",        "smartphone"),
    ("iphone",            "smartphone"),
    ("galaxy",            "smartphone"),
    ("android",           "smartphone"),
    ("tablet",            "tablet"),
    ("ipad",              "tablet"),
    ("watch",             "wearable"),
    ("wearable",          "wearable"),
    ("router",            "router"),
    ("femtocell",         "router"),
    ("modem",             "router"),
    ("switch",            "switch"),
    ("access point",      "access_point"),
    ("wireless lan controller", "wireless_controller"),
    ("wireless controller", "wireless_controller"),
    ("firewall",          "firewall"),
    ("security appliance","firewall"),
    ("camera",            "ip_camera"),
    ("printer",           "printer"),
    ("scanner",           "scanner"),
    ("multifunction",     "multifunction"),
    ("voip",              "voip_phone"),
    ("ip phone",          "voip_phone"),
    ("speaker",           "smart_speaker"),
    ("soundbar",          "smart_speaker"),
    ("set-top",           "set_top_box"),
    ("set top",           "set_top_box"),
    ("television",        "smart_tv"),
    ("smart tv",          "smart_tv"),
    ("game console",      "game_console"),
    ("nas",               "nas"),
    ("storage",           "nas"),
    ("plc",               "plc"),
    ("hmi",               "hmi"),
    ("scada",             "scada_server"),
    ("industrial",        "industrial_router"),  # generic catch
    ("medical",           "medical_device"),
    ("projector",         "media_player"),
    ("video conferencing","video_conferencing"),
    ("doorbell",          "doorbell"),
    ("thermostat",        "thermostat"),
    ("smart home",        "smart_home"),
    ("kiosk",             "kiosk"),
    ("pos",               "pos_terminal"),
]


# ---------------------------------------------------------------------------
# Vendor → OS family heuristic. When the hierarchy implies a specific vendor
# AND the device is mobile/wearable/etc., we can confidently infer the OS.
# ---------------------------------------------------------------------------
_VENDOR_MOBILE_OS: Dict[str, str] = {
    "Apple":      "iOS",
    "Samsung":    "Android",
    "Google":     "Android",
    "Huawei":     "Android",
    "Xiaomi":     "Android",
    "OnePlus":    "Android",
    "Oppo":       "Android",
    "Vivo":       "Android",
    "Motorola":   "Android",
    "LG":         "Android",
    "Sony":       "Android",
    "Nokia":      "Android",  # modern Nokias are Android
    "BlackBerry": "BlackBerry OS",  # legacy
}

# Hierarchy-level → OS family (used for "Operating System" rooted records and
# vendor-specific mobile records like "Apple Mobile Device").
_HIERARCHY_OS_HINTS: List[tuple] = [
    # (lowercase substring in any hierarchy level, os_family, os_vendor)
    ("ios",                "iOS",        "Apple"),
    ("apple mobile",       "iOS",        "Apple"),
    ("apple ios",          "iOS",        "Apple"),
    ("ipados",             "iPadOS",     "Apple"),
    ("watchos",            "watchOS",    "Apple"),
    ("tvos",               "tvOS",       "Apple"),
    ("mac os",             "macOS",      "Apple"),
    ("macos",              "macOS",      "Apple"),
    ("apple os",           "macOS",      "Apple"),
    ("windows phone",      "Windows Phone", "Microsoft"),
    ("windows mobile",     "Windows Mobile", "Microsoft"),
    ("windows server",     "Windows Server", "Microsoft"),
    ("windows os",         "Windows",    "Microsoft"),
    ("windows",            "Windows",    "Microsoft"),
    ("android mobile",     "Android",    "Google"),
    ("android os",         "Android",    "Google"),
    ("android",            "Android",    "Google"),
    ("chrome os",          "ChromeOS",   "Google"),
    ("chromeos",           "ChromeOS",   "Google"),
    ("ubuntu",             "Linux",      "Canonical"),
    ("debian",             "Linux",      "Debian"),
    ("centos",             "Linux",      "Red Hat"),
    ("red hat",            "Linux",      "Red Hat"),
    ("rhel",               "Linux",      "Red Hat"),
    ("fedora",             "Linux",      "Red Hat"),
    ("openwrt",            "Linux",      "OpenWrt"),
    ("dd-wrt",             "Linux",      "DD-WRT"),
    ("linux",              "Linux",      None),
    ("freebsd",            "FreeBSD",    None),
    ("netbsd",             "NetBSD",     None),
    ("openbsd",            "OpenBSD",    None),
    ("solaris",            "Solaris",    "Oracle"),
    ("aix",                "AIX",        "IBM"),
    ("hp-ux",              "HP-UX",      "HP"),
    ("vxworks",            "VxWorks",    "Wind River"),
    ("rtos",               "RTOS",       None),
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def normalize_huginn_record(entry: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """
    Convert a Huginn device entry into cygor's flat fingerprint shape.

    Returns a dict with the keys the FingerprintMatch fields expect:
        device_type, device_category, manufacturer, model, os_family, os_vendor

    All keys are always present; values may be None when the record doesn't
    provide enough information.
    """
    out: Dict[str, Optional[str]] = {
        "device_type":     None,
        "device_category": None,
        "manufacturer":    None,
        "model":           None,
        "os_family":       None,
        "os_vendor":       None,
    }
    if not isinstance(entry, dict):
        return out

    name = (entry.get("name") or "").strip()
    hierarchy = entry.get("hierarchy") or []
    if not isinstance(hierarchy, list):
        hierarchy = []
    is_mobile = bool(entry.get("mobile"))
    is_tablet = bool(entry.get("tablet"))

    # === OS records ("Operating System > …") are special ===
    if hierarchy and hierarchy[0] == "Operating System":
        os_info = _infer_os_from_hierarchy(hierarchy + [name])
        if os_info:
            out["os_family"] = os_info["family"]
            out["os_vendor"] = os_info["vendor"]
        return out

    # === Vendor-only records ("Hardware Manufacturer > …") ===
    if hierarchy and hierarchy[0] == "Hardware Manufacturer":
        # Just a vendor record — the leaf is the vendor name.
        if len(hierarchy) >= 2:
            out["manufacturer"] = hierarchy[-1] if hierarchy[-1] != hierarchy[0] else hierarchy[1]
        return out

    # === Device records ===
    if hierarchy:
        out["device_category"] = ROOT_TO_CATEGORY.get(hierarchy[0]) or "Unknown"

    out["device_type"] = _infer_device_type(hierarchy, name, is_mobile, is_tablet)
    out["manufacturer"] = _extract_vendor_from_hierarchy(hierarchy, name)
    if name and (not hierarchy or name != hierarchy[0]):
        out["model"] = name

    # OS inference: hierarchy-based hints first, then vendor-mobile heuristic.
    os_info = _infer_os_from_hierarchy(hierarchy + [name])
    if not os_info and out["manufacturer"] and (is_mobile or out["device_type"] in {"smartphone", "tablet"}):
        os_family = _VENDOR_MOBILE_OS.get(out["manufacturer"])
        if os_family:
            os_info = {"family": os_family, "vendor": _vendor_for_os(os_family) or out["manufacturer"]}
    if os_info:
        out["os_family"] = os_info["family"]
        out["os_vendor"] = os_info["vendor"]

    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


_TOKEN_SPLIT_RE = re.compile(r"[^a-zA-Z0-9]+")


def tokenize(text: str) -> List[str]:
    """Lowercase + split on non-alphanumeric. Used by hostname matching too."""
    if not text:
        return []
    return [t for t in _TOKEN_SPLIT_RE.split(text.lower()) if t]


def _strip_type_suffix(text: str) -> str:
    """Remove a trailing device-type word so 'HP Printer' → 'HP'."""
    for suffix in _VENDOR_TYPE_SUFFIXES:
        if text.endswith(" " + suffix):
            return text[: -(len(suffix) + 1)].strip()
        if text == suffix:
            return ""
    return text.strip()


def _extract_vendor_from_hierarchy(hierarchy: List[str], name: str) -> Optional[str]:
    """
    Walk hierarchy looking for a level whose phrasing reveals a vendor.

    Examples:
      ["Phone, Tablet or Wearable", "Apple Mobile Device", "Apple iPhone"]
        → "Apple Mobile Device" → strip "Mobile Device" → "Apple"
      ["Printer or Scanner", "HP Printer", "HP LaserJet 4250"]
        → "HP Printer" → strip "Printer" → "HP"
      ["Switch and Wireless Controller", "Cisco Switches", "Cisco Catalyst 2960"]
        → "Cisco Switches" → strip "Switches" → "Cisco"
    """
    # Check intermediate levels (skip the root category and the leaf model).
    for level in hierarchy[1:-1] if len(hierarchy) > 2 else hierarchy[1:]:
        candidate = _strip_type_suffix(level)
        if candidate and candidate != level and " " not in candidate.strip():
            # Single-word vendor extracted; that's a high-confidence signal.
            return candidate
        if candidate and candidate != level:
            return candidate
    # Fallback: try to extract a vendor word from the leaf model name.
    if name:
        # First word of model often is the vendor: "HP LaserJet 4250" → "HP".
        first = name.split()[0] if name else ""
        # Filter out generic words. Importantly, exclude device-type words
        # like "VoIP", "Camera", "Printer" — those are not vendors even when
        # they sit in the vendor slot of a thin Huginn record.
        generic_or_type = {
            "generic", "unknown", "the", "a", "an", "other",
            "voip", "camera", "printer", "router", "switch", "modem",
            "phone", "tablet", "wearable", "tv", "television", "scanner",
            "iot", "device", "appliance", "speaker", "soundbar", "projector",
            "firewall", "server", "storage", "nas", "kiosk", "pos",
        }
        if first and first.lower() not in generic_or_type and len(first) >= 2:
            # Sanity: vendor should appear elsewhere in hierarchy too, otherwise
            # we risk grabbing a model-name first word as a vendor.
            if any(first.lower() in lvl.lower() for lvl in hierarchy):
                return first
    return None


def _infer_device_type(hierarchy: List[str], name: str, is_mobile: bool, is_tablet: bool) -> Optional[str]:
    """
    Decide on a normalized device_type bucket.

    Order of precedence:
      1. Specific keyword match (e.g. 'ipad' → tablet) — Huginn often marks
         iPads as mobile=True/tablet=False, so the keyword wins.
      2. ``tablet`` boolean — authoritative when set.
      3. ``mobile`` boolean — broad fallback for phones.
      4. Root-category default (e.g. "Printer or Scanner" → printer).
    """
    haystack = " ".join(hierarchy + [name]).lower()
    for keyword, dtype in _TYPE_PATTERNS:
        if keyword in haystack:
            return dtype

    if is_tablet:
        return "tablet"
    if is_mobile:
        return "smartphone"

    # Map directly off the root category for last-resort buckets.
    if not hierarchy:
        return None
    root = hierarchy[0]
    root_to_type = {
        "Phone, Tablet or Wearable":          "smartphone",  # default for that root
        "Printer or Scanner":                 "printer",
        "Router, Access Point or Femtocell":  "router",
        "Switch and Wireless Controller":     "switch",
        "Internet of Things (IoT)":           "iot",
        "VoIP Device":                        "voip_phone",
        "Storage Device":                     "nas",
        "Firewall and Security Appliance":    "firewall",
        "Video Conferencing":                 "video_conferencing",
        "Projector":                          "media_player",
        "Point of Sale Device":               "pos_terminal",
        "Medical Device":                     "medical_device",
    }
    return root_to_type.get(root)


def _infer_os_from_hierarchy(levels: List[str]) -> Optional[Dict[str, Optional[str]]]:
    """Return {'family': ..., 'vendor': ...} when any level matches an OS hint."""
    haystack = " ".join(l.lower() for l in levels if l)
    for needle, family, vendor in _HIERARCHY_OS_HINTS:
        if needle in haystack:
            return {"family": family, "vendor": vendor}
    return None


def _vendor_for_os(os_family: str) -> Optional[str]:
    """Map an OS family back to its canonical vendor (e.g. iOS → Apple)."""
    mapping = {
        "iOS": "Apple", "iPadOS": "Apple", "macOS": "Apple",
        "watchOS": "Apple", "tvOS": "Apple",
        "Windows": "Microsoft", "Windows Server": "Microsoft",
        "Windows Phone": "Microsoft", "Windows Mobile": "Microsoft",
        "Android": "Google",
        "ChromeOS": "Google",
    }
    return mapping.get(os_family)
