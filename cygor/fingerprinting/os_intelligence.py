"""
OS Intelligence Database for Enhanced Fingerprint Validation.

This module contains databases for:
1. Vendor-to-firmware mappings (IoT/embedded devices)
2. Kernel-to-distribution mappings (Linux systems)
3. Plausibility rules for validation
"""

import re
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum


class ValidationStatus(Enum):
    """Validation status for OS fingerprints."""
    VALIDATED = "VALIDATED"   # 2+ sources agree AND plausible for device type
    PLAUSIBLE = "PLAUSIBLE"   # Single source but consistent with device/manufacturer
    SUSPECT = "SUSPECT"       # Detection conflicts with device type/manufacturer
    UNKNOWN = "UNKNOWN"       # Insufficient information to validate


# =============================================================================
# WINDOWS BUILD NUMBER MAPPING
# =============================================================================
WINDOWS_BUILD_MAP = {
    "2195": "Windows 2000",
    "2600": "Windows XP",
    "3790": "Windows Server 2003",
    "6000": "Windows Vista",
    "6001": "Windows Vista SP1 / Server 2008",
    "6002": "Windows Vista SP2 / Server 2008 SP2",
    "7600": "Windows 7 / Server 2008 R2",
    "7601": "Windows 7 SP1 / Server 2008 R2 SP1",
    "9200": "Windows 8 / Server 2012",
    "9600": "Windows 8.1 / Server 2012 R2",
    "10240": "Windows 10 (1507)",
    "10586": "Windows 10 (1511)",
    "14393": "Windows 10 (1607) / Server 2016",
    "15063": "Windows 10 (1703)",
    "16299": "Windows 10 (1709)",
    "17134": "Windows 10 (1803)",
    "17763": "Windows 10 (1809) / Server 2019",
    "18362": "Windows 10 (1903)",
    "18363": "Windows 10 (1909)",
    "19041": "Windows 10 (2004)",
    "19042": "Windows 10 (20H2)",
    "19043": "Windows 10 (21H1)",
    "19044": "Windows 10 (21H2)",
    "19045": "Windows 10 (22H2)",
    "20348": "Windows Server 2022",
    "22000": "Windows 11 (21H2)",
    "22621": "Windows 11 (22H2)",
    "22631": "Windows 11 (23H2)",
    "26100": "Windows 11 (24H2)",
}


def resolve_windows_build(build_str: str) -> Optional[str]:
    """Resolve Windows build number to friendly OS name."""
    if not build_str:
        return None
    # Try exact match
    result = WINDOWS_BUILD_MAP.get(build_str)
    if result:
        return result
    # Try numeric comparison for range matching
    try:
        build_num = int(build_str)
        if build_num >= 22000:
            return "Windows 11"
        elif build_num >= 10240:
            return "Windows 10"
        elif build_num >= 9200:
            return "Windows 8.x"
        elif build_num >= 7600:
            return "Windows 7"
        elif build_num >= 6000:
            return "Windows Vista"
        elif build_num >= 2600:
            return "Windows XP"
    except ValueError:
        pass
    return None


# =============================================================================
# macOS VERSION MAP
# =============================================================================
# macOS marketing version -> codename, and Darwin (kernel) major -> macOS
# release. Apple's nmap osmatch names ("Apple macOS 13 (Ventura)", "Apple
# Mac OS X 10.13"), Darwin uname strings, and SMB OS strings carry one of
# these; this lets a Mac report "macOS 14 (Sonoma)" instead of bare "macOS".
MACOS_CODENAMES = {
    "26": "Tahoe", "15": "Sequoia", "14": "Sonoma", "13": "Ventura",
    "12": "Monterey", "11": "Big Sur",
    "10.15": "Catalina", "10.14": "Mojave", "10.13": "High Sierra",
    "10.12": "Sierra", "10.11": "El Capitan", "10.10": "Yosemite",
    "10.9": "Mavericks", "10.8": "Mountain Lion", "10.7": "Lion",
    "10.6": "Snow Leopard", "10.5": "Leopard", "10.4": "Tiger",
    "10.3": "Panther", "10.2": "Jaguar", "10.1": "Puma", "10.0": "Cheetah",
}
# Darwin kernel major -> (macOS marketing version, codename). Complete range
# so a Darwin uname always resolves consistently with MACOS_CODENAMES.
DARWIN_TO_MACOS = {
    25: ("26", "Tahoe"), 24: ("15", "Sequoia"), 23: ("14", "Sonoma"),
    22: ("13", "Ventura"), 21: ("12", "Monterey"), 20: ("11", "Big Sur"),
    19: ("10.15", "Catalina"), 18: ("10.14", "Mojave"),
    17: ("10.13", "High Sierra"), 16: ("10.12", "Sierra"),
    15: ("10.11", "El Capitan"), 14: ("10.10", "Yosemite"),
    13: ("10.9", "Mavericks"), 12: ("10.8", "Mountain Lion"),
    11: ("10.7", "Lion"), 10: ("10.6", "Snow Leopard"),
    9: ("10.5", "Leopard"), 8: ("10.4", "Tiger"),
}


def macos_codename(version: Optional[str]) -> Optional[str]:
    """Return the macOS codename for a marketing version ("14" -> Sonoma,
    "10.15" -> Catalina)."""
    if not version:
        return None
    v = str(version).strip()
    parts = v.split(".")
    for key in (v, ".".join(parts[:2]), parts[0]):
        if key in MACOS_CODENAMES:
            return MACOS_CODENAMES[key]
    return None


def macos_release_from_text(text: Optional[str]) -> Optional[str]:
    """Parse a macOS release string out of an nmap osmatch name, Darwin uname,
    or SMB OS string. Returns e.g. "macOS 14 (Sonoma)" or None."""
    if not text:
        return None
    m = re.search(r"(?:mac\s*os\s*x|macos|os\s*x)\s*(\d+(?:\.\d+){0,2})", text, re.IGNORECASE)
    if m:
        ver = m.group(1)
        cn = macos_codename(ver)
        return f"macOS {ver} ({cn})" if cn else f"macOS {ver}"
    d = re.search(r"darwin\s*(\d+)", text, re.IGNORECASE)
    if d:
        info = DARWIN_TO_MACOS.get(int(d.group(1)))
        if info:
            return f"macOS {info[0]} ({info[1]})"
    return None


# =============================================================================
# VENDOR OS DATABASE
# =============================================================================
# Maps manufacturers to their expected OS/firmware information.
# Used to validate and infer firmware for IoT/embedded devices.
#
# Structure:
#   "Vendor Name": {
#       "os_family": default OS family,
#       "firmware_patterns": [(regex, firmware_name, version_regex), ...],
#       "expected_kernels": [(kernel_prefix, firmware_version), ...],
#       "device_types": [list of expected device types],
#       "aliases": [alternative vendor names],
#   }
# =============================================================================

VENDOR_OS_DATABASE: Dict[str, Dict[str, Any]] = {
    # ----- Network Equipment Vendors -----
    "Ubiquiti": {
        "os_family": "Linux",
        "aliases": ["Ubiquiti Inc", "Ubiquiti Networks", "UBNT"],
        "firmware_patterns": [
            (r"UniFi[\s-]?OS\s*([\d.]+)?", "UniFi OS", r"([\d.]+)"),
            (r"EdgeOS\s*([\d.]+)?", "EdgeOS", r"([\d.]+)"),
            (r"EdgeRouter", "EdgeOS", None),
            (r"EdgeSwitch", "EdgeSwitch OS", None),
            (r"AirOS\s*([\d.]+)?", "AirOS", r"([\d.]+)"),
            (r"AirMax", "AirOS", None),
            (r"UniFi\s*Protect", "UniFi OS", None),
            (r"UniFi\s*Video", "UniFi Video", None),
        ],
        "expected_kernels": [
            ("2.6", "Legacy Firmware"),
            ("3.2", "EdgeOS 1.x / AirOS 5.x"),
            ("3.10", "EdgeOS 1.x / UniFi OS 1.x"),
            ("4.4", "EdgeOS 2.x / UniFi OS 2.x"),
            ("4.9", "UniFi OS 3.x"),
            ("4.14", "EdgeOS 2.x"),
            ("5.4", "UniFi OS 4.x"),
            ("5.10", "UniFi OS 4.x"),
        ],
        "device_types": ["access_point", "router", "switch", "camera", "nvr", "general purpose"],
    },

    "MikroTik": {
        "os_family": "RouterOS",
        "aliases": ["Mikrotikls", "MikroTik Ltd"],
        "firmware_patterns": [
            (r"RouterOS\s*([\d.]+)?", "RouterOS", r"([\d.]+)"),
            (r"SwOS\s*([\d.]+)?", "SwOS", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("3.3", "RouterOS 6.x"),
            ("4.14", "RouterOS 7.x"),
            ("5.6", "RouterOS 7.x"),
        ],
        "device_types": ["router", "switch", "access_point"],
    },

    "Cisco": {
        "os_family": "Cisco IOS",
        "aliases": ["Cisco Systems", "Cisco-Linksys"],
        "firmware_patterns": [
            (r"IOS[\s-]?XE?\s*([\d.]+)?", "Cisco IOS", r"([\d.()]+)"),
            (r"NX-OS\s*([\d.]+)?", "NX-OS", r"([\d.]+)"),
            (r"ASA\s*([\d.]+)?", "Cisco ASA", r"([\d.]+)"),
            (r"Firepower", "Firepower", None),
        ],
        "expected_kernels": [],  # Cisco uses proprietary OS, kernel version not typically exposed
        "device_types": ["router", "switch", "firewall", "access_point"],
        "expected_os_families": ["Cisco IOS", "Linux"],  # Some newer Cisco runs Linux
    },

    "Juniper": {
        "os_family": "JunOS",
        "aliases": ["Juniper Networks"],
        "firmware_patterns": [
            (r"JunOS\s*([\d.]+)?", "JunOS", r"([\d.]+)"),
            (r"Junos\s*([\d.]+)?", "JunOS", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("2.6", "JunOS (FreeBSD-based)"),
            ("3.10", "JunOS Evolved"),
        ],
        "device_types": ["router", "switch", "firewall"],
        "expected_os_families": ["JunOS", "FreeBSD", "Linux"],
    },

    "Fortinet": {
        "os_family": "FortiOS",
        "aliases": ["Fortinet Inc"],
        "firmware_patterns": [
            (r"FortiOS\s*([\d.]+)?", "FortiOS", r"([\d.]+)"),
            (r"FortiGate", "FortiOS", None),
            (r"FortiWiFi", "FortiOS", None),
        ],
        "expected_kernels": [
            ("2.6", "FortiOS 5.x"),
            ("3.2", "FortiOS 6.x"),
            ("4.14", "FortiOS 7.x"),
        ],
        "device_types": ["firewall", "router", "access_point"],
    },

    "Aruba": {
        "os_family": "ArubaOS",
        "aliases": ["Aruba Networks", "HPE Aruba", "Aruba, a Hewlett Packard Enterprise Company"],
        "firmware_patterns": [
            (r"ArubaOS\s*([\d.]+)?", "ArubaOS", r"([\d.]+)"),
            (r"Aruba\s*Instant", "Aruba InstantOS", None),
        ],
        "expected_kernels": [
            ("3.10", "ArubaOS 6.x"),
            ("4.4", "ArubaOS 8.x"),
        ],
        "device_types": ["access_point", "switch", "controller"],
    },

    "Ruckus": {
        "os_family": "Linux",
        "aliases": ["Ruckus Wireless", "Ruckus Networks", "CommScope Ruckus"],
        "firmware_patterns": [
            (r"SmartZone\s*([\d.]+)?", "SmartZone", r"([\d.]+)"),
            (r"ZoneDirector", "ZoneDirector", None),
            (r"Unleashed\s*([\d.]+)?", "Ruckus Unleashed", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("3.14", "Ruckus Firmware"),
            ("4.4", "Ruckus Firmware"),
        ],
        "device_types": ["access_point", "controller"],
    },

    # ----- NAS Vendors -----
    "Synology": {
        "os_family": "Linux",
        "aliases": ["Synology Inc"],
        "firmware_patterns": [
            (r"DSM\s*([\d.]+)?", "DSM", r"([\d.]+)"),
            (r"DiskStation", "DSM", None),
            (r"RackStation", "DSM", None),
            (r"SRM\s*([\d.]+)?", "SRM", r"([\d.]+)"),  # Synology Router Manager
        ],
        "expected_kernels": [
            ("2.6", "DSM 4.x"),
            ("3.2", "DSM 5.x"),
            ("3.10", "DSM 5.x/6.x"),
            ("4.4", "DSM 6.x"),
            ("5.10", "DSM 7.x"),
        ],
        "device_types": ["storage", "nas", "router", "general purpose"],
    },

    "QNAP": {
        "os_family": "Linux",
        "aliases": ["QNAP Systems"],
        "firmware_patterns": [
            (r"QTS\s*([\d.]+)?", "QTS", r"([\d.]+)"),
            (r"QuTS\s*hero\s*([\d.]+)?", "QuTS Hero", r"([\d.]+)"),
            (r"QES\s*([\d.]+)?", "QES", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("3.4", "QTS 4.2.x"),
            ("4.2", "QTS 4.3.x"),
            ("4.14", "QTS 4.4.x/4.5.x"),
            ("5.10", "QTS 5.x"),
        ],
        "device_types": ["storage", "nas", "general purpose"],
    },

    "Western Digital": {
        "os_family": "Linux",
        "aliases": ["WD", "Western Digital Technologies"],
        "firmware_patterns": [
            (r"My\s*Cloud\s*OS\s*([\d.]+)?", "My Cloud OS", r"([\d.]+)"),
            (r"WD\s*My\s*Cloud", "My Cloud OS", None),
        ],
        "expected_kernels": [
            ("3.2", "My Cloud OS 3.x"),
            ("4.14", "My Cloud OS 5.x"),
        ],
        "device_types": ["storage", "nas"],
    },

    "Netgear": {
        "os_family": "Linux",
        "aliases": ["NETGEAR"],
        "firmware_patterns": [
            (r"ReadyNAS\s*OS\s*([\d.]+)?", "ReadyNAS OS", r"([\d.]+)"),
            (r"ReadyNAS", "ReadyNAS OS", None),
        ],
        "expected_kernels": [
            ("3.2", "ReadyNAS OS 6.x"),
            ("4.4", "ReadyNAS OS 6.x"),
        ],
        "device_types": ["storage", "nas", "router", "switch", "access_point"],
    },

    # ----- IoT / Smart Home Vendors -----
    "Raspberry Pi": {
        "os_family": "Linux",
        "aliases": ["Raspberry Pi Foundation", "Raspberry Pi Trading Ltd"],
        "firmware_patterns": [
            (r"Raspbian", "Raspberry Pi OS", None),
            (r"Raspberry\s*Pi\s*OS", "Raspberry Pi OS", None),
        ],
        "expected_kernels": [
            ("4.9", "Raspberry Pi OS (Stretch)"),
            ("4.19", "Raspberry Pi OS (Buster)"),
            ("5.10", "Raspberry Pi OS (Bullseye)"),
            ("5.15", "Raspberry Pi OS (Bullseye)"),
            ("6.1", "Raspberry Pi OS (Bookworm)"),
        ],
        "device_types": ["general purpose", "iot", "embedded"],
    },

    "Espressif": {
        "os_family": "RTOS",
        "aliases": ["Espressif Inc", "Espressif Systems"],
        "firmware_patterns": [
            (r"ESP-IDF\s*([\d.]+)?", "ESP-IDF", r"([\d.]+)"),
            (r"ESP32", "ESP-IDF", None),
            (r"ESP8266", "ESP SDK", None),
        ],
        "expected_kernels": [],  # FreeRTOS based
        "device_types": ["iot", "embedded"],
    },

    "TP-Link": {
        "os_family": "Linux",
        "aliases": ["TP-LINK"],
        "firmware_patterns": [
            (r"Omada", "Omada Controller", None),
            (r"EAP", "TP-Link EAP", None),
        ],
        "expected_kernels": [
            ("2.6", "Legacy TP-Link"),
            ("3.10", "TP-Link Firmware"),
            ("4.4", "TP-Link Firmware"),
        ],
        "device_types": ["router", "access_point", "switch"],
    },

    # ----- Printer Vendors -----
    "HP": {
        "os_family": "Linux",
        "aliases": ["Hewlett-Packard", "Hewlett Packard", "HP Inc"],
        "firmware_patterns": [
            (r"JetDirect", "HP JetDirect", None),
            (r"FutureSmart\s*([\d.]+)?", "HP FutureSmart", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("2.6", "HP Firmware"),
            ("3.10", "HP FutureSmart"),
            ("4.4", "HP FutureSmart"),
        ],
        "device_types": ["printer", "general purpose", "server"],
        "expected_os_families": ["Linux", "Windows"],  # HP makes both printers and servers
    },

    "Canon": {
        "os_family": "Embedded",
        "aliases": ["Canon Inc"],
        "firmware_patterns": [],
        "expected_kernels": [
            ("2.6", "Canon Firmware"),
            ("3.0", "Canon Firmware"),
        ],
        "device_types": ["printer", "camera"],
    },

    "Xerox": {
        "os_family": "Linux",
        "aliases": ["Xerox Corporation"],
        "firmware_patterns": [
            (r"ConnectKey", "Xerox ConnectKey", None),
        ],
        "expected_kernels": [
            ("3.10", "Xerox Firmware"),
            ("4.4", "Xerox Firmware"),
        ],
        "device_types": ["printer"],
    },

    # ----- Security Camera Vendors -----
    "Hikvision": {
        "os_family": "Linux",
        "aliases": ["Hangzhou Hikvision", "HIKVISION"],
        "firmware_patterns": [
            (r"Hikvision", "Hikvision Firmware", None),
        ],
        "expected_kernels": [
            ("3.0", "Hikvision Firmware"),
            ("3.4", "Hikvision Firmware"),
            ("4.9", "Hikvision Firmware"),
        ],
        "device_types": ["camera", "nvr", "dvr"],
    },

    "Dahua": {
        "os_family": "Linux",
        "aliases": ["Dahua Technology", "DAHUA"],
        "firmware_patterns": [
            (r"Dahua", "Dahua Firmware", None),
        ],
        "expected_kernels": [
            ("3.4", "Dahua Firmware"),
            ("4.9", "Dahua Firmware"),
        ],
        "device_types": ["camera", "nvr", "dvr"],
    },

    "Axis": {
        "os_family": "Linux",
        "aliases": ["Axis Communications"],
        "firmware_patterns": [
            (r"AXIS\s*OS\s*([\d.]+)?", "AXIS OS", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("3.4", "AXIS OS"),
            ("4.9", "AXIS OS"),
            ("4.14", "AXIS OS"),
        ],
        "device_types": ["camera"],
    },

    # ----- VMware / Virtualization -----
    "VMware": {
        "os_family": "VMkernel",
        "aliases": ["VMware, Inc"],
        "firmware_patterns": [
            (r"ESXi\s*([\d.]+)?", "VMware ESXi", r"([\d.]+)"),
            (r"vSphere", "VMware vSphere", None),
        ],
        "expected_kernels": [],  # VMkernel is not Linux
        "device_types": ["hypervisor", "server"],
        "expected_os_families": ["VMkernel", "Linux"],
    },

    # ----- Apple -----
    "Apple": {
        "os_family": "macOS",
        "aliases": ["Apple Inc", "Apple, Inc."],
        "firmware_patterns": [
            (r"macOS\s*([\d.]+)?", "macOS", r"([\d.]+)"),
            (r"Mac\s*OS\s*X\s*([\d.]+)?", "macOS", r"([\d.]+)"),
            (r"iPadOS\s*([\d.]+)?", "iPadOS", r"([\d.]+)"),
            (r"iOS\s*([\d.]+)?", "iOS", r"([\d.]+)"),
            (r"tvOS\s*([\d.]+)?", "tvOS", r"([\d.]+)"),
            (r"watchOS\s*([\d.]+)?", "watchOS", r"([\d.]+)"),
            (r"visionOS\s*([\d.]+)?", "visionOS", r"([\d.]+)"),
            (r"audioOS\s*([\d.]+)?", "audioOS", r"([\d.]+)"),
            (r"AirPort", "AirPort Firmware", None),
        ],
        "expected_kernels": [],  # Darwin kernel, version scheme different
        "device_types": ["workstation", "laptop", "phone", "smartphone", "tablet",
                         "media_player", "streaming_device", "smart_speaker",
                         "smartwatch", "wearable", "ar_headset", "access_point"],
        "expected_os_families": ["macOS", "iOS", "iPadOS", "tvOS", "watchOS",
                                "visionOS", "audioOS", "bridgeOS", "Darwin"],
    },

    # =========================================================================
    # EXPANDED VENDORS FROM device-detector PROJECT
    # Source: https://github.com/matomo-org/device-detector
    # =========================================================================

    # ----- Smart TV Vendors -----
    "Samsung": {
        "os_family": "Tizen",
        "aliases": ["Samsung Electronics", "Samsung Electronics Co."],
        "firmware_patterns": [
            (r"Tizen\s*([\d.]+)?", "Tizen", r"([\d.]+)"),
            (r"SmartTV", "Samsung Smart TV", None),
            (r"SMART-TV", "Samsung Smart TV", None),
        ],
        "expected_kernels": [
            ("3.0", "Tizen 2.x"),
            ("3.10", "Tizen 3.x"),
            ("4.4", "Tizen 4.x/5.x"),
            ("4.9", "Tizen 5.x/6.x"),
        ],
        "device_types": ["tv", "phone", "tablet", "camera", "storage", "general purpose"],
        "expected_os_families": ["Tizen", "Android", "Linux"],
    },

    "LG": {
        "os_family": "webOS",
        "aliases": ["LG Electronics", "LG Electronics Inc"],
        "firmware_patterns": [
            (r"webOS\s*([\d.]+)?", "webOS", r"([\d.]+)"),
            (r"Web0S", "webOS", None),
            (r"NetCast", "NetCast", None),
            (r"SMART-TV", "LG Smart TV", None),
        ],
        "expected_kernels": [
            ("3.4", "webOS 1.x/2.x"),
            ("3.10", "webOS 3.x"),
            ("4.4", "webOS 4.x"),
            ("4.9", "webOS 5.x/6.x"),
        ],
        "device_types": ["tv", "phone", "tablet", "general purpose"],
        "expected_os_families": ["webOS", "Android", "Linux"],
    },

    "Sony": {
        "os_family": "Linux",
        "aliases": ["Sony Corporation", "Sony Interactive Entertainment"],
        "firmware_patterns": [
            (r"PlayStation\s*(\d+)", "PlayStation", r"(\d+)"),
            (r"BRAVIA", "Sony BRAVIA", None),
            (r"Android\s*TV", "Android TV", None),
        ],
        "expected_kernels": [
            ("3.10", "Android TV / PlayStation 4"),
            ("4.4", "Android TV"),
            ("4.14", "PlayStation 5"),
        ],
        "device_types": ["tv", "console", "camera", "general purpose"],
        "expected_os_families": ["Linux", "Android", "FreeBSD", "Orbis OS"],
    },

    "Panasonic": {
        "os_family": "Linux",
        "aliases": ["Panasonic Corporation"],
        "firmware_patterns": [
            (r"Viera", "Panasonic Viera", None),
            (r"Firefox\s*OS", "Firefox OS", None),
        ],
        "expected_kernels": [
            ("3.0", "Viera Firmware"),
            ("3.10", "Firefox OS / Viera"),
            ("4.4", "Android TV"),
        ],
        "device_types": ["tv", "camera", "general purpose"],
        "expected_os_families": ["Linux", "Firefox OS", "Android"],
    },

    "Philips": {
        "os_family": "Linux",
        "aliases": ["Philips Electronics", "TP Vision"],
        "firmware_patterns": [
            (r"Saphi", "Saphi OS", None),
            (r"Android\s*TV", "Android TV", None),
        ],
        "expected_kernels": [
            ("3.10", "Saphi / Android TV"),
            ("4.4", "Android TV"),
            ("4.9", "Android TV"),
        ],
        "device_types": ["tv", "iot", "general purpose"],
        "expected_os_families": ["Linux", "Android"],
    },

    "TCL": {
        "os_family": "Linux",
        "aliases": ["TCL Corporation", "TCL Electronics"],
        "firmware_patterns": [
            (r"Roku\s*TV", "Roku TV", None),
            (r"Android\s*TV", "Android TV", None),
            (r"Google\s*TV", "Google TV", None),
        ],
        "expected_kernels": [
            ("3.10", "Roku TV / Android TV"),
            ("4.4", "Android TV"),
            ("4.9", "Android TV / Google TV"),
        ],
        "device_types": ["tv", "phone", "tablet"],
        "expected_os_families": ["Linux", "Android", "Roku OS"],
    },

    "Hisense": {
        "os_family": "Linux",
        "aliases": ["Hisense Electric", "Hisense Co."],
        "firmware_patterns": [
            (r"VIDAA", "VIDAA", None),
            (r"Roku\s*TV", "Roku TV", None),
            (r"Android\s*TV", "Android TV", None),
        ],
        "expected_kernels": [
            ("3.10", "VIDAA / Android TV"),
            ("4.4", "VIDAA / Android TV"),
            ("4.9", "VIDAA U"),
        ],
        "device_types": ["tv", "general purpose"],
        "expected_os_families": ["Linux", "VIDAA", "Android", "Roku OS"],
    },

    "Vizio": {
        "os_family": "Linux",
        "aliases": ["VIZIO Inc", "VIZIO"],
        "firmware_patterns": [
            (r"SmartCast", "SmartCast", None),
            (r"VIZIO", "Vizio Firmware", None),
        ],
        "expected_kernels": [
            ("3.10", "SmartCast"),
            ("4.4", "SmartCast"),
        ],
        "device_types": ["tv"],
        "expected_os_families": ["Linux", "SmartCast OS"],
    },

    "Roku": {
        "os_family": "Linux",
        "aliases": ["Roku, Inc"],
        "firmware_patterns": [
            (r"Roku\s*([\d.]+)?", "Roku OS", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("3.10", "Roku OS"),
            ("4.4", "Roku OS"),
            ("4.9", "Roku OS"),
        ],
        "device_types": ["tv", "media_player"],
        "expected_os_families": ["Linux", "Roku OS"],
    },

    # ----- Gaming Console Vendors -----
    "Microsoft": {
        "os_family": "Windows",
        "aliases": ["Microsoft Corporation"],
        "firmware_patterns": [
            (r"Xbox\s*One", "Xbox One OS", None),
            (r"Xbox\s*Series", "Xbox Series OS", None),
            (r"Xbox\s*360", "Xbox 360 OS", None),
            (r"Windows\s*([\d.]+)", "Windows", r"([\d.]+)"),
        ],
        "expected_kernels": [],  # Windows NT kernel
        "device_types": ["console", "server", "workstation", "general purpose"],
        "expected_os_families": ["Windows", "Xbox OS"],
    },

    "Nintendo": {
        "os_family": "Embedded",
        "aliases": ["Nintendo Co., Ltd"],
        "firmware_patterns": [
            (r"Switch", "Nintendo Switch", None),
            (r"Wii\s*U", "Wii U", None),
            (r"3DS", "Nintendo 3DS", None),
        ],
        "expected_kernels": [
            ("4.4", "Nintendo Switch (Horizon OS)"),
        ],
        "device_types": ["console", "handheld"],
        "expected_os_families": ["Horizon OS", "Embedded"],
    },

    # ----- Additional Printer Vendors -----
    "Brother": {
        "os_family": "Linux",
        "aliases": ["Brother Industries"],
        "firmware_patterns": [
            (r"Brother", "Brother Firmware", None),
        ],
        "expected_kernels": [
            ("2.6", "Brother Firmware"),
            ("3.10", "Brother Firmware"),
            ("4.4", "Brother Firmware"),
        ],
        "device_types": ["printer"],
        "expected_os_families": ["Linux", "Embedded"],
    },

    "Epson": {
        "os_family": "Embedded",
        "aliases": ["Seiko Epson", "Epson Corporation"],
        "firmware_patterns": [
            (r"EPSON", "Epson Firmware", None),
        ],
        "expected_kernels": [
            ("2.6", "Epson Firmware"),
            ("3.10", "Epson Firmware"),
        ],
        "device_types": ["printer"],
        "expected_os_families": ["Linux", "Embedded"],
    },

    "Lexmark": {
        "os_family": "Linux",
        "aliases": ["Lexmark International"],
        "firmware_patterns": [
            (r"Lexmark", "Lexmark Firmware", None),
        ],
        "expected_kernels": [
            ("2.6", "Lexmark Firmware"),
            ("3.10", "Lexmark Firmware"),
            ("4.4", "Lexmark Firmware"),
        ],
        "device_types": ["printer"],
        "expected_os_families": ["Linux"],
    },

    "Ricoh": {
        "os_family": "Linux",
        "aliases": ["Ricoh Company"],
        "firmware_patterns": [
            (r"Ricoh", "Ricoh Firmware", None),
        ],
        "expected_kernels": [
            ("3.10", "Ricoh Firmware"),
            ("4.4", "Ricoh Firmware"),
        ],
        "device_types": ["printer"],
        "expected_os_families": ["Linux"],
    },

    "Konica Minolta": {
        "os_family": "Linux",
        "aliases": ["Konica Minolta, Inc"],
        "firmware_patterns": [
            (r"Konica", "Konica Minolta Firmware", None),
        ],
        "expected_kernels": [
            ("3.10", "Konica Minolta Firmware"),
            ("4.4", "Konica Minolta Firmware"),
        ],
        "device_types": ["printer"],
        "expected_os_families": ["Linux"],
    },

    # ----- Additional NAS Vendors -----
    "Buffalo": {
        "os_family": "Linux",
        "aliases": ["Buffalo Inc", "Buffalo Technology"],
        "firmware_patterns": [
            (r"LinkStation", "LinkStation", None),
            (r"TeraStation", "TeraStation", None),
        ],
        "expected_kernels": [
            ("2.6", "Buffalo Firmware"),
            ("3.10", "Buffalo Firmware"),
            ("4.4", "Buffalo Firmware"),
        ],
        "device_types": ["storage", "nas", "router"],
        "expected_os_families": ["Linux"],
    },

    "Asustor": {
        "os_family": "Linux",
        "aliases": ["ASUSTOR Inc"],
        "firmware_patterns": [
            (r"ADM\s*([\d.]+)?", "ADM", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("3.10", "ADM 2.x/3.x"),
            ("4.4", "ADM 3.x/4.x"),
            ("5.10", "ADM 4.x"),
        ],
        "device_types": ["storage", "nas"],
        "expected_os_families": ["Linux"],
    },

    "Drobo": {
        "os_family": "Linux",
        "aliases": ["Drobo, Inc"],
        "firmware_patterns": [
            (r"Drobo", "Drobo Firmware", None),
        ],
        "expected_kernels": [
            ("2.6", "Drobo Firmware"),
            ("3.10", "Drobo Firmware"),
        ],
        "device_types": ["storage", "nas"],
        "expected_os_families": ["Linux"],
    },

    "TrueNAS": {
        "os_family": "FreeBSD",
        "aliases": ["iXsystems", "FreeNAS"],
        "firmware_patterns": [
            (r"TrueNAS\s*([\d.]+)?", "TrueNAS", r"([\d.]+)"),
            (r"FreeNAS\s*([\d.]+)?", "FreeNAS", r"([\d.]+)"),
        ],
        "expected_kernels": [],  # FreeBSD kernel
        "device_types": ["storage", "nas", "server"],
        "expected_os_families": ["FreeBSD", "Linux"],
    },

    # ----- Additional Network Equipment -----
    "D-Link": {
        "os_family": "Linux",
        "aliases": ["D-Link Corporation", "D-Link Systems"],
        "firmware_patterns": [
            (r"D-Link", "D-Link Firmware", None),
            (r"DIR-", "D-Link Router", None),
        ],
        "expected_kernels": [
            ("2.6", "D-Link Firmware"),
            ("3.10", "D-Link Firmware"),
            ("4.4", "D-Link Firmware"),
        ],
        "device_types": ["router", "switch", "access_point", "camera"],
        "expected_os_families": ["Linux"],
    },

    "Linksys": {
        "os_family": "Linux",
        "aliases": ["Linksys LLC", "Belkin Linksys"],
        "firmware_patterns": [
            (r"Linksys", "Linksys Firmware", None),
            (r"OpenWrt", "OpenWrt", None),
        ],
        "expected_kernels": [
            ("2.6", "Linksys Firmware"),
            ("3.10", "Linksys Firmware"),
            ("4.4", "Linksys Firmware / OpenWrt"),
            ("4.14", "OpenWrt"),
            ("5.4", "OpenWrt"),
        ],
        "device_types": ["router", "switch", "access_point"],
        "expected_os_families": ["Linux"],
    },

    "ASUS": {
        "os_family": "Linux",
        "aliases": ["ASUSTeK Computer", "ASUS Computer"],
        "firmware_patterns": [
            (r"ASUSWRT", "ASUSWRT", None),
            (r"ASUSWRT-Merlin", "ASUSWRT-Merlin", None),
        ],
        "expected_kernels": [
            ("2.6", "ASUSWRT"),
            ("3.10", "ASUSWRT"),
            ("4.4", "ASUSWRT"),
        ],
        "device_types": ["router", "access_point", "workstation", "general purpose"],
        "expected_os_families": ["Linux", "Windows"],
    },

    "Zyxel": {
        "os_family": "Linux",
        "aliases": ["ZyXEL Communications"],
        "firmware_patterns": [
            (r"ZyXEL", "ZyXEL Firmware", None),
            (r"Zyxel", "Zyxel Firmware", None),
        ],
        "expected_kernels": [
            ("2.6", "ZyXEL Firmware"),
            ("3.10", "ZyXEL Firmware"),
            ("4.4", "ZyXEL Firmware"),
        ],
        "device_types": ["router", "switch", "access_point", "firewall"],
        "expected_os_families": ["Linux"],
    },

    "Draytek": {
        "os_family": "Linux",
        "aliases": ["DrayTek Corporation"],
        "firmware_patterns": [
            (r"DrayTek", "DrayTek Firmware", None),
            (r"Vigor", "Vigor Firmware", None),
        ],
        "expected_kernels": [
            ("2.6", "DrayTek Firmware"),
            ("3.10", "DrayTek Firmware"),
            ("4.4", "DrayTek Firmware"),
        ],
        "device_types": ["router", "firewall", "vpn"],
        "expected_os_families": ["Linux"],
    },

    "Sophos": {
        "os_family": "Linux",
        "aliases": ["Sophos Ltd"],
        "firmware_patterns": [
            (r"SFOS\s*([\d.]+)?", "Sophos Firewall OS", r"([\d.]+)"),
            (r"UTM\s*([\d.]+)?", "Sophos UTM", r"([\d.]+)"),
            (r"XG\s*Firewall", "Sophos XG Firewall", None),
        ],
        "expected_kernels": [
            ("3.10", "SFOS"),
            ("4.4", "SFOS"),
            ("4.9", "SFOS"),
        ],
        "device_types": ["firewall", "router"],
        "expected_os_families": ["Linux"],
    },

    "pfSense": {
        "os_family": "FreeBSD",
        "aliases": ["Netgate", "pfSense"],
        "firmware_patterns": [
            (r"pfSense\s*([\d.]+)?", "pfSense", r"([\d.]+)"),
        ],
        "expected_kernels": [],  # FreeBSD kernel
        "device_types": ["firewall", "router"],
        "expected_os_families": ["FreeBSD"],
    },

    "OPNsense": {
        "os_family": "FreeBSD",
        "aliases": ["Deciso", "OPNsense"],
        "firmware_patterns": [
            (r"OPNsense\s*([\d.]+)?", "OPNsense", r"([\d.]+)"),
        ],
        "expected_kernels": [],  # FreeBSD kernel
        "device_types": ["firewall", "router"],
        "expected_os_families": ["FreeBSD"],
    },

    # ----- IoT / Smart Home Vendors -----
    "Amazon": {
        "os_family": "Linux",
        "aliases": ["Amazon.com", "Amazon Technologies"],
        "firmware_patterns": [
            (r"Fire\s*OS\s*([\d.]+)?", "Fire OS", r"([\d.]+)"),
            (r"Fire\s*TV", "Fire TV", None),
            (r"Echo", "Echo (Alexa)", None),
            (r"Kindle", "Kindle", None),
        ],
        "expected_kernels": [
            ("3.10", "Fire OS 5.x"),
            ("4.4", "Fire OS 6.x"),
            ("4.9", "Fire OS 7.x"),
        ],
        "device_types": ["media_player", "tv", "iot", "tablet", "ereader"],
        "expected_os_families": ["Linux", "Fire OS", "Android"],
    },

    "Google": {
        "os_family": "Linux",
        "aliases": ["Google LLC", "Google Inc"],
        "firmware_patterns": [
            (r"Chromecast", "Chromecast", None),
            (r"Google\s*TV", "Google TV", None),
            (r"Android\s*TV", "Android TV", None),
            (r"Google\s*Home", "Google Home", None),
            (r"Nest", "Nest", None),
        ],
        "expected_kernels": [
            ("3.10", "Chromecast / Android TV"),
            ("4.4", "Android TV / Google Home"),
            ("4.9", "Chromecast / Nest"),
        ],
        "device_types": ["media_player", "tv", "iot", "phone", "tablet", "camera"],
        "expected_os_families": ["Linux", "Android", "Chrome OS", "Fuchsia"],
    },

    "Ring": {
        "os_family": "Linux",
        "aliases": ["Ring LLC", "Ring (Amazon)"],
        "firmware_patterns": [
            (r"Ring", "Ring Firmware", None),
        ],
        "expected_kernels": [
            ("4.4", "Ring Firmware"),
            ("4.9", "Ring Firmware"),
        ],
        "device_types": ["camera", "iot"],
        "expected_os_families": ["Linux"],
    },

    "Nest": {
        "os_family": "Linux",
        "aliases": ["Nest Labs", "Google Nest"],
        "firmware_patterns": [
            (r"Nest", "Nest Firmware", None),
        ],
        "expected_kernels": [
            ("3.10", "Nest Firmware"),
            ("4.4", "Nest Firmware"),
            ("4.9", "Nest Firmware"),
        ],
        "device_types": ["iot", "camera", "thermostat"],
        "expected_os_families": ["Linux"],
    },

    "Sonos": {
        "os_family": "Linux",
        "aliases": ["Sonos, Inc"],
        "firmware_patterns": [
            (r"Sonos\s*([\d.]+)?", "Sonos OS", r"([\d.]+)"),
        ],
        "expected_kernels": [
            ("3.10", "Sonos OS"),
            ("4.4", "Sonos OS"),
            ("4.9", "Sonos OS"),
        ],
        "device_types": ["media_player", "iot"],
        "expected_os_families": ["Linux"],
    },

    # ----- Additional Security Camera Vendors -----
    "Amcrest": {
        "os_family": "Linux",
        "aliases": ["Amcrest Technologies"],
        "firmware_patterns": [
            (r"Amcrest", "Amcrest Firmware", None),
        ],
        "expected_kernels": [
            ("3.4", "Amcrest Firmware"),
            ("4.9", "Amcrest Firmware"),
        ],
        "device_types": ["camera", "nvr"],
        "expected_os_families": ["Linux"],
    },

    "Reolink": {
        "os_family": "Linux",
        "aliases": ["Reolink Digital"],
        "firmware_patterns": [
            (r"Reolink", "Reolink Firmware", None),
        ],
        "expected_kernels": [
            ("3.4", "Reolink Firmware"),
            ("4.9", "Reolink Firmware"),
        ],
        "device_types": ["camera", "nvr"],
        "expected_os_families": ["Linux"],
    },

    "Wyze": {
        "os_family": "Linux",
        "aliases": ["Wyze Labs"],
        "firmware_patterns": [
            (r"Wyze", "Wyze Firmware", None),
        ],
        "expected_kernels": [
            ("3.4", "Wyze Firmware"),
            ("4.9", "Wyze Firmware"),
        ],
        "device_types": ["camera", "iot"],
        "expected_os_families": ["Linux"],
    },

    "Eufy": {
        "os_family": "Linux",
        "aliases": ["Eufy (Anker)", "Anker Eufy"],
        "firmware_patterns": [
            (r"Eufy", "Eufy Firmware", None),
        ],
        "expected_kernels": [
            ("4.4", "Eufy Firmware"),
            ("4.9", "Eufy Firmware"),
        ],
        "device_types": ["camera", "iot"],
        "expected_os_families": ["Linux"],
    },

    "Foscam": {
        "os_family": "Linux",
        "aliases": ["Foscam Digital"],
        "firmware_patterns": [
            (r"Foscam", "Foscam Firmware", None),
        ],
        "expected_kernels": [
            ("2.6", "Foscam Firmware"),
            ("3.4", "Foscam Firmware"),
        ],
        "device_types": ["camera"],
        "expected_os_families": ["Linux"],
    },

    "Geovision": {
        "os_family": "Linux",
        "aliases": ["GeoVision Inc"],
        "firmware_patterns": [
            (r"GeoVision", "GeoVision Firmware", None),
        ],
        "expected_kernels": [
            ("3.4", "GeoVision Firmware"),
            ("4.9", "GeoVision Firmware"),
        ],
        "device_types": ["camera", "nvr", "dvr"],
        "expected_os_families": ["Linux", "Windows"],
    },

    "Vivotek": {
        "os_family": "Linux",
        "aliases": ["VIVOTEK Inc"],
        "firmware_patterns": [
            (r"VIVOTEK", "VIVOTEK Firmware", None),
        ],
        "expected_kernels": [
            ("3.4", "VIVOTEK Firmware"),
            ("4.9", "VIVOTEK Firmware"),
        ],
        "device_types": ["camera", "nvr"],
        "expected_os_families": ["Linux"],
    },

    # ----- Industrial / SCADA Vendors -----
    "Siemens": {
        "os_family": "Linux",
        "aliases": ["Siemens AG"],
        "firmware_patterns": [
            (r"SIMATIC", "SIMATIC", None),
            (r"SCALANCE", "SCALANCE", None),
        ],
        "expected_kernels": [
            ("2.6", "SIMATIC Firmware"),
            ("3.10", "SIMATIC Firmware"),
            ("4.4", "SIMATIC Firmware"),
        ],
        "device_types": ["plc", "scada", "switch", "router"],
        "expected_os_families": ["Linux", "Windows", "VxWorks"],
    },

    "Schneider Electric": {
        "os_family": "Linux",
        "aliases": ["Schneider Electric SE"],
        "firmware_patterns": [
            (r"Modicon", "Modicon", None),
        ],
        "expected_kernels": [
            ("2.6", "Schneider Firmware"),
            ("3.10", "Schneider Firmware"),
        ],
        "device_types": ["plc", "scada"],
        "expected_os_families": ["Linux", "VxWorks"],
    },

    "Rockwell Automation": {
        "os_family": "Embedded",
        "aliases": ["Rockwell", "Allen-Bradley"],
        "firmware_patterns": [
            (r"ControlLogix", "ControlLogix", None),
            (r"CompactLogix", "CompactLogix", None),
        ],
        "expected_kernels": [],
        "device_types": ["plc", "scada"],
        "expected_os_families": ["VxWorks", "Embedded"],
    },

    "Honeywell": {
        "os_family": "Linux",
        "aliases": ["Honeywell International"],
        "firmware_patterns": [
            (r"Honeywell", "Honeywell Firmware", None),
        ],
        "expected_kernels": [
            ("2.6", "Honeywell Firmware"),
            ("3.10", "Honeywell Firmware"),
        ],
        "device_types": ["plc", "scada", "iot", "thermostat"],
        "expected_os_families": ["Linux", "VxWorks", "QNX"],
    },

    # ----- Virtualization / Hypervisors -----
    "Proxmox": {
        "os_family": "Linux",
        "aliases": ["Proxmox Server Solutions"],
        "firmware_patterns": [
            (r"Proxmox\s*VE\s*([\d.]+)?", "Proxmox VE", r"([\d.]+)"),
        ],
        "expected_kernels": [
            # Proxmox VE version to kernel mapping (based on Debian base)
            # https://pve.proxmox.com/wiki/Roadmap
            ("4.13", "Proxmox VE 5.0-5.1"),  # Debian 9 Stretch
            ("4.15", "Proxmox VE 5.2-5.4"),  # Debian 9 Stretch
            ("5.0", "Proxmox VE 6.0"),       # Debian 10 Buster
            ("5.3", "Proxmox VE 6.1"),       # Debian 10 Buster
            ("5.4", "Proxmox VE 6.2-6.4"),   # Debian 10 Buster
            ("5.11", "Proxmox VE 7.0"),      # Debian 11 Bullseye
            ("5.13", "Proxmox VE 7.1"),      # Debian 11 Bullseye
            ("5.15", "Proxmox VE 7.2-7.4"),  # Debian 11 Bullseye
            ("5.19", "Proxmox VE 7.4"),      # Debian 11 Bullseye (backport)
            ("6.2", "Proxmox VE 8.0"),       # Debian 12 Bookworm
            ("6.5", "Proxmox VE 8.1"),       # Debian 12 Bookworm
            ("6.8", "Proxmox VE 8.2"),       # Debian 12 Bookworm
            ("6.11", "Proxmox VE 8.3"),      # Debian 12 Bookworm
            # Proxmox VE 9.x will use Debian 13 Trixie (future)
            ("6.12", "Proxmox VE 9.x"),      # Debian 13 Trixie (anticipated)
            ("6.13", "Proxmox VE 9.x"),      # Debian 13 Trixie
        ],
        "device_types": ["hypervisor", "server"],
        "expected_os_families": ["Linux"],
    },

    "Citrix": {
        "os_family": "Linux",
        "aliases": ["Citrix Systems"],
        "firmware_patterns": [
            (r"XenServer\s*([\d.]+)?", "XenServer", r"([\d.]+)"),
            (r"Citrix\s*Hypervisor", "Citrix Hypervisor", None),
        ],
        "expected_kernels": [
            ("4.4", "XenServer 7.x"),
            ("4.19", "Citrix Hypervisor 8.x"),
        ],
        "device_types": ["hypervisor", "server"],
        "expected_os_families": ["Linux", "Xen"],
    },

    "Nutanix": {
        "os_family": "AOS",
        "aliases": ["Nutanix, Inc", "Nutanix Inc"],
        "firmware_patterns": [
            (r"AHV\s*([\d.]+)?", "Nutanix AHV", r"([\d.]+)"),
            (r"AOS\s*([\d.]+)?", "Nutanix AOS", r"([\d.]+)"),
            (r"Prism", "Nutanix Prism", None),
        ],
        "expected_kernels": [
            ("3.10", "AOS 5.x"),
            ("4.4", "AHV / AOS"),
            ("4.14", "AOS 6.x"),
        ],
        "device_types": ["hypervisor", "server"],
        "expected_os_families": ["Linux"],
    },

    # ----- VoIP / Telephony -----
    "Cisco Meraki": {
        "os_family": "Linux",
        "aliases": ["Meraki", "Cisco Meraki"],
        "firmware_patterns": [
            (r"Meraki\s*MR", "Meraki MR", None),
            (r"Meraki\s*MS", "Meraki MS", None),
            (r"Meraki\s*MX", "Meraki MX", None),
        ],
        "expected_kernels": [
            ("3.10", "Meraki Firmware"),
            ("4.4", "Meraki Firmware"),
            ("4.9", "Meraki Firmware"),
        ],
        "device_types": ["access_point", "switch", "firewall", "camera"],
        "expected_os_families": ["Linux"],
    },

    "Polycom": {
        "os_family": "Linux",
        "aliases": ["Poly", "Polycom Inc"],
        "firmware_patterns": [
            (r"Polycom", "Polycom Firmware", None),
        ],
        "expected_kernels": [
            ("2.6", "Polycom Firmware"),
            ("3.10", "Polycom Firmware"),
            ("4.4", "Polycom Firmware"),
        ],
        "device_types": ["phone", "voip", "video_conferencing"],
        "expected_os_families": ["Linux"],
    },

    "Yealink": {
        "os_family": "Linux",
        "aliases": ["Yealink Network Technology"],
        "firmware_patterns": [
            (r"Yealink", "Yealink Firmware", None),
        ],
        "expected_kernels": [
            ("3.4", "Yealink Firmware"),
            ("4.4", "Yealink Firmware"),
        ],
        "device_types": ["phone", "voip"],
        "expected_os_families": ["Linux"],
    },

    "Grandstream": {
        "os_family": "Linux",
        "aliases": ["Grandstream Networks"],
        "firmware_patterns": [
            (r"Grandstream", "Grandstream Firmware", None),
        ],
        "expected_kernels": [
            ("2.6", "Grandstream Firmware"),
            ("3.10", "Grandstream Firmware"),
            ("4.4", "Grandstream Firmware"),
        ],
        "device_types": ["phone", "voip", "access_point"],
        "expected_os_families": ["Linux"],
    },

    "Avaya": {
        "os_family": "Linux",
        "aliases": ["Avaya Inc"],
        "firmware_patterns": [
            (r"Avaya", "Avaya Firmware", None),
        ],
        "expected_kernels": [
            ("2.6", "Avaya Firmware"),
            ("3.10", "Avaya Firmware"),
        ],
        "device_types": ["phone", "voip", "switch"],
        "expected_os_families": ["Linux", "Windows"],
    },

    # ----- Wireless / Mobile Infrastructure -----
    "Cambium": {
        "os_family": "Linux",
        "aliases": ["Cambium Networks"],
        "firmware_patterns": [
            (r"cnPilot", "cnPilot", None),
            (r"cnMatrix", "cnMatrix", None),
            (r"ePMP", "ePMP", None),
            (r"PMP", "PMP", None),
        ],
        "expected_kernels": [
            ("3.10", "Legacy"),
            ("4.4", "Cambium Firmware"),
            ("4.14", "Current"),
        ],
        "device_types": ["access_point", "router", "switch"],
        "expected_os_families": ["Linux"],
    },

    "Mimosa": {
        "os_family": "Linux",
        "aliases": ["Mimosa Networks"],
        "firmware_patterns": [
            (r"Mimosa", "Mimosa Firmware", None),
        ],
        "expected_kernels": [
            ("4.4", "Mimosa Firmware"),
            ("4.9", "Mimosa Firmware"),
        ],
        "device_types": ["access_point", "router"],
        "expected_os_families": ["Linux"],
    },

    # ----- Additional Network Equipment -----
    "Arista": {
        "os_family": "EOS",
        "aliases": ["Arista Networks"],
        "firmware_patterns": [
            (r"EOS\s*([\d.]+)?", "Arista EOS", r"([\d.]+)"),
            (r"CloudEOS", "CloudEOS", None),
        ],
        "expected_kernels": [("3.18", "EOS 4.x"), ("4.9", "EOS 4.2x+"), ("5.4", "EOS 4.3x+")],
        "device_types": ["switch", "router"],
    },

    "Calix": {
        "os_family": "Linux",
        "aliases": ["Calix Inc"],
        "firmware_patterns": [(r"AXOS\s*([\d.]+)?", "AXOS", r"([\d.]+)")],
        "expected_kernels": [("4.4", "AXOS"), ("4.14", "AXOS")],
        "device_types": ["router", "switch"],
    },

    "Adtran": {
        "os_family": "Linux",
        "aliases": ["ADTRAN"],
        "firmware_patterns": [(r"AOS\s*([\d.]+)?", "AOS", r"([\d.]+)")],
        "expected_kernels": [("3.10", "AOS"), ("4.4", "AOS")],
        "device_types": ["router", "switch"],
    },

    # ----- IoT/Smart Home -----
    "Shelly": {
        "os_family": "RTOS",
        "aliases": ["Allterco", "Shelly Group"],
        "firmware_patterns": [(r"Shelly[\s-]?([\d.]+)?", "Shelly OS", r"([\d.]+)")],
        "expected_kernels": [],
        "device_types": ["smart_plug", "smart_lighting", "iot"],
    },

    "Tuya": {
        "os_family": "RTOS",
        "aliases": ["Tuya Inc", "Tuya Smart"],
        "firmware_patterns": [(r"Tuya\s*([\d.]+)?", "Tuya OS", r"([\d.]+)")],
        "expected_kernels": [],
        "device_types": ["smart_plug", "smart_lighting", "iot", "camera"],
    },

    "Tasmota": {
        "os_family": "RTOS",
        "aliases": [],
        "firmware_patterns": [(r"Tasmota\s*([\d.]+)?", "Tasmota", r"([\d.]+)")],
        "expected_kernels": [],
        "device_types": ["smart_plug", "smart_lighting", "iot"],
    },

    # ----- Enterprise Storage -----
    "NetApp": {
        "os_family": "ONTAP",
        "aliases": ["NetApp Inc"],
        "firmware_patterns": [
            (r"ONTAP\s*([\d.]+)?", "ONTAP", r"([\d.]+)"),
            (r"Data ONTAP\s*([\d.]+)?", "Data ONTAP", r"([\d.]+)"),
        ],
        "expected_kernels": [],
        "device_types": ["nas", "san", "storage_array"],
    },

    "Pure Storage": {
        "os_family": "Purity",
        "aliases": ["Pure Storage Inc"],
        "firmware_patterns": [(r"Purity\s*([\d.]+)?", "Purity", r"([\d.]+)")],
        "expected_kernels": [],
        "device_types": ["storage_array", "san"],
    },

    # --- Server / out-of-band management (BMC) vendors ---
    # iDRAC / iLO / IMM / IPMI controllers run embedded Linux; the host servers
    # run Windows, Linux, or ESXi. Without these, BMC/server hosts skipped
    # vendor plausibility + firmware inference entirely.
    "Dell": {
        "os_family": "Linux",
        "aliases": ["Dell Inc", "Dell Inc.", "Dell EMC", "Dell Technologies", "iDRAC"],
        "firmware_patterns": [
            (r"iDRAC\s*([\d.]+)?", "Dell iDRAC", r"([\d.]+)"),
            (r"PowerEdge", "Dell PowerEdge", None),
        ],
        "expected_kernels": [],
        "device_types": ["server", "bmc", "workstation", "laptop", "switch"],
        "expected_os_families": ["Linux", "Windows", "VMkernel", "Embedded"],
    },
    "HPE": {
        "os_family": "Linux",
        "aliases": ["Hewlett Packard Enterprise", "HP Enterprise", "HPE", "iLO",
                    "Integrated Lights-Out"],
        "firmware_patterns": [
            (r"iLO\s*([\d]+)?", "HPE iLO", r"([\d.]+)"),
            (r"ProLiant", "HPE ProLiant", None),
        ],
        "expected_kernels": [],
        "device_types": ["server", "bmc"],
        "expected_os_families": ["Linux", "Windows", "VMkernel", "Embedded"],
    },
    "Lenovo": {
        "os_family": "Linux",
        "aliases": ["Lenovo Group", "IBM", "XClarity", "ThinkSystem"],
        "firmware_patterns": [
            (r"XClarity|IMM2?", "Lenovo XClarity/IMM", None),
            (r"ThinkSystem|ThinkServer", "Lenovo ThinkSystem", None),
        ],
        "expected_kernels": [],
        "device_types": ["server", "bmc", "workstation", "laptop"],
        "expected_os_families": ["Linux", "Windows", "VMkernel", "Embedded"],
    },
    "Supermicro": {
        "os_family": "Linux",
        "aliases": ["Super Micro Computer", "Supermicro Computer"],
        "firmware_patterns": [(r"IPMI|BMC|ASPEED", "Supermicro BMC/IPMI", None)],
        "expected_kernels": [],
        "device_types": ["server", "bmc"],
        "expected_os_families": ["Linux", "Windows", "VMkernel", "Embedded"],
    },

    # --- Enterprise firewall / security appliance vendors ---
    "Palo Alto Networks": {
        "os_family": "PAN-OS",
        "aliases": ["Palo Alto", "PaloAlto"],
        "firmware_patterns": [(r"PAN-?OS\s*([\d.]+)?", "PAN-OS", r"([\d.]+)")],
        "expected_kernels": [],
        "device_types": ["firewall"],
        "expected_os_families": ["PAN-OS", "Linux"],
    },
    "Check Point": {
        "os_family": "Gaia",
        "aliases": ["CheckPoint", "Check Point Software"],
        "firmware_patterns": [(r"Gaia|GAiA|SecurePlatform", "Check Point Gaia", None)],
        "expected_kernels": [],
        "device_types": ["firewall"],
        "expected_os_families": ["Gaia", "Linux"],
    },
    "Extreme Networks": {
        "os_family": "EXOS",
        "aliases": ["Extreme", "Enterasys"],
        "firmware_patterns": [(r"EXOS|ExtremeXOS\s*([\d.]+)?", "ExtremeXOS", r"([\d.]+)")],
        "expected_kernels": [],
        "device_types": ["switch", "router", "access_point"],
        "expected_os_families": ["EXOS", "Linux"],
    },

    # --- Building automation / lighting ---
    "Lutron": {
        "os_family": "Linux",
        "aliases": ["Lutron Electronics"],
        "firmware_patterns": [],
        "expected_kernels": [],
        "device_types": ["lighting_controller", "automation", "smart_home"],
        "expected_os_families": ["Linux", "Embedded"],
    },

    # --- Network-managed UPS / power (web + SNMP management cards) ---
    "APC": {
        "os_family": "Embedded",
        "aliases": ["American Power Conversion", "Schneider Electric IT"],
        "firmware_patterns": [(r"AOS\s*([\d.]+)?", "APC AOS", r"([\d.]+)"),
                              (r"Smart-?UPS|Back-?UPS|Symmetra", "APC UPS", None)],
        "expected_kernels": [],
        "device_types": ["ups", "pdu"],
        "expected_os_families": ["Embedded", "Linux", "RTOS"],
    },
    "Eaton": {
        "os_family": "Embedded",
        "aliases": ["Eaton Corporation", "Powerware"],
        "firmware_patterns": [(r"Eaton|Powerware|9PX|5PX", "Eaton UPS", None)],
        "expected_kernels": [],
        "device_types": ["ups", "pdu"],
        "expected_os_families": ["Embedded", "Linux", "RTOS"],
    },
    "CyberPower": {
        "os_family": "Embedded",
        "aliases": ["CyberPower Systems"],
        "firmware_patterns": [(r"CyberPower|PR\d{3,4}|OR\d{3,4}", "CyberPower UPS", None)],
        "expected_kernels": [],
        "device_types": ["ups", "pdu"],
        "expected_os_families": ["Embedded", "Linux", "RTOS"],
    },
    "Vertiv": {
        "os_family": "Embedded",
        "aliases": ["Liebert", "Geist", "Emerson Network Power"],
        "firmware_patterns": [(r"Liebert|Vertiv|Geist|GXT|PSI", "Vertiv UPS/PDU", None)],
        "expected_kernels": [],
        "device_types": ["ups", "pdu"],
        "expected_os_families": ["Embedded", "Linux", "RTOS"],
    },
    "Tripp Lite": {
        "os_family": "Embedded",
        "aliases": ["TrippLite", "Eaton Tripp Lite"],
        "firmware_patterns": [(r"Tripp[- ]?Lite|SMART\d{3,4}", "Tripp Lite UPS", None)],
        "expected_kernels": [],
        "device_types": ["ups", "pdu"],
        "expected_os_families": ["Embedded", "Linux", "RTOS"],
    },

    # --- Solar inverters / energy gateways ---
    "SolarEdge": {
        "os_family": "Linux",
        "aliases": ["SolarEdge Technologies"],
        "firmware_patterns": [(r"SolarEdge", "SolarEdge", None)],
        "expected_kernels": [],
        "device_types": ["solar_inverter", "energy_gateway"],
        "expected_os_families": ["Linux", "Embedded"],
    },
    "Enphase": {
        "os_family": "Linux",
        "aliases": ["Enphase Energy", "Envoy", "IQ Gateway"],
        "firmware_patterns": [(r"Envoy|Enphase|IQ\s*Gateway", "Enphase Envoy", None)],
        "expected_kernels": [],
        "device_types": ["solar_inverter", "energy_gateway"],
        "expected_os_families": ["Linux", "Embedded"],
    },
}


# =============================================================================
# KERNEL TO DISTRIBUTION DATABASE
# =============================================================================
# Maps Linux kernel versions to likely distributions.
# When multiple distros share a kernel version, they're all listed.
#
# Structure:
#   "kernel_version": [
#       ("distro_name", "distro_version", "release_year"),
#       ...
#   ]
# =============================================================================

KERNEL_TO_DISTRO_DATABASE: Dict[str, List[Tuple[str, str, str]]] = {
    # Legacy kernels (2.6.x)
    "2.6.9": [("RHEL", "4", "2005"), ("CentOS", "4", "2005")],
    "2.6.18": [("RHEL", "5", "2007"), ("CentOS", "5", "2007")],
    "2.6.24": [("Ubuntu", "8.04", "2008")],
    "2.6.27": [("Ubuntu", "8.10", "2008")],
    "2.6.28": [("Ubuntu", "9.04", "2009")],
    "2.6.31": [("Ubuntu", "9.10", "2009")],
    "2.6.32": [("RHEL", "6", "2010"), ("CentOS", "6", "2010"), ("Debian", "6", "2011"), ("Ubuntu", "10.04", "2010")],
    "2.6.35": [("Ubuntu", "10.10", "2010")],
    "2.6.38": [("Ubuntu", "11.04", "2011")],

    # 3.x kernels
    "3.0": [("Ubuntu", "11.10", "2011"), ("Debian", "7", "2013")],
    "3.2": [("Ubuntu", "12.04", "2012"), ("Debian", "7", "2013")],
    "3.5": [("Ubuntu", "12.10", "2012")],
    "3.8": [("Ubuntu", "13.04", "2013")],
    "3.10": [("RHEL", "7", "2014"), ("CentOS", "7", "2014")],
    "3.11": [("Ubuntu", "13.10", "2013")],
    "3.13": [("Ubuntu", "14.04", "2014")],
    "3.16": [("Debian", "8", "2015"), ("Ubuntu", "14.10", "2014")],
    "3.19": [("Ubuntu", "15.04", "2015")],

    # 4.x kernels
    "4.0": [("Fedora", "22", "2015")],
    "4.2": [("Ubuntu", "15.10", "2015")],
    "4.4": [("Ubuntu", "16.04", "2016")],
    "4.8": [("Ubuntu", "16.10", "2016")],
    "4.9": [("Debian", "9", "2017")],
    "4.10": [("Ubuntu", "17.04", "2017")],
    "4.13": [("Ubuntu", "17.10", "2017")],
    "4.14": [("Debian", "9", "2017")],  # Long-term support kernel
    "4.15": [("Ubuntu", "18.04", "2018")],
    "4.18": [("RHEL", "8", "2019"), ("CentOS", "8", "2019"), ("Ubuntu", "18.10", "2018")],
    "4.19": [("Debian", "10", "2019")],

    # 5.x kernels
    "5.0": [("Ubuntu", "19.04", "2019")],
    "5.3": [("Ubuntu", "19.10", "2019")],
    "5.4": [("Ubuntu", "20.04", "2020"), ("Debian", "10", "2019")],  # LTS kernel
    "5.8": [("Ubuntu", "20.10", "2020")],
    "5.10": [("Debian", "11", "2021")],  # LTS kernel
    "5.11": [("Ubuntu", "21.04", "2021")],
    "5.13": [("Ubuntu", "21.10", "2021")],
    "5.15": [("Ubuntu", "22.04", "2022")],  # LTS kernel
    "5.19": [("Ubuntu", "22.10", "2022")],

    # 6.x kernels
    "6.0": [("Fedora", "37", "2022")],
    "6.1": [("Debian", "12", "2023")],  # LTS kernel
    "6.2": [("Ubuntu", "23.04", "2023")],
    "6.5": [("Ubuntu", "23.10", "2023")],
    "6.6": [("Debian", "12", "2023")],  # LTS kernel
    "6.8": [("Ubuntu", "24.04", "2024")],
    "6.11": [("Ubuntu", "24.10", "2024")],
}


# =============================================================================
# WINDOWS VERSION DATABASE
# =============================================================================
# Maps Windows build/version strings to friendly names.
# =============================================================================

WINDOWS_VERSION_DATABASE: Dict[str, str] = {
    # NT versions from Nmap
    "5.0": "Windows 2000",
    "5.1": "Windows XP",
    "5.2": "Windows Server 2003 / XP x64",
    "6.0": "Windows Vista / Server 2008",
    "6.1": "Windows 7 / Server 2008 R2",
    "6.2": "Windows 8 / Server 2012",
    "6.3": "Windows 8.1 / Server 2012 R2",
    "10.0": "Windows 10 / 11 / Server 2016+",

    # Build numbers for Windows 10/11 differentiation
    "10.0.10240": "Windows 10 (1507)",
    "10.0.10586": "Windows 10 (1511)",
    "10.0.14393": "Windows 10 (1607) / Server 2016",
    "10.0.15063": "Windows 10 (1703)",
    "10.0.16299": "Windows 10 (1709)",
    "10.0.17134": "Windows 10 (1803)",
    "10.0.17763": "Windows 10 (1809) / Server 2019",
    "10.0.18362": "Windows 10 (1903)",
    "10.0.18363": "Windows 10 (1909)",
    "10.0.19041": "Windows 10 (2004)",
    "10.0.19042": "Windows 10 (20H2)",
    "10.0.19043": "Windows 10 (21H1)",
    "10.0.19044": "Windows 10 (21H2)",
    "10.0.19045": "Windows 10 (22H2)",
    "10.0.20348": "Windows Server 2022",
    "10.0.22000": "Windows 11 (21H2)",
    "10.0.22621": "Windows 11 (22H2)",
    "10.0.22631": "Windows 11 (23H2)",
    "10.0.26100": "Windows 11 (24H2)",
}


# =============================================================================
# PLAUSIBILITY RULES
# =============================================================================
# Defines what OS families are plausible for various device types and manufacturers.
# =============================================================================

# Device types and their plausible OS families
DEVICE_TYPE_OS_RULES: Dict[str, List[str]] = {
    "router": ["Linux", "RouterOS", "Cisco IOS", "JunOS", "FortiOS", "BSD", "FreeBSD", "EXOS", "PAN-OS"],
    "switch": ["Linux", "Cisco IOS", "JunOS", "RouterOS", "ArubaOS", "EXOS", "NX-OS"],
    "firewall": ["Linux", "FortiOS", "Cisco IOS", "BSD", "FreeBSD", "PAN-OS", "Gaia", "JunOS"],
    "access_point": ["Linux", "ArubaOS", "Cisco IOS", "RouterOS"],
    "printer": ["Linux", "Embedded", "Windows"],
    "camera": ["Linux", "Embedded", "RTOS"],
    "nvr": ["Linux", "Windows"],
    "dvr": ["Linux", "Windows"],
    "nas": ["Linux", "FreeBSD"],
    "storage": ["Linux", "FreeBSD", "Windows"],
    "server": ["Linux", "Windows", "FreeBSD", "BSD", "VMkernel"],
    "workstation": ["Linux", "Windows", "macOS"],
    "phone": ["iOS", "Android", "Linux"],
    "tablet": ["iOS", "iPadOS", "Android", "Linux", "Windows"],
    "smartwatch": ["watchOS", "Wear OS", "Tizen", "RTOS", "Embedded"],
    "wearable": ["watchOS", "Wear OS", "RTOS", "Embedded", "Linux"],
    "ar_headset": ["visionOS", "Android", "Linux"],
    "vr_headset": ["visionOS", "Android", "Linux"],
    "iot": ["Linux", "RTOS", "Embedded"],
    "embedded": ["Linux", "RTOS", "Embedded"],
    "general purpose": ["Linux", "Windows", "macOS", "BSD", "FreeBSD"],
    "hypervisor": ["VMkernel", "Linux"],
    # Added: device types emitted by patterns/Huginn that previously had no
    # plausibility rule (so the device-type OS check was skipped for them).
    "ip_camera": ["Linux", "Embedded", "RTOS", "Android"],
    "ptz_camera": ["Linux", "Embedded", "RTOS"],
    "doorbell": ["Linux", "Embedded", "RTOS", "Android"],
    "bmc": ["Linux", "Embedded"],
    "esxi": ["VMkernel"],
    "vcenter": ["Linux", "VMkernel"],
    "controller": ["Linux", "Embedded", "RTOS"],
    "wireless_controller": ["Linux", "ArubaOS", "Cisco IOS"],
    "streaming_device": ["Linux", "Android", "tvOS", "Embedded"],
    "media_server": ["Linux", "Windows", "FreeBSD"],
    "media_player": ["Linux", "Android", "Embedded"],
    "smart_speaker": ["Linux", "Android", "Embedded", "RTOS", "audioOS"],
    "smart_tv": ["Linux", "Android", "tvOS", "Tizen", "webOS"],
    "game_console": ["FreeBSD", "Linux", "Windows"],
    "voip_phone": ["Linux", "Embedded", "Android"],
    "pbx": ["Linux", "FreeBSD", "Embedded"],
    "lighting_controller": ["Linux", "Embedded", "RTOS"],
    "smart_home": ["Linux", "Embedded", "RTOS"],
    "home_hub": ["Linux", "Embedded", "RTOS"],
    "smartphone": ["iOS", "Android"],
    "mobile": ["iOS", "Android", "Linux"],
    "plc": ["RTOS", "Embedded", "Linux"],
    "smart_plug": ["Embedded", "RTOS", "Linux"],
    "smart_lighting": ["Embedded", "RTOS", "Linux"],
    "thermostat": ["Embedded", "RTOS", "Linux"],
    "ups": ["Embedded", "RTOS", "Linux"],
    "pdu": ["Embedded", "RTOS", "Linux"],
    "solar_inverter": ["Linux", "Embedded", "RTOS"],
    "energy_gateway": ["Linux", "Embedded", "RTOS"],
    "ev_charger": ["Linux", "Embedded", "RTOS", "Android"],
    "garage_door": ["Embedded", "RTOS", "Linux"],
    "building_automation": ["Embedded", "Linux", "RTOS", "QNX"],
    "av_controller": ["Embedded", "Linux", "RTOS"],
    # ICS / SCADA / OT device types
    "hmi": ["Windows", "Linux", "Embedded", "RTOS", "WinCE"],
    "rtu": ["Embedded", "RTOS", "Linux", "VxWorks", "QNX"],
    "scada_server": ["Windows", "Linux"],
    "dcs": ["Windows", "Linux", "Embedded", "VxWorks", "QNX"],
    "ied": ["Embedded", "RTOS", "Linux", "VxWorks"],
    "industrial_switch": ["Linux", "Embedded", "Cisco IOS", "RTOS"],
    "industrial_router": ["Linux", "Embedded", "RouterOS", "Cisco IOS", "RTOS"],
    "thermal_camera": ["Linux", "Embedded", "RTOS"],
    "webcam": ["Linux", "Embedded", "Windows"],
    "conference_camera": ["Linux", "Embedded", "Android"],
}


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def normalize_vendor_name(vendor: str) -> Optional[str]:
    """
    Normalize vendor name to match database keys.

    Args:
        vendor: Raw vendor name from OUI or other source

    Returns:
        Normalized vendor name or None if not found
    """
    if not vendor:
        return None

    vendor_lower = vendor.lower()

    # Pass 1: EXACT match on vendor name or alias, across ALL vendors first.
    # Exact must win over any partial -- otherwise an early vendor's loose
    # alias substring (e.g. Aruba's "HPE Aruba" contains "hp"/"hpe") shadows a
    # later vendor's exact key, which mis-mapped "HP"/"HPE" -> Aruba.
    for db_vendor, info in VENDOR_OS_DATABASE.items():
        if db_vendor.lower() == vendor_lower:
            return db_vendor
        for alias in info.get("aliases", []):
            if alias.lower() == vendor_lower:
                return db_vendor

    # Pass 2: partial alias match (only after no exact match anywhere). Require
    # the overlapping token to be >= 4 chars to avoid 2-3 char false hits.
    for db_vendor, info in VENDOR_OS_DATABASE.items():
        for alias in info.get("aliases", []):
            a = alias.lower()
            if len(a) >= 4 and (a in vendor_lower or vendor_lower in a):
                return db_vendor

    # Pass 3: partial match on the main vendor name.
    for db_vendor in VENDOR_OS_DATABASE:
        d = db_vendor.lower()
        if len(d) >= 4 and (d in vendor_lower or vendor_lower in d):
            return db_vendor

    return None


def parse_kernel_version(kernel_str: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Parse a kernel version string, handling ranges like "3.2 - 4.14".

    Args:
        kernel_str: Kernel version string (e.g., "3.2 - 4.14" or "5.15")

    Returns:
        Tuple of (min_version, max_version) or (version, None) for single versions
    """
    if not kernel_str:
        return None, None

    # Handle range format "X.Y - X.Y"
    range_match = re.match(r'(\d+\.\d+)\s*-\s*(\d+\.\d+)', kernel_str)
    if range_match:
        return range_match.group(1), range_match.group(2)

    # Handle single version
    single_match = re.match(r'(\d+\.\d+)', kernel_str)
    if single_match:
        return single_match.group(1), None

    return None, None


def get_kernel_major_minor(version: str) -> Tuple[int, int]:
    """Extract major and minor version numbers from kernel string."""
    parts = version.split('.')
    major = int(parts[0]) if len(parts) > 0 else 0
    minor = int(parts[1]) if len(parts) > 1 else 0
    return major, minor


def kernel_version_in_range(version: str, min_ver: str, max_ver: Optional[str]) -> bool:
    """Check if a kernel version falls within a range."""
    try:
        v_major, v_minor = get_kernel_major_minor(version)
        min_major, min_minor = get_kernel_major_minor(min_ver)

        if max_ver:
            max_major, max_minor = get_kernel_major_minor(max_ver)
            return (min_major, min_minor) <= (v_major, v_minor) <= (max_major, max_minor)
        else:
            # Single version - check if it matches the major.minor
            return (v_major, v_minor) == (min_major, min_minor)
    except (ValueError, IndexError):
        return False


def infer_os_from_kernel(kernel_version: str) -> Optional[List[Dict[str, str]]]:
    """
    Map a kernel version to likely Linux distributions.

    Args:
        kernel_version: Kernel version string (e.g., "5.15" or "3.2 - 4.14")

    Returns:
        List of possible distros: [{"distro": "Ubuntu", "version": "22.04", "release": "2022"}, ...]
    """
    if not kernel_version:
        return None

    min_ver, max_ver = parse_kernel_version(kernel_version)
    if not min_ver:
        return None

    results = []

    # If it's a range, find all distros that could match any kernel in the range
    if max_ver:
        for db_kernel, distros in KERNEL_TO_DISTRO_DATABASE.items():
            if kernel_version_in_range(db_kernel, min_ver, max_ver):
                for distro, version, release in distros:
                    results.append({
                        "distro": distro,
                        "version": version,
                        "release": release,
                        "kernel": db_kernel,
                    })
    else:
        # Single version - find exact or closest match
        if min_ver in KERNEL_TO_DISTRO_DATABASE:
            for distro, version, release in KERNEL_TO_DISTRO_DATABASE[min_ver]:
                results.append({
                    "distro": distro,
                    "version": version,
                    "release": release,
                    "kernel": min_ver,
                })
        else:
            # Find closest kernel version
            kernel_keys = sorted(KERNEL_TO_DISTRO_DATABASE.keys(),
                               key=lambda k: get_kernel_major_minor(k))
            for db_kernel in kernel_keys:
                if db_kernel.startswith(min_ver.split('.')[0] + '.'):
                    db_major, db_minor = get_kernel_major_minor(db_kernel)
                    v_major, v_minor = get_kernel_major_minor(min_ver)
                    if abs(db_minor - v_minor) <= 2:  # Within 2 minor versions
                        for distro, version, release in KERNEL_TO_DISTRO_DATABASE[db_kernel]:
                            results.append({
                                "distro": distro,
                                "version": version,
                                "release": release,
                                "kernel": db_kernel,
                                "approximate": True,
                            })

    # Fuzzy match: try nearby minor versions (+-2) across all major versions
    if not results and min_ver:
        try:
            parts = min_ver.split(".")
            if len(parts) >= 2:
                major = int(parts[0])
                minor = int(parts[1])
                for offset in [-1, 1, -2, 2]:
                    fuzzy_version = f"{major}.{minor + offset}"
                    if fuzzy_version in KERNEL_TO_DISTRO_DATABASE:
                        for distro, version, release in KERNEL_TO_DISTRO_DATABASE[fuzzy_version]:
                            results.append({
                                "distro": distro,
                                "version": version,
                                "release": release,
                                "kernel": fuzzy_version,
                                "approximate": True,
                                "original_kernel": min_ver,
                                "matched_kernel": fuzzy_version,
                            })
                        if results:
                            break
        except (ValueError, IndexError):
            pass

    # Remove duplicates and sort by release year (newest first)
    seen = set()
    unique_results = []
    for r in results:
        key = (r["distro"], r["version"])
        if key not in seen:
            seen.add(key)
            unique_results.append(r)

    unique_results.sort(key=lambda x: x.get("release", "0"), reverse=True)
    return unique_results if unique_results else None


def infer_firmware_from_manufacturer(
    manufacturer: str,
    device_type: str,
    kernel_version: Optional[str],
    banners: Optional[List[str]] = None,
    os_family: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Infer specific firmware for IoT/embedded devices based on manufacturer.

    Args:
        manufacturer: Device manufacturer (e.g., "Ubiquiti")
        device_type: Device type (e.g., "access_point")
        kernel_version: Kernel version if known
        banners: Service banners from the device
        os_family: Detected OS family (e.g., "Windows", "Linux")

    Returns:
        {"firmware_name": "UniFi OS", "version": "3.x", "confidence": 0.85} or None
    """
    normalized = normalize_vendor_name(manufacturer)
    if not normalized or normalized not in VENDOR_OS_DATABASE:
        return None

    # Skip firmware inference for standard desktop operating systems
    # These manufacturers make both embedded devices AND regular computers
    # Don't infer firmware when running Windows, macOS, or clearly desktop OSes
    DESKTOP_OS_FAMILIES = {"windows", "macos", "mac os x", "os x"}
    MIXED_MANUFACTURERS = {"ASUS", "HP", "Dell", "Lenovo", "Acer", "Samsung", "LG", "Intel", "Microsoft"}

    # Always skip firmware inference for Windows/macOS regardless of manufacturer
    if os_family:
        os_family_lower = os_family.lower()
        if os_family_lower in DESKTOP_OS_FAMILIES or "windows" in os_family_lower:
            return None

    if os_family and normalized in MIXED_MANUFACTURERS:
        os_family_lower = os_family.lower()
        if os_family_lower in DESKTOP_OS_FAMILIES:
            return None
        if "windows" in os_family_lower:
            return None

    vendor_info = VENDOR_OS_DATABASE[normalized]
    result = {
        "firmware_name": None,
        "version": None,
        "confidence": 0.5,
        "manufacturer": normalized,
    }

    # Try to match firmware from banners
    if banners:
        banner_text = " ".join(banners)
        for pattern, fw_name, version_regex in vendor_info.get("firmware_patterns", []):
            match = re.search(pattern, banner_text, re.IGNORECASE)
            if match:
                result["firmware_name"] = fw_name
                result["confidence"] = 0.90

                # Try to extract version
                if version_regex and match.lastindex:
                    try:
                        version_match = re.search(version_regex, banner_text)
                        if version_match:
                            result["version"] = version_match.group(1)
                    except (IndexError, AttributeError):
                        pass

                return result

    # Infer from kernel version
    # When there's a kernel range (e.g., "4.15 - 5.19"), find all matching versions
    # and pick the HIGHEST/most recent one for the most accurate inference
    if kernel_version:
        min_ver, max_ver = parse_kernel_version(kernel_version)
        if min_ver:
            matching_versions = []
            for expected_kernel, fw_version in vendor_info.get("expected_kernels", []):
                if max_ver:
                    # Kernel range - find all kernels within the range
                    if kernel_version_in_range(expected_kernel, min_ver, max_ver):
                        matching_versions.append((expected_kernel, fw_version))
                elif min_ver.startswith(expected_kernel) or expected_kernel.startswith(min_ver):
                    # Exact/prefix match
                    result["firmware_name"] = f"{normalized} Firmware"
                    result["version"] = fw_version
                    result["confidence"] = 0.75
                    return result

            # If we found matches in a range, pick the highest kernel version
            # (most recent firmware for the detected range)
            if matching_versions:
                # Sort by kernel version descending and pick the highest
                matching_versions.sort(key=lambda x: get_kernel_major_minor(x[0]), reverse=True)
                best_kernel, best_fw_version = matching_versions[0]
                result["firmware_name"] = f"{normalized} Firmware"
                result["version"] = best_fw_version
                result["confidence"] = 0.70
                return result

    # Fallback: Generic firmware name based on vendor
    if normalized:
        result["firmware_name"] = f"{normalized} Firmware"
        result["confidence"] = 0.50
        return result

    return None


def check_os_plausibility(
    detected_os_family: Optional[str],
    manufacturer: Optional[str],
    device_type: str,
    kernel_version: Optional[str] = None
) -> Tuple[bool, str, float]:
    """
    Check if an OS detection is plausible for the given device.

    Args:
        detected_os_family: Detected OS family (e.g., "Linux", "Windows")
        manufacturer: Device manufacturer
        device_type: Device type (e.g., "router", "printer")
        kernel_version: Kernel version if available

    Returns:
        Tuple of (is_plausible, reason, plausibility_score)
    """
    if not detected_os_family:
        return True, "No OS family to validate", 0.5

    normalized_os = detected_os_family.lower()
    plausibility_score = 0.5

    # "embedded" / "embedded linux" is a generic, non-committal OS family that
    # network appliances, IoT gear, and BMCs all legitimately report. It is
    # never a *conflicting* signal, so it must not fail vendor/device
    # plausibility -- doing so falsely marked UniFi controllers and APs SUSPECT
    # (nmap reports "embedded" while Ubiquiti's expected-family list says
    # "Linux"). Specific conflicts (Windows on a switch, Cisco IOS on a
    # non-Cisco device) are still caught below for concrete OS families.
    if normalized_os in ("embedded", "embedded linux", "linux/embedded", "rtos"):
        return True, f"Generic OS family '{detected_os_family}' is plausible for any device", 0.6

    # Check against device type rules
    device_type_lower = device_type.lower() if device_type else "unknown"
    allowed_os_families = DEVICE_TYPE_OS_RULES.get(device_type_lower, [])

    if allowed_os_families:
        os_matches = any(
            allowed.lower() in normalized_os or normalized_os in allowed.lower()
            for allowed in allowed_os_families
        )
        if not os_matches:
            return False, f"OS '{detected_os_family}' unusual for device type '{device_type}'", 0.3
        plausibility_score = 0.7

    # Check against manufacturer expectations
    if manufacturer:
        normalized_vendor = normalize_vendor_name(manufacturer)
        if normalized_vendor and normalized_vendor in VENDOR_OS_DATABASE:
            vendor_info = VENDOR_OS_DATABASE[normalized_vendor]
            expected_os = vendor_info.get("os_family", "").lower()
            expected_families = vendor_info.get("expected_os_families", [expected_os])
            expected_families = [f.lower() for f in expected_families if f]

            if expected_families:
                os_matches_vendor = any(
                    exp in normalized_os or normalized_os in exp
                    for exp in expected_families
                )
                if not os_matches_vendor:
                    return False, f"OS '{detected_os_family}' unexpected for {normalized_vendor} device", 0.25
                plausibility_score = 0.85

            # Validate kernel version against manufacturer expectations
            if kernel_version:
                expected_kernels = vendor_info.get("expected_kernels", [])
                if expected_kernels:
                    min_ver, max_ver = parse_kernel_version(kernel_version)
                    if min_ver:
                        kernel_matches = False
                        for exp_kernel, _ in expected_kernels:
                            if max_ver:
                                if kernel_version_in_range(exp_kernel, min_ver, max_ver):
                                    kernel_matches = True
                                    break
                            elif min_ver.startswith(exp_kernel) or exp_kernel.startswith(min_ver.split('.')[0]):
                                kernel_matches = True
                                break

                        if kernel_matches:
                            plausibility_score = min(1.0, plausibility_score + 0.1)

    # Special case: Windows on network equipment is almost always wrong
    if "windows" in normalized_os and device_type_lower in ["router", "switch", "access_point", "firewall"]:
        return False, f"Windows detection highly improbable for {device_type}", 0.1

    # Special case: Cisco IOS on non-Cisco devices
    if "cisco" in normalized_os and manufacturer:
        normalized_vendor = normalize_vendor_name(manufacturer)
        if normalized_vendor and normalized_vendor.lower() != "cisco":
            return False, f"Cisco IOS detection on non-Cisco device ({manufacturer})", 0.2

    return True, "OS detection is plausible", plausibility_score


def get_inferred_os_display(
    inferred_distros: Optional[List[Dict[str, str]]],
    inferred_firmware: Optional[Dict[str, Any]],
    max_distros: int = 3
) -> Optional[str]:
    """
    Generate a display string for the inferred OS.

    Args:
        inferred_distros: List of inferred distributions
        inferred_firmware: Inferred firmware info
        max_distros: Maximum number of distros to show

    Returns:
        Display string like "Ubuntu 22.04 / Debian 11" or "UniFi OS 3.x"
    """
    # Prefer firmware for IoT devices
    if inferred_firmware and inferred_firmware.get("firmware_name"):
        fw_name = inferred_firmware["firmware_name"]
        fw_version = inferred_firmware.get("version", "")
        if fw_version:
            return f"{fw_name} ({fw_version})"
        return fw_name

    # Fall back to distro list
    if inferred_distros:
        distro_strs = []
        for d in inferred_distros[:max_distros]:
            distro_strs.append(f"{d['distro']} {d['version']}")
        return " / ".join(distro_strs)

    return None
