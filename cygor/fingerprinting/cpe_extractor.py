"""
CPE (Common Platform Enumeration) parsing for fingerprint evidence.

Nmap emits one or more CPE strings per service when ``-sV`` (and per host
when ``-O``) is used. CPEs are the most-precise identifier nmap produces:

    cpe:/o:microsoft:windows_server_2019:standard
    cpe:/o:linux:linux_kernel:5.4.0
    cpe:/o:vmware:esxi:6.7.0
    cpe:/a:apache:http_server:2.4.41
    cpe:/h:cisco:catalyst_2960

The orchestrator wasn't reading them at all — leaving the most reliable
OS / vendor / version source on the table. This module extracts every
CPE attached to every service on a host and yields high-confidence
``FingerprintMatch`` evidence rows.

CPE format (CPE 2.2 URI form, which is what nmap emits):

    cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<lang>

Where ``<part>`` is one of:
  - ``o`` = operating system
  - ``a`` = application
  - ``h`` = hardware

Only the OS-part CPEs contribute to ``os_family / os_vendor / os_version``;
hardware-part CPEs contribute to manufacturer/model; application CPEs are
not used for OS identification but are recorded in ``raw_data`` for audit.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


# CPE 2.2 URI form: cpe:/<part>:<vendor>:<product>:<version>:<update>:...
_CPE_RE = re.compile(
    r"^cpe:/([aoh])"           # part
    r":([^:]*)"                # vendor
    r"(?::([^:]*))?"           # product
    r"(?::([^:]*))?"           # version
    r"(?::([^:]*))?"           # update
    r"(?::([^:]*))?"           # edition
    r"(?::([^:]*))?"           # language
    r"$",
    re.IGNORECASE,
)


@dataclass
class ParsedCPE:
    """A CPE 2.2 URI parsed into its components."""
    raw: str
    part: str            # 'a' | 'o' | 'h'
    vendor: str
    product: str = ""
    version: str = ""
    update: str = ""
    edition: str = ""
    language: str = ""

    @property
    def is_os(self) -> bool:
        return self.part == "o"

    @property
    def is_hardware(self) -> bool:
        return self.part == "h"


def parse_cpe(cpe_str: str) -> Optional[ParsedCPE]:
    """
    Parse a CPE 2.2 URI string. Returns None when the string doesn't match
    the canonical form — caller should fall back to other extractors.

    Quietly tolerates trailing components being absent.
    """
    if not cpe_str or not isinstance(cpe_str, str):
        return None
    m = _CPE_RE.match(cpe_str.strip())
    if not m:
        return None
    part, vendor, product, version, update, edition, language = m.groups()
    return ParsedCPE(
        raw=cpe_str.strip(),
        part=(part or "").lower(),
        vendor=(vendor or "").lower(),
        product=(product or "").lower(),
        version=(version or ""),
        update=(update or ""),
        edition=(edition or ""),
        language=(language or ""),
    )


# Vendor → display name normalization. CPE encodes vendor in lowercase
# underscore-separated form ("microsoft", "red_hat", "vmware") — the cygor
# UI surfaces the prettier form.
_VENDOR_DISPLAY: Dict[str, str] = {
    "microsoft": "Microsoft",
    "red_hat":   "Red Hat",
    "redhat":    "Red Hat",
    "canonical": "Canonical",
    "debian":    "Debian",
    "centos":    "CentOS",
    "fedora":    "Fedora",
    "oracle":    "Oracle",
    "suse":      "SUSE",
    "vmware":    "VMware",
    "linux":     None,             # generic; not a real vendor
    "openbsd":   "OpenBSD",
    "freebsd":   "FreeBSD",
    "netbsd":    "NetBSD",
    "apple":     "Apple",
    "google":    "Google",
    "cisco":     "Cisco",
    "hp":        "HP",
    "hewlett-packard": "HP",
    "dell":      "Dell",
    "ibm":       "IBM",
    "juniper":   "Juniper",
    "f5":        "F5",
    "fortinet":  "Fortinet",
    "checkpoint": "Check Point",
    "palo_alto_networks": "Palo Alto",
    "ubiquiti":  "Ubiquiti",
    "mikrotik":  "MikroTik",
}


# CPE product → cygor's normalized OS family name. The CPE product slot
# carries names like "windows_server_2019" or "linux_kernel" which we need
# to map to cygor's flat os_family scheme.
_PRODUCT_TO_FAMILY: List[tuple] = [
    # (substring in product, os_family)
    ("windows_server",    "Windows Server"),
    ("windows_nt",        "Windows"),
    ("windows_10",        "Windows"),
    ("windows_11",        "Windows"),
    ("windows_xp",        "Windows"),
    ("windows_7",         "Windows"),
    ("windows_8",         "Windows"),
    ("windows",           "Windows"),  # catch-all last
    ("linux_kernel",      "Linux"),
    ("linux",             "Linux"),
    ("ubuntu_linux",      "Linux"),
    ("ubuntu",            "Linux"),
    ("debian_linux",      "Linux"),
    ("debian",            "Linux"),
    ("centos",            "Linux"),
    ("fedora",            "Linux"),
    ("rhel",              "Linux"),
    ("enterprise_linux",  "Linux"),
    ("esxi",              "VMkernel"),
    ("vsphere",           "VMkernel"),
    ("mac_os_x",          "macOS"),
    ("macos",             "macOS"),
    ("ios",               "iOS"),
    ("ipados",            "iPadOS"),
    ("android",           "Android"),
    ("freebsd",           "FreeBSD"),
    ("openbsd",           "OpenBSD"),
    ("netbsd",            "NetBSD"),
    ("ios_xe",            "Cisco IOS XE"),
    ("ios_xr",            "Cisco IOS XR"),
    ("nx-os",             "Cisco NX-OS"),
    ("ios",               "Cisco IOS"),  # last so it doesn't clobber Apple iOS earlier
]


def _normalize_vendor(vendor: str) -> Optional[str]:
    """Map CPE vendor token to display name, returning None for generics."""
    if not vendor:
        return None
    key = vendor.lower().replace(" ", "_")
    if key in _VENDOR_DISPLAY:
        return _VENDOR_DISPLAY[key]
    # Unknown vendor — title-case it as a best effort
    return vendor.replace("_", " ").title()


def _normalize_os_family(product: str) -> Optional[str]:
    """Map CPE product slot to cygor's os_family bucket."""
    if not product:
        return None
    p = product.lower()
    for needle, family in _PRODUCT_TO_FAMILY:
        if needle in p:
            return family
    return None


def _build_os_name(parsed: ParsedCPE) -> Optional[str]:
    """
    Produce a friendly OS name from a CPE.

    Examples:
      cpe:/o:microsoft:windows_server_2019:standard
        → "Windows Server 2019 Standard"
      cpe:/o:canonical:ubuntu_linux:22.04
        → "Ubuntu 22.04"
      cpe:/o:vmware:esxi:6.7.0
        → "VMware ESXi 6.7.0"
    """
    bits: List[str] = []
    vendor = _normalize_vendor(parsed.vendor)
    product = parsed.product.replace("_", " ").title() if parsed.product else ""

    # Drop redundant vendor when it already appears in the product name.
    if vendor and product and vendor.lower() not in product.lower():
        bits.append(vendor)
    if product:
        # "Linux Kernel" -> "Linux"; "Ubuntu Linux" -> "Ubuntu"
        product = product.replace(" Linux", "").strip() or product
        bits.append(product)
    if parsed.version:
        bits.append(parsed.version)
    if parsed.update:
        bits.append(parsed.update.title())
    if parsed.edition:
        bits.append(parsed.edition.title())
    return " ".join(bits) if bits else None


def cpe_to_match_payload(parsed: ParsedCPE) -> Optional[Dict[str, Any]]:
    """
    Convert a parsed CPE into a dict of fields suitable for wrapping in a
    ``FingerprintMatch``. Returns None when the CPE doesn't carry enough
    information to be useful (e.g., bare vendor with no product).
    """
    if not parsed.product and not parsed.vendor:
        return None

    payload: Dict[str, Any] = {
        "raw": {
            "cpe": parsed.raw,
            "part": parsed.part,
            "vendor_raw": parsed.vendor,
            "product_raw": parsed.product,
            "version_raw": parsed.version,
        },
    }

    if parsed.is_os:
        payload["os_family"] = _normalize_os_family(parsed.product)
        payload["os_vendor"] = _normalize_vendor(parsed.vendor)
        payload["os_version"] = parsed.version or None
        payload["os_name"] = _build_os_name(parsed)
    elif parsed.is_hardware:
        payload["manufacturer"] = _normalize_vendor(parsed.vendor)
        # Hardware CPE product is the model.
        if parsed.product:
            payload["model"] = parsed.product.replace("_", " ").title()

    return payload


def extract_cpes_from_host(host) -> List[Dict[str, Any]]:
    """
    Walk every service on a libnmap host and collect its CPEs.

    Returns a list of dicts, each suitable for passing to FingerprintMatch:
        {raw, os_family, os_vendor, os_version, os_name,
         manufacturer, model, source_port, source_service}

    The caller is responsible for wrapping each into a FingerprintMatch with
    the appropriate confidence — typical confidence for CPE-derived OS info
    is 0.92 (very high; nmap doesn't emit CPE unless service-version
    detection produced a confident match).
    """
    out: List[Dict[str, Any]] = []
    if not hasattr(host, "services"):
        return out

    for svc in host.services:
        cpelist = getattr(svc, "cpelist", None) or []
        for cpe_obj in cpelist:
            cpe_str = str(cpe_obj)
            parsed = parse_cpe(cpe_str)
            if parsed is None:
                continue
            payload = cpe_to_match_payload(parsed)
            if payload is None:
                continue
            payload["source_port"] = getattr(svc, "port", None)
            payload["source_service"] = getattr(svc, "service", None)
            out.append(payload)
    return out
