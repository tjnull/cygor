"""
FingerprintDB Lookup Interface.

Provides unified access to all fingerprint databases for device identification.
Uses JSON file cache by default - no SQLite required.
"""

import re
import json
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Any

from .cache import get_cache, FingerprintCache
from .patterns import match_banner, match_mdns_service, match_dhcp_opt55, match_dhcp_opt60
from . import patterns as _patterns_pkg
from .patterns import vendor_patterns as _vp_module

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Vendor MAC prefix lookup table — auto-discovered from vendor_patterns
# ---------------------------------------------------------------------------
#
# The previous implementation imported ~36 specific *_MAC_PREFIXES dicts by
# hand. The vendor_patterns module actually defines 200+ such dicts, and
# leaving most of them out meant cygor was structurally blind to common
# device categories (Ring, Nest, Eufy, smart-home IoT, modern game consoles,
# Tesla, Mellanox NICs, etc.) even though the pattern data was right there.
#
# We auto-discover every attribute matching ``*_MAC_PREFIXES`` whose value is
# a ``Dict[str, tuple]`` and fold them all into ``_VENDOR_MAC_LOOKUP``. New
# vendor dicts added in the future are picked up automatically — no edits
# needed in this file.
#
# Override-style dicts (declared below for cloud VMs / Hyper-V VMs / mesh
# WiFi) are applied LAST so they win over any generic vendor entry for the
# same OUI block.

# --- Cloud provider VM MAC OUIs ------------------------------------------
# These are the OUIs that map distinctively to cloud VM ENIs. AWS uses
# random locally-administered MACs (no fixed OUI), so we don't list AWS
# here — IMDS / reverse-DNS is the right path for AWS detection.
#
# References: IEEE OUI registry (cited per entry); cloud provider docs;
# OpenStack Neutron source for the FA:16:3E default.
_CLOUD_VM_MAC_PREFIXES: Dict[str, tuple] = {
    # GCP Compute Engine encodes the internal IPv4 into the MAC.
    # First 3 octets are 42:01:<first_internal_ip_octet>.
    "42:01:0A": ("virtual_machine", "Virtualization", "GCP Compute Engine VM"),
    "42:01:AC": ("virtual_machine", "Virtualization", "GCP Compute Engine VM"),  # 172.x range
    "42:01:C0": ("virtual_machine", "Virtualization", "GCP Compute Engine VM"),  # 192.x range
    # Azure VM ENIs (Microsoft-registered, observed on Azure).
    "00:0D:3A": ("virtual_machine", "Virtualization", "Azure VM"),
    "00:22:48": ("virtual_machine", "Virtualization", "Azure VM"),
    # OpenStack Neutron default — covers OVH Public Cloud and any OpenStack
    # deployment.
    "FA:16:3E": ("virtual_machine", "Virtualization", "OpenStack VM"),
}

# --- Hyper-V VM override -------------------------------------------------
# 00:15:5D is in MICROSOFT_MAC_PREFIXES generically as "computer/Microsoft",
# but that prefix is the Hyper-V dynamically-generated MAC pool. Override so
# VMs on Hyper-V are correctly identified as virtual machines.
_HYPERV_VM_MAC_PREFIXES: Dict[str, tuple] = {
    "00:15:5D": ("virtual_machine", "Virtualization", "Hyper-V VM"),
}

# --- Mesh WiFi — newer brands that don't have dedicated dicts ------------
# Eero (Amazon), Nest WiFi (Google), TP-Link Deco. AMAZON_MAC_PREFIXES and
# GOOGLE_MAC_PREFIXES already cover the parent vendor; these prefixes
# narrow to the specific mesh product line.
_MESH_WIFI_MAC_PREFIXES: Dict[str, tuple] = {
    "8C:85:80": ("access_point", "Network Device", "Eero Mesh WiFi"),     # Amazon Eero
    "F0:9F:C2": ("access_point", "Network Device", "Eero Mesh WiFi"),     # Amazon Eero
    "78:67:0E": ("access_point", "Network Device", "Eero Mesh WiFi"),     # Amazon Eero
    "F4:F5:D8": ("access_point", "Network Device", "Nest WiFi"),          # Google Nest WiFi
    "F4:F5:E8": ("access_point", "Network Device", "Nest WiFi"),          # Google Nest WiFi
    "F4:F5:DB": ("access_point", "Network Device", "Nest WiFi"),
    "1C:61:B4": ("access_point", "Network Device", "TP-Link Deco"),
    "AC:84:C6": ("access_point", "Network Device", "TP-Link Deco"),
    "98:48:27": ("access_point", "Network Device", "TP-Link Deco"),
}


def _discover_vendor_mac_dicts() -> List[Dict]:
    """
    Walk the vendor_patterns module and return every attribute whose name
    ends with ``_MAC_PREFIXES`` and whose value is a non-empty dict. Skips
    attributes that don't fit the expected shape so a malformed entry never
    breaks lookup at import time.
    """
    found: List[Dict] = []
    for name in dir(_vp_module):
        if not name.endswith("_MAC_PREFIXES"):
            continue
        value = getattr(_vp_module, name, None)
        if not isinstance(value, dict) or not value:
            continue
        # Sanity-check the first entry's shape so a malformed dict can't
        # silently corrupt lookups.
        sample_key, sample_val = next(iter(value.items()))
        if not isinstance(sample_key, str) or not isinstance(sample_val, tuple):
            continue
        if len(sample_val) < 3:
            continue
        found.append(value)
    return found


_VENDOR_MAC_LOOKUP: Dict[str, tuple] = {}
# Apply auto-discovered dicts first…
for _d in _discover_vendor_mac_dicts():
    _VENDOR_MAC_LOOKUP.update(_d)
# …then overrides last so they win for shared OUI blocks.
for _d in (_CLOUD_VM_MAC_PREFIXES, _HYPERV_VM_MAC_PREFIXES, _MESH_WIFI_MAC_PREFIXES):
    _VENDOR_MAC_LOOKUP.update(_d)
logger.debug(f"Loaded {len(_VENDOR_MAC_LOOKUP)} vendor MAC prefix entries from {len(_discover_vendor_mac_dicts())} dicts")


@dataclass
class FingerprintMatch:
    """Result from a fingerprint lookup."""

    source: str  # oui, tcp, banner, mdns, dhcp, nmap_os, ttl, hostname, http_ua
    match_type: str  # exact, pattern, partial, heuristic
    confidence: float  # 0.0-1.0

    # Device classification
    device_type: Optional[str] = None
    device_category: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None

    # OS information
    os_family: Optional[str] = None
    os_version: Optional[str] = None
    os_vendor: Optional[str] = None

    # Raw match data
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())


class FingerprintLookup:
    """
    Unified interface for fingerprint database lookups.

    Uses JSON file cache by default - no SQLite required.
    Focused on device/OS identification from scan data.

    Provides methods to lookup device info by:
    - MAC address (OUI) -> Manufacturer
    - TCP/IP stack signature (p0f) -> OS family
    - Service banner (SSH, HTTP, SMB, FTP) -> OS, product, vendor
    - mDNS service -> Device type
    - DHCP options -> Device type, OS
    """

    def __init__(self, session=None, cache: FingerprintCache = None):
        """
        Initialize lookup interface.

        Args:
            session: Deprecated - no longer used
            cache: Optional FingerprintCache instance (uses global if not provided)
        """
        self.session = session  # Kept for backwards compatibility
        self.cache = cache or get_cache()

    async def lookup_mac(self, mac: str) -> Optional[FingerprintMatch]:
        """
        Lookup manufacturer and device type from MAC address.

        Uses vendor MAC prefix databases first (more specific), then falls back
        to OUI-Master-Database which includes device type classifications
        (Router, Switch, Phone, Camera, IoT, etc.) for many entries.

        Args:
            mac: MAC address in any format (XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX)

        Returns:
            FingerprintMatch or None
        """
        if not mac:
            return None

        # Normalize MAC
        mac_clean = mac.upper().replace("-", ":").replace(".", ":")
        parts = mac_clean.split(":")
        if len(parts) == 6:
            oui = ":".join(parts[:3])
        elif len(parts) == 3 and len(parts[0]) == 4:
            flat = mac_clean.replace(":", "")
            oui = f"{flat[0:2]}:{flat[2:4]}:{flat[4:6]}"
        else:
            oui = mac_clean[:8].replace("-", ":")

        # 1. Check vendor MAC prefix databases first (more specific than OUI)
        vendor_match = _VENDOR_MAC_LOOKUP.get(oui)
        if vendor_match:
            device_type, device_category, manufacturer = vendor_match
            return FingerprintMatch(
                source="oui",
                match_type="exact",
                confidence=0.88,  # Higher than generic OUI
                manufacturer=manufacturer,
                device_type=device_type.lower() if device_type else None,
                device_category=device_category,
                raw_data={"vendor": manufacturer, "vendor_prefix_match": True}
            )

        # 2. Try Huginn-Muninn MAC vendors (10.1M entries — much more granular
        # than the standard OUI cache). Result is a thin {name, device_id}
        # but the larger entry set catches blocks the OUI cache misses.
        huginn_vendor = self.cache.lookup_huginn_mac_vendor(mac)
        if huginn_vendor:
            return FingerprintMatch(
                source="huginn_mac_vendor",
                match_type="exact",
                confidence=0.86,  # Slightly above plain OUI (0.85)
                manufacturer=huginn_vendor.get("name"),
                raw_data={
                    "vendor": huginn_vendor.get("name"),
                    "huginn_device_id": huginn_vendor.get("device_id"),
                    "source_db": "huginn_mac_vendors",
                },
            )

        # 3. Fall back to OUI cache (generic manufacturer)
        entry = self.cache.lookup_oui(mac)
        if entry:
            device_type = entry.get("device_type")
            device_category = self._get_device_category(device_type) if device_type else None
            return FingerprintMatch(
                source="oui",
                match_type="exact",
                confidence=0.85,
                manufacturer=entry.get("vendor"),
                device_type=device_type.lower() if device_type else None,
                device_category=device_category,
                raw_data={
                    "vendor": entry.get("vendor"),
                    "vendor_short": entry.get("vendor_short"),
                    "device_type": device_type,
                    "registry": entry.get("registry"),
                    "sources": entry.get("sources"),
                }
            )
        return None

    def _get_device_category(self, device_type: str) -> Optional[str]:
        """Map OUI device_type to a standardized category."""
        if not device_type:
            return None

        device_type_lower = device_type.lower()

        # Network devices
        if device_type_lower in ("router", "switch", "hub", "bridge", "gateway", "firewall", "access point", "ap", "wap"):
            return "Network Device"

        # Computing
        if device_type_lower in ("server", "workstation", "desktop", "laptop", "computer", "pc"):
            return "Computing"

        # Mobile
        if device_type_lower in ("phone", "smartphone", "mobile", "tablet", "pda"):
            return "Mobile Device"

        # IoT
        if device_type_lower in ("iot", "sensor", "smart home", "thermostat", "camera", "doorbell", "lock"):
            return "IoT Device"

        # Peripherals
        if device_type_lower in ("printer", "scanner", "mfp", "multifunction"):
            return "Peripheral"

        # Media
        if device_type_lower in ("tv", "smart tv", "media player", "streaming", "set-top box", "stb"):
            return "Media Device"

        # Industrial
        if device_type_lower in ("plc", "hmi", "scada", "industrial", "automation"):
            return "Industrial/SCADA"

        return "Unknown"

    async def lookup_tcp(self, signature: str) -> Optional[FingerprintMatch]:
        """
        Lookup by TCP/IP stack fingerprint (p0f-style).

        Args:
            signature: p0f signature string

        Returns:
            FingerprintMatch or None
        """
        if not signature:
            return None

        # Use JSON cache lookup
        entries = self.cache.load_tcpip()

        for entry in entries:
            if entry.get("signature") == signature:
                confidence = entry.get("confidence", 80)
                return FingerprintMatch(
                    source="tcp",
                    match_type="exact",
                    confidence=confidence / 100.0 if confidence > 1 else confidence,
                    os_family=entry.get("os_family"),
                    os_version=entry.get("os_version"),
                    device_type=entry.get("device_type"),
                    raw_data={
                        "signature": entry.get("signature"),
                        "label": entry.get("label"),
                        "ttl": entry.get("ttl"),
                        "window_size": entry.get("window_size"),
                        "mss": entry.get("mss"),
                    }
                )

        return None

    async def lookup_banner(
        self,
        protocol: str,
        banner: str
    ) -> Optional[FingerprintMatch]:
        """
        Match service banner against patterns.

        Args:
            protocol: Service protocol (ssh, http, smb, ftp)
            banner: Service banner string

        Returns:
            FingerprintMatch or None
        """
        if not banner:
            return None

        # Try built-in patterns first
        result = match_banner(protocol, banner)
        if result:
            return FingerprintMatch(
                source="banner",
                match_type="pattern",
                confidence=result["confidence"] / 100.0,
                os_family=result.get("os_family"),
                manufacturer=result.get("vendor"),
                raw_data={
                    "product": result.get("product"),
                    "vendor": result.get("vendor"),
                    "version": result.get("version"),
                    "matched_pattern": result.get("matched_pattern"),
                }
            )

        # Try patterns from JSON cache
        patterns = self.cache.load_banners()
        for pattern_entry in patterns:
            if pattern_entry.get("protocol") != protocol.lower():
                continue

            pattern = pattern_entry.get("pattern", "")
            pattern_type = pattern_entry.get("pattern_type", "regex")

            try:
                if pattern_type == "regex":
                    match = re.search(pattern, banner, re.IGNORECASE)
                elif pattern_type == "exact":
                    match = banner == pattern
                elif pattern_type == "contains":
                    match = pattern.lower() in banner.lower()
                else:
                    continue

                if match:
                    confidence = pattern_entry.get("confidence", 65)
                    return FingerprintMatch(
                        source="banner_cache",
                        match_type="pattern",
                        confidence=confidence / 100.0 if confidence > 1 else confidence,
                        os_family=pattern_entry.get("os_family"),
                        manufacturer=pattern_entry.get("vendor"),
                        device_type=pattern_entry.get("device_type"),
                        raw_data={
                            "product": pattern_entry.get("product"),
                        }
                    )
            except re.error:
                continue

        return None

    def lookup_mdns(
        self,
        service_type: str,
        name: str = None
    ) -> Optional[FingerprintMatch]:
        """
        Identify device from mDNS service type.

        Args:
            service_type: mDNS service type (e.g., "_airplay._tcp")
            name: Optional service name for additional matching

        Returns:
            FingerprintMatch or None (sync - uses built-in patterns only)
        """
        result = match_mdns_service(service_type, name)
        if result:
            return FingerprintMatch(
                source="mdns",
                match_type="pattern",
                confidence=result["confidence"] / 100.0,
                device_type=result.get("device_type"),
                manufacturer=result.get("manufacturer"),
                os_family=result.get("os_family"),
                raw_data={
                    "service_type": service_type,
                    "name": name,
                    "match_source": result.get("match_source"),
                }
            )
        return None

    def lookup_dhcp(
        self,
        opt55: str = None,
        opt60: str = None
    ) -> Optional[FingerprintMatch]:
        """
        Lookup by DHCP options.

        Uses Huginn-Muninn database (368K DHCP fingerprints, 425K vendor IDs) with
        fallback to built-in patterns.

        Args:
            opt55: DHCP Option 55 (Parameter Request List)
            opt60: DHCP Option 60 (Vendor Class Identifier)

        Returns:
            FingerprintMatch or None
        """
        # Try Huginn-Muninn DHCP vendor lookup first (Option 60)
        if opt60:
            hm_vendor = self.cache.lookup_huginn_dhcp_vendor(opt60)
            if hm_vendor and hm_vendor.get("device_id"):
                device_info = self.cache.get_device_info_from_huginn(hm_vendor["device_id"])
                if device_info:
                    return FingerprintMatch(
                        source="huginn_dhcp_vendor",
                        match_type="exact",
                        confidence=0.85,
                        device_type=device_info.get("name"),
                        device_category=device_info.get("hierarchy"),
                        manufacturer=hm_vendor.get("vendor_hint"),
                        raw_data={
                            "vendor_class": opt60,
                            "huginn_device_id": hm_vendor.get("device_id"),
                            "hierarchy": device_info.get("hierarchy"),
                            "mobile": device_info.get("mobile"),
                            "tablet": device_info.get("tablet"),
                        }
                    )

            # Fallback to built-in Option 60 patterns
            result = match_dhcp_opt60(opt60)
            if result:
                return FingerprintMatch(
                    source="dhcp_opt60",
                    match_type="pattern",
                    confidence=result["confidence"] / 100.0,
                    device_type=result.get("device_type"),
                    manufacturer=result.get("manufacturer"),
                    os_family=result.get("os_family"),
                    raw_data={
                        "vendor_class": opt60,
                    }
                )

        # Try Huginn-Muninn DHCP fingerprint lookup (Option 55)
        if opt55:
            hm_dhcp = self.cache.lookup_huginn_dhcp_by_options(opt55)
            if hm_dhcp and hm_dhcp.get("device_id"):
                device_info = self.cache.get_device_info_from_huginn(hm_dhcp["device_id"])
                if device_info:
                    return FingerprintMatch(
                        source="huginn_dhcp",
                        match_type="exact",
                        confidence=0.80,
                        device_type=device_info.get("name"),
                        device_category=device_info.get("hierarchy"),
                        raw_data={
                            "options": opt55,
                            "huginn_device_id": hm_dhcp.get("device_id"),
                            "hierarchy": device_info.get("hierarchy"),
                            "mobile": device_info.get("mobile"),
                            "tablet": device_info.get("tablet"),
                        }
                    )

            # Fallback to built-in Option 55 patterns
            result = match_dhcp_opt55(opt55)
            if result:
                return FingerprintMatch(
                    source="dhcp_opt55",
                    match_type=result.get("match_source", "pattern"),
                    confidence=result["confidence"] / 100.0,
                    device_type=result.get("device_type"),
                    manufacturer=result.get("manufacturer"),
                    os_family=result.get("os_family"),
                    raw_data={
                        "options": opt55,
                    }
                )

        return None

    def lookup_huginn_device(
        self,
        device_name: str = None,
        device_id: str = None,
        hostname: str = None,
        match_type: str = "exact",
        confidence: float = 0.90,
    ) -> Optional[FingerprintMatch]:
        """
        Lookup device info directly from Huginn-Muninn device database.

        Uses the 116K device profile database with hierarchical classification.
        Pipes the raw Huginn record through ``huginn_normalize`` to produce
        cygor's flat schema (device_type / device_category / manufacturer /
        os_family / os_vendor) — never returns the leaf model name as the
        device_type or the full hierarchy path as the category.

        Resolution order:
          1. ``device_id`` — direct ID lookup (highest confidence).
          2. ``device_name`` — exact case-insensitive name lookup.
          3. ``hostname`` — token-based fuzzy match (lower default confidence).

        Args:
            device_name: Exact device name to search for
            device_id: Huginn-Muninn device ID (if known)
            hostname: Real-world hostname to fuzzy-match
            match_type: How the caller resolved this record (exact|substring|fuzzy)
            confidence: Override the default 0.90 confidence (e.g. callers using
                substring matching pass a lower value)

        Returns:
            FingerprintMatch or None
        """
        from .huginn_normalize import normalize_huginn_record

        device_info = None
        used_match_type = match_type
        used_confidence = confidence

        if device_id:
            device_info = self.cache.lookup_huginn_device(device_id)
        elif device_name:
            device_info = self.cache.lookup_huginn_device_by_name(device_name)

        # Hostname fuzzy fallback — real hostnames almost never equal Huginn
        # canonical names, so token matching is the only path that fires for
        # most real scan data.
        if not device_info and hostname:
            device_info = self.cache.lookup_huginn_device_by_hostname(hostname)
            if device_info:
                used_match_type = "fuzzy_hostname"
                # Lower confidence: substring/token overlap, not exact match.
                used_confidence = min(confidence, 0.70)

        if not device_info:
            return None

        norm = normalize_huginn_record(device_info)
        return FingerprintMatch(
            source="huginn_device",
            match_type=used_match_type,
            confidence=used_confidence,
            device_type=norm["device_type"],
            device_category=norm["device_category"],
            manufacturer=norm["manufacturer"],
            model=norm["model"],
            os_family=norm["os_family"],
            os_vendor=norm["os_vendor"],
            raw_data={
                "device_id": device_id,
                "huginn_name": device_info.get("name"),
                "hierarchy": device_info.get("hierarchy"),
                "hierarchy_str": device_info.get("hierarchy_str"),
                "mobile": device_info.get("mobile", False),
                "tablet": device_info.get("tablet", False),
            },
        )

    def lookup_nmap_os(
        self,
        os_name: str = None,
        vendor: str = None
    ) -> List[FingerprintMatch]:
        """
        Lookup OS info from Nmap OS fingerprint database.

        Uses the 6K+ Nmap OS signatures for OS identification.
        Note: This is a search function, not an active probe matcher.

        Args:
            os_name: OS/device name to search for
            vendor: Vendor name to search for

        Returns:
            List of FingerprintMatch objects (may return multiple matches)
        """
        matches = []

        if os_name:
            entries = self.cache.lookup_nmap_os_by_name(os_name)
        elif vendor:
            entries = self.cache.lookup_nmap_os_by_vendor(vendor)
        else:
            return matches

        for entry in entries[:10]:  # Limit to top 10 matches
            matches.append(FingerprintMatch(
                source="nmap_os",
                match_type="search",
                confidence=0.88,  # Nmap signatures are highly accurate
                device_type=entry.get("device_type"),
                os_family=entry.get("os_type"),
                os_vendor=entry.get("vendor"),
                raw_data={
                    "name": entry.get("name"),
                    "class": entry.get("class"),
                    "cpe": entry.get("cpe", []),
                    "vendor": entry.get("vendor"),
                }
            ))

        return matches

    async def lookup_satori_ssh(self, banner: str) -> Optional[FingerprintMatch]:
        """Match SSH banner against Satori SSH fingerprint database."""
        if not banner:
            return None
        result = self.cache.lookup_satori_ssh(banner)
        if result:
            return FingerprintMatch(
                source="satori_ssh",
                match_type="exact" if result.get("exact") else "pattern",
                confidence=0.85,
                os_family=result.get("os"),
                device_type=result.get("device_type"),
                manufacturer=result.get("vendor"),
                raw_data={"banner": banner, "satori_match": result.get("name", "")}
            )
        return None

    async def lookup_satori_smb(self, native_os: str, lanman: str = None) -> Optional[FingerprintMatch]:
        """
        Match SMB strings against Satori SMB database.

        Tries native_os first; falls back to lanman when native_os doesn't
        match. Windows Server lanman strings often carry the build version
        that native_os omits ("Windows Server 2019 Standard 6.3" vs the
        plainer "Windows Server 2019").
        """
        result = None
        used_field = None
        if native_os:
            result = self.cache.lookup_satori_smb(native_os)
            used_field = "native_os"
        if not result and lanman:
            result = self.cache.lookup_satori_smb(lanman)
            used_field = "lanman"
        if not result:
            return None
        return FingerprintMatch(
            source="satori_smb",
            match_type="exact" if result.get("exact") else "pattern",
            confidence=0.88,
            os_family=result.get("os"),
            os_version=result.get("version"),
            device_type=result.get("device_type"),
            manufacturer=result.get("vendor"),
            raw_data={
                "native_os": native_os,
                "lanman": lanman,
                "matched_field": used_field,
                "satori_match": result.get("name", ""),
            },
        )

    async def lookup_satori_dhcp(self, dhcp_options: str) -> Optional[FingerprintMatch]:
        """
        Match a DHCP option string (e.g. the comma-joined option55 list)
        against Satori's DHCP fingerprint database.

        Satori DHCP fingerprints are pattern-based — different shape than
        Huginn's hashed-options index — and frequently catch consumer-grade
        gear (TVs, printers, IoT) that Huginn misses.
        """
        if not dhcp_options:
            return None
        result = self.cache.lookup_satori_dhcp(dhcp_options)
        if not result:
            return None
        return FingerprintMatch(
            source="satori_dhcp",
            match_type="pattern",
            confidence=0.78,
            os_family=result.get("os"),
            device_type=result.get("device_type"),
            manufacturer=result.get("vendor"),
            raw_data={
                "dhcp_options": dhcp_options,
                "satori_match": result.get("name", ""),
                "pattern": result.get("pattern", ""),
            },
        )

    def lookup_huginn_combination_dhcp(self, opt55: str) -> Optional[FingerprintMatch]:
        """
        Resolve a DHCP option55 string against the Huginn combinations
        table — high confidence when the option list matches exactly.

        Each combination row carries a vendor + device_type + Satori name
        already correlated to the underlying DHCP fingerprint, so a single
        lookup gives us all three at once.
        """
        if not opt55:
            return None
        entry = self.cache.lookup_huginn_combination_by_dhcp_options(opt55)
        if not entry:
            return None
        return FingerprintMatch(
            source="huginn_combination",
            match_type="exact",
            confidence=0.89,  # Exact opt55 match is very strong
            device_type=(entry.get("device_type") or "").lower() or None,
            manufacturer=entry.get("device_vendor"),
            model=entry.get("satori_name"),
            raw_data={
                "dhcp_option55": opt55,
                "huginn_device_id": entry.get("device_id"),
                "satori_name": entry.get("satori_name"),
            },
        )

    async def lookup_satori_http(self, server_header: str) -> Optional[FingerprintMatch]:
        """Match HTTP Server header against Satori HTTP database."""
        if not server_header:
            return None
        result = self.cache.lookup_satori_http(server_header)
        if result:
            return FingerprintMatch(
                source="satori_http",
                match_type="exact" if result.get("exact") else "pattern",
                confidence=0.82,
                os_family=result.get("os"),
                device_type=result.get("device_type"),
                manufacturer=result.get("vendor"),
                raw_data={"server": server_header, "satori_match": result.get("name", "")}
            )
        return None

    async def lookup_satori_useragent(self, ua: str) -> Optional[FingerprintMatch]:
        """Match User-Agent against Satori User-Agent database."""
        if not ua:
            return None
        result = self.cache.lookup_satori_useragent(ua)
        if result:
            return FingerprintMatch(
                source="satori_useragent",
                match_type="exact" if result.get("exact") else "pattern",
                confidence=0.80,
                os_family=result.get("os"),
                device_type=result.get("device_type"),
                manufacturer=result.get("vendor"),
                raw_data={"user_agent": ua, "satori_match": result.get("name", "")}
            )
        return None

    async def lookup_satori_sip(self, ua: str) -> Optional[FingerprintMatch]:
        """Match SIP User-Agent against Satori SIP database."""
        if not ua:
            return None
        result = self.cache.lookup_satori_sip(ua)
        if result:
            return FingerprintMatch(
                source="satori_sip",
                match_type="exact" if result.get("exact") else "pattern",
                confidence=0.75,
                os_family=result.get("os"),
                device_type=result.get("device_type", "voip_phone"),
                manufacturer=result.get("vendor"),
                raw_data={"sip_ua": ua, "satori_match": result.get("name", "")}
            )
        return None

    async def identify(
        self,
        mac: str = None,
        tcp_sig: str = None,
        banners: Dict[str, str] = None,
        mdns_services: List[str] = None,
        dhcp_opt55: str = None,
        dhcp_opt60: str = None
    ) -> List[FingerprintMatch]:
        """
        Perform all available lookups and aggregate results.

        Args:
            mac: MAC address
            tcp_sig: TCP/IP stack signature
            banners: Dict of protocol -> banner
            mdns_services: List of mDNS service types
            dhcp_opt55: DHCP Option 55
            dhcp_opt60: DHCP Option 60

        Returns:
            List of all matches sorted by confidence
        """
        matches = []

        # MAC OUI lookup
        if mac:
            match = await self.lookup_mac(mac)
            if match:
                matches.append(match)

        # TCP lookup
        if tcp_sig:
            match = await self.lookup_tcp(tcp_sig)
            if match:
                matches.append(match)

        # Banner lookups
        if banners:
            for protocol, banner in banners.items():
                match = await self.lookup_banner(protocol, banner)
                if match:
                    matches.append(match)

        # mDNS lookups (sync)
        if mdns_services:
            for service in mdns_services:
                match = self.lookup_mdns(service)
                if match:
                    matches.append(match)

        # DHCP lookup (sync)
        if dhcp_opt55 or dhcp_opt60:
            match = self.lookup_dhcp(dhcp_opt55, dhcp_opt60)
            if match:
                matches.append(match)

        # Sort by confidence (highest first)
        matches.sort(key=lambda m: m.confidence, reverse=True)

        return matches


def aggregate_evidence(matches: List[FingerprintMatch]) -> Dict[str, Any]:
    """
    Aggregate multiple fingerprint matches into a unified device profile.

    Uses weighted voting based on confidence and source reliability.

    Args:
        matches: List of FingerprintMatch objects

    Returns:
        Aggregated device info dict
    """
    if not matches:
        return {
            "device_type": "Unknown",
            "device_category": "Unknown",
            "manufacturer": None,
            "os_family": None,
            "os_name": None,
            "confidence": 0.0,
        }

    # Source reliability weights - tiered by data quality and comprehensiveness
    # Higher weight = more trustworthy for device/OS identification
    #
    # Tier 1 (0.85-0.92): Large curated databases with high accuracy
    # Tier 2 (0.75-0.84): Standard tools and validated patterns
    # Tier 3 (0.60-0.74): Complementary/secondary sources
    # Tier 4 (0.50-0.59): Heuristic/low-confidence sources
    #
    SOURCE_WEIGHTS = {
        # === Tier 1: Primary Sources (Large curated databases / definitive) ===
        "cloud_iprange": 0.96,            # Cloud provider's own published CIDR — definitive
        "cpe": 0.93,                      # nmap-emitted CPE strings — most-precise identifier nmap produces
        "windows_build": 0.93,            # Windows build number resolved to friendly OS version
        "cloud_ptr": 0.92,                # Reverse DNS matches a cloud-managed pattern
        "huginn_device": 0.92,            # Direct Huginn-Muninn device lookup (116K profiles, hierarchical)
        "hostname_domain": 0.91,          # FQDN manufacturer domain (authoritative - device reports to manufacturer)
        "huginn_dhcp_vendor": 0.90,       # Huginn-Muninn DHCP vendor class (425K entries, curated)
        "nmap_os": 0.88,                  # Nmap OS detection (6K signatures, highly accurate)
        "huginn_dhcp": 0.87,              # Huginn-Muninn DHCP fingerprints (368K entries)
        "huginn_mac_vendor": 0.86,        # Huginn-Muninn MAC vendors (10.1M entries — supersets OUI)
        "oui": 0.85,                      # MAC vendor (86K entries, authoritative)

        # === Tier 2: Standard Tools (Validated, specialized) ===
        "huginn_combination": 0.89,       # DHCP option55 → device exact match
        "nmap_script": 0.89,              # NSE-script-derived virt/product info
        "cloud_tls_san": 0.88,            # TLS SAN matches a cloud-managed hostname pattern
        "satori_smb": 0.88,               # SMB native_os/lanman → curated OS
        "tcp": 0.80,                      # p0f TCP/IP stack fingerprints (de facto standard)
        "banner": 0.80,                   # Built-in service banner patterns
        "banner_cache": 0.80,             # Cached banner patterns
        "satori_dhcp": 0.78,              # Satori DHCP option pattern → OS family
        "mdns": 0.78,                     # mDNS services (reliable for device type)
        "virt_ports": 0.75,               # Hypervisor / K8s / container port-set heuristic
        "dhcp_opt60": 0.75,               # Built-in DHCP Vendor Class patterns
        "hostname": 0.72,                 # Hostname pattern hints (increased from 0.65)

        # === Tier 3: Secondary Sources (Complementary, may overlap) ===
        "http_ua": 0.70,                  # HTTP User-Agent from scripts
        "dhcp_opt55": 0.68,               # Built-in DHCP Option 55 patterns (less specific)

        # === Tier 4: Heuristic Sources (Low confidence) ===
        "ttl": 0.55,                      # TTL-based OS guess
    }

    # Collect votes for each field
    votes = {
        "device_type": {},
        "manufacturer": {},
        "os_family": {},
    }

    for match in matches:
        weight = SOURCE_WEIGHTS.get(match.source, 0.5) * match.confidence

        if match.device_type:
            votes["device_type"][match.device_type] = \
                votes["device_type"].get(match.device_type, 0) + weight

        if match.manufacturer:
            votes["manufacturer"][match.manufacturer] = \
                votes["manufacturer"].get(match.manufacturer, 0) + weight

        if match.os_family:
            votes["os_family"][match.os_family] = \
                votes["os_family"].get(match.os_family, 0) + weight

    # ==========================================================================
    # OUI-Based Manufacturer Validation
    # ==========================================================================
    # MAC OUI is authoritative for manufacturer identity. If OUI says "Ubiquiti"
    # but nmap says "Netgear", the OUI is correct (nmap matched TCP/IP stack,
    # not the actual device manufacturer). This prevents misidentification
    # when devices from different vendors have similar TCP/IP stacks.
    #
    # Example: Ubiquiti AC Pro (E0:63:DA:xx) running Linux 3.18 was being
    # identified as "Netgear GS108Tv3 switch" because nmap's fingerprint
    # matched a Netgear device with the same kernel version.
    # ==========================================================================

    # Check if we have an OUI-based manufacturer that should take precedence
    oui_manufacturer = None
    oui_device_type = None
    for match in matches:
        if match.source == "oui" and match.manufacturer:
            oui_manufacturer = match.manufacturer
            oui_device_type = match.device_type
            break

    # Also check hostname_domain which is equally authoritative
    domain_manufacturer = None
    domain_device_type = None
    for match in matches:
        if match.source == "hostname_domain" and match.manufacturer:
            domain_manufacturer = match.manufacturer
            domain_device_type = match.device_type
            break

    # Check for high-confidence hostname patterns that indicate device type
    # This handles cases like Samsung TV (SmartViewSDK) vs Samsung phone (Galaxy)
    # where the same manufacturer makes different device types
    hostname_device_type = None
    for match in matches:
        if match.source == "hostname" and match.device_type and match.confidence >= 0.60:
            hostname_device_type = match.device_type
            break

    # Determine authoritative manufacturer (OUI or domain-based)
    authoritative_manufacturer = domain_manufacturer or oui_manufacturer

    # For device type, prefer: domain > hostname (specific patterns) > OUI
    # This allows hostname patterns like "SmartViewSDK" to correctly identify
    # a Samsung TV even when the MAC OUI might suggest "phone" due to Samsung
    # using shared OUI pools across product lines
    if domain_device_type:
        authoritative_device_type = domain_device_type
    elif hostname_device_type:
        # Hostname-derived device type takes precedence over OUI
        # because hostnames are more specific (e.g., "SmartViewSDK" = TV, not phone)
        authoritative_device_type = hostname_device_type
    else:
        authoritative_device_type = oui_device_type

    # If we have authoritative manufacturer, boost its votes significantly
    # This ensures OUI/domain-based identification wins over nmap OS detection
    if authoritative_manufacturer:
        # Give authoritative source a massive boost to ensure it wins
        current_votes = votes["manufacturer"].get(authoritative_manufacturer, 0)
        votes["manufacturer"][authoritative_manufacturer] = current_votes + 2.0  # Dominant boost

    # Boost device type from authoritative sources
    # Hostname patterns get a significant boost when they provide specific device type
    # (e.g., SmartViewSDK indicates TV, not generic Samsung device)
    if authoritative_device_type:
        # Network equipment vendors (Ubiquiti, Cisco, etc.) have very specific OUI assignments
        # Their OUI-derived device type should strongly override nmap OS detection
        # because nmap often just sees "Linux" or "OpenWrt" without knowing the actual device
        network_equipment_types = {
            "switch", "router", "access_point", "firewall", "wireless_bridge",
            "wireless_controller", "gateway", "mesh_router", "load_balancer"
        }

        if hostname_device_type:
            boost = 1.5  # Hostname patterns are specific
        elif authoritative_device_type in network_equipment_types:
            boost = 1.5  # Network equipment OUI assignments are highly reliable
        else:
            boost = 0.5  # Consumer devices may have shared OUI pools

        current_type_votes = votes["device_type"].get(authoritative_device_type, 0)
        votes["device_type"][authoritative_device_type] = current_type_votes + boost

    # Select winners
    result = {
        "device_type": max(votes["device_type"], key=votes["device_type"].get) if votes["device_type"] else "Unknown",
        "manufacturer": max(votes["manufacturer"], key=votes["manufacturer"].get) if votes["manufacturer"] else None,
        "os_family": max(votes["os_family"], key=votes["os_family"].get) if votes["os_family"] else None,
        "os_name": None,
        "os_version": None,
        "confidence": max(m.confidence for m in matches),
        "evidence": [m.to_dict() for m in matches],
    }

    # Get OS version from best OS match
    os_matches = [m for m in matches if m.os_family]
    if os_matches:
        best_os = max(os_matches, key=lambda m: m.confidence)
        result["os_version"] = best_os.os_version

    # Derive device category from device type
    DEVICE_CATEGORIES = {
        # Network Infrastructure
        "router": "Network Device",
        "switch": "Network Device",
        "firewall": "Network Device",
        "access_point": "Network Device",
        "load_balancer": "Network Device",
        "vpn_gateway": "Network Device",
        "wireless_controller": "Network Device",

        # Computing Devices
        "workstation": "Computing",
        "laptop": "Computing",
        "server": "Computing",
        "desktop": "Computing",
        "thin_client": "Computing",

        # Mobile Devices
        "mobile": "Mobile",
        "tablet": "Mobile",
        "smartphone": "Mobile",

        # Peripherals
        "printer": "Peripheral",
        "scanner": "Peripheral",
        "multifunction": "Peripheral",

        # Media Devices
        "smart_tv": "Media",
        "smart_speaker": "Media",
        "game_console": "Media",
        "media_server": "Media",
        "streaming_device": "Media",
        "set_top_box": "Media",

        # IoT Devices
        "camera": "IoT",
        "ip_camera": "IoT",
        "iot": "IoT",
        "iot_gateway": "IoT",
        "smart_sensor": "IoT",
        "smart_lock": "IoT",
        "thermostat": "IoT",
        "doorbell": "IoT",
        "smart_plug": "IoT",
        "smart_lighting": "IoT",
        "wearable": "IoT",

        # Smart Home
        "smart_home": "Smart Home",
        "home_hub": "Smart Home",
        "home_automation": "Smart Home",

        # Storage
        "nas": "Storage",
        "san": "Storage",
        "storage_array": "Storage",
        "backup_appliance": "Storage",

        # Communication
        "voip_phone": "Communication",
        "pbx": "Communication",
        "video_conferencing": "Communication",
        "sip_gateway": "Communication",

        # SCADA/ICS (Industrial Control Systems)
        "plc": "SCADA/ICS",
        "hmi": "SCADA/ICS",
        "rtu": "SCADA/ICS",
        "scada_server": "SCADA/ICS",
        "dcs": "SCADA/ICS",
        "ied": "SCADA/ICS",
        "industrial_switch": "SCADA/ICS",
        "industrial_router": "SCADA/ICS",
        "motor_drive": "SCADA/ICS",
        "power_meter": "SCADA/ICS",
        "building_automation": "SCADA/ICS",

        # Virtualization
        "hypervisor": "Virtualization",
        "virtual_machine": "Virtualization",
        "esxi": "Virtualization",
        "vcenter": "Virtualization",
        "proxmox": "Virtualization",
        "hyper_v": "Virtualization",
        "xen": "Virtualization",
        "kvm_host": "Virtualization",

        # Containers & Orchestration
        "container": "Container",
        "container_host": "Container",
        "kubernetes_node": "Container",
        "kubernetes_master": "Container",
        "docker_host": "Container",
        "container_registry": "Container",
        "openshift": "Container",

        # Web Services & Applications
        "web_server": "Web Service",
        "application_server": "Web Service",
        "api_gateway": "Web Service",
        "reverse_proxy": "Web Service",
        "cdn_node": "Web Service",
        "waf": "Web Service",

        # Database
        "database_server": "Database",
        "cache_server": "Database",

        # Security Appliances
        "ids_ips": "Security",
        "siem": "Security",
        "proxy": "Security",
        "authentication_server": "Security",

        # Embedded & Specialty
        "embedded": "Embedded",
        "kiosk": "Embedded",
        "pos_terminal": "Embedded",
        "atm": "Embedded",
        "digital_signage": "Embedded",

        # Medical
        "medical_device": "Medical",
        "patient_monitor": "Medical",
        "imaging_system": "Medical",
    }
    result["device_category"] = DEVICE_CATEGORIES.get(result["device_type"], "Unknown")

    return result
