"""
VerdictEngine: weighted evidence aggregation for device fingerprinting.

Replaces the monolithic ``aggregate_evidence()`` helper in lookup.py with a
structured dataclass output and richer scoring logic (per-field certainty,
agreement bonuses, hostname coherence, vendor-OS inference, plausibility
cross-checks).
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .lookup import FingerprintMatch
from .os_intelligence import VENDOR_OS_DATABASE, ValidationStatus, check_os_plausibility


# ---------------------------------------------------------------------------
# Manufacturer hygiene
# ---------------------------------------------------------------------------
# OS names, kernels, and device-type words are never manufacturers, but they
# routinely leak into the manufacturer field from SNMP sysDescr, nmap OS class
# strings, UPnP descriptions ("Router,"), and CPE parsing. A real vendor is
# never literally "Linux" or "Router". Reject these as standalone manufacturer
# values (substrings are fine -- "Bridgewater" must survive while bare "Bridge"
# is dropped).
_NON_MANUFACTURER_VALUES = frozenset({
    # operating systems / kernels / platforms
    "linux", "windows", "windows server", "windows ce", "freebsd", "openbsd",
    "netbsd", "unix", "macos", "mac os", "os x", "ios", "ipados", "android",
    "embedded", "embedded linux", "rtos", "vxworks", "qnx", "junos", "fortios",
    "chrome os", "chromeos", "tizen", "webos", "solaris", "aix", "hp-ux",
    # device-type / role words
    "router", "switch", "firewall", "gateway", "access point", "accesspoint",
    "ap", "wap", "server", "workstation", "computer", "pc", "desktop",
    "laptop", "printer", "scanner", "camera", "phone", "smartphone", "tablet",
    "bridge", "modem", "nas", "load balancer", "controller", "hub", "repeater",
    "general purpose", "storage", "media device", "media server", "iot",
    "appliance", "device", "unknown", "n/a", "none", "null",
})


def _clean_manufacturer(value: Optional[str]) -> Optional[str]:
    """Return a usable manufacturer string, or None if *value* is really an OS
    name, a device-type word, or garbage. Strips trailing punctuation so a
    UPnP "Router," collapses to "router" and is then rejected."""
    if not value:
        return None
    cleaned = value.strip().strip(",;:.|/").strip()
    if not cleaned:
        return None
    if cleaned.lower() in _NON_MANUFACTURER_VALUES:
        return None
    return cleaned


# ---------------------------------------------------------------------------
# Verdict dataclass
# ---------------------------------------------------------------------------

@dataclass
class Verdict:
    """Aggregated identification result for a single network entity."""

    device_type: str = "Unknown"
    device_category: str = "Unknown"
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    os_family: Optional[str] = None
    os_name: Optional[str] = None
    os_version: Optional[str] = None
    hostname: Optional[str] = None

    # Per-field certainty  (0.0 – 1.0)
    device_type_certainty: float = 0.0
    manufacturer_certainty: float = 0.0
    os_family_certainty: float = 0.0
    overall_certainty: float = 0.0

    evidence_chain: List[FingerprintMatch] = field(default_factory=list)
    computed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # -- helpers --
    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["computed_at"] = self.computed_at.isoformat()
        d["evidence_chain"] = [m.to_dict() for m in self.evidence_chain]
        return d


# ---------------------------------------------------------------------------
# VerdictEngine
# ---------------------------------------------------------------------------

class VerdictEngine:
    """Stateless engine that turns a bag of ``FingerprintMatch`` objects into
    a single :class:`Verdict`."""

    # ---- Source reliability weights ----------------------------------------

    SOURCE_WEIGHTS: Dict[str, float] = {
        # Tier 0: Infrastructure protocols
        "lldp": 0.95,
        "cdp": 0.92,
        "snmp_sysdescr": 0.90,
        # Tier 1: Large curated databases
        "huginn_device": 0.92,
        "hostname_domain": 0.91,
        "huginn_dhcp_vendor": 0.90,
        "satori_smb": 0.88,
        "nmap_os": 0.88,
        "huginn_dhcp": 0.87,
        "oui": 0.85,
        "satori_ssh": 0.85,
        # Tier 2: Standard tools
        "satori_http": 0.82,
        "tcp": 0.80,
        "banner": 0.80,
        "banner_cache": 0.80,
        "satori_useragent": 0.80,
        "upnp_ssdp": 0.78,
        "mdns": 0.78,
        "dhcp_opt60": 0.75,
        "satori_sip": 0.75,
        "hostname": 0.72,
        # Tier 3: Secondary
        "http_ua": 0.70,
        "http_title": 0.70,
        "satori_dhcp": 0.70,
        "ws_discovery": 0.68,
        "dhcp_opt55": 0.68,
        # Tier 4: Heuristic
        "ttl": 0.55,
    }

    # ---- Device-type → category mapping -----------------------------------

    DEVICE_CATEGORIES: Dict[str, str] = {
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

    # Vendor keywords used for hostname coherence checks
    _VENDOR_KEYWORDS: List[str] = [
        "lutron", "sonos", "cisco", "ubiquiti", "ubnt", "mikrotik",
        "aruba", "juniper", "fortinet", "netgear", "tplink", "tp-link",
        "hikvision", "dahua", "axis", "ruckus", "meraki", "dlink",
        "synology", "qnap", "apple", "samsung", "huawei", "zyxel",
    ]

    _NETWORK_EQUIPMENT_TYPES = frozenset({
        "switch", "router", "access_point", "firewall", "wireless_bridge",
        "wireless_controller", "gateway", "mesh_router", "load_balancer",
    })

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def compute(self, matches: List[FingerprintMatch]) -> Verdict:
        """Aggregate *matches* into a single :class:`Verdict`."""

        if not matches:
            return Verdict()

        capped = self._cap_evidence(matches)

        # --- weighted voting per field ---
        field_votes: Dict[str, Dict[str, float]] = {
            "device_type": defaultdict(float),
            "manufacturer": defaultdict(float),
            "os_family": defaultdict(float),
        }
        # Track distinct sources per (field, value) for agreement bonus
        field_sources: Dict[str, Dict[str, set]] = {
            "device_type": defaultdict(set),
            "manufacturer": defaultdict(set),
            "os_family": defaultdict(set),
        }

        for m in capped:
            weight = self.SOURCE_WEIGHTS.get(m.source, 0.5) * m.confidence

            if m.device_type:
                field_votes["device_type"][m.device_type] += weight
                field_sources["device_type"][m.device_type].add(m.source)
            mfr = _clean_manufacturer(m.manufacturer)
            if mfr:
                field_votes["manufacturer"][mfr] += weight
                field_sources["manufacturer"][mfr].add(m.source)
            if m.os_family:
                field_votes["os_family"][m.os_family] += weight
                field_sources["os_family"][m.os_family].add(m.source)

        # Apply agreement bonuses
        for fld in field_votes:
            for value in field_votes[fld]:
                n_sources = len(field_sources[fld][value])
                bonus = self._agreement_bonus(n_sources)
                field_votes[fld][value] *= bonus

        # --- OUI / hostname_domain manufacturer validation ---
        self._apply_authoritative_boosts(capped, field_votes)

        # --- pick winners ---
        device_type = self._pick_winner(field_votes["device_type"], "Unknown")
        manufacturer = self._pick_winner(field_votes["manufacturer"])
        os_family = self._pick_winner(field_votes["os_family"])

        # --- hostname ---
        hostname = self._resolve_hostname(capped, manufacturer)

        # --- OS version from best OS match ---
        os_version: Optional[str] = None
        os_matches = [m for m in capped if m.os_family]
        if os_matches:
            best_os = max(os_matches, key=lambda m: m.confidence)
            os_version = best_os.os_version

        # --- infer OS when no evidence ---
        if os_family is None and manufacturer is not None:
            os_family = self._infer_os_from_vendor(manufacturer)

        # --- plausibility cross-check ---
        if device_type != "Unknown" and os_family is not None:
            plausible, _reason, _score = check_os_plausibility(
                os_family, manufacturer, device_type
            )
            if not plausible:
                # Demote os_family certainty; keep the value but mark low
                # confidence so downstream consumers can decide
                total = sum(field_votes["os_family"].values()) or 1.0
                field_votes["os_family"][os_family] = total * 0.3

        # --- certainties ---
        dt_cert = self._certainty(field_votes["device_type"], device_type)
        mf_cert = self._certainty(field_votes["manufacturer"], manufacturer)
        os_cert = self._certainty(field_votes["os_family"], os_family)
        overall = max(dt_cert, mf_cert, os_cert)

        # --- model: pick from highest-confidence match that has one ---
        model: Optional[str] = None
        model_matches = [m for m in capped if m.model]
        if model_matches:
            model = max(model_matches, key=lambda m: m.confidence).model

        return Verdict(
            device_type=device_type,
            device_category=self.DEVICE_CATEGORIES.get(device_type, "Unknown"),
            manufacturer=manufacturer,
            model=model,
            os_family=os_family,
            os_name=os_family,  # alias; refine later if needed
            os_version=os_version,
            hostname=hostname,
            device_type_certainty=dt_cert,
            manufacturer_certainty=mf_cert,
            os_family_certainty=os_cert,
            overall_certainty=overall,
            evidence_chain=list(capped),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _cap_evidence(
        matches: List[FingerprintMatch],
        per_source: int = 3,
        total: int = 100,
    ) -> List[FingerprintMatch]:
        """Keep at most *per_source* matches per source and *total* overall."""
        grouped: Dict[str, List[FingerprintMatch]] = defaultdict(list)
        for m in matches:
            grouped[m.source].append(m)

        kept: List[FingerprintMatch] = []
        for source, items in grouped.items():
            # Keep the last N (most recent) per source
            kept.extend(items[-per_source:])

        return kept[:total]

    @staticmethod
    def _agreement_bonus(n_sources: int) -> float:
        """Return a multiplicative bonus based on how many distinct sources
        agree on a value."""
        if n_sources <= 1:
            return 1.0
        if n_sources == 2:
            return 1.1
        if n_sources == 3:
            return 1.2
        return 1.25

    @staticmethod
    def _pick_winner(
        votes: Dict[str, float],
        default: Optional[str] = None,
    ) -> Optional[str]:
        if not votes:
            return default
        winner = max(votes, key=lambda k: votes[k])
        # Return default when default is a str and winner would be None-ish
        return winner if winner else default

    @staticmethod
    def _certainty(votes: Dict[str, float], winner: Optional[str]) -> float:
        if not votes or winner is None:
            return 0.0
        total = sum(votes.values())
        if total == 0.0:
            return 0.0
        return min(votes.get(winner, 0.0) / total, 1.0)

    # ---- authoritative manufacturer / device-type boosts -----------------

    def _apply_authoritative_boosts(
        self,
        matches: List[FingerprintMatch],
        field_votes: Dict[str, Dict[str, float]],
    ) -> None:
        """Boost OUI / hostname_domain manufacturer and device_type scores."""

        oui_manufacturer: Optional[str] = None
        oui_device_type: Optional[str] = None
        domain_manufacturer: Optional[str] = None
        domain_device_type: Optional[str] = None
        hostname_device_type: Optional[str] = None

        for m in matches:
            if m.source == "oui" and m.manufacturer and oui_manufacturer is None:
                oui_manufacturer = _clean_manufacturer(m.manufacturer)
                oui_device_type = m.device_type
            if m.source == "hostname_domain" and m.manufacturer and domain_manufacturer is None:
                domain_manufacturer = _clean_manufacturer(m.manufacturer)
                domain_device_type = m.device_type
            if m.source == "hostname" and m.device_type and m.confidence >= 0.60 and hostname_device_type is None:
                hostname_device_type = m.device_type

        authoritative_manufacturer = domain_manufacturer or oui_manufacturer

        # Choose device type: domain > hostname pattern > OUI
        if domain_device_type:
            authoritative_device_type = domain_device_type
        elif hostname_device_type:
            authoritative_device_type = hostname_device_type
        else:
            authoritative_device_type = oui_device_type

        if authoritative_manufacturer:
            field_votes["manufacturer"][authoritative_manufacturer] = (
                field_votes["manufacturer"].get(authoritative_manufacturer, 0) + 2.0
            )

        if authoritative_device_type:
            if hostname_device_type:
                boost = 1.5
            elif authoritative_device_type in self._NETWORK_EQUIPMENT_TYPES:
                boost = 1.5
            else:
                boost = 0.5

            field_votes["device_type"][authoritative_device_type] = (
                field_votes["device_type"].get(authoritative_device_type, 0) + boost
            )

    # ---- hostname coherence ----------------------------------------------

    def _resolve_hostname(
        self,
        matches: List[FingerprintMatch],
        manufacturer: Optional[str],
    ) -> Optional[str]:
        """Return a cleaned hostname, rejecting it when it conflicts with the
        resolved manufacturer."""

        raw: Optional[str] = None
        for m in matches:
            if m.source in ("hostname", "mdns", "lldp", "cdp", "snmp_sysdescr"):
                hostname_val = m.raw_data.get("hostname") or m.raw_data.get("name")
                if hostname_val:
                    raw = hostname_val
                    break

        if raw is None:
            return None

        cleaned = self._clean_hostname(raw)
        if not cleaned:
            return None

        # Coherence: reject hostname if it contains a vendor keyword that
        # conflicts with the resolved manufacturer
        if manufacturer:
            mfr_lower = manufacturer.lower()
            cleaned_lower = cleaned.lower()
            for kw in self._VENDOR_KEYWORDS:
                if kw in cleaned_lower and kw not in mfr_lower:
                    # Hostname mentions a different vendor – reject it
                    return None

        return cleaned

    @staticmethod
    def _clean_hostname(raw: str) -> Optional[str]:
        """Strip mDNS / AirPlay suffixes and hex prefixes."""
        h = raw.strip()
        # Strip common mDNS suffixes
        for suffix in ("._tcp.local", ".local"):
            if h.lower().endswith(suffix):
                h = h[: -len(suffix)]
        # Strip AirPlay-style hex prefix  (e.g. "AABBCCDDEE@DeviceName")
        if "@" in h:
            h = h.split("@", 1)[1]
        # Remove leading/trailing whitespace / dots
        h = h.strip(". ")
        return h or None

    # ---- vendor → OS inference -------------------------------------------

    @staticmethod
    def _infer_os_from_vendor(manufacturer: str) -> Optional[str]:
        """When no OS evidence exists, derive os_family from the manufacturer
        using ``VENDOR_OS_DATABASE``."""

        mfr_lower = manufacturer.lower()
        for vendor, info in VENDOR_OS_DATABASE.items():
            names = [vendor.lower()] + [a.lower() for a in info.get("aliases", [])]
            if mfr_lower in names:
                return info.get("os_family")

        # Common fallbacks not necessarily in VENDOR_OS_DATABASE
        _QUICK_MAP: Dict[str, str] = {
            "apple": "macOS",
            "microsoft": "Windows",
            "samsung": "Android",
            "google": "Android",
            "amazon": "Fire OS",
        }
        return _QUICK_MAP.get(mfr_lower)
