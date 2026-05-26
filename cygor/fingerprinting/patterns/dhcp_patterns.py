"""
Built-in DHCP fingerprint patterns for device identification.

DHCP Option 55 (Parameter Request List) and Option 60 (Vendor Class Identifier)
patterns can identify device types, operating systems, and manufacturers.
"""

import re
import hashlib
from typing import Optional, Dict, List, Tuple

# =============================================================================
# DHCP Option 55 (Parameter Request List) Patterns
# =============================================================================

# options_list -> (device_type, os_family, manufacturer, confidence)
DHCP_OPT55_PATTERNS: Dict[str, Tuple[str, Optional[str], Optional[str], int]] = {
    # Windows patterns
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252": ("workstation", "Windows", "Microsoft", 85),
    "1,15,3,6,44,46,47,31,33,121,249,252,43": ("workstation", "Windows 10/11", "Microsoft", 90),
    "1,3,6,15,44,46,47,31,33,121,249,252": ("workstation", "Windows", "Microsoft", 80),
    "1,15,3,6,44,46,47,31,33,249,43": ("workstation", "Windows 7", "Microsoft", 85),
    "1,15,3,6,44,46,47,31,33,43": ("workstation", "Windows XP", "Microsoft", 80),

    # Linux patterns
    "1,28,2,3,15,6,119,12,44,47,26,121,42": ("workstation", "Linux", None, 80),
    "1,3,6,12,15,17,28,40,41,42": ("workstation", "Linux (Debian)", None, 85),
    "1,3,6,12,15,28,42,119": ("workstation", "Linux (Ubuntu)", None, 85),
    "1,28,2,3,15,6,12": ("workstation", "Linux", None, 75),
    "1,3,6,15,119,95,252,44,46,101": ("workstation", "Linux (Fedora)", None, 85),

    # macOS/iOS patterns
    "1,121,3,6,15,119,252,95,44,46": ("workstation", "macOS", "Apple", 90),
    "1,3,6,15,119,252": ("mobile", "iOS", "Apple", 85),
    "1,3,6,15,119,252,95,44,46": ("mobile", "iOS", "Apple", 88),
    "1,121,3,6,15,119,252": ("workstation", "macOS", "Apple", 85),
    "1,3,6,15,119,95,252,44,46,47": ("tablet", "iPadOS", "Apple", 88),

    # Android patterns
    "1,3,6,15,26,28,51,58,59,43": ("mobile", "Android", None, 80),
    "1,3,6,28,33,51,58,59": ("mobile", "Android", None, 75),
    "1,3,6,15,26,28,51,58,59": ("mobile", "Android", None, 78),
    "1,121,3,6,15,26,28,51,58,59,43": ("mobile", "Android", None, 82),

    # Network devices - Cisco
    "1,3,6,15,66,67,150": ("router", "IOS", "Cisco", 85),
    "1,3,6,15,42,66,150": ("switch", "IOS", "Cisco", 85),
    "1,66,6,15,44,3,67,12,43,150": ("voip_phone", "IOS", "Cisco", 90),
    "1,3,66,15,6,67,2,42,43": ("access_point", "IOS", "Cisco", 85),

    # Network devices - Other vendors
    "1,3,6,12,15,28,42,43": ("access_point", None, None, 70),
    "1,3,6,15,43,66,67": ("router", None, None, 65),
    "1,3,28,6": ("router", None, "MikroTik", 75),
    "1,3,6,15,119,252,44,46": ("router", "Linux (Embedded)", None, 70),

    # Printers
    "1,3,6,15,44,47": ("printer", None, None, 75),
    "6,3,1,15,66,67,13,44": ("printer", None, "HP", 80),
    "1,3,6,15,44,47,43": ("printer", None, None, 75),
    "1,3,6,12,15,44,47": ("printer", None, None, 70),
    "1,3,6,23,44": ("printer", None, "Epson", 75),

    # VoIP phones
    "1,3,6,15,66,67,150,43": ("voip_phone", None, None, 80),
    "1,3,42,6,15,66,67,150": ("voip_phone", None, "Polycom", 85),
    "1,3,6,15,66,67,42,150,12": ("voip_phone", None, "Yealink", 85),

    # IoT devices
    "1,3,6,15,28,33": ("iot", None, None, 60),
    "1,3,6,12,15,28,42": ("iot", "Linux (Embedded)", None, 65),
    "1,3,6,12,15,28": ("iot", None, None, 55),
    "1,3,6": ("iot", None, None, 40),

    # Smart TV
    "1,3,6,15,28,33,44": ("smart_tv", None, None, 65),
    "1,3,6,28,43": ("smart_tv", None, "Samsung", 70),

    # Gaming consoles
    "1,3,6,15,119,252,44,46,121": ("game_console", None, None, 60),
}

# =============================================================================
# DHCP Option 60 (Vendor Class Identifier) Patterns
# =============================================================================

# (regex_pattern, device_type, manufacturer, os_family, confidence)
DHCP_OPT60_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], int]] = [
    # Windows
    (r"^MSFT\s+\d+\.\d+", "workstation", "Microsoft", "Windows", 90),
    (r"^MSFT\s+5\.0", "workstation", "Microsoft", "Windows 2000/XP", 85),

    # Android
    (r"^android-dhcp-\d+", "mobile", None, "Android", 85),
    (r"^dhcpcd-\d+\.\d+\.\d+:Linux", "mobile", None, "Android", 80),

    # Linux
    (r"^dhcpcd-\d+", "workstation", None, "Linux", 75),
    (r"^udhcp\s+\d+", "router", None, "Linux (Embedded)", 70),
    (r"^dhclient", "workstation", None, "Linux", 70),

    # Cisco
    (r"^Cisco\s+AP", "access_point", "Cisco", None, 95),
    (r"^Cisco\s+Systems", "network", "Cisco", "IOS", 90),
    (r"^Cisco-IP-Phone", "voip_phone", "Cisco", None, 95),
    (r"^Cisco.*Firepower", "firewall", "Cisco", None, 95),
    (r"^Cisco.*ASA", "firewall", "Cisco", None, 95),

    # Aruba/HPE
    (r"^Aruba\s+AP", "access_point", "Aruba", None, 95),
    (r"^ArubaOS", "network", "Aruba", "ArubaOS", 90),

    # HP
    (r"^HP\s+(LaserJet|OfficeJet|DeskJet|Printer)", "printer", "HP", None, 95),
    (r"^Hewlett-?Packard", "workstation", "HP", None, 70),

    # Printers
    (r"^EPSON", "printer", "Epson", None, 95),
    (r"^Brother", "printer", "Brother", None, 90),
    (r"^Canon", "printer", "Canon", None, 90),
    (r"^XEROX", "printer", "Xerox", None, 90),
    (r"^Ricoh", "printer", "Ricoh", None, 90),
    (r"^Lexmark", "printer", "Lexmark", None, 90),
    (r"^Konica.*Minolta", "printer", "Konica Minolta", None, 90),
    (r"^Sharp.*MFP", "multifunction", "Sharp", None, 85),

    # Apple
    (r"^AAPLBSDPC/", "workstation", "Apple", "macOS", 90),

    # VoIP Phones
    (r"^Polycom", "voip_phone", "Polycom", None, 95),
    (r"^Yealink", "voip_phone", "Yealink", None, 95),
    (r"^Grandstream", "voip_phone", "Grandstream", None, 90),
    (r"^Snom", "voip_phone", "Snom", None, 90),
    (r"^Avaya", "voip_phone", "Avaya", None, 90),
    (r"^Mitel", "voip_phone", "Mitel", None, 90),
    (r"^SIP", "voip_phone", None, None, 70),
    (r"^VoIP", "voip_phone", None, None, 70),

    # Network Devices
    (r"^MikroTik", "router", "MikroTik", "RouterOS", 95),
    (r"^(ubnt|UniFi)", "access_point", "Ubiquiti", None, 90),
    (r"^Ruckus", "access_point", "Ruckus", None, 90),
    (r"^Meraki", "access_point", "Cisco Meraki", None, 95),
    (r"^Fortinet", "firewall", "Fortinet", "FortiOS", 95),
    (r"^PaloAlto", "firewall", "Palo Alto", "PAN-OS", 95),
    (r"^SonicWall", "firewall", "SonicWall", None, 90),
    (r"^Juniper", "router", "Juniper", "JunOS", 90),
    (r"^F5.*BIG-IP", "load_balancer", "F5", None, 95),
    (r"^Citrix.*NetScaler", "load_balancer", "Citrix", None, 95),
    (r"^A10.*Networks", "load_balancer", "A10 Networks", None, 90),

    # Virtualization
    (r"^VMware", "virtual_machine", "VMware", None, 90),
    (r"^VMware.*ESXi", "esxi", "VMware", "ESXi", 95),
    (r"^Proxmox", "proxmox", "Proxmox", "Proxmox VE", 95),
    (r"^Hyper-V", "hyper_v", "Microsoft", "Windows Server", 90),
    (r"^Citrix.*Xen", "xen", "Citrix", "XenServer", 90),
    (r"^oVirt", "kvm_host", "Red Hat", "Linux", 85),
    (r"^Nutanix", "hypervisor", "Nutanix", "AHV", 90),

    # Containers
    (r"^Docker", "docker_host", "Docker", None, 85),
    (r"^Kubernetes", "kubernetes_node", "CNCF", None, 85),
    (r"^Rancher", "container_host", "SUSE", None, 85),
    (r"^OpenShift", "openshift", "Red Hat", None, 90),
    (r"^CoreOS", "container_host", "Red Hat", "CoreOS", 85),
    (r"^Flatcar", "container_host", None, "Flatcar", 85),

    # IP Cameras
    (r"^Hikvision", "ip_camera", "Hikvision", None, 95),
    (r"^Dahua", "ip_camera", "Dahua", None, 95),
    (r"^AXIS", "ip_camera", "Axis", None, 95),
    (r"^Foscam", "ip_camera", "Foscam", None, 90),
    (r"^Amcrest", "ip_camera", "Amcrest", None, 90),
    (r"^Reolink", "ip_camera", "Reolink", None, 90),
    (r"^Vivotek", "ip_camera", "Vivotek", None, 90),
    (r"^Mobotix", "ip_camera", "Mobotix", None, 90),
    (r"^Avigilon", "ip_camera", "Avigilon", None, 90),
    (r"^Hanwha.*Wisenet", "ip_camera", "Hanwha", None, 90),
    (r"^Bosch.*Video", "ip_camera", "Bosch", None, 85),

    # Smart Home / IoT
    (r"^Philips.*hue", "smart_home", "Philips", None, 95),
    (r"^SmartThings", "home_hub", "Samsung", None, 90),
    (r"^Nest", "thermostat", "Google", None, 90),
    (r"^ecobee", "thermostat", "ecobee", None, 90),
    (r"^Ring", "doorbell", "Ring", None, 90),
    (r"^Amazon.*Echo", "smart_speaker", "Amazon", None, 90),
    (r"^Google.*Home", "smart_speaker", "Google", None, 90),
    (r"^Sonos", "smart_speaker", "Sonos", None, 90),
    (r"^HomePod", "smart_speaker", "Apple", None, 90),
    (r"^Wemo", "smart_plug", "Belkin", None, 85),
    (r"^TP-Link.*Kasa", "smart_plug", "TP-Link", None, 85),
    (r"^Shelly", "smart_plug", "Shelly", None, 85),
    (r"^Tuya", "iot", "Tuya", None, 80),
    (r"^LIFX", "smart_lighting", "LIFX", None, 85),
    (r"^Lutron", "smart_lighting", "Lutron", None, 85),
    (r"^August", "smart_lock", "August", None, 85),

    # NAS devices
    (r"^Synology", "nas", "Synology", "DSM", 95),
    (r"^QNAP", "nas", "QNAP", "QTS", 95),
    (r"^Western.*Digital.*My.*Cloud", "nas", "Western Digital", None, 90),
    (r"^Buffalo", "nas", "Buffalo", None, 85),
    (r"^TrueNAS", "nas", None, "TrueNAS", 90),
    (r"^FreeNAS", "nas", None, "FreeNAS", 85),
    (r"^NetApp", "nas", "NetApp", None, 95),
    (r"^EMC", "storage_array", "Dell EMC", None, 90),
    (r"^Pure.*Storage", "storage_array", "Pure Storage", None, 90),

    # SCADA/ICS
    (r"^Siemens.*S7", "plc", "Siemens", None, 95),
    (r"^Siemens.*SIMATIC", "plc", "Siemens", None, 95),
    (r"^Siemens.*SCALANCE", "industrial_switch", "Siemens", None, 90),
    (r"^Schneider.*Modicon", "plc", "Schneider Electric", None, 95),
    (r"^Schneider", "plc", "Schneider Electric", None, 80),
    (r"^Allen-Bradley", "plc", "Rockwell", None, 95),
    (r"^Rockwell", "plc", "Rockwell", None, 90),
    (r"^ABB.*AC500", "plc", "ABB", None, 95),
    (r"^ABB", "plc", "ABB", None, 80),
    (r"^GE.*Fanuc", "plc", "GE", None, 90),
    (r"^Omron", "plc", "Omron", None, 90),
    (r"^Mitsubishi.*MELSEC", "plc", "Mitsubishi", None, 95),
    (r"^Beckhoff", "plc", "Beckhoff", None, 90),
    (r"^Phoenix.*Contact", "plc", "Phoenix Contact", None, 90),
    (r"^WAGO", "plc", "WAGO", None, 85),
    (r"^Moxa", "industrial_switch", "Moxa", None, 90),
    (r"^Hirschmann", "industrial_switch", "Hirschmann", None, 90),
    (r"^Red.*Lion", "industrial_switch", "Red Lion", None, 85),
    (r"^Advantech", "industrial_switch", "Advantech", None, 85),
    (r"^BACnet", "building_automation", None, None, 80),
    (r"^Tridium.*Niagara", "building_automation", "Tridium", None, 90),
    (r"^Johnson.*Controls", "building_automation", "Johnson Controls", None, 90),

    # Security Appliances
    (r"^Snort", "ids_ips", "Cisco", None, 80),
    (r"^Suricata", "ids_ips", "OISF", None, 80),
    (r"^Wazuh", "ids_ips", "Wazuh", None, 85),
    (r"^Splunk", "siem", "Splunk", None, 90),
    (r"^QRadar", "siem", "IBM", None, 90),
    (r"^ArcSight", "siem", "Micro Focus", None, 85),
    (r"^Squid", "proxy", None, None, 80),

    # PBX Systems
    (r"^Asterisk", "pbx", "Sangoma", None, 90),
    (r"^FreePBX", "pbx", "Sangoma", None, 90),
    (r"^3CX", "pbx", "3CX", None, 90),

    # Medical Devices
    (r"^Philips.*Healthcare", "medical_device", "Philips", None, 85),
    (r"^GE.*Healthcare", "medical_device", "GE", None, 85),
    (r"^Siemens.*Healthineers", "medical_device", "Siemens", None, 85),

    # Media Devices
    (r"^Roku", "streaming_device", "Roku", None, 90),
    (r"^Apple.*TV", "streaming_device", "Apple", "tvOS", 90),
    (r"^Chromecast", "streaming_device", "Google", None, 90),
    (r"^Fire.*TV", "streaming_device", "Amazon", None, 90),
    (r"^Samsung.*Smart.*TV", "smart_tv", "Samsung", "Tizen", 90),
    (r"^LG.*Smart.*TV", "smart_tv", "LG", "webOS", 90),
    (r"^Sony.*Bravia", "smart_tv", "Sony", None, 85),
    (r"^PlayStation", "game_console", "Sony", "PlayStation", 95),
    (r"^Xbox", "game_console", "Microsoft", "Xbox", 95),
    (r"^Nintendo", "game_console", "Nintendo", None, 90),

    # Thin Clients
    (r"^Dell.*Wyse", "thin_client", "Dell", None, 90),
    (r"^HP.*Thin.*Client", "thin_client", "HP", None, 90),
    (r"^IGEL", "thin_client", "IGEL", None, 90),

    # IoT Gateways
    (r"^MultiTech", "iot_gateway", "MultiTech", None, 85),
    (r"^Digi.*Gateway", "iot_gateway", "Digi", None, 85),
    (r"^Sierra.*Wireless", "iot_gateway", "Sierra Wireless", None, 85),
]


# =============================================================================
# Matching Functions
# =============================================================================

def match_dhcp_opt55(options: str) -> Optional[Dict]:
    """
    Match DHCP Option 55 (Parameter Request List) to device info.

    Args:
        options: Comma-separated option numbers (e.g., "1,3,6,15,28,51")

    Returns:
        Dict with device info or None
    """
    if not options:
        return None

    # Normalize: sort options
    try:
        opts = [int(o.strip()) for o in options.split(",") if o.strip()]
        normalized = ",".join(str(o) for o in sorted(opts))
    except ValueError:
        normalized = options

    # Try exact match first
    if normalized in DHCP_OPT55_PATTERNS:
        device_type, os_family, manufacturer, confidence = DHCP_OPT55_PATTERNS[normalized]
        return {
            "device_type": device_type,
            "os_family": os_family,
            "manufacturer": manufacturer,
            "confidence": confidence,
            "match_source": "dhcp_opt55_exact",
        }

    # Try original order match
    if options in DHCP_OPT55_PATTERNS:
        device_type, os_family, manufacturer, confidence = DHCP_OPT55_PATTERNS[options]
        return {
            "device_type": device_type,
            "os_family": os_family,
            "manufacturer": manufacturer,
            "confidence": confidence,
            "match_source": "dhcp_opt55_exact",
        }

    # Try partial match (for common prefixes)
    for pattern, (device_type, os_family, manufacturer, confidence) in DHCP_OPT55_PATTERNS.items():
        if options.startswith(pattern[:20]) or normalized.startswith(pattern[:20]):
            return {
                "device_type": device_type,
                "os_family": os_family,
                "manufacturer": manufacturer,
                "confidence": confidence - 20,  # Lower confidence for partial match
                "match_source": "dhcp_opt55_partial",
            }

    return None


def match_dhcp_opt60(vendor_class: str) -> Optional[Dict]:
    """
    Match DHCP Option 60 (Vendor Class Identifier) to device info.

    Args:
        vendor_class: Vendor class identifier string

    Returns:
        Dict with device info or None
    """
    if not vendor_class:
        return None

    for pattern, device_type, manufacturer, os_family, confidence in DHCP_OPT60_PATTERNS:
        if re.match(pattern, vendor_class, re.IGNORECASE):
            return {
                "device_type": device_type,
                "manufacturer": manufacturer,
                "os_family": os_family,
                "confidence": confidence,
                "match_source": "dhcp_opt60",
            }

    return None


def get_dhcp_fingerprint_hash(options: str) -> str:
    """
    Generate MD5 hash of DHCP options for database lookup.

    Args:
        options: Comma-separated option numbers

    Returns:
        MD5 hash of normalized options
    """
    try:
        opts = [int(o.strip()) for o in options.split(",") if o.strip()]
        normalized = ",".join(str(o) for o in sorted(opts))
    except ValueError:
        normalized = options

    return hashlib.md5(normalized.encode()).hexdigest()
