"""
Built-in fingerprint patterns for Cygor.

These patterns are maintained in-code and provide device identification
without requiring external database syncs.

Patterns:
- Banner: SSH, HTTP, SMB, FTP, and many more service banner regex
- mDNS: Service type to device mappings
- DHCP: Option 55/60 fingerprints
"""

from .banner_patterns import (
    # Core protocol patterns (6-element tuples)
    SSH_PATTERNS,
    HTTP_PATTERNS,
    SMB_PATTERNS,
    FTP_PATTERNS,
    SMTP_PATTERNS,
    IMAP_POP_PATTERNS,
    TELNET_PATTERNS,
    DNS_PATTERNS,
    LDAP_PATTERNS,
    SNMP_PATTERNS,
    RDP_VNC_PATTERNS,
    SIP_PATTERNS,
    NTP_PATTERNS,
    MQTT_PATTERNS,
    PRINTER_PATTERNS,
    GAMING_MEDIA_PATTERNS,
    NETWORK_PATTERNS,
    STORAGE_PATTERNS,
    BACKUP_PATTERNS,
    KERBEROS_PATTERNS,
    RADIUS_PATTERNS,
    MESSAGE_QUEUE_PATTERNS,
    CACHE_PATTERNS,
    STREAMING_PATTERNS,
    VCS_PATTERNS,
    CHAT_PATTERNS,
    WEBRTC_PATTERNS,
    INDUSTRIAL_PATTERNS,
    IOT_PROTOCOL_PATTERNS,
    FILE_SYNC_PATTERNS,
    API_PATTERNS,
    # Extended patterns (7-element tuples with device_type)
    IOT_HTTP_PATTERNS,
    SCADA_PATTERNS,
    VIRTUALIZATION_PATTERNS,
    CONTAINER_PATTERNS,
    WEBAPP_PATTERNS,
    DATABASE_PATTERNS,
    SECURITY_PATTERNS,
    COMMUNICATION_PATTERNS,
    CLOUD_PATTERNS,
    # Matching function
    match_banner,
)
from .mdns_patterns import (
    MDNS_SERVICE_PATTERNS,
    MDNS_NAME_PATTERNS,
    match_mdns_service,
)
from .dhcp_patterns import (
    DHCP_OPT55_PATTERNS,
    DHCP_OPT60_PATTERNS,
    match_dhcp_opt55,
    match_dhcp_opt60,
)
from .vendor_patterns import (
    UBIQUITI_MAC_PREFIXES,
    UBIQUITI_BANNER_PATTERNS,
    UBIQUITI_PORT_SIGNATURES,
    MIKROTIK_MAC_PREFIXES,
    MIKROTIK_BANNER_PATTERNS,
    enrich_ubiquiti_device,
    enrich_mikrotik_device,
    enrich_vendor_device,
)

# All 6-element pattern lists (regex, product, vendor, os_family, version_regex, confidence)
BASIC_PATTERN_LISTS = [
    ("ssh", SSH_PATTERNS),
    ("http", HTTP_PATTERNS),
    ("smb", SMB_PATTERNS),
    ("ftp", FTP_PATTERNS),
    ("smtp", SMTP_PATTERNS),
    ("imap", IMAP_POP_PATTERNS),
    ("telnet", TELNET_PATTERNS),
    ("dns", DNS_PATTERNS),
    ("ldap", LDAP_PATTERNS),
    ("snmp", SNMP_PATTERNS),
    ("rdp", RDP_VNC_PATTERNS),
    ("sip", SIP_PATTERNS),
    ("ntp", NTP_PATTERNS),
    ("mqtt", MQTT_PATTERNS),
    ("printer", PRINTER_PATTERNS),
    ("gaming", GAMING_MEDIA_PATTERNS),
    ("network", NETWORK_PATTERNS),
    ("storage", STORAGE_PATTERNS),
    ("backup", BACKUP_PATTERNS),
    ("kerberos", KERBEROS_PATTERNS),
    ("radius", RADIUS_PATTERNS),
    ("mq", MESSAGE_QUEUE_PATTERNS),
    ("cache", CACHE_PATTERNS),
    ("streaming", STREAMING_PATTERNS),
    ("vcs", VCS_PATTERNS),
    ("chat", CHAT_PATTERNS),
    ("webrtc", WEBRTC_PATTERNS),
    ("industrial", INDUSTRIAL_PATTERNS),
    ("iot", IOT_PROTOCOL_PATTERNS),
    ("filesync", FILE_SYNC_PATTERNS),
    ("api", API_PATTERNS),
]

# All 7-element pattern lists (regex, product, vendor, os_family, version_regex, confidence, device_type)
EXTENDED_PATTERN_LISTS = [
    ("iot_http", IOT_HTTP_PATTERNS),
    ("scada", SCADA_PATTERNS),
    ("virtualization", VIRTUALIZATION_PATTERNS),
    ("container", CONTAINER_PATTERNS),
    ("webapp", WEBAPP_PATTERNS),
    ("database", DATABASE_PATTERNS),
    ("security", SECURITY_PATTERNS),
    ("communication", COMMUNICATION_PATTERNS),
    ("cloud", CLOUD_PATTERNS),
]

__all__ = [
    # Core protocol patterns
    "SSH_PATTERNS",
    "HTTP_PATTERNS",
    "SMB_PATTERNS",
    "FTP_PATTERNS",
    "SMTP_PATTERNS",
    "IMAP_POP_PATTERNS",
    "TELNET_PATTERNS",
    "DNS_PATTERNS",
    "LDAP_PATTERNS",
    "SNMP_PATTERNS",
    "RDP_VNC_PATTERNS",
    "SIP_PATTERNS",
    "NTP_PATTERNS",
    "MQTT_PATTERNS",
    "PRINTER_PATTERNS",
    "GAMING_MEDIA_PATTERNS",
    "NETWORK_PATTERNS",
    "STORAGE_PATTERNS",
    "BACKUP_PATTERNS",
    "KERBEROS_PATTERNS",
    "RADIUS_PATTERNS",
    "MESSAGE_QUEUE_PATTERNS",
    "CACHE_PATTERNS",
    "STREAMING_PATTERNS",
    "VCS_PATTERNS",
    "CHAT_PATTERNS",
    "WEBRTC_PATTERNS",
    "INDUSTRIAL_PATTERNS",
    "IOT_PROTOCOL_PATTERNS",
    "FILE_SYNC_PATTERNS",
    "API_PATTERNS",
    # Extended patterns
    "IOT_HTTP_PATTERNS",
    "SCADA_PATTERNS",
    "VIRTUALIZATION_PATTERNS",
    "CONTAINER_PATTERNS",
    "WEBAPP_PATTERNS",
    "DATABASE_PATTERNS",
    "SECURITY_PATTERNS",
    "COMMUNICATION_PATTERNS",
    "CLOUD_PATTERNS",
    # Pattern list groups
    "BASIC_PATTERN_LISTS",
    "EXTENDED_PATTERN_LISTS",
    # Matching function
    "match_banner",
    # mDNS patterns
    "MDNS_SERVICE_PATTERNS",
    "MDNS_NAME_PATTERNS",
    "match_mdns_service",
    # DHCP patterns
    "DHCP_OPT55_PATTERNS",
    "DHCP_OPT60_PATTERNS",
    "match_dhcp_opt55",
    "match_dhcp_opt60",
    # Vendor-specific patterns
    "UBIQUITI_MAC_PREFIXES",
    "UBIQUITI_BANNER_PATTERNS",
    "UBIQUITI_PORT_SIGNATURES",
    "MIKROTIK_MAC_PREFIXES",
    "MIKROTIK_BANNER_PATTERNS",
    "enrich_ubiquiti_device",
    "enrich_mikrotik_device",
    "enrich_vendor_device",
]
