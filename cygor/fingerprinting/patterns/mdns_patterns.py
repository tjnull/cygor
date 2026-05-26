"""
Built-in mDNS/Bonjour service patterns for device identification.

Maps mDNS service types to device types and manufacturers.
"""

import re
from typing import Optional, Dict, List, Tuple

# =============================================================================
# mDNS Service Type Patterns
# =============================================================================

# Service type -> (device_type, manufacturer, os_family, confidence)
MDNS_SERVICE_PATTERNS: Dict[str, Tuple[str, Optional[str], Optional[str], int]] = {
    # Apple services
    "_airplay._tcp": ("smart_tv", "Apple", "tvOS/macOS", 95),
    "_raop._tcp": ("smart_speaker", "Apple", "tvOS/macOS", 90),
    "_afpovertcp._tcp": ("workstation", "Apple", "macOS", 85),
    "_homekit._tcp": ("smart_home", None, None, 85),
    "_hap._tcp": ("smart_home", None, None, 85),
    "_companion-link._tcp": ("mobile", "Apple", "iOS", 90),
    "_apple-mobdev2._tcp": ("mobile", "Apple", "iOS", 90),
    "_remotepairing._tcp": ("mobile", "Apple", "iOS", 85),
    "_rdlink._tcp": ("mobile", "Apple", "iOS", 80),
    "_daap._tcp": ("workstation", "Apple", "macOS", 75),
    "_touch-able._tcp": ("mobile", "Apple", "iOS", 85),

    # Google services
    "_googlecast._tcp": ("smart_tv", "Google", None, 95),
    "_googlerpc._tcp": ("smart_speaker", "Google", None, 90),
    "_googlezone._tcp": ("smart_speaker", "Google", None, 85),

    # Printing
    "_printer._tcp": ("printer", None, None, 90),
    "_ipp._tcp": ("printer", None, None, 90),
    "_ipps._tcp": ("printer", None, None, 90),
    "_pdl-datastream._tcp": ("printer", None, None, 85),
    "_scanner._tcp": ("scanner", None, None, 90),
    "_uscan._tcp": ("scanner", None, None, 85),
    "_privet._tcp": ("printer", None, None, 80),

    # File sharing
    "_smb._tcp": ("workstation", None, None, 70),
    "_nfs._tcp": ("nas", None, None, 80),
    "_afpovertcp._tcp.": ("workstation", "Apple", "macOS", 85),
    "_ftp._tcp": ("server", None, None, 65),
    "_webdav._tcp": ("nas", None, None, 75),

    # Media streaming
    "_spotify-connect._tcp": ("smart_speaker", None, None, 80),
    "_sonos._tcp": ("smart_speaker", "Sonos", None, 95),
    "_plex._tcp": ("media_server", "Plex", None, 90),
    "_roku._tcp": ("smart_tv", "Roku", None, 95),
    "_amazontv._tcp": ("smart_tv", "Amazon", "Fire OS", 90),

    # SSH/Remote access
    "_ssh._tcp": ("server", None, None, 65),
    "_sftp-ssh._tcp": ("server", None, None, 65),
    "_rfb._tcp": ("workstation", None, None, 70),  # VNC

    # HTTP
    "_http._tcp": ("server", None, None, 50),
    "_https._tcp": ("server", None, None, 50),
    "_http-alt._tcp": ("server", None, None, 45),

    # Smart home
    "_hue._tcp": ("smart_home", "Philips", None, 95),
    "_wemo._tcp": ("smart_home", "Belkin", None, 90),
    "_smartthings._tcp": ("smart_home", "Samsung", None, 90),
    "_hass._tcp": ("smart_home", None, "Home Assistant", 85),

    # Network devices
    "_workstation._tcp": ("workstation", None, None, 60),
    "_device-info._tcp": ("unknown", None, None, 40),
    "_sleep-proxy._udp": ("network", "Apple", None, 70),

    # IoT specific
    "_matter._tcp": ("smart_home", None, None, 80),
    "_thread._tcp": ("smart_home", None, None, 75),
    "_esphomelib._tcp": ("iot", None, "ESPHome", 85),
    "_tasmota._tcp": ("iot", None, "Tasmota", 85),

    # Databases
    "_postgresql._tcp": ("server", None, None, 80),
    "_mysql._tcp": ("server", None, None, 80),
    "_mongodb._tcp": ("server", None, None, 80),

    # Gaming
    "_xbox._tcp": ("game_console", "Microsoft", "Xbox", 95),
    "_xbone._tcp": ("game_console", "Microsoft", "Xbox", 90),
    "_playstation._tcp": ("game_console", "Sony", "PlayStation", 95),
}

# =============================================================================
# mDNS Name Patterns (regex patterns for device names)
# =============================================================================

# (regex, device_type, manufacturer, os_family, confidence)
MDNS_NAME_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], int]] = [
    # Apple devices
    (r".*iPhone.*", "mobile", "Apple", "iOS", 95),
    (r".*iPad.*", "tablet", "Apple", "iPadOS", 95),
    (r".*MacBook.*", "laptop", "Apple", "macOS", 95),
    (r".*iMac.*", "workstation", "Apple", "macOS", 95),
    (r".*Mac[\s\-]?mini.*", "workstation", "Apple", "macOS", 95),
    (r".*Mac[\s\-]?Pro.*", "workstation", "Apple", "macOS", 95),
    (r".*Mac[\s\-]?Studio.*", "workstation", "Apple", "macOS", 95),
    (r".*Apple[\s\-]?TV.*", "smart_tv", "Apple", "tvOS", 95),
    (r".*HomePod.*", "smart_speaker", "Apple", "tvOS", 95),
    (r".*AirPort.*", "access_point", "Apple", None, 90),
    (r".*Time[\s\-]?Capsule.*", "nas", "Apple", None, 90),

    # Google devices
    (r".*Chromecast.*", "smart_tv", "Google", None, 95),
    (r".*Google[\s\-]?Home.*", "smart_speaker", "Google", None, 95),
    (r".*Google[\s\-]?Nest.*", "smart_home", "Google", None, 90),
    (r".*Nest[\s\-]?Hub.*", "smart_speaker", "Google", None, 90),
    (r".*Nest[\s\-]?Mini.*", "smart_speaker", "Google", None, 90),
    (r".*Nest[\s\-]?Audio.*", "smart_speaker", "Google", None, 90),
    (r".*Pixel.*", "mobile", "Google", "Android", 85),

    # Amazon devices
    (r".*Echo.*", "smart_speaker", "Amazon", None, 90),
    (r".*Fire[\s\-]?TV.*", "smart_tv", "Amazon", "Fire OS", 90),
    (r".*Fire[\s\-]?Stick.*", "smart_tv", "Amazon", "Fire OS", 90),
    (r".*Kindle.*", "tablet", "Amazon", "Fire OS", 85),
    (r".*Alexa.*", "smart_speaker", "Amazon", None, 80),
    (r".*Ring.*", "camera", "Amazon", None, 85),

    # Samsung
    (r".*Samsung[\s\-]?TV.*", "smart_tv", "Samsung", "Tizen", 90),
    (r".*Galaxy.*", "mobile", "Samsung", "Android", 80),

    # Sonos
    (r".*Sonos.*", "smart_speaker", "Sonos", None, 95),

    # Roku
    (r".*Roku.*", "smart_tv", "Roku", None, 95),

    # NAS devices
    (r".*Synology.*", "nas", "Synology", "DSM", 95),
    (r".*DS\d{3,4}.*", "nas", "Synology", "DSM", 85),  # DS920+, DS1821+
    (r".*QNAP.*", "nas", "QNAP", "QTS", 95),
    (r".*TS-\d{3,4}.*", "nas", "QNAP", "QTS", 80),  # TS-453D

    # Printers
    (r".*HP[\s\-]?(LaserJet|OfficeJet|DeskJet|Envy).*", "printer", "HP", None, 90),
    (r".*EPSON.*", "printer", "Epson", None, 85),
    (r".*Brother.*", "printer", "Brother", None, 85),
    (r".*Canon.*MF.*", "printer", "Canon", None, 85),

    # Gaming
    (r".*Xbox.*", "game_console", "Microsoft", "Xbox", 90),
    (r".*PlayStation.*", "game_console", "Sony", "PlayStation", 90),
    (r".*PS[45].*", "game_console", "Sony", "PlayStation", 85),
    (r".*Nintendo[\s\-]?Switch.*", "game_console", "Nintendo", None, 90),

    # Network devices
    (r".*UniFi.*", "network", "Ubiquiti", None, 90),
    (r".*MikroTik.*", "router", "MikroTik", "RouterOS", 90),
    (r".*Netgear.*", "router", "Netgear", None, 80),
    (r".*TP-?Link.*", "router", "TP-Link", None, 80),
    (r".*Asus.*RT-.*", "router", "ASUS", None, 85),
    (r".*Linksys.*", "router", "Linksys", None, 80),
    (r".*eero.*", "access_point", "Amazon", None, 85),
    (r".*Orbi.*", "access_point", "Netgear", None, 85),

    # Cameras
    (r".*Hikvision.*", "camera", "Hikvision", None, 90),
    (r".*Dahua.*", "camera", "Dahua", None, 90),
    (r".*Wyze.*", "camera", "Wyze", None, 85),
    (r".*Arlo.*", "camera", "Arlo", None, 85),
    (r".*Nest[\s\-]?Cam.*", "camera", "Google", None, 90),
]


# =============================================================================
# Matching Functions
# =============================================================================

def match_mdns_service(
    service_type: str,
    name: str = None
) -> Optional[Dict]:
    """
    Match an mDNS service to device info.

    Args:
        service_type: mDNS service type (e.g., "_airplay._tcp")
        name: Optional service name for additional matching

    Returns:
        Dict with device info or None
    """
    result = None

    # Clean service type
    service_clean = service_type.lower().strip()
    if not service_clean.endswith(".local."):
        if not service_clean.endswith("."):
            service_clean = service_clean
    else:
        service_clean = service_clean[:-7]  # Remove ".local."

    # Try service type match first
    if service_clean in MDNS_SERVICE_PATTERNS:
        device_type, manufacturer, os_family, confidence = MDNS_SERVICE_PATTERNS[service_clean]
        result = {
            "device_type": device_type,
            "manufacturer": manufacturer,
            "os_family": os_family,
            "confidence": confidence,
            "match_source": "service_type",
        }

    # Try name patterns if name provided
    if name:
        for pattern, device_type, manufacturer, os_family, confidence in MDNS_NAME_PATTERNS:
            if re.search(pattern, name, re.IGNORECASE):
                # Name match has higher confidence, use it
                if result is None or confidence > result.get("confidence", 0):
                    result = {
                        "device_type": device_type,
                        "manufacturer": manufacturer,
                        "os_family": os_family,
                        "confidence": confidence,
                        "match_source": "name_pattern",
                    }
                break

    return result
