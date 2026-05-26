"""
CredRecon Service Validation Module
====================================

Provides robust service validation with protocol-specific probes
and fingerprinting capabilities for accurate credential testing.

Features:
- Protocol-specific service detection probes
- Service fingerprinting (product, version, variant)
- Confidence scoring (HIGH/MEDIUM/LOW)
- CPE generation for detected services
"""

import socket
import re
import struct
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List, Tuple
from enum import Enum

logger = logging.getLogger("credrecon.validation")


class ConfidenceLevel(Enum):
    """Confidence levels for service detection."""
    HIGH = "HIGH"      # 0.9+ - Protocol handshake confirmed
    MEDIUM = "MEDIUM"  # 0.6-0.8 - Banner pattern matched
    LOW = "LOW"        # 0.3-0.5 - Port-based assumption
    UNKNOWN = "UNKNOWN"  # <0.3 - Cannot determine


@dataclass
class ServiceFingerprint:
    """
    Result of service fingerprinting.

    Contains detailed information about the detected service including
    product name, version, and confidence level.
    """
    service: str                              # Protocol name (ssh, mysql, http, etc.)
    product: Optional[str] = None             # Product name (OpenSSH, MariaDB, Apache)
    version: Optional[str] = None             # Version string
    variant: Optional[str] = None             # Variant (e.g., MariaDB for MySQL)
    vendor: Optional[str] = None              # Vendor name
    cpe: Optional[str] = None                 # CPE URI
    os_hint: Optional[str] = None             # Detected OS hint
    confidence: float = 0.5                   # 0.0-1.0 confidence level
    auth_methods: List[str] = field(default_factory=list)  # Supported auth methods
    features: List[str] = field(default_factory=list)      # Detected features
    extra_info: Dict[str, Any] = field(default_factory=dict)  # Additional details
    raw_banner: Optional[str] = None          # Raw banner/response data
    detection_method: Optional[str] = None    # How detection was performed

    @property
    def confidence_level(self) -> ConfidenceLevel:
        """Get human-readable confidence level."""
        if self.confidence >= 0.9:
            return ConfidenceLevel.HIGH
        elif self.confidence >= 0.6:
            return ConfidenceLevel.MEDIUM
        elif self.confidence >= 0.3:
            return ConfidenceLevel.LOW
        return ConfidenceLevel.UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "variant": self.variant,
            "vendor": self.vendor,
            "cpe": self.cpe,
            "os_hint": self.os_hint,
            "confidence": self.confidence,
            "confidence_level": self.confidence_level.value,
            "auth_methods": self.auth_methods,
            "features": self.features,
            "extra_info": self.extra_info,
            "raw_banner": self.raw_banner,
            "detection_method": self.detection_method,
        }


def build_cpe(vendor: str, product: str, version: Optional[str] = None) -> str:
    """
    Build CPE 2.3 URI.

    Args:
        vendor: Vendor name
        product: Product name
        version: Version string (optional)

    Returns:
        CPE URI string
    """
    # Normalize for CPE
    vendor = vendor.lower().replace(" ", "_").replace("-", "_")
    product = product.lower().replace(" ", "_").replace("-", "_")

    if version:
        version = version.replace(" ", "_")
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    else:
        return f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"


# =============================================================================
# SSH Fingerprinting
# =============================================================================

# SSH banner patterns: (regex, vendor, product, os_hint)
SSH_PATTERNS = [
    (r"OpenSSH[_-]?([\d.p]+).*Ubuntu", "openbsd", "openssh", "ubuntu"),
    (r"OpenSSH[_-]?([\d.p]+).*Debian", "openbsd", "openssh", "debian"),
    (r"OpenSSH[_-]?([\d.p]+).*FreeBSD", "openbsd", "openssh", "freebsd"),
    (r"OpenSSH[_-]?([\d.p]+).*CentOS", "openbsd", "openssh", "centos"),
    (r"OpenSSH[_-]?([\d.p]+).*Red Hat", "openbsd", "openssh", "redhat"),
    (r"OpenSSH[_-]?([\d.p]+)", "openbsd", "openssh", None),
    (r"dropbear[_-]?([\d.]+)?", "dropbear", "dropbear", "embedded"),
    (r"libssh[_-]?([\d.]+)?", "libssh", "libssh", None),
    (r"Cisco[_-]?([\d.]+)?", "cisco", "ios_ssh", "ios"),
    (r"Bitvise SSH Server[_-]?([\d.]+)?", "bitvise", "bitvise_ssh", "windows"),
    (r"paramiko[_-]?([\d.]+)?", "paramiko", "paramiko", None),
    (r"WeOnlyDo[_-]?([\d.]+)?", "weonlydo", "wodsshdaemon", "windows"),
    (r"RomSShell[_-]?([\d.]+)?", "allegro", "romsshell", "embedded"),
]


def probe_ssh(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """
    Probe SSH service and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout

    Returns:
        ServiceFingerprint or None if not SSH
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Receive SSH banner
        banner = sock.recv(256).decode('utf-8', errors='ignore').strip()
        sock.close()

        if not banner.startswith('SSH-'):
            return None

        # Parse SSH version
        # Format: SSH-protoversion-softwareversion [comments]
        parts = banner.split(' ', 1)
        version_part = parts[0]
        comment = parts[1] if len(parts) > 1 else ""

        # Extract software version
        ssh_parts = version_part.split('-')
        if len(ssh_parts) >= 3:
            software_version = '-'.join(ssh_parts[2:])
        else:
            software_version = banner

        # Match against known patterns
        full_banner = f"{software_version} {comment}".strip()

        for pattern, vendor, product, os_hint in SSH_PATTERNS:
            match = re.search(pattern, full_banner, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None
                return ServiceFingerprint(
                    service="ssh",
                    product=product.title(),
                    version=version,
                    vendor=vendor,
                    cpe=build_cpe(vendor, product, version),
                    os_hint=os_hint,
                    confidence=0.95,
                    detection_method="SSH banner analysis",
                    raw_banner=banner,
                    extra_info={"protocol_version": ssh_parts[1] if len(ssh_parts) > 1 else None}
                )

        # Unknown SSH server but still SSH
        return ServiceFingerprint(
            service="ssh",
            product="Unknown SSH",
            confidence=0.85,
            detection_method="SSH banner (unknown product)",
            raw_banner=banner
        )

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"SSH probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# FTP Fingerprinting
# =============================================================================

# FTP banner patterns: (regex, vendor, product)
FTP_PATTERNS = [
    (r"vsftpd[_\s]*([\d.]+)?", "vsftpd", "vsftpd"),
    (r"ProFTPD[_\s]*([\d.]+)?", "proftpd", "proftpd"),
    (r"Pure-FTPd", "pureftpd", "pure-ftpd"),
    (r"FileZilla Server[_\s]*([\d.]+)?", "filezilla", "filezilla_server"),
    (r"Microsoft FTP Service", "microsoft", "iis_ftp"),
    (r"vsFTPd", "vsftpd", "vsftpd"),
    (r"Wu-FTPd", "wuftpd", "wu-ftpd"),
    (r"glFTPd", "glftpd", "glftpd"),
    (r"Serv-U FTP", "solarwinds", "serv-u"),
]


def probe_ftp(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """
    Probe FTP service and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout

    Returns:
        ServiceFingerprint or None if not FTP
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Receive FTP banner (220 response)
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()

        # FTP banners typically start with 220
        if not banner.startswith('220'):
            return None

        # Check for anonymous login hint
        features = []
        if 'anonymous' in banner.lower():
            features.append("anonymous_login_hint")

        # Match against known patterns
        for pattern, vendor, product in FTP_PATTERNS:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None
                return ServiceFingerprint(
                    service="ftp",
                    product=product,
                    version=version,
                    vendor=vendor,
                    cpe=build_cpe(vendor, product, version),
                    confidence=0.92,
                    features=features,
                    detection_method="FTP banner analysis",
                    raw_banner=banner
                )

        # Unknown FTP server
        return ServiceFingerprint(
            service="ftp",
            product="Unknown FTP",
            confidence=0.80,
            features=features,
            detection_method="FTP banner (unknown product)",
            raw_banner=banner
        )

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"FTP probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# MySQL/MariaDB Fingerprinting
# =============================================================================

def probe_mysql(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """
    Probe MySQL/MariaDB service and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout

    Returns:
        ServiceFingerprint or None if not MySQL/MariaDB
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Receive MySQL handshake packet
        packet = sock.recv(1024)
        sock.close()

        if len(packet) < 5:
            return None

        # MySQL packet format: 3 bytes length + 1 byte sequence + payload
        # Protocol version is first byte of payload
        protocol_version = packet[4]

        # Protocol 10 is MySQL 3.21.0+
        if protocol_version != 10:
            return None

        # Find null terminator for version string
        version_end = packet.find(b'\x00', 5)
        if version_end == -1:
            return None

        version_str = packet[5:version_end].decode('utf-8', errors='ignore')

        # Determine if MariaDB
        is_mariadb = 'mariadb' in version_str.lower()

        if is_mariadb:
            # Extract MariaDB version
            match = re.search(r'([\d.]+)-MariaDB', version_str, re.IGNORECASE)
            version = match.group(1) if match else version_str.split('-')[0]
            return ServiceFingerprint(
                service="mysql",
                product="MariaDB",
                version=version,
                variant="mariadb",
                vendor="mariadb",
                cpe=build_cpe("mariadb", "mariadb", version),
                confidence=0.95,
                detection_method="MySQL handshake packet (MariaDB detected)",
                raw_banner=version_str,
                extra_info={"protocol_version": protocol_version, "full_version": version_str}
            )
        else:
            # Standard MySQL
            version = version_str.split('-')[0]
            return ServiceFingerprint(
                service="mysql",
                product="MySQL",
                version=version,
                vendor="oracle",
                cpe=build_cpe("oracle", "mysql", version),
                confidence=0.95,
                detection_method="MySQL handshake packet",
                raw_banner=version_str,
                extra_info={"protocol_version": protocol_version, "full_version": version_str}
            )

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"MySQL probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# PostgreSQL Fingerprinting
# =============================================================================

def probe_postgres(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """
    Probe PostgreSQL service and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout

    Returns:
        ServiceFingerprint or None if not PostgreSQL
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send SSL request (this triggers a response without needing auth)
        ssl_request = struct.pack('>II', 8, 80877103)  # SSLRequest
        sock.send(ssl_request)

        response = sock.recv(1)

        features = []
        if response == b'S':
            features.append("ssl_supported")
        elif response == b'N':
            features.append("ssl_not_supported")
        else:
            sock.close()
            return None

        sock.close()

        # PostgreSQL confirmed
        return ServiceFingerprint(
            service="postgres",
            product="PostgreSQL",
            vendor="postgresql",
            cpe=build_cpe("postgresql", "postgresql"),
            confidence=0.90,
            features=features,
            detection_method="PostgreSQL SSLRequest probe",
            extra_info={"ssl_response": response.decode() if response else None}
        )

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"PostgreSQL probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# MSSQL Fingerprinting
# =============================================================================

def probe_mssql(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """
    Probe Microsoft SQL Server and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout

    Returns:
        ServiceFingerprint or None if not MSSQL
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # TDS Pre-login packet
        prelogin_packet = bytes([
            0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x00, 0x00,  # TDS header
            0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b,  # Pre-login options
            0x00, 0x01, 0x02, 0x00, 0x1c, 0x00, 0x0c, 0x03,
            0x00, 0x28, 0x00, 0x04, 0xff, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        ])

        sock.send(prelogin_packet)
        response = sock.recv(1024)
        sock.close()

        # Check for TDS response
        if len(response) > 0 and response[0] == 0x04:  # TDS response type
            return ServiceFingerprint(
                service="mssql",
                product="Microsoft SQL Server",
                vendor="microsoft",
                cpe=build_cpe("microsoft", "sql_server"),
                confidence=0.90,
                detection_method="TDS pre-login probe",
                raw_banner=response[:50].hex() if response else None
            )

        return None

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"MSSQL probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# MongoDB Fingerprinting
# =============================================================================

def probe_mongodb(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """
    Probe MongoDB and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout

    Returns:
        ServiceFingerprint or None if not MongoDB
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # MongoDB isMaster command (simplified BSON)
        # This is a minimal OP_QUERY for isMaster
        is_master_query = bytes([
            0x3f, 0x00, 0x00, 0x00,  # Message length
            0x01, 0x00, 0x00, 0x00,  # Request ID
            0x00, 0x00, 0x00, 0x00,  # Response to
            0xd4, 0x07, 0x00, 0x00,  # OP_QUERY opcode
            0x00, 0x00, 0x00, 0x00,  # Flags
            0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00,  # "admin.$cmd"
            0x00, 0x00, 0x00, 0x00,  # Number to skip
            0x01, 0x00, 0x00, 0x00,  # Number to return
            # BSON document: {isMaster: 1}
            0x13, 0x00, 0x00, 0x00,  # Document length
            0x10, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,  # "isMaster"
            0x01, 0x00, 0x00, 0x00,  # Int32 value: 1
            0x00  # Document terminator
        ])

        sock.send(is_master_query)
        response = sock.recv(4096)
        sock.close()

        # Check for MongoDB response
        if len(response) >= 16:
            # Try to extract version from response
            response_str = response.decode('utf-8', errors='ignore')
            version_match = re.search(r'"version"\s*:\s*"([\d.]+)"', response_str)
            version = version_match.group(1) if version_match else None

            # Check if auth is required
            auth_required = b'unauthorized' in response.lower() or b'auth' in response.lower()
            features = ["auth_required"] if auth_required else ["no_auth"]

            return ServiceFingerprint(
                service="mongodb",
                product="MongoDB",
                version=version,
                vendor="mongodb",
                cpe=build_cpe("mongodb", "mongodb", version),
                confidence=0.90,
                features=features,
                detection_method="MongoDB isMaster probe",
                raw_banner=response[:200].decode('utf-8', errors='ignore')
            )

        return None

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"MongoDB probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# Redis Fingerprinting
# =============================================================================

def probe_redis(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """
    Probe Redis and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout

    Returns:
        ServiceFingerprint or None if not Redis
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Send PING command
        sock.send(b"*1\r\n$4\r\nPING\r\n")
        response = sock.recv(1024).decode('utf-8', errors='ignore')

        features = []
        version = None

        if '+PONG' in response:
            features.append("no_auth")
            # Try INFO to get version
            sock.send(b"*1\r\n$4\r\nINFO\r\n")
            info_response = sock.recv(4096).decode('utf-8', errors='ignore')

            version_match = re.search(r'redis_version:([\d.]+)', info_response)
            if version_match:
                version = version_match.group(1)

        elif '-NOAUTH' in response or 'Authentication required' in response:
            features.append("auth_required")
        else:
            sock.close()
            return None

        sock.close()

        return ServiceFingerprint(
            service="redis",
            product="Redis",
            version=version,
            vendor="redis",
            cpe=build_cpe("redis", "redis", version),
            confidence=0.95,
            features=features,
            detection_method="Redis PING probe",
            raw_banner=response[:100]
        )

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"Redis probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# VNC Fingerprinting
# =============================================================================

def probe_vnc(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """
    Probe VNC and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout

    Returns:
        ServiceFingerprint or None if not VNC
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Receive RFB version
        version = sock.recv(12).decode('utf-8', errors='ignore')

        if not version.startswith('RFB '):
            sock.close()
            return None

        # Parse version (e.g., "RFB 003.008\n")
        rfb_version = version.strip()

        # Send back same version
        sock.send(version.encode())

        # Receive security types
        security_data = sock.recv(64)

        auth_methods = []
        features = []

        if len(security_data) > 0:
            num_types = security_data[0]
            if num_types > 0 and len(security_data) > num_types:
                sec_types = security_data[1:num_types+1]
                if 1 in sec_types:
                    auth_methods.append("none")
                    features.append("no_auth_available")
                if 2 in sec_types:
                    auth_methods.append("vnc_auth")

        sock.close()

        return ServiceFingerprint(
            service="vnc",
            product="VNC",
            version=rfb_version,
            confidence=0.95,
            auth_methods=auth_methods,
            features=features,
            detection_method="RFB protocol handshake",
            raw_banner=rfb_version
        )

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"VNC probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# RDP Fingerprinting
# =============================================================================

def probe_rdp(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """
    Probe RDP and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout

    Returns:
        ServiceFingerprint or None if not RDP
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # X.224 Connection Request
        x224_req = bytes([
            0x03, 0x00,  # TPKT version and reserved
            0x00, 0x2c,  # Length (44 bytes)
            0x27,        # X.224 length
            0xe0,        # X.224 PDU type (Connection Request)
            0x00, 0x00,  # Destination reference
            0x00, 0x00,  # Source reference
            0x00,        # Class and options
        ])
        # Add RDP negotiation request
        x224_req += bytes([
            0x43, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x3a, 0x20,  # "Cookie: "
            0x6d, 0x73, 0x74, 0x73, 0x68, 0x61, 0x73, 0x68, 0x3d, 0x20, 0x0d, 0x0a,  # "mstshash= \r\n"
            0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00  # RDP Negotiation Request
        ])

        sock.send(x224_req)
        response = sock.recv(1024)
        sock.close()

        features = []

        if len(response) > 0:
            # Check for RDP response
            if response[0] == 0x03:  # TPKT
                # Check negotiation response type
                if len(response) > 11:
                    neg_type = response[11]
                    if neg_type == 0x02:  # Negotiation Response
                        features.append("standard_rdp")
                    elif neg_type == 0x03:  # Negotiation Failure
                        features.append("nla_required")

                return ServiceFingerprint(
                    service="rdp",
                    product="Microsoft RDP",
                    vendor="microsoft",
                    cpe=build_cpe("microsoft", "remote_desktop"),
                    confidence=0.90,
                    features=features,
                    detection_method="X.224 Connection Request",
                    raw_banner=response[:50].hex()
                )

        return None

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"RDP probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# Telnet Fingerprinting
# =============================================================================

def probe_telnet(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """
    Probe Telnet and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout

    Returns:
        ServiceFingerprint or None if not Telnet
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Receive initial data (banner or IAC negotiations)
        data = sock.recv(1024)
        sock.close()

        # Check for IAC (Interpret As Command) sequences or login prompt
        features = []
        product = "Telnet"
        os_hint = None

        # Decode what we can
        try:
            banner = data.decode('utf-8', errors='ignore')
        except:
            banner = str(data)

        # Look for IAC sequences (0xFF followed by command)
        if b'\xff' in data:
            features.append("iac_negotiation")

        # Detect device type from banner
        banner_lower = banner.lower()
        if 'cisco' in banner_lower:
            product = "Cisco IOS Telnet"
            os_hint = "ios"
        elif 'mikrotik' in banner_lower:
            product = "MikroTik Telnet"
            os_hint = "routeros"
        elif 'linux' in banner_lower:
            os_hint = "linux"
        elif 'windows' in banner_lower:
            os_hint = "windows"
        elif 'bsd' in banner_lower:
            os_hint = "bsd"

        # Check for login prompt
        if 'login' in banner_lower or 'username' in banner_lower:
            features.append("login_prompt")

        return ServiceFingerprint(
            service="telnet",
            product=product,
            os_hint=os_hint,
            confidence=0.75 if features else 0.60,
            features=features,
            detection_method="Telnet banner analysis",
            raw_banner=banner[:200]
        )

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"Telnet probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# HTTP Fingerprinting
# =============================================================================

# HTTP application patterns: (patterns, product, vendor, cred_category)
HTTP_APPLICATION_PATTERNS = [
    (["Apache Tomcat", "Tomcat/", "/manager/html"], "Apache Tomcat", "apache", "tomcat"),
    (["X-Jenkins:", "/jenkins", "Dashboard [Jenkins]"], "Jenkins", "jenkins", "jenkins"),
    (["grafana", "Grafana"], "Grafana", "grafana", "grafana"),
    (["X-GitLab", "/gitlab", "GitLab"], "GitLab", "gitlab", "gitlab"),
    (["Jira", "Atlassian JIRA"], "Atlassian Jira", "atlassian", "jira"),
    (["RabbitMQ", "rabbitmq"], "RabbitMQ", "vmware", "rabbitmq"),
    (["elasticsearch", "Elasticsearch"], "Elasticsearch", "elastic", "elasticsearch"),
    (["kibana", "Kibana"], "Kibana", "elastic", "kibana"),
    (["Webmin", "webmin"], "Webmin", "webmin", "webmin"),
    (["phpMyAdmin", "phpmyadmin"], "phpMyAdmin", "phpmyadmin", "phpmyadmin"),
    (["Zabbix", "zabbix"], "Zabbix", "zabbix", "zabbix"),
    (["Nagios", "nagios"], "Nagios", "nagios", "nagios"),
    (["pfSense", "pfsense"], "pfSense", "netgate", "pfsense"),
    (["OPNsense", "opnsense"], "OPNsense", "opnsense", "opnsense"),
    (["WordPress", "wp-admin", "wp-login"], "WordPress", "wordpress", "wordpress"),
    (["Drupal", "drupal"], "Drupal", "drupal", "drupal"),
    (["Joomla", "joomla"], "Joomla", "joomla", "joomla"),
]


def probe_http(host: str, port: int, timeout: float = 5.0, use_https: bool = False) -> Optional[ServiceFingerprint]:
    """
    Probe HTTP/HTTPS and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout
        use_https: Use HTTPS instead of HTTP

    Returns:
        ServiceFingerprint or None if not HTTP
    """
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except ImportError:
        return None

    try:
        scheme = "https" if use_https or port == 443 else "http"
        url = f"{scheme}://{host}:{port}/"

        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)

        server = response.headers.get('Server', '')
        powered_by = response.headers.get('X-Powered-By', '')
        content = response.text[:5000]  # Limit content check

        all_text = f"{server} {powered_by} {content}".lower()
        headers_text = f"{server} {powered_by}"

        # Check for specific applications
        for patterns, product, vendor, cred_category in HTTP_APPLICATION_PATTERNS:
            for pattern in patterns:
                if pattern.lower() in all_text:
                    # Extract version if possible
                    version_match = re.search(rf'{product}[/\s]*([\d.]+)', headers_text, re.IGNORECASE)
                    version = version_match.group(1) if version_match else None

                    return ServiceFingerprint(
                        service="http",
                        product=product,
                        version=version,
                        vendor=vendor,
                        cpe=build_cpe(vendor, product.lower().replace(' ', '_'), version),
                        confidence=0.90,
                        detection_method=f"HTTP content analysis ({product})",
                        raw_banner=server[:100],
                        extra_info={
                            "cred_category": cred_category,
                            "server_header": server,
                            "status_code": response.status_code
                        }
                    )

        # Generic HTTP server
        server_product = "Unknown HTTP"
        if 'apache' in server.lower():
            server_product = "Apache httpd"
        elif 'nginx' in server.lower():
            server_product = "nginx"
        elif 'iis' in server.lower() or 'microsoft' in server.lower():
            server_product = "Microsoft IIS"

        return ServiceFingerprint(
            service="http",
            product=server_product,
            confidence=0.70,
            detection_method="HTTP Server header",
            raw_banner=server[:100],
            extra_info={"server_header": server, "status_code": response.status_code}
        )

    except Exception as e:
        logger.debug(f"HTTP probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# SNMP Fingerprinting
# =============================================================================

def probe_snmp(host: str, port: int = 161, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """
    Probe SNMP and fingerprint using UDP.

    Args:
        host: Target IP/hostname
        port: Target port (default 161)
        timeout: Connection timeout

    Returns:
        ServiceFingerprint or None if not SNMP
    """
    try:
        from pysnmp.hlapi import (
            getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
            ContextData, ObjectType, ObjectIdentity
        )

        # Try with 'public' community string
        error_indication, error_status, error_index, var_binds = next(
            getCmd(
                SnmpEngine(),
                CommunityData('public', mpModel=0),  # SNMPv1
                UdpTransportTarget((host, port), timeout=timeout, retries=0),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))  # sysDescr
            )
        )

        features = []
        sys_descr = None

        if error_indication:
            # Try 'private'
            error_indication, error_status, error_index, var_binds = next(
                getCmd(
                    SnmpEngine(),
                    CommunityData('private', mpModel=0),
                    UdpTransportTarget((host, port), timeout=timeout, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))
                )
            )
            if not error_indication:
                features.append("private_community")
                sys_descr = str(var_binds[0][1]) if var_binds else None
        else:
            features.append("public_community")
            sys_descr = str(var_binds[0][1]) if var_binds else None

        if sys_descr:
            return ServiceFingerprint(
                service="snmp",
                product="SNMP Agent",
                confidence=0.95,
                features=features,
                detection_method="SNMP GET sysDescr",
                raw_banner=sys_descr[:200],
                extra_info={"sys_descr": sys_descr}
            )

        return None

    except ImportError:
        logger.debug("pysnmp not available for SNMP probing")
        return None
    except Exception as e:
        logger.debug(f"SNMP probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# LDAP Fingerprinting
# =============================================================================

# LDAP server patterns
LDAP_PATTERNS = [
    (r"Microsoft.*Active Directory", "microsoft", "active_directory", "windows"),
    (r"389 Directory Server", "redhat", "389_directory_server", "linux"),
    (r"OpenLDAP", "openldap", "openldap", None),
    (r"ApacheDS", "apache", "apacheds", None),
    (r"OpenDJ", "forgerock", "opendj", None),
    (r"eDirectory", "netiq", "edirectory", None),
    (r"IBM.*Security Directory", "ibm", "security_directory_server", None),
]


def probe_ldap(host: str, port: int, timeout: float = 5.0, use_ssl: bool = False) -> Optional[ServiceFingerprint]:
    """
    Probe LDAP/LDAPS service and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout
        use_ssl: Whether to use SSL/TLS

    Returns:
        ServiceFingerprint or None if not LDAP
    """
    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, DSA

        # Determine if SSL based on port
        if port == 636:
            use_ssl = True

        protocol = "ldaps" if use_ssl else "ldap"

        # Create server and try to get info
        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL, connect_timeout=timeout)

        # Try anonymous bind to get server info
        try:
            conn = Connection(server, auto_bind=True)
            server_info = server.info

            features = []
            vendor = None
            product = None
            version = None
            os_hint = None

            if server_info:
                # Check for vendor info
                if hasattr(server_info, 'vendor_name') and server_info.vendor_name:
                    vendor = str(server_info.vendor_name[0]) if isinstance(server_info.vendor_name, list) else str(server_info.vendor_name)

                if hasattr(server_info, 'vendor_version') and server_info.vendor_version:
                    version = str(server_info.vendor_version[0]) if isinstance(server_info.vendor_version, list) else str(server_info.vendor_version)

                # Check supported SASL mechanisms
                if hasattr(server_info, 'supported_sasl_mechanisms') and server_info.supported_sasl_mechanisms:
                    features.extend([f"sasl_{m.lower()}" for m in server_info.supported_sasl_mechanisms[:5]])

                # Check if anonymous bind is allowed
                features.append("anonymous_bind_allowed")

                # Try to detect server type
                info_str = str(server_info).lower() if server_info else ""
                for pattern, v, p, os in LDAP_PATTERNS:
                    if re.search(pattern, info_str, re.IGNORECASE):
                        vendor = vendor or v
                        product = p
                        os_hint = os
                        break

                if not product:
                    product = "LDAP Server"

            conn.unbind()

            return ServiceFingerprint(
                service=protocol,
                product=product or "LDAP Server",
                version=version,
                vendor=vendor,
                os_hint=os_hint,
                confidence=0.90,
                features=features,
                detection_method="LDAP anonymous bind",
                cpe=build_cpe(vendor or "unknown", product or "ldap", version) if vendor else None,
                raw_banner=str(server_info)[:200] if server_info else None
            )

        except Exception:
            # Anonymous bind not allowed, but we can still confirm it's LDAP
            return ServiceFingerprint(
                service=protocol,
                product="LDAP Server",
                confidence=0.70,
                features=["anonymous_bind_denied"],
                detection_method="LDAP connection (auth required)"
            )

    except ImportError:
        logger.debug("ldap3 not available for LDAP probing")
        return None
    except Exception as e:
        logger.debug(f"LDAP probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# IPMI Fingerprinting
# =============================================================================

# IPMI manufacturer IDs (partial list)
IPMI_MANUFACTURERS = {
    0x0002: ("IBM", "ibm"),
    0x0003: ("HP", "hp"),
    0x000B: ("Dell", "dell"),
    0x001C: ("Supermicro", "supermicro"),
    0x002A: ("Lenovo", "lenovo"),
    0x00CF: ("Fujitsu", "fujitsu"),
    0x0157: ("Quanta", "quanta"),
    0x0424: ("Intel", "intel"),
    0x103C: ("HP", "hp"),
}

# Known IPMI products
IPMI_PRODUCTS = {
    ("dell", "idrac"): "Dell iDRAC",
    ("hp", "ilo"): "HP iLO",
    ("supermicro", "ipmi"): "Supermicro IPMI",
    ("lenovo", "imm"): "Lenovo IMM",
}


def probe_ipmi(host: str, port: int = 623, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """
    Probe IPMI/BMC service and fingerprint using UDP RMCP.

    Args:
        host: Target IP/hostname
        port: Target port (default 623)
        timeout: Connection timeout

    Returns:
        ServiceFingerprint or None if not IPMI
    """
    try:
        import socket

        # IPMI Get Channel Authentication Capabilities (RMCP ASF Ping is simpler)
        # ASF Ping packet
        asf_ping = bytes([
            0x06, 0x00,  # RMCP version 6, reserved
            0xff,        # Message class: ASF
            0x06,        # ASF Type: Presence Ping
            0x00, 0x00, 0x11, 0xbe,  # IANA Enterprise Number: ASF
            0x80,        # Message Type: Ping
            0x00,        # Message Tag
            0x00,        # Reserved
            0x00,        # Data Length
        ])

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(asf_ping, (host, port))

        try:
            response, addr = sock.recvfrom(1024)
            sock.close()

            # Check for valid RMCP/ASF response
            if len(response) >= 12:
                # Check RMCP header
                if response[0] == 0x06 and response[2] == 0x06:
                    # This is an ASF Pong response
                    features = ["asf_pong"]

                    # Try to get more info via IPMI Get Channel Auth
                    product_info = _probe_ipmi_auth_capabilities(host, port, timeout)
                    if product_info:
                        return ServiceFingerprint(
                            service="ipmi",
                            product=product_info.get("product", "IPMI BMC"),
                            version=product_info.get("version"),
                            vendor=product_info.get("vendor"),
                            confidence=0.95,
                            features=features + product_info.get("features", []),
                            detection_method="IPMI ASF Ping + Auth Capabilities",
                            cpe=build_cpe(
                                product_info.get("vendor", "unknown"),
                                product_info.get("product", "ipmi"),
                                product_info.get("version")
                            )
                        )

                    return ServiceFingerprint(
                        service="ipmi",
                        product="IPMI BMC",
                        confidence=0.90,
                        features=features,
                        detection_method="IPMI ASF Ping response"
                    )

        except socket.timeout:
            pass
        finally:
            sock.close()

        return None

    except Exception as e:
        logger.debug(f"IPMI probe error for {host}:{port}: {e}")
        return None


def _probe_ipmi_auth_capabilities(host: str, port: int, timeout: float) -> Optional[dict]:
    """
    Send IPMI Get Channel Authentication Capabilities request.
    """
    try:
        import socket

        # IPMI 2.0 Get Channel Auth Capabilities (RMCP+)
        get_auth_caps = bytes([
            0x06, 0x00, 0xff, 0x07,  # RMCP Header
            0x00, 0x00, 0x00, 0x00,  # Session ID
            0x00, 0x00, 0x00, 0x00,  # Session Seq
            0x20, 0x18, 0xc8, 0x81, 0x00, 0x38, 0x8e, 0x04, 0xb5  # IPMI Message
        ])

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(get_auth_caps, (host, port))

        try:
            response, addr = sock.recvfrom(1024)
            sock.close()

            if len(response) >= 20:
                features = []

                # Check supported auth types
                auth_byte = response[19] if len(response) > 19 else 0
                if auth_byte & 0x01:
                    features.append("auth_none")
                if auth_byte & 0x02:
                    features.append("auth_md2")
                if auth_byte & 0x04:
                    features.append("auth_md5")
                if auth_byte & 0x20:
                    features.append("auth_oem")

                # Check for IPMI 2.0 support
                if len(response) > 20 and response[20] & 0x80:
                    features.append("ipmi_2.0")

                return {
                    "product": "IPMI BMC",
                    "features": features
                }

        except socket.timeout:
            pass
        finally:
            sock.close()

    except Exception:
        pass

    return None


# =============================================================================
# MQTT Fingerprinting
# =============================================================================

def probe_mqtt(host: str, port: int, timeout: float = 5.0, use_tls: bool = False) -> Optional[ServiceFingerprint]:
    """
    Probe MQTT broker and fingerprint.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout
        use_tls: Whether to use TLS

    Returns:
        ServiceFingerprint or None if not MQTT
    """
    try:
        import socket
        import ssl

        # Determine TLS based on port
        if port == 8883:
            use_tls = True

        protocol = "mqtts" if use_tls else "mqtt"

        # MQTT CONNECT packet (minimal, protocol version 4 = MQTT 3.1.1)
        # This is a simple CONNECT to test if server responds with CONNACK
        client_id = b"cygor_probe"
        connect_packet = bytes([
            0x10,  # CONNECT packet type
        ])

        # Variable header + payload length
        variable_header = bytes([
            0x00, 0x04,  # Protocol name length
            0x4d, 0x51, 0x54, 0x54,  # "MQTT"
            0x04,  # Protocol version (4 = 3.1.1)
            0x02,  # Connect flags (clean session)
            0x00, 0x3c,  # Keep alive (60 seconds)
        ])

        # Payload (client ID)
        payload = bytes([0x00, len(client_id)]) + client_id

        remaining = variable_header + payload
        remaining_length = len(remaining)

        # Encode remaining length
        if remaining_length < 128:
            connect_packet += bytes([remaining_length])
        else:
            connect_packet += bytes([
                (remaining_length % 128) | 0x80,
                remaining_length // 128
            ])

        connect_packet += remaining

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        try:
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            sock.connect((host, port))
            sock.send(connect_packet)

            # Receive CONNACK
            response = sock.recv(4)
            sock.close()

            if len(response) >= 4:
                packet_type = (response[0] & 0xf0) >> 4
                if packet_type == 2:  # CONNACK
                    return_code = response[3]

                    features = []
                    if return_code == 0:
                        features.append("anonymous_allowed")
                    elif return_code == 4:
                        features.append("auth_required")
                    elif return_code == 5:
                        features.append("not_authorized")

                    return ServiceFingerprint(
                        service=protocol,
                        product="MQTT Broker",
                        confidence=0.95,
                        features=features,
                        detection_method="MQTT CONNECT/CONNACK handshake",
                        extra_info={"connack_return_code": return_code}
                    )

            return None

        except socket.timeout:
            return None
        finally:
            try:
                sock.close()
            except:
                pass

    except Exception as e:
        logger.debug(f"MQTT probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# SMTP Fingerprinting
# =============================================================================

def probe_smtp(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """Probe SMTP service and fingerprint."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()

        if not banner.startswith('220'):
            return None

        features = []
        product = "SMTP Server"
        vendor = None
        version = None

        banner_lower = banner.lower()
        if 'postfix' in banner_lower:
            product = "Postfix"
            vendor = "postfix"
        elif 'exim' in banner_lower:
            product = "Exim"
            vendor = "exim"
            match = re.search(r'Exim\s+([\d.]+)', banner, re.IGNORECASE)
            if match:
                version = match.group(1)
        elif 'sendmail' in banner_lower:
            product = "Sendmail"
            vendor = "sendmail"
        elif 'microsoft' in banner_lower or 'exchange' in banner_lower:
            product = "Microsoft Exchange"
            vendor = "microsoft"
        elif 'hmail' in banner_lower:
            product = "hMailServer"
            vendor = "hmailserver"

        if 'esmtp' in banner_lower:
            features.append("esmtp")

        service = "smtps" if port == 465 else "smtp"

        return ServiceFingerprint(
            service=service,
            product=product,
            version=version,
            vendor=vendor,
            cpe=build_cpe(vendor or "unknown", product.lower().replace(' ', '_'), version) if vendor else None,
            confidence=0.92,
            features=features,
            detection_method="SMTP banner analysis",
            raw_banner=banner[:200]
        )

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"SMTP probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# IMAP Fingerprinting
# =============================================================================

def probe_imap(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """Probe IMAP service and fingerprint."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if port == 993:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()

        if not banner.startswith('* OK'):
            return None

        product = "IMAP Server"
        vendor = None
        version = None

        banner_lower = banner.lower()
        if 'dovecot' in banner_lower:
            product = "Dovecot"
            vendor = "dovecot"
        elif 'cyrus' in banner_lower:
            product = "Cyrus IMAP"
            vendor = "cmu"
        elif 'courier' in banner_lower:
            product = "Courier IMAP"
            vendor = "courier"
        elif 'microsoft' in banner_lower or 'exchange' in banner_lower:
            product = "Microsoft Exchange IMAP"
            vendor = "microsoft"

        service = "imaps" if port == 993 else "imap"

        return ServiceFingerprint(
            service=service,
            product=product,
            version=version,
            vendor=vendor,
            cpe=build_cpe(vendor or "unknown", product.lower().replace(' ', '_'), version) if vendor else None,
            confidence=0.92,
            detection_method="IMAP banner analysis",
            raw_banner=banner[:200]
        )

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"IMAP probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# POP3 Fingerprinting
# =============================================================================

def probe_pop3(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """Probe POP3 service and fingerprint."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        if port == 995:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)

        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()

        if not banner.startswith('+OK'):
            return None

        product = "POP3 Server"
        vendor = None

        banner_lower = banner.lower()
        if 'dovecot' in banner_lower:
            product = "Dovecot"
            vendor = "dovecot"
        elif 'cyrus' in banner_lower:
            product = "Cyrus POP3"
            vendor = "cmu"
        elif 'courier' in banner_lower:
            product = "Courier POP3"
            vendor = "courier"

        service = "pop3s" if port == 995 else "pop3"

        return ServiceFingerprint(
            service=service,
            product=product,
            vendor=vendor,
            cpe=build_cpe(vendor or "unknown", product.lower().replace(' ', '_')) if vendor else None,
            confidence=0.90,
            detection_method="POP3 banner analysis",
            raw_banner=banner[:200]
        )

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"POP3 probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# Elasticsearch Fingerprinting
# =============================================================================

def probe_elasticsearch(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """Probe Elasticsearch via REST API."""
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except ImportError:
        return None

    try:
        url = f"http://{host}:{port}/"
        resp = requests.get(url, timeout=timeout, verify=False)

        if resp.status_code in (200, 401):
            features = []
            version = None

            if resp.status_code == 401:
                features.append("auth_required")
            else:
                features.append("no_auth")
                try:
                    data = resp.json()
                    version = data.get("version", {}).get("number")
                except Exception:
                    pass

            return ServiceFingerprint(
                service="elasticsearch",
                product="Elasticsearch",
                version=version,
                vendor="elastic",
                cpe=build_cpe("elastic", "elasticsearch", version),
                confidence=0.90,
                features=features,
                detection_method="Elasticsearch REST API probe",
                raw_banner=resp.text[:200]
            )

        return None

    except Exception as e:
        logger.debug(f"Elasticsearch probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# CouchDB Fingerprinting
# =============================================================================

def probe_couchdb(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """Probe CouchDB via REST API."""
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except ImportError:
        return None

    try:
        url = f"http://{host}:{port}/"
        resp = requests.get(url, timeout=timeout, verify=False)

        if resp.status_code == 200:
            try:
                data = resp.json()
                if "couchdb" in data or "CouchDB" in resp.text:
                    version = data.get("version")
                    features = []
                    return ServiceFingerprint(
                        service="couchdb",
                        product="CouchDB",
                        version=version,
                        vendor="apache",
                        cpe=build_cpe("apache", "couchdb", version),
                        confidence=0.95,
                        features=features,
                        detection_method="CouchDB REST API probe",
                        raw_banner=resp.text[:200]
                    )
            except Exception:
                pass
        elif resp.status_code == 401:
            return ServiceFingerprint(
                service="couchdb",
                product="CouchDB",
                vendor="apache",
                cpe=build_cpe("apache", "couchdb"),
                confidence=0.80,
                features=["auth_required"],
                detection_method="CouchDB REST API probe (auth required)"
            )

        return None

    except Exception as e:
        logger.debug(f"CouchDB probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# InfluxDB Fingerprinting
# =============================================================================

def probe_influxdb(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """Probe InfluxDB via REST API."""
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except ImportError:
        return None

    try:
        url = f"http://{host}:{port}/ping"
        resp = requests.get(url, timeout=timeout, verify=False)

        if resp.status_code == 204:
            version = resp.headers.get("X-Influxdb-Version")
            return ServiceFingerprint(
                service="influxdb",
                product="InfluxDB",
                version=version,
                vendor="influxdata",
                cpe=build_cpe("influxdata", "influxdb", version),
                confidence=0.95,
                detection_method="InfluxDB /ping probe",
                extra_info={"influxdb_version_header": version}
            )

        return None

    except Exception as e:
        logger.debug(f"InfluxDB probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# Cassandra Fingerprinting
# =============================================================================

def probe_cassandra(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """Probe Cassandra native protocol."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # CQL native protocol OPTIONS request (v4)
        options_frame = bytes([
            0x04,        # Version 4 (request)
            0x00,        # Flags
            0x00, 0x00,  # Stream ID
            0x05,        # Opcode: OPTIONS
            0x00, 0x00, 0x00, 0x00,  # Length: 0
        ])

        sock.send(options_frame)
        response = sock.recv(1024)
        sock.close()

        if len(response) >= 9:
            resp_version = response[0] & 0x7F
            resp_opcode = response[4]
            # SUPPORTED response opcode is 0x06
            if resp_opcode == 0x06:
                return ServiceFingerprint(
                    service="cassandra",
                    product="Apache Cassandra",
                    vendor="apache",
                    cpe=build_cpe("apache", "cassandra"),
                    confidence=0.95,
                    detection_method="CQL native protocol OPTIONS probe",
                    extra_info={"cql_version": resp_version}
                )

        return None

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"Cassandra probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# Neo4j Fingerprinting
# =============================================================================

def probe_neo4j(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """Probe Neo4j via HTTP REST API or Bolt protocol."""
    if port == 7687:
        return _probe_neo4j_bolt(host, port, timeout)

    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except ImportError:
        return None

    try:
        url = f"http://{host}:{port}/"
        resp = requests.get(url, timeout=timeout, verify=False)

        if resp.status_code in (200, 401):
            features = []
            version = None

            if resp.status_code == 401:
                features.append("auth_required")
            else:
                features.append("no_auth")
                try:
                    data = resp.json()
                    version = data.get("neo4j_version")
                except Exception:
                    pass

            if "neo4j" in resp.text.lower() or resp.status_code == 200:
                return ServiceFingerprint(
                    service="neo4j",
                    product="Neo4j",
                    version=version,
                    vendor="neo4j",
                    cpe=build_cpe("neo4j", "neo4j", version),
                    confidence=0.85,
                    features=features,
                    detection_method="Neo4j HTTP API probe",
                    raw_banner=resp.text[:200]
                )

        return None

    except Exception as e:
        logger.debug(f"Neo4j probe error for {host}:{port}: {e}")
        return None


def _probe_neo4j_bolt(host: str, port: int, timeout: float) -> Optional[ServiceFingerprint]:
    """Probe Neo4j Bolt protocol on port 7687."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Bolt handshake: magic preamble + 4 version proposals
        bolt_handshake = bytes([
            0x60, 0x60, 0xB0, 0x17,  # Bolt magic preamble
            0x00, 0x00, 0x04, 0x04,  # Version 4.4
            0x00, 0x00, 0x03, 0x04,  # Version 4.3
            0x00, 0x00, 0x02, 0x04,  # Version 4.2
            0x00, 0x00, 0x01, 0x04,  # Version 4.1
        ])

        sock.send(bolt_handshake)
        response = sock.recv(4)
        sock.close()

        if len(response) == 4 and response != b'\x00\x00\x00\x00':
            major = response[3]
            minor = response[2]
            return ServiceFingerprint(
                service="neo4j",
                product="Neo4j",
                vendor="neo4j",
                cpe=build_cpe("neo4j", "neo4j"),
                confidence=0.95,
                detection_method="Neo4j Bolt protocol handshake",
                extra_info={"bolt_version": f"{major}.{minor}"}
            )

        return None

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"Neo4j Bolt probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# Memcached Fingerprinting
# =============================================================================

def probe_memcached(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """Probe Memcached via stats command."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        sock.send(b"stats\r\n")
        response = sock.recv(4096).decode('utf-8', errors='ignore')
        sock.close()

        if 'STAT' in response:
            version = None
            version_match = re.search(r'STAT version ([\d.]+)', response)
            if version_match:
                version = version_match.group(1)

            return ServiceFingerprint(
                service="memcached",
                product="Memcached",
                version=version,
                vendor="memcached",
                cpe=build_cpe("memcached", "memcached", version),
                confidence=0.95,
                features=["no_auth"],
                detection_method="Memcached stats probe",
                raw_banner=response[:200]
            )

        return None

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"Memcached probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# SMB Fingerprinting
# =============================================================================

def probe_smb(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """Probe SMB service via SMB2 negotiate."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # SMB2 Negotiate Protocol Request (minimal)
        smb2_negotiate = bytes([
            # NetBIOS Session Service
            0x00, 0x00, 0x00, 0x44,  # Length: 68
            # SMB2 Header
            0xFE, 0x53, 0x4D, 0x42,  # Protocol: SMB2
            0x40, 0x00,              # Header length: 64
            0x00, 0x00,              # Credit charge
            0x00, 0x00, 0x00, 0x00,  # Status
            0x00, 0x00,              # Command: NEGOTIATE
            0x00, 0x00,              # Credits requested
            0x00, 0x00, 0x00, 0x00,  # Flags
            0x00, 0x00, 0x00, 0x00,  # Next command
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Message ID
            0x00, 0x00, 0x00, 0x00,  # Reserved
            0x00, 0x00, 0x00, 0x00,  # Tree ID
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Session ID
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature (first 8)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature (last 8)
            # Negotiate body (minimal)
            0x24, 0x00,  # Structure size
            0x01, 0x00,  # Dialect count: 1
            0x00, 0x00,  # Security mode
            0x00, 0x00,  # Reserved
            0x00, 0x00, 0x00, 0x00,  # Capabilities
            # Dialect: SMB 2.0.2
            0x02, 0x02,
        ])

        sock.send(smb2_negotiate)
        response = sock.recv(1024)
        sock.close()

        if len(response) > 4 and response[4:8] == b'\xFE\x53\x4D\x42':
            return ServiceFingerprint(
                service="smb",
                product="SMB Server",
                vendor="microsoft",
                cpe=build_cpe("microsoft", "smb"),
                confidence=0.90,
                detection_method="SMB2 Negotiate probe",
                raw_banner=response[:50].hex()
            )

        return None

    except socket.timeout:
        return None
    except Exception as e:
        logger.debug(f"SMB probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# WinRM Fingerprinting
# =============================================================================

def probe_winrm(host: str, port: int, timeout: float = 5.0) -> Optional[ServiceFingerprint]:
    """Probe WinRM service via HTTP."""
    try:
        import requests
        requests.packages.urllib3.disable_warnings()
    except ImportError:
        return None

    try:
        scheme = "https" if port == 5986 else "http"
        url = f"{scheme}://{host}:{port}/wsman"
        resp = requests.post(url, timeout=timeout, verify=False, data="")

        if resp.status_code in (401, 403, 405, 200):
            service = "winrm-ssl" if port == 5986 else "winrm"
            return ServiceFingerprint(
                service=service,
                product="Windows Remote Management",
                vendor="microsoft",
                cpe=build_cpe("microsoft", "winrm"),
                confidence=0.85,
                features=["auth_required"] if resp.status_code == 401 else [],
                detection_method="WinRM /wsman probe",
                raw_banner=resp.text[:200]
            )

        return None

    except Exception as e:
        logger.debug(f"WinRM probe error for {host}:{port}: {e}")
        return None


# =============================================================================
# Main Validation Function
# =============================================================================

# Port to protocol/probe mapping (comprehensive)
PORT_PROBE_MAP = {
    # FTP
    21: ("ftp", probe_ftp),

    # SSH
    22: ("ssh", probe_ssh),
    2222: ("ssh", probe_ssh),  # Alternative SSH port

    # Telnet
    23: ("telnet", probe_telnet),

    # HTTP/HTTPS
    80: ("http", lambda h, p, t: probe_http(h, p, t, False)),
    443: ("https", lambda h, p, t: probe_http(h, p, t, True)),
    8000: ("http", lambda h, p, t: probe_http(h, p, t, False)),
    8008: ("http", lambda h, p, t: probe_http(h, p, t, False)),
    8080: ("http", lambda h, p, t: probe_http(h, p, t, False)),
    8081: ("http", lambda h, p, t: probe_http(h, p, t, False)),
    8443: ("https", lambda h, p, t: probe_http(h, p, t, True)),
    8888: ("http", lambda h, p, t: probe_http(h, p, t, False)),
    9000: ("http", lambda h, p, t: probe_http(h, p, t, False)),  # Portainer, SonarQube
    9090: ("http", lambda h, p, t: probe_http(h, p, t, False)),  # Prometheus, Cockpit
    9443: ("https", lambda h, p, t: probe_http(h, p, t, True)),
    10000: ("http", lambda h, p, t: probe_http(h, p, t, False)),  # Webmin

    # SNMP
    161: ("snmp", probe_snmp),

    # LDAP
    389: ("ldap", lambda h, p, t: probe_ldap(h, p, t, False)),
    636: ("ldaps", lambda h, p, t: probe_ldap(h, p, t, True)),
    3268: ("ldap", lambda h, p, t: probe_ldap(h, p, t, False)),   # Global Catalog
    3269: ("ldaps", lambda h, p, t: probe_ldap(h, p, t, True)),   # Global Catalog SSL

    # IPMI
    623: ("ipmi", probe_ipmi),

    # MQTT
    1883: ("mqtt", lambda h, p, t: probe_mqtt(h, p, t, False)),
    8883: ("mqtts", lambda h, p, t: probe_mqtt(h, p, t, True)),

    # Databases
    1433: ("mssql", probe_mssql),
    1434: ("mssql", probe_mssql),  # MSSQL Browser
    3306: ("mysql", probe_mysql),
    5432: ("postgres", probe_postgres),
    5433: ("postgres", probe_postgres),  # Alternative PostgreSQL
    6379: ("redis", probe_redis),
    6380: ("redis", probe_redis),  # Alternative Redis
    27017: ("mongodb", probe_mongodb),
    27018: ("mongodb", probe_mongodb),

    # SMTP/IMAP/POP3
    25: ("smtp", probe_smtp),
    110: ("pop3", probe_pop3),
    143: ("imap", probe_imap),
    465: ("smtps", lambda h, p, t: probe_smtp(h, p, t)),
    587: ("smtp", probe_smtp),
    993: ("imaps", lambda h, p, t: probe_imap(h, p, t)),
    995: ("pop3s", lambda h, p, t: probe_pop3(h, p, t)),

    # SMB/WinRM
    445: ("smb", probe_smb),
    5985: ("winrm", probe_winrm),
    5986: ("winrm-ssl", lambda h, p, t: probe_winrm(h, p, t)),

    # RDP/VNC
    3389: ("rdp", probe_rdp),
    5800: ("vnc", probe_vnc),
    5900: ("vnc", probe_vnc),
    5901: ("vnc", probe_vnc),
    5902: ("vnc", probe_vnc),
    5903: ("vnc", probe_vnc),
    5904: ("vnc", probe_vnc),
    5905: ("vnc", probe_vnc),

    # Elasticsearch/CouchDB/InfluxDB
    5984: ("couchdb", probe_couchdb),
    8086: ("influxdb", probe_influxdb),
    9200: ("elasticsearch", probe_elasticsearch),
    9300: ("elasticsearch", probe_elasticsearch),

    # Cassandra/Neo4j/Memcached
    7474: ("neo4j", probe_neo4j),
    7687: ("neo4j", lambda h, p, t: probe_neo4j(h, p, t)),
    9042: ("cassandra", probe_cassandra),
    11211: ("memcached", probe_memcached),

    # Container/Orchestration (HTTP-based)
    2375: ("http", lambda h, p, t: probe_http(h, p, t, False)),  # Docker API
    2376: ("https", lambda h, p, t: probe_http(h, p, t, True)),  # Docker API TLS
    6443: ("https", lambda h, p, t: probe_http(h, p, t, True)),  # Kubernetes API
    10250: ("https", lambda h, p, t: probe_http(h, p, t, True)), # Kubelet API

    # Web UIs (HTTP)
    15672: ("http", lambda h, p, t: probe_http(h, p, t, False)),  # RabbitMQ Management
    8161: ("http", lambda h, p, t: probe_http(h, p, t, False)),   # ActiveMQ Web Console
    9001: ("http", lambda h, p, t: probe_http(h, p, t, False)),   # Various web UIs
    50000: ("http", lambda h, p, t: probe_http(h, p, t, False)),  # Jenkins agent
    50070: ("http", lambda h, p, t: probe_http(h, p, t, False)),  # Hadoop NameNode
}

# Protocol to probe mapping (for explicit protocol specification)
PROTOCOL_PROBE_MAP = {
    "ssh": probe_ssh,
    "ftp": probe_ftp,
    "mysql": probe_mysql,
    "postgres": probe_postgres,
    "mssql": probe_mssql,
    "mongodb": probe_mongodb,
    "redis": probe_redis,
    "vnc": probe_vnc,
    "rdp": probe_rdp,
    "telnet": probe_telnet,
    "snmp": probe_snmp,
    "http": lambda h, p, t: probe_http(h, p, t, False),
    "https": lambda h, p, t: probe_http(h, p, t, True),
    "ldap": lambda h, p, t: probe_ldap(h, p, t, False),
    "ldaps": lambda h, p, t: probe_ldap(h, p, t, True),
    "ipmi": probe_ipmi,
    "mqtt": lambda h, p, t: probe_mqtt(h, p, t, False),
    "mqtts": lambda h, p, t: probe_mqtt(h, p, t, True),
    "smtp": probe_smtp,
    "smtps": probe_smtp,
    "imap": probe_imap,
    "imaps": probe_imap,
    "pop3": probe_pop3,
    "pop3s": probe_pop3,
    "smb": probe_smb,
    "winrm": probe_winrm,
    "winrm-ssl": probe_winrm,
    "elasticsearch": probe_elasticsearch,
    "couchdb": probe_couchdb,
    "influxdb": probe_influxdb,
    "cassandra": probe_cassandra,
    "neo4j": probe_neo4j,
    "memcached": probe_memcached,
}


def validate_and_fingerprint(
    host: str,
    port: int,
    protocol: str = "auto",
    timeout: float = 5.0
) -> ServiceFingerprint:
    """
    Validate service and return detailed fingerprint.

    Uses protocol-specific probes instead of generic banner grabbing.

    Args:
        host: Target IP/hostname
        port: Target port
        protocol: Protocol to probe ("auto" for port-based detection)
        timeout: Connection timeout

    Returns:
        ServiceFingerprint with detection results
    """
    # Determine which probe to use
    probe_func = None
    expected_protocol = protocol

    if protocol == "auto" or protocol == "unknown":
        # Use port-based detection
        if port in PORT_PROBE_MAP:
            expected_protocol, probe_func = PORT_PROBE_MAP[port]
        else:
            # Default to banner grabbing
            expected_protocol = "unknown"
    else:
        # Use specified protocol
        probe_func = PROTOCOL_PROBE_MAP.get(protocol.lower())

    # Try the specific probe
    if probe_func:
        result = probe_func(host, port, timeout)
        if result:
            return result

    # Fallback: Try generic banner detection
    return _generic_banner_probe(host, port, timeout, expected_protocol)


def _generic_banner_probe(
    host: str,
    port: int,
    timeout: float,
    expected_protocol: str
) -> ServiceFingerprint:
    """
    Fallback generic banner detection.

    Args:
        host: Target IP/hostname
        port: Target port
        timeout: Connection timeout
        expected_protocol: Expected protocol based on port

    Returns:
        ServiceFingerprint with low confidence
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Try to read banner
        sock.settimeout(2)
        try:
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        except:
            banner = None

        sock.close()

        # Try to detect service from banner
        if banner:
            banner_lower = banner.lower()
            detected_service = expected_protocol

            if 'ssh' in banner_lower:
                detected_service = "ssh"
            elif 'ftp' in banner_lower or banner.startswith('220'):
                detected_service = "ftp"
            elif 'mysql' in banner_lower:
                detected_service = "mysql"
            elif 'postgres' in banner_lower:
                detected_service = "postgres"
            elif 'redis' in banner_lower:
                detected_service = "redis"
            elif 'http' in banner_lower:
                detected_service = "http"

            return ServiceFingerprint(
                service=detected_service,
                confidence=0.50,
                detection_method="Generic banner detection",
                raw_banner=banner[:200]
            )

        # Port-based assumption only
        return ServiceFingerprint(
            service=expected_protocol,
            confidence=0.30,
            detection_method="Port-based assumption"
        )

    except Exception:
        # Connection failed
        return ServiceFingerprint(
            service=expected_protocol,
            confidence=0.10,
            detection_method="Connection failed"
        )
