"""
Device Fingerprinting for Cygor Scan.

Provides the fingerprint_host() function that extracts device information
from Nmap XML results and runs FingerprintDB lookups to identify devices,
manufacturers, and operating systems.

Data Sources (powered by Huginn-Muninn):
- MAC OUI: Manufacturer identification
- Service Banners: OS, product, version detection (SSH, HTTP, SMB, FTP)
- Nmap OS Detection: TCP/IP stack fingerprinting
- SSL/TLS Certificates: CommonName often contains OS/hostname hints
- SMB OS Discovery: Detailed OS info from NetBIOS/SMB enumeration
- DHCP Options: Device type and OS (from Nmap scripts)
- HTTP Server Headers: Web server version with OS hints (e.g., "Apache (Ubuntu)")
- Hostname: Device hints from naming conventions
- TTL: Basic OS family heuristic

Enhanced OS Detection:
- Extracts Linux distribution from SSH banners (e.g., "Debian 8ubuntu1" → Ubuntu)
- Parses HTTP Server headers for OS hints (e.g., "(Ubuntu)")
- Extracts OS version from SSL certificate CN (e.g., "ubuntu804" → Ubuntu 8.04)
- Combines kernel version from Nmap OS detection with distro hints

Multi-source validation increases confidence when sources agree.
"""

import os
import re
import logging
from typing import Optional, Dict, List, Any, Tuple
from dataclasses import dataclass, field, asdict

from libnmap.parser import NmapParser, NmapParserException

from .lookup import FingerprintLookup, FingerprintMatch, aggregate_evidence
from .patterns import match_banner, match_dhcp_opt55, match_dhcp_opt60, enrich_vendor_device
from .os_intelligence import (
    ValidationStatus,
    infer_os_from_kernel,
    infer_firmware_from_manufacturer,
    check_os_plausibility,
    get_inferred_os_display,
)

logger = logging.getLogger(__name__)


# =============================================================================
# Linux Distribution Detection Patterns
# =============================================================================

# SSH banner patterns that reveal Linux distribution
SSH_DISTRO_PATTERNS = [
    # ==========================================================================
    # Security / Penetration Testing Distributions (HIGH PRIORITY)
    # ==========================================================================

    # Kali Linux - Most popular penetration testing distro
    (r'[Kk]ali', 'Kali Linux', None),
    (r'kali-rolling', 'Kali Linux', None),

    # Parrot Security OS - Debian-based security distro
    (r'[Pp]arrot', 'Parrot Security OS', None),
    (r'parrot-security', 'Parrot Security OS', None),

    # BlackArch - Arch-based with 2500+ security tools
    (r'[Bb]lack[Aa]rch', 'BlackArch Linux', None),

    # Pentoo - Gentoo-based pentesting distro
    (r'[Pp]entoo', 'Pentoo Linux', None),

    # BackBox - Ubuntu-based security distro
    (r'[Bb]ack[Bb]ox', 'BackBox Linux', None),

    # ArchStrike - Arch-based security distro
    (r'[Aa]rch[Ss]trike', 'ArchStrike', None),

    # Athena OS - Arch-based pentesting distro
    (r'[Aa]thena[- ]?[Oo][Ss]', 'Athena OS', None),

    # Bugtraq - Debian-based for malware analysis
    (r'[Bb]ugtraq', 'Bugtraq', None),

    # Cyborg Hawk - Ubuntu-based ethical hacking distro
    (r'[Cc]yborg[- ]?[Hh]awk', 'Cyborg Hawk', None),

    # Network Security Toolkit (NST) - Fedora-based
    (r'NST|Network[- ]?Security[- ]?Toolkit', 'Network Security Toolkit', None),

    # Fedora Security Lab
    (r'[Ff]edora[- ]?[Ss]ecurity', 'Fedora Security Lab', None),

    # ==========================================================================
    # Digital Forensics / Incident Response Distributions
    # ==========================================================================

    # CAINE - Computer Aided Investigative Environment
    (r'CAINE|caine', 'CAINE', None),

    # DEFT - Digital Evidence & Forensic Toolkit
    (r'DEFT|deft', 'DEFT Linux', None),

    # Tsurugi Linux - DFIR and OSINT distro
    (r'[Tt]surugi', 'Tsurugi Linux', None),

    # SIFT Workstation - SANS forensics
    (r'SIFT|sift', 'SIFT Workstation', None),

    # Paladin - Sumuri forensic distro
    (r'[Pp]aladin', 'Paladin Forensic Suite', None),

    # ==========================================================================
    # Malware Analysis Distributions
    # ==========================================================================

    # REMnux - Malware analysis toolkit (Ubuntu-based)
    (r'REMnux|remnux', 'REMnux', None),

    # ==========================================================================
    # Docker/Container-Based Security Environments
    # ==========================================================================

    # Exegol - Docker-based pentesting environment
    (r'[Ee]xegol', 'Exegol', None),

    # ==========================================================================
    # Privacy / Anonymity Distributions
    # ==========================================================================

    # Tails - Privacy-focused live OS
    (r'[Tt]ails', 'Tails OS', None),

    # Whonix - Anonymous OS using Tor
    (r'[Ww]honix', 'Whonix', None),

    # Qubes OS - Security-focused desktop OS
    (r'[Qq]ubes', 'Qubes OS', None),

    # ==========================================================================
    # Standard Linux Distributions
    # ==========================================================================

    # Ubuntu variants. The trailing "ubuntu1"/"3ubuntu0.6" in an OpenSSH banner
    # is the *package* revision, NOT the Ubuntu release, so we must not report
    # it as a version. Only accept a genuine "Ubuntu XX.YY" release string
    # (rare in SSH banners); otherwise leave the version to kernel inference.
    (r'ubuntu', 'Ubuntu', r'Ubuntu[_\s-]+(\d{2}\.\d{2})'),

    # Debian variants. Debian's OpenSSH banner is e.g.
    # "OpenSSH 9.2p1 Debian 2+deb12u9": the "2" after "Debian" is the package
    # revision (NOT a Debian release), and the real release lives in "+deb12".
    # Parse the +deb / ~deb major so we report Debian 12, not "Debian 2".
    (r'Debian', 'Debian', r'[+~]deb(\d+)'),

    # Red Hat / CentOS / RHEL
    (r'RHEL|Red\s*Hat', 'RHEL', None),
    (r'CentOS', 'CentOS', None),
    (r'Rocky|rocky', 'Rocky Linux', None),
    (r'AlmaLinux|alma', 'AlmaLinux', None),
    (r'el(\d+)', 'RHEL/CentOS', r'el(\d+)'),  # el7, el8, etc.

    # Fedora
    (r'Fedora|fc(\d+)', 'Fedora', r'fc(\d+)'),

    # SUSE
    (r'SUSE|SLE[SD]', 'SUSE', None),
    (r'openSUSE', 'openSUSE', None),

    # Arch
    (r'Arch', 'Arch Linux', None),

    # Alpine
    (r'Alpine', 'Alpine Linux', None),

    # Gentoo
    (r'Gentoo', 'Gentoo', None),

    # Raspbian / Raspberry Pi OS
    (r'Raspbian|raspberrypi', 'Raspberry Pi OS', None),

    # Void Linux
    (r'[Vv]oid', 'Void Linux', None),

    # NixOS
    (r'[Nn]ix[Oo][Ss]', 'NixOS', None),
]

# HTTP Server header OS hints
HTTP_SERVER_OS_PATTERNS = [
    # ==========================================================================
    # Security Distributions (HIGH PRIORITY)
    # ==========================================================================
    (r'Apache/[\d.]+\s*\([Kk]ali\)', 'Kali Linux', None),
    (r'Apache/[\d.]+\s*\([Pp]arrot\)', 'Parrot Security OS', None),
    (r'Apache/[\d.]+\s*\([Bb]lack[Aa]rch\)', 'BlackArch Linux', None),
    (r'Apache/[\d.]+\s*\([Bb]ack[Bb]ox\)', 'BackBox Linux', None),
    (r'Apache/[\d.]+\s*\(REMnux\)', 'REMnux', None),
    (r'Apache/[\d.]+\s*\(CAINE\)', 'CAINE', None),
    (r'Apache/[\d.]+\s*\(DEFT\)', 'DEFT Linux', None),
    (r'Apache/[\d.]+\s*\([Tt]surugi\)', 'Tsurugi Linux', None),
    (r'nginx.*[Kk]ali', 'Kali Linux', None),
    (r'nginx.*[Pp]arrot', 'Parrot Security OS', None),

    # ==========================================================================
    # Standard Distributions
    # ==========================================================================
    # Apache with OS in parentheses
    (r'Apache/[\d.]+\s*\(Ubuntu\)', 'Ubuntu', None),
    (r'Apache/[\d.]+\s*\(Debian\)', 'Debian', None),
    (r'Apache/[\d.]+\s*\(CentOS\)', 'CentOS', None),
    (r'Apache/[\d.]+\s*\(Red\s*Hat[^)]*\)', 'RHEL', None),
    (r'Apache/[\d.]+\s*\(Fedora\)', 'Fedora', None),
    (r'Apache/[\d.]+\s*\(Win32\)', 'Windows', None),
    (r'Apache/[\d.]+\s*\(Win64\)', 'Windows', None),
    (r'Apache/[\d.]+\s*\(FreeBSD\)', 'FreeBSD', None),
    (r'Apache/[\d.]+\s*\(Rocky\)', 'Rocky Linux', None),
    (r'Apache/[\d.]+\s*\(AlmaLinux\)', 'AlmaLinux', None),

    # nginx with OS hints
    (r'nginx.*Ubuntu', 'Ubuntu', None),
    (r'nginx.*Debian', 'Debian', None),

    # Microsoft IIS (Windows)
    (r'Microsoft-IIS/([\d.]+)', 'Windows', r'IIS/([\d.]+)'),

    # PHP often reveals OS
    (r'PHP/[\d.]+.*Ubuntu', 'Ubuntu', None),
    (r'PHP/[\d.]+.*Debian', 'Debian', None),
    (r'PHP/[\d.]+.*[Kk]ali', 'Kali Linux', None),
    (r'PHP/[\d.]+.*[Pp]arrot', 'Parrot Security OS', None),
]

# Release-version -> codename, so "Debian 12" reads as "Debian 12 (bookworm)"
# and the distro release is unambiguous. Keep current + recent releases.
_DEBIAN_CODENAMES = {
    "7": "wheezy", "8": "jessie", "9": "stretch", "10": "buster",
    "11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky",
}
_UBUNTU_CODENAMES = {
    "14.04": "trusty", "16.04": "xenial", "18.04": "bionic", "20.04": "focal",
    "22.04": "jammy", "23.04": "lunar", "23.10": "mantic", "24.04": "noble",
    "24.10": "oracular", "25.04": "plucky",
}


def _distro_codename(os_name, os_version):
    """Return the release codename for a Debian/Ubuntu version, or None."""
    if not os_name or not os_version:
        return None
    v = str(os_version).strip()
    if os_name == "Debian":
        return _DEBIAN_CODENAMES.get(v.split(".")[0])
    if os_name == "Ubuntu":
        return _UBUNTU_CODENAMES.get(v)
    return None

# SSL Certificate CommonName patterns for OS detection
SSL_CN_PATTERNS = [
    # ==========================================================================
    # Security Distributions (HIGH PRIORITY)
    # ==========================================================================
    (r'kali', 'Kali Linux', None),
    (r'parrot', 'Parrot Security OS', None),
    (r'blackarch', 'BlackArch Linux', None),
    (r'backbox', 'BackBox Linux', None),
    (r'remnux', 'REMnux', None),
    (r'caine', 'CAINE', None),
    (r'deft', 'DEFT Linux', None),
    (r'tsurugi', 'Tsurugi Linux', None),
    (r'sift', 'SIFT Workstation', None),
    (r'pentoo', 'Pentoo Linux', None),
    (r'exegol', 'Exegol', None),
    (r'whonix', 'Whonix', None),
    (r'tails', 'Tails OS', None),
    (r'qubes', 'Qubes OS', None),

    # ==========================================================================
    # Standard Distributions
    # ==========================================================================
    # Ubuntu version patterns (e.g., ubuntu804, ubuntu1604)
    (r'ubuntu(\d)(\d{2})', 'Ubuntu', lambda m: f"Ubuntu {m.group(1)}.{m.group(2)}"),
    (r'ubuntu-?(\d+\.?\d*)', 'Ubuntu', lambda m: f"Ubuntu {m.group(1)}"),

    # Debian version
    (r'debian(\d+)', 'Debian', lambda m: f"Debian {m.group(1)}"),

    # CentOS/RHEL version
    (r'centos(\d+)', 'CentOS', lambda m: f"CentOS {m.group(1)}"),
    (r'rhel(\d+)', 'RHEL', lambda m: f"RHEL {m.group(1)}"),
    (r'rocky(\d+)', 'Rocky Linux', lambda m: f"Rocky Linux {m.group(1)}"),
    (r'alma(\d+)', 'AlmaLinux', lambda m: f"AlmaLinux {m.group(1)}"),

    # Generic Linux hints
    (r'linux', 'Linux', None),
]


# =============================================================================
# Hostname Patterns for Device Detection
# =============================================================================

HOSTNAME_PATTERNS = [
    # ==========================================================================
    # Security / Penetration Testing Systems (HIGH PRIORITY)
    # ==========================================================================
    # These patterns detect security-focused systems which are often used by
    # pentesters, red teamers, security researchers, and forensic analysts

    # Kali Linux - Default and common hostname patterns
    (r'^kali$', 'workstation', None, 'Kali Linux'),
    (r'^kali[0-9-]*$', 'workstation', None, 'Kali Linux'),
    (r'kali-?linux', 'workstation', None, 'Kali Linux'),
    (r'kali-?rolling', 'workstation', None, 'Kali Linux'),

    # Parrot Security OS
    (r'^parrot$', 'workstation', None, 'Parrot Security OS'),
    (r'^parrot[0-9-]*$', 'workstation', None, 'Parrot Security OS'),
    (r'parrot-?sec', 'workstation', None, 'Parrot Security OS'),

    # BlackArch
    (r'^blackarch$', 'workstation', None, 'BlackArch Linux'),
    (r'blackarch[0-9-]*', 'workstation', None, 'BlackArch Linux'),

    # BackBox
    (r'^backbox$', 'workstation', None, 'BackBox Linux'),
    (r'backbox[0-9-]*', 'workstation', None, 'BackBox Linux'),

    # Pentoo
    (r'^pentoo$', 'workstation', None, 'Pentoo Linux'),
    (r'pentoo[0-9-]*', 'workstation', None, 'Pentoo Linux'),

    # ArchStrike
    (r'^archstrike$', 'workstation', None, 'ArchStrike'),
    (r'archstrike[0-9-]*', 'workstation', None, 'ArchStrike'),

    # Exegol (Docker-based)
    (r'^exegol$', 'workstation', None, 'Exegol'),
    (r'exegol[0-9-]*', 'workstation', None, 'Exegol'),

    # Common attacker/pentester hostname patterns
    (r'^attacker[0-9-]*$', 'workstation', None, None),
    (r'^pentester?[0-9-]*$', 'workstation', None, None),
    (r'^pentest[0-9-]*$', 'workstation', None, None),
    (r'^redteam[0-9-]*$', 'workstation', None, None),
    (r'^blueteam[0-9-]*$', 'workstation', None, None),
    (r'^hacker[0-9-]*$', 'workstation', None, None),
    (r'^hackbox[0-9-]*$', 'workstation', None, None),
    (r'^pwn[a-z0-9-]*$', 'workstation', None, None),
    (r'^htb[0-9-]*$', 'workstation', None, None),  # HackTheBox
    (r'^thm[0-9-]*$', 'workstation', None, None),  # TryHackMe
    (r'^ctf[0-9-]*$', 'workstation', None, None),  # CTF machines
    (r'^oscp[0-9-]*$', 'workstation', None, None),  # OSCP lab machines

    # ==========================================================================
    # Digital Forensics / Incident Response Systems
    # ==========================================================================

    # CAINE - Computer Aided Investigative Environment
    (r'^caine$', 'workstation', None, 'CAINE'),
    (r'caine[0-9-]*', 'workstation', None, 'CAINE'),

    # DEFT Linux
    (r'^deft$', 'workstation', None, 'DEFT Linux'),
    (r'deft[0-9-]*', 'workstation', None, 'DEFT Linux'),

    # Tsurugi Linux
    (r'^tsurugi$', 'workstation', None, 'Tsurugi Linux'),
    (r'tsurugi[0-9-]*', 'workstation', None, 'Tsurugi Linux'),

    # SIFT Workstation (SANS)
    (r'^sift$', 'workstation', None, 'SIFT Workstation'),
    (r'sift[0-9-]*', 'workstation', None, 'SIFT Workstation'),

    # Paladin
    (r'^paladin$', 'workstation', None, 'Paladin Forensic Suite'),
    (r'paladin[0-9-]*', 'workstation', None, 'Paladin Forensic Suite'),

    # Common forensics hostname patterns
    (r'^forensic[s]?[0-9-]*$', 'workstation', None, None),
    (r'^dfir[0-9-]*$', 'workstation', None, None),
    (r'^analyst[0-9-]*$', 'workstation', None, None),
    (r'^ir[0-9-]*$', 'workstation', None, None),  # Incident Response

    # ==========================================================================
    # Malware Analysis Systems
    # ==========================================================================

    # REMnux
    (r'^remnux$', 'workstation', None, 'REMnux'),
    (r'remnux[0-9-]*', 'workstation', None, 'REMnux'),

    # FLARE VM (Windows-based) - Common hostname patterns
    (r'^flare[- ]?vm[0-9-]*$', 'workstation', None, 'FLARE VM'),
    (r'^flarevm[0-9-]*$', 'workstation', None, 'FLARE VM'),

    # Commando VM (Windows-based)
    (r'^commando[- ]?vm[0-9-]*$', 'workstation', None, 'Commando VM'),
    (r'^commandovm[0-9-]*$', 'workstation', None, 'Commando VM'),

    # Common malware analysis hostname patterns
    (r'^malware[- ]?lab[0-9-]*$', 'workstation', None, None),
    (r'^sandbox[0-9-]*$', 'workstation', None, None),
    (r'^analysis[0-9-]*$', 'workstation', None, None),
    (r'^reverse[0-9-]*$', 'workstation', None, None),

    # ==========================================================================
    # Privacy / Anonymity Systems
    # ==========================================================================

    # Tails OS
    (r'^tails$', 'workstation', None, 'Tails OS'),
    (r'tails[0-9-]*', 'workstation', None, 'Tails OS'),
    (r'^amnesia$', 'workstation', None, 'Tails OS'),  # Tails default hostname

    # Whonix
    (r'^whonix$', 'workstation', None, 'Whonix'),
    (r'whonix[0-9-]*', 'workstation', None, 'Whonix'),
    (r'^host$', 'workstation', None, None),  # Whonix Gateway default

    # Qubes OS
    (r'^qubes$', 'workstation', None, 'Qubes OS'),
    (r'qubes[0-9-]*', 'workstation', None, 'Qubes OS'),
    (r'^dom0$', 'workstation', None, 'Qubes OS'),  # Qubes admin domain

    # ==========================================================================
    # Windows Security VMs
    # ==========================================================================

    # Windows naming conventions
    (r'^DESKTOP-[A-Z0-9]+$', 'workstation', None, 'Windows'),
    (r'^WIN-[A-Z0-9]+$', 'server', None, 'Windows'),
    (r'^PC-?[A-Z0-9]+$', 'workstation', None, 'Windows'),
    (r'^LAPTOP-?[A-Z0-9]+$', 'laptop', None, 'Windows'),

    # Apple devices
    (r"iPhone", 'mobile', 'Apple', 'iOS'),
    (r"iPad", 'tablet', 'Apple', 'iPadOS'),
    (r"MacBook", 'laptop', 'Apple', 'macOS'),
    (r"iMac", 'workstation', 'Apple', 'macOS'),
    (r"Mac-?mini", 'workstation', 'Apple', 'macOS'),
    (r"Mac-?Pro", 'workstation', 'Apple', 'macOS'),
    (r"Mac-?Studio", 'workstation', 'Apple', 'macOS'),
    (r"Apple-?TV", 'streaming_device', 'Apple', 'tvOS'),
    (r"HomePod", 'smart_speaker', 'Apple', 'audioOS'),
    (r"Apple-?Watch|Watch\d", 'smartwatch', 'Apple', 'watchOS'),
    (r"Vision-?Pro|AppleVision", 'ar_headset', 'Apple', 'visionOS'),
    (r"AirPods|AirTag", 'wearable', 'Apple', None),

    # Android devices
    (r'android', 'mobile', None, 'Android'),
    (r'Galaxy', 'mobile', 'Samsung', 'Android'),
    (r'Pixel', 'mobile', 'Google', 'Android'),

    # Network devices
    (r'^(R|RT|RTR|ROUTER)[0-9-]+$', 'router', None, None),
    (r'^(SW|SWITCH)[0-9-]+$', 'switch', None, None),
    (r'^(FW|FIREWALL)[0-9-]+$', 'firewall', None, None),
    (r'^(AP|WAP|WIRELESS)[0-9-]+$', 'access_point', None, None),
    (r'mikrotik', 'router', 'MikroTik', 'RouterOS'),
    (r'ubnt|unifi', 'access_point', 'Ubiquiti', None),
    (r'^(LB|LOADBAL|F5|NETSCALER)[0-9-]*$', 'load_balancer', None, None),
    (r'^(VPN|VPNGW)[0-9-]*$', 'vpn_gateway', None, None),

    # Out-of-band server management (BMC) — these prefixes are vendor-specific
    # and authoritative: an "idrac-*" host IS a Dell BMC, "ilo*" IS HPE, etc.
    (r'idrac|drac[0-9]?', 'bmc', 'Dell', None),
    (r'(^|[-_.])ilo[0-9]?([-_.]|$)', 'bmc', 'HPE', None),
    (r'(^|[-_.])imm([-_.]|$)|xclarity', 'bmc', 'Lenovo', None),
    (r'(^|[-_.])cimc([-_.]|$)', 'bmc', 'Cisco', None),
    (r'(^|[-_.])(bmc|ipmi)([-_.0-9]|$)', 'bmc', None, None),

    # Servers
    (r'^(SRV|SERVER|DC|SQL|WEB|MAIL|FILE)[0-9-]+$', 'server', None, None),
    (r'git(ea|lab|hub)', 'server', None, 'Linux'),
    (r'^(ESX|VCENTER|VMWARE)', 'esxi', 'VMware', 'ESXi'),
    (r'^(PROXMOX|PVE)[0-9-]*$', 'proxmox', 'Proxmox', 'Proxmox VE'),
    (r'(^|[-_.])pve([-_.0-9]|$)', 'proxmox', 'Proxmox', 'Proxmox VE'),
    (r'^(HYPERV|HV)[0-9-]*$', 'hyper_v', 'Microsoft', 'Windows Server'),
    (r'^(DB|DATABASE|MYSQL|POSTGRES|MONGO|REDIS)[0-9-]*$', 'database_server', None, None),
    (r'^(K8S|KUBE|KUBERNETES)[0-9-]*$', 'kubernetes_node', None, None),
    (r'^(DOCKER|CONTAINER)[0-9-]*$', 'docker_host', None, None),

    # Printers
    (r'^(PRN|PRINTER|HP|CANON|EPSON|BROTHER|XEROX)[0-9-]+$', 'printer', None, None),
    (r'laserjet|officejet|deskjet', 'printer', 'HP', None),
    (r'^(MFP|MULTIFUNCTION)[0-9-]*$', 'multifunction', None, None),

    # NAS devices
    (r'synology|diskstation|ds\d{3,4}', 'nas', 'Synology', 'DSM'),
    (r'qnap|ts-?\d{3,4}', 'nas', 'QNAP', 'QTS'),
    (r'freenas|truenas', 'nas', None, 'TrueNAS'),
    (r'^(NAS|NETAPP|EMC|PURE)[0-9-]*$', 'nas', None, None),

    # IoT / Smart Home
    (r'nest|google-home', 'smart_speaker', 'Google', None),
    (r'echo|alexa|amazon-echo', 'smart_speaker', 'Amazon', None),
    (r'philips-hue|hue-bridge', 'smart_home', 'Philips', None),
    (r'ring|ring-doorbell', 'doorbell', 'Ring', None),
    (r'ecobee', 'thermostat', 'ecobee', None),
    (r'nest-thermostat', 'thermostat', 'Google', None),
    (r'smartthings', 'home_hub', 'Samsung', None),
    (r'homeassistant|hass', 'home_automation', None, None),
    (r'shelly|tasmota', 'smart_plug', None, None),
    (r'lifx|nanoleaf|yeelight', 'smart_lighting', None, None),
    (r'lutron|caseta', 'smart_lighting', 'Lutron', None),
    (r'august|schlage|yale-lock', 'smart_lock', None, None),
    (r'ratgdo', 'iot', None, None),  # ESP32 garage-door controller (ESPHome)
    (r'esphome|esp32|esp8266', 'iot', None, None),

    # Smart garage door openers
    (r'myq|chamberlain|liftmaster', 'garage_door', 'Chamberlain', None),
    (r'genie-?garage|aladdin-?connect', 'garage_door', None, None),

    # Solar inverters / energy gateways (web/API-managed, commonly scanned)
    (r'solaredge', 'solar_inverter', 'SolarEdge', None),
    (r'envoy|enphase', 'solar_inverter', 'Enphase', None),
    (r'fronius', 'solar_inverter', 'Fronius', None),
    (r'sungrow', 'solar_inverter', 'Sungrow', None),
    (r'growatt', 'solar_inverter', 'Growatt', None),
    (r'sma-?(inverter|solar)|sunny-?(boy|tripower|island)', 'solar_inverter', 'SMA', None),
    (r'solis|ginlong', 'solar_inverter', 'Solis', None),
    (r'powerwall|tesla-?energy|gateway-?\d', 'energy_gateway', 'Tesla', None),
    (r'ecoflow', 'energy_gateway', 'EcoFlow', None),
    (r'\b(inverter|solar)[-_]?\d*\b', 'solar_inverter', None, None),

    # Network-managed UPS / PDU (server-room gear with web/SNMP cards)
    (r'apc|smart-?ups|back-?ups', 'ups', 'APC', None),
    (r'eaton-?ups|powerware|eaton', 'ups', 'Eaton', None),
    (r'cyberpower', 'ups', 'CyberPower', None),
    (r'vertiv|liebert|geist|netsure', 'ups', 'Vertiv', None),
    (r'tripp-?lite|tripplite', 'ups', 'Tripp Lite', None),
    (r'\bups[-_]?\d*\b', 'ups', None, None),
    (r'\b(pdu|rpdu)[-_]?\d*\b', 'pdu', None, None),

    # Building automation controllers (BACnet / web)
    (r'distech', 'building_automation', 'Distech', None),
    (r'webctrl|automated-?logic', 'building_automation', 'Automated Logic', None),
    (r'jci|metasys|johnson-?controls', 'building_automation', 'Johnson Controls', None),
    (r'kmc-?controls|delta-?controls', 'building_automation', None, None),

    # Media players / streamers
    (r'libreelec|openelec|libreelec|osmc|kodi|xbmc', 'streaming_device', None, 'Linux'),
    (r'librelec', 'streaming_device', None, 'Linux'),
    (r'plex|plexmediaserver', 'media_server', None, None),
    (r'shield-?tv|nvidia-?shield', 'streaming_device', 'NVIDIA', 'Android'),
    (r'firetv|fire-?tv|aftt', 'streaming_device', 'Amazon', 'Android'),
    (r'appletv|apple-?tv', 'streaming_device', 'Apple', 'tvOS'),
    (r'chromecast|googlecast', 'streaming_device', 'Google', None),
    (r'roku', 'streaming_device', 'Roku', 'Roku OS'),
    (r'audiocast|musiccast|airplay', 'streaming_device', None, None),

    # Doorbells / surveillance (UniFi Protect G4 line, generic doorbells)
    (r'g4-?(doorbell|bullet|dome|pro|instant|flex)', 'ip_camera', 'Ubiquiti', None),
    (r'doorbell', 'doorbell', None, None),

    # Mesh WiFi / Home Routers
    (r'eero[- ]?pro', 'mesh_router', 'eero', 'eeroOS'),
    (r'eero[- ]?max', 'mesh_router', 'eero', 'eeroOS'),
    (r'eero[- ]?beacon', 'range_extender', 'eero', 'eeroOS'),
    (r'eero[- ]?\d', 'mesh_router', 'eero', 'eeroOS'),
    (r'eero', 'mesh_router', 'eero', 'eeroOS'),
    (r'google[- ]?wifi', 'mesh_router', 'Google', None),
    (r'nest[- ]?wifi', 'mesh_router', 'Google', None),
    (r'orbi', 'mesh_router', 'Netgear', None),
    (r'velop', 'mesh_router', 'Linksys', None),
    (r'deco', 'mesh_router', 'TP-Link', None),
    (r'asus[- ]?zen[- ]?wifi', 'mesh_router', 'ASUS', None),
    (r'amplifi', 'mesh_router', 'Ubiquiti', None),

    # Audio Speakers / Soundbars (HIGH PRIORITY - match before generic patterns)
    (r'jbl[- ]?bar\d+', 'soundbar', 'JBL', 'Linux'),
    (r'jbl[- ]?authentics', 'smart_speaker', 'JBL', 'Linux'),
    (r'jbl[- ]?link', 'smart_speaker', 'JBL', 'Linux'),
    (r'jbl[- ]?partybox', 'speaker', 'JBL', 'Linux'),
    (r'jbl[- ]?boombox', 'speaker', 'JBL', 'Linux'),
    (r'jbl[- ]?flip', 'speaker', 'JBL', None),
    (r'jbl[- ]?charge', 'speaker', 'JBL', None),
    (r'jbl[- ]?pulse', 'speaker', 'JBL', None),
    (r'jbl[- ]?xtreme', 'speaker', 'JBL', None),
    (r'jbl', 'speaker', 'JBL', None),
    (r'harman[- ]?kardon', 'speaker', 'Harman Kardon', None),
    (r'\.harman\.com$', 'speaker', 'Harman', 'Linux'),
    (r'\.devices\.harman\.com$', 'smart_speaker', 'Harman', 'Linux'),
    (r'sonos', 'smart_speaker', 'Sonos', None),
    (r'bose[- ]?soundbar', 'soundbar', 'Bose', None),
    (r'bose[- ]?home', 'smart_speaker', 'Bose', None),
    (r'bose[- ]?smart', 'smart_speaker', 'Bose', None),
    (r'bose', 'speaker', 'Bose', None),
    (r'marshall[- ]?stanmore', 'speaker', 'Marshall', None),
    (r'marshall[- ]?woburn', 'speaker', 'Marshall', None),
    (r'marshall[- ]?uxbridge', 'smart_speaker', 'Marshall', None),
    (r'bang[- ]?olufsen|b&o|beoplay|beosound', 'speaker', 'Bang & Olufsen', None),
    (r'denon[- ]?heos', 'smart_speaker', 'Denon', None),
    (r'yamaha[- ]?musiccast', 'smart_speaker', 'Yamaha', None),
    (r'klipsch', 'speaker', 'Klipsch', None),
    (r'kef[- ]?ls', 'speaker', 'KEF', None),
    (r'devialet', 'speaker', 'Devialet', None),
    (r'bluesound', 'smart_speaker', 'Bluesound', None),
    (r'naim[- ]?mu-so', 'smart_speaker', 'Naim', None),

    # Gaming
    (r'playstation|ps[345]', 'game_console', 'Sony', 'PlayStation'),
    (r'xbox', 'game_console', 'Microsoft', 'Xbox'),
    (r'nintendo|switch', 'game_console', 'Nintendo', None),

    # IP Cameras
    (r'hikvision|hikv', 'ip_camera', 'Hikvision', None),
    (r'dahua', 'ip_camera', 'Dahua', None),
    (r'axis', 'ip_camera', 'Axis', None),
    (r'foscam|amcrest|reolink', 'ip_camera', None, None),
    (r'camera|cam\d+|ipcam|nvr|dvr', 'ip_camera', None, None),
    (r'vivotek|mobotix|avigilon', 'ip_camera', None, None),

    # SCADA/ICS devices
    (r'^(PLC|SIMATIC|S7)[0-9-]*$', 'plc', 'Siemens', None),
    (r'^(HMI|PANEL)[0-9-]*$', 'hmi', None, None),
    (r'^(RTU)[0-9-]*$', 'rtu', None, None),
    (r'^(SCADA|DCS)[0-9-]*$', 'scada_server', None, None),
    (r'modicon|schneider', 'plc', 'Schneider Electric', None),
    (r'allen-bradley|controllogix|compactlogix|micrologix|guardlogix', 'plc', 'Rockwell', None),
    (r'omron|mitsubishi-plc|melsec', 'plc', None, None),
    (r'beckhoff|twincat', 'plc', 'Beckhoff', None),
    (r'wago|pfc\d{3}', 'plc', 'WAGO', None),
    (r'codesys', 'plc', None, None),
    (r'yokogawa|centum|stardom', 'dcs', 'Yokogawa', None),
    (r'ge-?fanuc|rx3i|versamax|proficy', 'plc', 'GE', None),
    (r'red-?lion|crimson', 'hmi', 'Red Lion', None),
    (r'automationdirect|productivity\d|do-?more|click-?plc', 'plc', 'AutomationDirect', None),
    (r'phoenix-?contact|pcworx|ilc\d', 'plc', 'Phoenix Contact', None),
    (r'^(BMS|HVAC|BACNET)[0-9-]*$', 'building_automation', None, None),
    (r'niagara|tridium', 'building_automation', 'Tridium', None),
    (r'moxa|hirschmann', 'industrial_switch', None, None),

    # VoIP/Communication
    (r'^(PBX|CUCM|CALLMANAGER)[0-9-]*$', 'pbx', None, None),
    (r'asterisk|freepbx', 'pbx', 'Sangoma', None),
    (r'^(VOIP|SIP)[0-9-]*$', 'voip_phone', None, None),
    (r'polycom|yealink|grandstream', 'voip_phone', None, None),
    (r'^(VC|VIDEO|WEBEX|ZOOM)[0-9-]*$', 'video_conferencing', None, None),

    # Security appliances
    (r'^(IDS|IPS|SNORT|SURICATA)[0-9-]*$', 'ids_ips', None, None),
    (r'^(SIEM|SPLUNK|QRADAR)[0-9-]*$', 'siem', None, None),
    (r'^(PROXY|SQUID)[0-9-]*$', 'proxy', None, None),
    (r'^(WAF)[0-9-]*$', 'waf', None, None),
    (r'pfsense|opnsense|untangle', 'firewall', None, None),
    (r'fortinet|fortigate', 'firewall', 'Fortinet', 'FortiOS'),
    (r'paloalto|pa-\d+', 'firewall', 'Palo Alto', 'PAN-OS'),
    (r'sonicwall', 'firewall', 'SonicWall', None),

    # Containers/Kubernetes
    (r'^(NODE|WORKER|MASTER)[0-9-]*$', 'kubernetes_node', None, None),
    (r'^(RANCHER|HARBOR)[0-9-]*$', 'container_host', None, None),
    (r'openshift', 'openshift', 'Red Hat', None),

    # Medical devices
    (r'^(MED|MEDICAL|PATIENT)[0-9-]*$', 'medical_device', None, None),
    (r'^(MONITOR|VITAL)[0-9-]*$', 'patient_monitor', None, None),
    (r'^(PACS|DICOM|CT|MRI)[0-9-]*$', 'imaging_system', None, None),

    # Embedded/Specialty
    (r'^(KIOSK)[0-9-]*$', 'kiosk', None, None),
    (r'^(POS|TERMINAL)[0-9-]*$', 'pos_terminal', None, None),
    (r'^(ATM)[0-9-]*$', 'atm', None, None),
    (r'^(SIGNAGE|DISPLAY)[0-9-]*$', 'digital_signage', None, None),

    # IoT Gateways
    (r'^(IOT|GATEWAY|GW)[0-9-]*$', 'iot_gateway', None, None),
    (r'multitech|digi|sierra', 'iot_gateway', None, None),
]


# =============================================================================
# HTTP User-Agent Patterns
# =============================================================================

USER_AGENT_PATTERNS = [
    # Windows versions
    (r'Windows NT 10\.0.*Win64', 'workstation', None, 'Windows 10/11'),
    (r'Windows NT 10\.0', 'workstation', None, 'Windows 10'),
    (r'Windows NT 6\.3', 'workstation', None, 'Windows 8.1'),
    (r'Windows NT 6\.2', 'workstation', None, 'Windows 8'),
    (r'Windows NT 6\.1', 'workstation', None, 'Windows 7'),
    (r'Windows NT 6\.0', 'workstation', None, 'Windows Vista'),
    (r'Windows NT 5\.1', 'workstation', None, 'Windows XP'),
    (r'Windows Server', 'server', None, 'Windows Server'),

    # macOS
    (r'Macintosh.*Mac OS X (\d+)[._](\d+)', 'workstation', 'Apple', 'macOS'),
    (r'Macintosh', 'workstation', 'Apple', 'macOS'),

    # Linux
    (r'Ubuntu', 'workstation', None, 'Linux (Ubuntu)'),
    (r'Fedora', 'workstation', None, 'Linux (Fedora)'),
    (r'Debian', 'workstation', None, 'Linux (Debian)'),
    (r'CentOS|Red Hat|RHEL', 'server', None, 'Linux (RHEL)'),
    (r'Linux.*Android', 'mobile', None, 'Android'),
    (r'Linux', 'workstation', None, 'Linux'),

    # iOS
    (r'iPhone.*OS (\d+)', 'mobile', 'Apple', 'iOS'),
    (r'iPad.*OS (\d+)', 'tablet', 'Apple', 'iPadOS'),
    (r'iPhone', 'mobile', 'Apple', 'iOS'),
    (r'iPad', 'tablet', 'Apple', 'iPadOS'),

    # Android
    (r'Android (\d+)', 'mobile', None, 'Android'),
    (r'Android', 'mobile', None, 'Android'),

    # Bots and tools (low confidence)
    (r'curl/', None, None, None),
    (r'wget/', None, None, None),
    (r'python-requests', None, None, None),

    # Smart TVs - Samsung TV patterns (MUST be before generic 'Galaxy' mobile pattern)
    (r'SmartViewSDK', 'smart_tv', 'Samsung', 'Tizen'),  # Samsung TV screen casting
    (r'SmartView', 'smart_tv', 'Samsung', 'Tizen'),     # Samsung TV screen casting
    (r'\[TV\]', 'smart_tv', 'Samsung', 'Tizen'),        # Samsung TV hostname format
    (r'Samsung.*TV', 'smart_tv', 'Samsung', 'Tizen'),   # Samsung TV
    (r'SAMSUNG.*TV', 'smart_tv', 'Samsung', 'Tizen'),   # Samsung TV uppercase
    (r'SmartTV|SMART-TV', 'smart_tv', None, None),
    (r'Tizen', 'smart_tv', 'Samsung', 'Tizen'),
    (r'webOS', 'smart_tv', 'LG', 'webOS'),
    (r'LG.*TV', 'smart_tv', 'LG', 'webOS'),
    (r'Roku', 'smart_tv', 'Roku', None),
    (r'AppleTV', 'smart_tv', 'Apple', 'tvOS'),
    (r'BRAVIA', 'smart_tv', 'Sony', 'Android TV'),      # Sony TV
    (r'GoogleTV', 'smart_tv', None, 'Google TV'),
    (r'AndroidTV', 'smart_tv', None, 'Android TV'),
    (r'FireTV', 'smart_tv', 'Amazon', 'Fire OS'),

    # Game consoles
    (r'PlayStation', 'game_console', 'Sony', 'PlayStation'),
    (r'Xbox', 'game_console', 'Microsoft', 'Xbox'),
    (r'Nintendo', 'game_console', 'Nintendo', None),
]


@dataclass
class DeviceFingerprint:
    """Aggregated device fingerprint result."""

    # Host identification
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    netbios_name: Optional[str] = None  # NetBIOS computer name

    # Device classification
    device_type: str = "Unknown"
    device_category: str = "Unknown"
    manufacturer: Optional[str] = None
    model: Optional[str] = None

    # OS information (aggregated from multiple sources)
    os_family: Optional[str] = None  # e.g., "Linux", "Windows", "macOS"
    os_name: Optional[str] = None    # e.g., "Ubuntu", "Debian", "Windows 10"
    os_version: Optional[str] = None # e.g., "8.04", "10", "22.04"
    os_kernel: Optional[str] = None  # e.g., "2.6.9 - 2.6.33", "5.15"
    os_full: Optional[str] = None    # Combined: "Ubuntu 8.04 (Linux 2.6.x)"

    # Confidence score (0.0 - 1.0)
    confidence: float = 0.0

    # Validation status
    validated: bool = False  # True if 2+ sources agree
    validation_sources: int = 0  # Number of agreeing sources

    # Enhanced OS detection (raw vs inferred)
    nmap_os_raw: Optional[str] = None  # Raw Nmap detection: "Linux 3.2 - 4.14"
    inferred_os: Optional[str] = None  # Inferred OS: "Debian 7 / Ubuntu 12.04"
    inferred_firmware: Optional[str] = None  # For IoT: "UniFi OS 3.x"

    # Enhanced validation
    validation_status: str = "UNKNOWN"  # VALIDATED/PLAUSIBLE/SUSPECT/UNKNOWN
    validation_reason: Optional[str] = None  # Human-readable validation reason
    plausibility_score: float = 0.0  # 0.0 - 1.0 plausibility rating

    # Sources that contributed to this fingerprint
    sources: List[str] = field(default_factory=list)

    # All evidence collected (detailed breakdown by source)
    evidence: List[Dict[str, Any]] = field(default_factory=list)

    # Raw Nmap data preserved
    nmap_os_matches: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)

    # SSL/TLS certificate info
    ssl_certs: List[Dict[str, Any]] = field(default_factory=list)

    # SMB discovery info
    smb_info: Optional[Dict[str, Any]] = None

    # DHCP data if available
    dhcp_data: Optional[Dict[str, Any]] = None

    # HTTP User-Agents found
    user_agents: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def get_sources_summary(self) -> str:
        """Get a human-readable summary of sources used."""
        if not self.sources:
            return "No sources"
        return ", ".join(sorted(set(self.sources)))

    def get_validation_status(self) -> str:
        """Get validation status string."""
        if self.validated:
            return f"Validated ({self.validation_sources} sources agree)"
        elif self.validation_sources == 1:
            return "Single source (unvalidated)"
        else:
            return "No consensus"


async def fingerprint_host(
    nmap_xml_path: str,
    lookup: FingerprintLookup = None,
    host_index: int = 0
) -> Optional[DeviceFingerprint]:
    """
    Fingerprint a host from Nmap XML results.

    Extracts evidence from multiple sources:
    - MAC address (OUI lookup for manufacturer)
    - Service banners (SSH, HTTP, SMB, FTP, etc.)
    - Nmap OS detection results
    - DHCP options (from dhcp-discover script)
    - HTTP User-Agent (from http-headers script)
    - Hostname patterns
    - TTL-based OS heuristics

    Runs FingerprintDB lookups and aggregates evidence with validation.

    Args:
        nmap_xml_path: Path to Nmap XML output file
        lookup: Optional FingerprintLookup instance (creates one if not provided)
        host_index: Index of host in multi-host scan (default: 0)

    Returns:
        DeviceFingerprint or None if parsing fails
    """
    if not os.path.exists(nmap_xml_path):
        logger.warning(f"Nmap XML file not found: {nmap_xml_path}")
        return None

    # Parse Nmap XML
    try:
        report = NmapParser.parse_fromfile(nmap_xml_path)
    except NmapParserException as e:
        logger.error(f"Failed to parse Nmap XML: {e}")
        return None

    if not report.hosts:
        logger.warning(f"No hosts in Nmap XML: {nmap_xml_path}")
        return None

    if host_index >= len(report.hosts):
        logger.warning(f"Host index {host_index} out of range")
        return None

    host = report.hosts[host_index]

    # Initialize lookup if not provided (uses JSON cache, no database needed)
    if lookup is None:
        lookup = FingerprintLookup()

    return await fingerprint_from_host(host, lookup)


# ---------------------------------------------------------------------------
# Virtualization-specific Nmap script extractors
# ---------------------------------------------------------------------------


def _extract_virt_scripts(host) -> List[FingerprintMatch]:
    """
    Pull hypervisor / VM info out of Nmap NSE script results.

    Recognized scripts:
      - ``vmware-version`` — version of an exposed vCenter / ESXi service
      - ``http-vmware-path-vuln`` — confirms VMware product running
      - ``broadcast-igmp-discovery`` (with VMware indicator) — VM cluster

    Each match becomes a high-confidence FingerprintMatch with VMware as
    vendor / VMkernel as os_family.
    """
    matches: List[FingerprintMatch] = []
    if not hasattr(host, "scripts_results"):
        # Some libnmap versions only expose script output per-service.
        return matches

    for script in host.scripts_results or []:
        sid = (script.get("id") or "").lower()
        out = script.get("output", "") or ""
        if "vmware-version" in sid or "vmware" in sid:
            ver_m = re.search(r"version[:\s]+(\d+(?:\.\d+)+)", out, re.IGNORECASE)
            matches.append(FingerprintMatch(
                source="nmap_script",
                match_type="vmware-version",
                confidence=0.94,
                device_type="hypervisor",
                manufacturer="VMware",
                os_family="VMkernel",
                os_version=ver_m.group(1) if ver_m else None,
                raw_data={"script_id": sid, "output": out[:500]},
            ))
            continue

    # Per-service scripts — also walk those.
    for svc in getattr(host, "services", []) or []:
        for script in getattr(svc, "scripts_results", []) or []:
            sid = (script.get("id") or "").lower()
            out = script.get("output", "") or ""
            if sid == "vmware-version":
                ver_m = re.search(r"version[:\s]+(\d+(?:\.\d+)+)", out, re.IGNORECASE)
                matches.append(FingerprintMatch(
                    source="nmap_script",
                    match_type="vmware-version",
                    confidence=0.94,
                    device_type="hypervisor",
                    manufacturer="VMware",
                    os_family="VMkernel",
                    os_version=ver_m.group(1) if ver_m else None,
                    raw_data={"script_id": sid, "port": svc.port, "output": out[:500]},
                ))
            elif sid in ("http-vmware-path-vuln", "vsphere-version"):
                matches.append(FingerprintMatch(
                    source="nmap_script",
                    match_type=sid,
                    confidence=0.90,
                    device_type="hypervisor",
                    manufacturer="VMware",
                    os_family="VMkernel",
                    raw_data={"script_id": sid, "port": svc.port, "output": out[:500]},
                ))
            elif sid == "http-title" and "vmware" in out.lower():
                # Generic catch — the title carries a VMware brand.
                matches.append(FingerprintMatch(
                    source="nmap_script",
                    match_type="http-title-vmware",
                    confidence=0.78,
                    manufacturer="VMware",
                    raw_data={"script_id": sid, "port": svc.port, "output": out[:200]},
                ))
    return matches


# ---------------------------------------------------------------------------
# Virtualization / Container port heuristics
# ---------------------------------------------------------------------------
# Port-set signatures for common hypervisors and container orchestrators.
# Each signature is `(required_ports, optional_ports, device_type, vendor,
# os_family, os_name, label)`. A signature fires when ALL required ports
# are open and at least one optional port (when supplied) is open too.
#
# The heuristic is intentionally conservative — these ports get used by
# other software, but the COMBINATIONS are distinctive enough to fire only
# on real virt/container platforms.
_VIRT_PORT_SIGNATURES = [
    # ESXi: SDK on 902, optional WBEM (5988/5989), HTTP/HTTPS management.
    ({902}, {903, 5988, 5989, 443, 80}, "hypervisor", "VMware", "VMkernel", "VMware ESXi", "esxi-port-set"),
    # vCenter: 443 + 902 + 5480 (appliance management).
    ({443, 902}, {5480, 5989}, "vcenter", "VMware", "VMkernel", "VMware vCenter", "vcenter-port-set"),
    # Proxmox VE: 8006 (web UI) + ssh + corosync ports.
    ({8006}, {22, 5900, 3128, 8007}, "hypervisor", "Proxmox", "Linux", "Proxmox VE", "proxmox-port-set"),
    # XenServer / XCP-ng: must see the distinctive 27000 (xapi storage) port.
    # 80+443 alone is universal and 5900/5989 (VNC/WBEM) ride on any web host
    # with a console -- requiring only those falsely tagged Dell iDRACs and
    # other BMCs as "Citrix". Pin to 27000 so the signature actually means Xen.
    ({443, 27000}, {80, 5900, 5989}, "hypervisor", "Citrix", None, "Citrix XenServer/XCP-ng", "xen-port-set"),

    # ── Container orchestration ──
    # Kubernetes API server + kubelet + (etcd or NodePort range).
    ({6443}, {10250, 10255, 2379, 2380}, "kubernetes_master", None, "Linux", "Kubernetes Control Plane", "k8s-master-port-set"),
    # Pure kubelet (worker node).
    ({10250}, {10255, 30000}, "kubernetes_node", None, "Linux", "Kubernetes Worker", "k8s-worker-port-set"),
    # K8s read-only kubelet alone (deprecated but still seen).
    ({10255}, set(), "kubernetes_node", None, "Linux", "Kubernetes Worker (RO kubelet)", "k8s-ro-kubelet-port-set"),
    # K8s service proxy port (kube-proxy on a node)
    ({10256}, {10250}, "kubernetes_node", None, "Linux", "Kubernetes Worker (kube-proxy)", "k8s-kube-proxy-port-set"),
    # etcd cluster member (often dedicated node).
    ({2379, 2380}, set(), "etcd_node", None, "Linux", "etcd Cluster Node", "etcd-port-set"),

    # ── Container daemons (huge security risk when exposed) ──
    # Docker daemon (unencrypted) — exposed = full RCE on host.
    ({2375}, set(), "container_host", "Docker", "Linux", "Docker Daemon (UNENCRYPTED — full host RCE if reachable)", "docker-daemon-tcp"),
    # Docker daemon (TLS).
    ({2376}, set(), "container_host", "Docker", "Linux", "Docker Daemon (TLS)", "docker-daemon-tls"),
    # containerd CRI socket on TCP.
    ({1338}, set(), "container_host", None, "Linux", "containerd CRI", "containerd-cri-port-set"),

    # ── Docker Swarm ──
    # Docker Swarm manager: 2377 cluster mgmt + 7946 + 4789 overlay.
    ({2377}, {7946, 4789}, "container_host", "Docker", "Linux", "Docker Swarm Manager", "swarm-port-set"),

    # ── Container registries ──
    # NOTE: a bare "port 5000 + 80/443" signature was removed -- port 5000 is
    # massively overloaded (Windows UPnP/SSDP, Flask dev servers, AirPlay,
    # Synology, etc.), so it tagged ordinary Windows/NAS hosts as Docker
    # registries. Real registries are caught by Harbor's distinctive notary
    # port below or by the Docker-Distribution-Api banner, not raw 5000.
    # Harbor uses 443 + 4443 (notary) + 5000 — distinctive enough to keep.
    ({443, 4443}, {5000}, "container_registry", "Harbor", "Linux", "Harbor Registry", "harbor-port-set"),

    # ── Management dashboards on top of containers ──
    # Portainer — Docker management UI on 9000 / 9443.
    ({9000}, {2375, 2376, 9443}, "container_host", "Portainer", "Linux", "Portainer", "portainer-port-set"),
    # Rancher — k8s/cluster management on 80 + 443 + 8080.
    ({80, 443, 8080}, {6443, 10250}, "container_host", "Rancher", "Linux", "Rancher", "rancher-port-set"),

    # ── Lightweight Kubernetes distros ──
    # K3s — single-binary k8s, often 6443 + 10250 only, with embedded etcd.
    ({6443, 10250}, {2379, 51820}, "kubernetes_master", None, "Linux", "K3s / Lightweight Kubernetes", "k3s-port-set"),
]


def _detect_virtualization_by_ports(open_ports: set, host) -> List[FingerprintMatch]:
    """
    Emit FingerprintMatch evidence for any virt/container signature whose
    port-set is satisfied by the host's open ports.

    Multiple signatures can fire (e.g. ESXi + vCenter). Confidence is
    deliberately moderate (0.75) because port sets can be coincidental;
    weighted aggregation lets stronger sources (CPE, banner) override.
    """
    matches: List[FingerprintMatch] = []
    if not open_ports:
        return matches
    for required, optional, dtype, vendor, os_family, label, sig_id in _VIRT_PORT_SIGNATURES:
        if not required.issubset(open_ports):
            continue
        if optional and not (optional & open_ports):
            continue
        matches.append(FingerprintMatch(
            source="virt_ports",
            match_type="port_set",
            confidence=0.75,
            device_type=dtype,
            manufacturer=vendor,
            os_family=os_family,
            raw_data={
                "signature": sig_id,
                "platform_label": label,  # "VMware ESXi", "Kubernetes Control Plane", ...
                "required_ports": sorted(required),
                "optional_ports_seen": sorted(optional & open_ports),
                "host_open_ports": sorted(open_ports),
            },
        ))
    return matches


# ICS / SCADA / OT protocol ports. A host exposing one of these is almost
# certainly industrial control / building automation gear -- these ports are
# very rarely used by anything else, so they're a high-signal device-type +
# (often) vendor indicator. port -> (device_type, vendor_or_None, protocol).
_ICS_PORT_SIGNATURES = {
    102:   ("plc", "Siemens", "Siemens S7comm (ISO-TSAP)"),
    502:   ("plc", None, "Modbus/TCP"),
    789:   ("hmi", "Red Lion", "Red Lion Crimson"),
    1089:  ("plc", None, "Foundation Fieldbus HSE"),
    1911:  ("building_automation", "Tridium", "Niagara Fox"),
    1962:  ("plc", "Phoenix Contact", "PCWorx"),
    2222:  ("plc", None, "EtherNet/IP I/O (CIP)"),
    2404:  ("rtu", None, "IEC 60870-5-104"),
    4840:  ("scada_server", None, "OPC-UA"),
    4911:  ("building_automation", "Tridium", "Niagara Fox (TLS)"),
    9600:  ("plc", "Omron", "Omron FINS"),
    18245: ("plc", "GE", "GE SRTP"),
    18246: ("plc", "GE", "GE SRTP"),
    20000: ("rtu", None, "DNP3"),
    34962: ("plc", None, "PROFINET RT"),
    34964: ("plc", None, "PROFINET CM"),
    44818: ("plc", None, "EtherNet/IP (CIP)"),
    47808: ("building_automation", None, "BACnet/IP"),
    48898: ("plc", "Beckhoff", "Beckhoff TwinCAT ADS"),
    5006:  ("plc", "Mitsubishi", "MELSEC MC"),
    5007:  ("plc", "Mitsubishi", "MELSEC MC"),
}


def _detect_ics_by_ports(open_ports: set) -> List[FingerprintMatch]:
    """Emit evidence for ICS/SCADA/OT protocol ports. These ports are highly
    distinctive (Modbus 502, S7 102, EtherNet/IP 44818, BACnet 47808, DNP3
    20000, OPC-UA 4840, ...), so an open one is a strong industrial signal --
    higher confidence than the virt heuristic. Where the protocol implies a
    vendor (S7->Siemens, FINS->Omron), that is asserted too."""
    matches: List[FingerprintMatch] = []
    for port in open_ports or ():
        sig = _ICS_PORT_SIGNATURES.get(port)
        if not sig:
            continue
        dtype, vendor, protocol = sig
        matches.append(FingerprintMatch(
            source="ics_ports",
            match_type="port",
            confidence=0.80,
            device_type=dtype,
            manufacturer=vendor,
            os_family="Embedded",
            raw_data={"port": port, "protocol": protocol},
        ))
    return matches


# ---------------------------------------------------------------------------
# Windows build → version resolver
# ---------------------------------------------------------------------------
# Windows leaks build numbers in three places:
#   - SMB native_os / lanman strings ("Windows Server 2019 ... Build 17763")
#   - nmap -O classifications ("Microsoft Windows 10 1809")
#   - HTTP banners ("Server: Microsoft-IIS/10.0 (Windows Server 2019)")
# `os_intelligence.WINDOWS_BUILD_MAP` already has the full table; this
# function harvests build numbers wherever they appear and emits dedicated
# FingerprintMatch evidence at high confidence. Ahead-of-aggregation
# resolution means downstream code never has to know about build numbers.

# Build number patterns: bare 4-5 digit numbers between 6000 and 30000 are
# Windows builds with very few false positives.
_WINBUILD_PATTERNS = [
    re.compile(r"\bBuild\s*(\d{4,5})\b", re.IGNORECASE),
    re.compile(r"\b(?:Microsoft\s+)?Windows[^\d]{0,30}([12]\d{4})\b"),
    re.compile(r"\b10\.0\.(\d{4,5})\b"),  # "10.0.17763.1234" form
    re.compile(r"\b(2[02]\d{3})\b"),  # standalone Server 2022/2025 builds
]


def _harvest_windows_builds(*texts: str) -> List[str]:
    """Pull Windows build numbers from any of the provided strings."""
    found: List[str] = []
    for text in texts:
        if not text:
            continue
        for pat in _WINBUILD_PATTERNS:
            for match in pat.finditer(text):
                build = match.group(1)
                # Sanity: 6000–30000 is the valid Windows-build range we map.
                try:
                    n = int(build)
                except ValueError:
                    continue
                if 2600 <= n <= 30000 and build not in found:
                    found.append(build)
    return found


def _collect_ntlm_build_texts(host) -> List[str]:
    """Gather NSE script outputs that expose a Windows ``Product_Version`` /
    build number. NTLM-info scripts (rdp-ntlm-info, http-ntlm-info,
    mssql-ntlm-info, *-ntlm-info) and smb-os-discovery report e.g.
    ``Product_Version: 10.0.26100`` -- the single most precise Windows build
    source, far better than the nmap osmatch's fuzzy "Windows 11 21H2 - 23H2".
    """
    texts: List[str] = []

    def _grab(scripts):
        for s in scripts or []:
            sid = (s.get("id") or "").lower()
            out = s.get("output") or ""
            if out and ("ntlm" in sid or "Product_Version" in out
                        or sid in ("smb-os-discovery", "nbstat")):
                texts.append(out)

    _grab(getattr(host, "scripts_results", []))
    for svc in getattr(host, "services", []) or []:
        _grab(getattr(svc, "scripts_results", []))
    return texts


def _extract_windows_build_evidence(
    smb_info: Optional[Dict[str, Any]],
    nmap_os_matches: List[Dict[str, Any]],
    services: List[Dict[str, Any]],
    extra_texts: Optional[List[str]] = None,
) -> List[FingerprintMatch]:
    """
    Find Windows build numbers across SMB/nmap-OS/banner/NTLM-script sources
    and emit one FingerprintMatch per unique build, with the friendly name
    resolved.
    """
    from .os_intelligence import resolve_windows_build

    candidate_strings: List[str] = list(extra_texts or [])
    if smb_info:
        candidate_strings.append(smb_info.get("os") or "")
        candidate_strings.append(smb_info.get("native_os") or "")
        candidate_strings.append(smb_info.get("lanman") or "")
    for nm in nmap_os_matches or []:
        candidate_strings.append(nm.get("name") or "")
    for svc in services or []:
        if svc.get("service") in ("microsoft-ds", "netbios-ssn", "msrpc", "http", "https"):
            candidate_strings.append(svc.get("banner") or "")
            candidate_strings.append(svc.get("product") or "")
            candidate_strings.append(svc.get("version") or "")

    builds = _harvest_windows_builds(*candidate_strings)
    matches: List[FingerprintMatch] = []
    for build in builds:
        friendly = resolve_windows_build(build)
        if not friendly:
            continue
        is_server = "Server" in friendly
        os_family = "Windows Server" if is_server else "Windows"
        matches.append(FingerprintMatch(
            source="windows_build",
            match_type="build_number",
            confidence=0.93,  # Build numbers are very precise
            os_family=os_family,
            os_vendor="Microsoft",
            os_version=build,
            # A resolved Server build is authoritative for device_type.
            device_type="server" if is_server else None,
            raw_data={
                "build": build,
                "resolved_name": friendly,
                "harvested_from": [s for s in candidate_strings if build in s][:3],
            },
        ))
    return matches


def _extract_ics_info(host) -> List[FingerprintMatch]:
    """Parse ICS/SCADA NSE script results (s7-info, enip-info, modbus-discover,
    bacnet-info, omron-info, ...). These return vendor / model / firmware
    directly from the control protocol, so they're high-confidence OT
    identifications -- e.g. s7-info exposes the Siemens module order number,
    enip-info the Rockwell product name."""
    matches: List[FingerprintMatch] = []

    def _scripts():
        for s in getattr(host, "scripts_results", []) or []:
            yield s
        for svc in getattr(host, "services", []) or []:
            for s in getattr(svc, "scripts_results", []) or []:
                yield s

    for script in _scripts():
        sid = (script.get("id") or "").lower()
        out = script.get("output") or ""
        if not out:
            continue
        vendor = dtype = model = os_family = None
        proto = None

        if sid == "s7-info" or "s7-info" in sid:
            vendor, dtype, os_family, proto = "Siemens", "plc", "Embedded", "S7comm"
            m = re.search(r"Module:\s*(.+)", out) or re.search(r"Basic Hardware:\s*(.+)", out)
            if m:
                model = m.group(1).strip()
        elif "enip" in sid:  # enip-info / enip-enumerate (EtherNet/IP CIP)
            dtype, os_family, proto = "plc", "Embedded", "EtherNet/IP"
            vm = re.search(r"Vendor:\s*([^\n(]+)", out)
            if vm:
                vendor = vm.group(1).strip()
            pm = re.search(r"Product Name:\s*([^\n]+)", out)
            if pm:
                model = pm.group(1).strip()
        elif "modbus" in sid:  # modbus-discover
            dtype, os_family, proto = "plc", "Embedded", "Modbus"
            dm = re.search(r"Device identification:\s*([^\n]+)", out)
            if dm:
                model = dm.group(1).strip()
                vendor = model.split()[0] if model else None
        elif "bacnet" in sid:  # bacnet-info
            dtype, os_family, proto = "building_automation", "Embedded", "BACnet"
            vm = re.search(r"Vendor (?:Name|ID):\s*([^\n]+)", out)
            if vm:
                vendor = vm.group(1).strip()
        elif "omron" in sid:
            vendor, dtype, os_family, proto = "Omron", "plc", "Embedded", "Omron FINS"
        elif "fox" in sid or "niagara" in sid:  # niagara fox
            vendor, dtype, os_family, proto = "Tridium", "building_automation", "Embedded", "Niagara Fox"
        elif "pcworx" in sid or "proconos" in sid:
            vendor, dtype, os_family, proto = "Phoenix Contact", "plc", "Embedded", "PCWorx"
        else:
            continue

        matches.append(FingerprintMatch(
            source="ics_nse",
            match_type="protocol",
            confidence=0.92,  # protocol-confirmed OT identification
            device_type=dtype,
            manufacturer=vendor,
            model=model,
            os_family=os_family,
            raw_data={"script": sid, "protocol": proto, "output": out[:500]},
        ))
    return matches


def _summarize_partial(evidence: List[FingerprintMatch]) -> Dict[str, Optional[str]]:
    """
    Pick the best-confidence value seen so far for manufacturer / os_family /
    device_type across the collected evidence. Used to seed cross-source
    Huginn searches before the full aggregation runs.
    """
    out: Dict[str, Optional[str]] = {
        "manufacturer": None,
        "os_family": None,
        "device_type": None,
    }
    best_conf: Dict[str, float] = {"manufacturer": 0.0, "os_family": 0.0, "device_type": 0.0}
    for m in evidence:
        for field in ("manufacturer", "os_family", "device_type"):
            v = getattr(m, field, None)
            if v and m.confidence > best_conf[field]:
                out[field] = v
                best_conf[field] = m.confidence
    return out


def _extract_mdns_services(host) -> List[str]:
    """Extract mDNS service types from Nmap script output."""
    services = []
    for service in host.services:
        if not hasattr(service, 'scripts_results'):
            continue
        for script in service.scripts_results:
            script_id = script.get('id', '')
            output = script.get('output', '')
            if script_id in ('dns-service-discovery', 'broadcast-dns-service-discovery'):
                # Parse service types from output like "_http._tcp" or "_airplay._tcp"
                for match in re.finditer(r'(_[a-zA-Z0-9_-]+\._(?:tcp|udp))', output):
                    svc_type = match.group(1)
                    if svc_type not in services:
                        services.append(svc_type)
    return services


def _extract_tcp_signature(host) -> Optional[str]:
    """Extract TCP/IP stack signature from Nmap OS detection data."""
    # Nmap OS fingerprint section sometimes includes TCP characteristics
    if hasattr(host, 'os_fingerprinted') and host.os_fingerprinted:
        # Try to extract fingerprint from os section
        if hasattr(host, 'os') and hasattr(host.os, 'fingerprint'):
            return host.os.fingerprint
    return None


def _extract_upnp_info(host) -> List[FingerprintMatch]:
    """Extract device info from UPnP/SSDP Nmap scripts."""
    matches = []
    for service in host.services:
        if not hasattr(service, 'scripts_results'):
            continue
        for script in service.scripts_results:
            script_id = script.get('id', '')
            output = script.get('output', '')
            if script_id in ('upnp-info', 'broadcast-upnp-info'):
                # Extract device type
                device_type_m = re.search(r'deviceType:\s*urn:schemas-upnp-org:device:(\w+)', output)
                # Extract manufacturer
                mfr_m = re.search(r'manufacturer:\s*(.+?)(?:\n|$)', output, re.IGNORECASE)
                # Extract model
                model_m = re.search(r'modelName:\s*(.+?)(?:\n|$)', output, re.IGNORECASE)
                # Extract friendly name
                friendly_m = re.search(r'friendlyName:\s*(.+?)(?:\n|$)', output, re.IGNORECASE)

                if device_type_m or mfr_m:
                    upnp_device_type = None
                    if device_type_m:
                        dt = device_type_m.group(1).lower()
                        type_map = {
                            "internetgatewaydevice": "router",
                            "wandevice": "router",
                            "mediaserver": "media_server",
                            "mediarenderer": "streaming_device",
                            "printer": "printer",
                            "basic": None,
                        }
                        upnp_device_type = type_map.get(dt, dt)

                    matches.append(FingerprintMatch(
                        source="upnp_ssdp",
                        match_type="exact",
                        confidence=0.78,
                        device_type=upnp_device_type,
                        manufacturer=mfr_m.group(1).strip() if mfr_m else None,
                        model=model_m.group(1).strip() if model_m else None,
                        raw_data={
                            "upnp_device_type": device_type_m.group(1) if device_type_m else None,
                            "friendly_name": friendly_m.group(1).strip() if friendly_m else None,
                        }
                    ))
    return matches


def _extract_snmp_info(host) -> List[FingerprintMatch]:
    """Extract device info from SNMP Nmap scripts."""
    matches = []
    for service in host.services:
        if not hasattr(service, 'scripts_results'):
            continue
        for script in service.scripts_results:
            script_id = script.get('id', '')
            output = script.get('output', '')
            if script_id in ('snmp-info', 'snmp-sysdescr'):
                # Parse sysDescr - often contains full OS/device description
                os_family = None
                device_type = None
                manufacturer = None

                output_lower = output.lower()
                if 'cisco ios' in output_lower or 'cisco nx-os' in output_lower:
                    os_family = "Cisco IOS"
                    manufacturer = "Cisco"
                    device_type = "switch" if "switch" in output_lower or "c2960" in output_lower else "router"
                elif 'junos' in output_lower:
                    os_family = "JunOS"
                    manufacturer = "Juniper"
                    device_type = "router"
                elif 'linux' in output_lower:
                    os_family = "Linux"
                elif 'windows' in output_lower:
                    os_family = "Windows"
                    device_type = "server" if "server" in output_lower else "workstation"
                elif 'hp' in output_lower and ('procurve' in output_lower or 'aruba' in output_lower):
                    manufacturer = "HPE Aruba"
                    device_type = "switch"
                elif 'fortinet' in output_lower or 'fortigate' in output_lower:
                    manufacturer = "Fortinet"
                    os_family = "FortiOS"
                    device_type = "firewall"

                if os_family or manufacturer:
                    matches.append(FingerprintMatch(
                        source="snmp_sysdescr",
                        match_type="pattern",
                        confidence=0.90,
                        os_family=os_family,
                        device_type=device_type,
                        manufacturer=manufacturer,
                        raw_data={"sysdescr": output[:500]}
                    ))
    return matches


def _extract_ws_discovery(host) -> List[FingerprintMatch]:
    """Extract Windows device info from WS-Discovery Nmap scripts."""
    matches = []
    for service in host.services:
        if not hasattr(service, 'scripts_results'):
            continue
        for script in service.scripts_results:
            script_id = script.get('id', '')
            output = script.get('output', '')
            if script_id == 'broadcast-ws-discovery':
                if 'Device' in output or 'Computer' in output:
                    matches.append(FingerprintMatch(
                        source="ws_discovery",
                        match_type="pattern",
                        confidence=0.68,
                        os_family="Windows",
                        device_type="workstation",
                        raw_data={"ws_discovery": output[:300]}
                    ))
    return matches


def _extract_sip_ua(host, lookup) -> List[FingerprintMatch]:
    """Extract VoIP phone info from SIP Nmap scripts."""
    matches = []
    for service in host.services:
        if not hasattr(service, 'scripts_results'):
            continue
        for script in service.scripts_results:
            script_id = script.get('id', '')
            output = script.get('output', '')
            if script_id == 'sip-methods':
                ua_match = re.search(r'User-Agent:\s*(.+?)(?:\n|$)', output, re.IGNORECASE)
                if ua_match:
                    sip_ua = ua_match.group(1).strip()
                    # Note: lookup is async but we handle it in caller
                    matches.append(FingerprintMatch(
                        source="satori_sip",
                        match_type="heuristic",
                        confidence=0.75,
                        device_type="voip_phone",
                        raw_data={"sip_ua": sip_ua}
                    ))
    return matches


async def fingerprint_from_host(
    host,
    lookup: FingerprintLookup = None,
) -> Optional[DeviceFingerprint]:
    """
    Fingerprint a pre-parsed NmapHost object.

    Same logic as fingerprint_host() but accepts an already-parsed host object,
    avoiding redundant XML parsing when the caller has already parsed the file.

    Args:
        host: A parsed NmapHost object from libnmap
        lookup: Optional FingerprintLookup instance (creates one if not provided)

    Returns:
        DeviceFingerprint or None
    """
    if lookup is None:
        lookup = FingerprintLookup()

    # Collect all fingerprint evidence
    evidence: List[FingerprintMatch] = []

    # Get hostname
    hostname = host.hostnames[0] if host.hostnames else None

    # Create result object
    result = DeviceFingerprint(
        ip_address=host.address,
        hostname=hostname,
    )

    # === 1. MAC Address Lookup (Manufacturer) ===
    mac_address = _extract_mac(host)
    if mac_address:
        result.mac_address = mac_address
        match = await lookup.lookup_mac(mac_address)
        if match:
            evidence.append(match)
            logger.debug(f"MAC match: {match.manufacturer}")

    # === 1b. Huginn Device Profile Lookup ===
    # Try exact match against the hostname, then fall back to token-based
    # fuzzy matching against the same hostname (handles real names like
    # ``iphone-bob`` matching the canonical ``Apple iPhone`` record).
    # MAC presence is no longer required — the Huginn lookup is useful even
    # for L3-only scans where the MAC isn't observable.
    if hostname:
        huginn_match = lookup.lookup_huginn_device(
            device_name=hostname,
            hostname=hostname,
        )
        if huginn_match:
            evidence.append(huginn_match)
            logger.debug(
                f"Huginn device match ({huginn_match.match_type}): "
                f"{huginn_match.manufacturer} / {huginn_match.device_type} / {huginn_match.os_family}"
            )

    # === 2. Hostname-based Detection ===
    if hostname:
        match = _analyze_hostname(hostname)
        if match:
            evidence.append(match)
            logger.debug(f"Hostname match: {match.device_type}, {match.os_family}")

    # === 3. Service Banner Lookups ===
    services = []
    user_agents = []

    for service in host.services:
        svc_info = {
            "port": service.port,
            "protocol": service.protocol,
            "state": service.state,
            "service": service.service,
            "product": getattr(service, 'product', None),
            "version": getattr(service, 'version', None),
            "banner": getattr(service, 'banner', None),
        }
        services.append(svc_info)

        # Get banner from service
        banner = _extract_banner(service)
        if banner:
            svc_info["extracted_banner"] = banner

            # Determine protocol for lookup
            protocol = _map_service_to_protocol(service.service, service.port)
            if protocol:
                match = await lookup.lookup_banner(protocol, banner)
                if match:
                    evidence.append(match)
                    logger.debug(f"Banner match ({protocol}): {match.raw_data}")

                # Satori SSH lookup (curated database, higher specificity)
                if protocol == 'ssh':
                    satori_match = await lookup.lookup_satori_ssh(banner)
                    if satori_match:
                        evidence.append(satori_match)

        # === 4. HTTP User-Agent from script results ===
        if hasattr(service, 'scripts_results'):
            for script in service.scripts_results:
                script_id = script.get('id', '')
                output = script.get('output', '')

                # Extract User-Agent from http-headers
                if script_id == 'http-headers':
                    ua = _extract_user_agent_from_headers(output)
                    if ua:
                        user_agents.append(ua)
                        ua_match = _analyze_user_agent(ua)
                        if ua_match:
                            evidence.append(ua_match)

                        # Satori User-Agent lookup
                        satori_ua_match = await lookup.lookup_satori_useragent(ua)
                        if satori_ua_match:
                            evidence.append(satori_ua_match)

                    # Extract HTTP Server header for Satori lookup
                    if 'Server:' in output:
                        server_match = re.search(r'Server:\s*(.+)', output, re.IGNORECASE)
                        if server_match:
                            server_header = server_match.group(1).strip()
                            satori_http_match = await lookup.lookup_satori_http(server_header)
                            if satori_http_match:
                                evidence.append(satori_http_match)

                # Extract from http-title (sometimes contains hints)
                elif script_id == 'http-title':
                    title_match = _analyze_http_title(output)
                    if title_match:
                        evidence.append(title_match)

    result.services = services
    result.user_agents = user_agents

    # === 5. DHCP Options from dhcp-discover script ===
    dhcp_data = _extract_dhcp_from_scripts(host)
    if dhcp_data:
        result.dhcp_data = dhcp_data

        # Lookup DHCP Option 55 (Parameter Request List). Three sources
        # consult option55 in increasing order of specificity:
        opt55 = dhcp_data.get('option_55')
        if opt55:
            # 5a. Built-in DHCP fingerprints (Huginn dhcp + cygor patterns)
            dhcp_match = lookup.lookup_dhcp(opt55=opt55)
            if dhcp_match:
                evidence.append(dhcp_match)
                logger.debug(f"DHCP Opt55 match: {dhcp_match.os_family}")

            # 5b. Satori DHCP — pattern-matched OS family / vendor.
            # Catches consumer/IoT gear that the Huginn dhcp index misses.
            satori_dhcp_match = await lookup.lookup_satori_dhcp(opt55)
            if satori_dhcp_match:
                evidence.append(satori_dhcp_match)
                logger.debug(f"Satori DHCP match: {satori_dhcp_match.os_family} / {satori_dhcp_match.manufacturer}")

            # 5c. Huginn combinations — exact opt55-string lookup that
            # resolves to a specific device + vendor in one step. Highest
            # confidence for known-device DHCP fingerprints.
            combo_match = lookup.lookup_huginn_combination_dhcp(opt55)
            if combo_match:
                evidence.append(combo_match)
                logger.debug(f"Huginn combination match: {combo_match.manufacturer} / {combo_match.model}")

        # Lookup DHCP Option 60 (Vendor Class Identifier)
        if dhcp_data.get('option_60'):
            dhcp_match = lookup.lookup_dhcp(opt60=dhcp_data['option_60'])
            if dhcp_match:
                evidence.append(dhcp_match)
                logger.debug(f"DHCP Opt60 match: {dhcp_match.device_type}")

    # === 5b. mDNS Service Discovery ===
    mdns_services = _extract_mdns_services(host)
    for svc_type in mdns_services:
        mdns_match = lookup.lookup_mdns(svc_type)
        if mdns_match:
            evidence.append(mdns_match)
            logger.debug(f"mDNS match: {mdns_match.device_type} from {svc_type}")

    # === 6. Extract SSL/TLS Certificates ===
    ssl_certs = _extract_ssl_certs(host)
    result.ssl_certs = ssl_certs
    if ssl_certs:
        logger.debug(f"Found {len(ssl_certs)} SSL certificates")
        for cert in ssl_certs:
            cn = cert.get('cn', '')
            if cn:
                # Add evidence from SSL cert
                os_info = _extract_os_from_ssl_cn(cn)
                if os_info:
                    evidence.append(FingerprintMatch(
                        source="ssl_cert",
                        match_type="certificate",
                        confidence=0.90,
                        os_family=os_info.get('distro'),
                        os_version=os_info.get('os_full'),
                        raw_data={'cn': cn, **os_info}
                    ))
                # The cert CN is often the only identifying name a host exposes
                # (no PTR / NetBIOS) -- e.g. an iDRAC presents CN=idrac-XXXX.
                # Run the same hostname-pattern inference on it so vendor /
                # device-type signals ("idrac" -> Dell BMC, "pve" -> Proxmox)
                # aren't lost. Slightly lower confidence than a real hostname.
                if cn != hostname:
                    cn_match = _analyze_hostname(cn)
                    if cn_match and (cn_match.manufacturer or cn_match.device_type):
                        cn_match.source = "ssl_cn"
                        cn_match.confidence = min(cn_match.confidence, 0.70)
                        evidence.append(cn_match)

    # === 7. Extract SMB/NetBIOS Info ===
    smb_info = _extract_smb_info(host)
    result.smb_info = smb_info
    if smb_info:
        logger.debug(f"SMB info: {smb_info}")
        # Set NetBIOS name
        if smb_info.get('netbios_name'):
            result.netbios_name = smb_info['netbios_name']
        elif smb_info.get('computer_name'):
            result.netbios_name = smb_info['computer_name']

        # Add evidence from SMB discovery
        if smb_info.get('is_samba'):
            evidence.append(FingerprintMatch(
                source="smb_discovery",
                match_type="smb",
                confidence=0.85,
                os_family="Linux",
                raw_data=smb_info
            ))

        # Satori SMB lookup — pass both native_os AND lanman so the curated
        # DB can match on whichever string is more identifying. Windows
        # Server lanman strings often carry the OS build that native_os omits.
        smb_os_str = smb_info.get('os') or smb_info.get('native_os')
        smb_lanman = smb_info.get('lanman')
        if smb_os_str or smb_lanman:
            satori_smb_match = await lookup.lookup_satori_smb(smb_os_str or "", smb_lanman)
            if satori_smb_match:
                evidence.append(satori_smb_match)
                logger.debug(f"Satori SMB match: {satori_smb_match.os_family} / {satori_smb_match.os_version}")

    # === 7b. CPE extraction (every -sV service can attach CPEs) ===
    # CPEs are the most-precise identifier nmap produces. Each os-part CPE
    # gives us (os_family, os_vendor, os_version) at very high confidence;
    # hardware-part CPEs give manufacturer/model. The friendly OS name (e.g.
    # "Windows Server 2019 Standard") goes into raw_data — FingerprintMatch
    # has no os_name slot, so the aggregator picks os_version + os_family
    # and the verdict layer derives the display string from those.
    from .cpe_extractor import extract_cpes_from_host
    for cpe_payload in extract_cpes_from_host(host):
        port_label = cpe_payload.pop("source_port", None)
        svc_label = cpe_payload.pop("source_service", None)
        os_name = cpe_payload.pop("os_name", None)
        raw = cpe_payload.get("raw") or {}
        raw["source_port"] = port_label
        raw["source_service"] = svc_label
        if os_name:
            raw["os_name_display"] = os_name
        evidence.append(FingerprintMatch(
            source="cpe",
            match_type="exact",
            confidence=0.92,
            os_family=cpe_payload.get("os_family"),
            os_vendor=cpe_payload.get("os_vendor"),
            os_version=cpe_payload.get("os_version"),
            manufacturer=cpe_payload.get("manufacturer"),
            model=cpe_payload.get("model"),
            raw_data=raw,
        ))
        logger.debug(f"CPE match {raw.get('cpe')}: family={cpe_payload.get('os_family')} version={cpe_payload.get('os_version')}")

    # === 7b'. Cloud-provider attribution ===
    # Three independent signals, each with a confidence reflecting how
    # definitive the attribution is:
    #   - PTR / reverse-DNS regex (high — cloud providers control PTRs)
    #   - TLS cert SAN regex (high — managed services bake provider into SANs)
    #   - Published IP-range membership (definitive when present)
    # Multiple signals on the same host produce multiple evidence rows
    # — they corroborate each other in the aggregator.
    from .cloud_detector import detect_from_hostnames, detect_from_tls_sans
    from .cloud_ipranges import lookup_ip
    cloud_hostnames = list(host.hostnames or [])
    if hostname:
        cloud_hostnames.append(hostname)
    ptr_hit = detect_from_hostnames(cloud_hostnames)
    if ptr_hit:
        evidence.append(FingerprintMatch(
            source="cloud_ptr",
            match_type="reverse_dns",
            confidence=0.92,
            manufacturer=ptr_hit.provider,
            raw_data={
                "provider": ptr_hit.provider,
                "service": ptr_hit.service,
                "description": ptr_hit.description,
                "matched_value": ptr_hit.matched_value,
            },
        ))
        logger.debug(f"Cloud PTR match: {ptr_hit.provider} ({ptr_hit.service})")

    # TLS SAN check uses the cert SANs we already extracted in step 6.
    tls_sans: List[str] = []
    for cert in result.ssl_certs or []:
        sans = cert.get("sans") or []
        if isinstance(sans, list):
            tls_sans.extend(s for s in sans if isinstance(s, str))
    for san_hit in detect_from_tls_sans(tls_sans):
        evidence.append(FingerprintMatch(
            source="cloud_tls_san",
            match_type="tls_san",
            confidence=0.88,
            manufacturer=san_hit.provider,
            raw_data={
                "provider": san_hit.provider,
                "service": san_hit.service,
                "description": san_hit.description,
                "matched_value": san_hit.matched_value,
            },
        ))
        logger.debug(f"Cloud TLS SAN match: {san_hit.provider} ({san_hit.service})")

    # IP range membership — definitive when our cache has data.
    ip_hit = lookup_ip(host.address)
    if ip_hit:
        evidence.append(FingerprintMatch(
            source="cloud_iprange",
            match_type="cidr_membership",
            confidence=0.96,  # Highest — the provider published their own ranges
            manufacturer=ip_hit.provider,
            raw_data={
                "provider": ip_hit.provider,
                "service": ip_hit.service,
                "region": ip_hit.region,
                "matched_cidr": ip_hit.cidr,
            },
        ))
        logger.debug(f"Cloud IP range match: {ip_hit.provider}/{ip_hit.service} in {ip_hit.cidr}")

    # === 7c. Hypervisor / Container port heuristics ===
    # Specific port combinations are strong indicators of virt platforms and
    # container orchestrators. We look at the open-port set (ignore service
    # version specifics) and emit evidence when a known signature is met.
    open_ports = {svc.port for svc in host.services if getattr(svc, "state", "") == "open"}
    for vmatch in _detect_virtualization_by_ports(open_ports, host):
        evidence.append(vmatch)
        logger.debug(f"Virt port match: {vmatch.device_type} ({vmatch.raw_data.get('signature')})")

    # === 7c'. ICS / SCADA / OT protocol detection ===
    # Open ICS protocol ports (Modbus/S7/EtherNet-IP/BACnet/DNP3/OPC-UA/...) are
    # a strong industrial signal; ICS NSE scripts add protocol-confirmed vendor
    # and model when run.
    for ics_match in _detect_ics_by_ports(open_ports):
        evidence.append(ics_match)
        logger.debug(f"ICS port match: {ics_match.device_type} ({ics_match.raw_data.get('protocol')})")
    for ics_match in _extract_ics_info(host):
        evidence.append(ics_match)
        logger.debug(f"ICS NSE match: {ics_match.manufacturer} / {ics_match.model} ({ics_match.raw_data.get('protocol')})")

    # === 7d. Virtualization-specific NSE script extraction ===
    for vscript_match in _extract_virt_scripts(host):
        evidence.append(vscript_match)
        logger.debug(f"Virt script match: {vscript_match.match_type}")

    # === 8. Nmap OS Detection ===
    nmap_os_matches = _extract_os_matches(host)
    result.nmap_os_matches = nmap_os_matches

    for idx, os_match in enumerate(nmap_os_matches):
        # Only the top (highest-accuracy) osmatch contributes a device_type
        # vote. nmap routinely returns several osmatches at the SAME accuracy
        # (e.g. "general purpose Linux" AND "router RouterOS" both at 100%);
        # counting the lower guesses let a spurious "router/RouterOS" override
        # the primary classification of an ordinary Linux host. Lower guesses
        # still vote on os_family, where consensus across them is useful.
        evidence.append(FingerprintMatch(
            source="nmap_os",
            match_type="fingerprint",
            confidence=os_match.get("accuracy", 0) / 100.0,
            os_family=os_match.get("osfamily"),
            os_version=os_match.get("name"),
            os_vendor=os_match.get("vendor"),
            device_type=os_match.get("type") if idx == 0 else None,
            raw_data=os_match
        ))

    # === 8b. Nmap OS Database Cross-Reference ===
    if nmap_os_matches:
        best_nmap = nmap_os_matches[0]
        nmap_db_matches = lookup.lookup_nmap_os(os_name=best_nmap.get("name"))
        if nmap_db_matches:
            for ndb_match in nmap_db_matches[:2]:  # Limit to top 2
                evidence.append(ndb_match)
                logger.debug(f"Nmap DB cross-ref: {ndb_match.os_family}")
    else:
        # No nmap -O run (or it found nothing) — try seeding the Nmap OS
        # database from any OS family / vendor we already extracted from
        # banners. This rescues the 6K Nmap signatures from being unused
        # whenever the user can't run with sudo.
        seed_os = None
        seed_vendor = None
        for m in evidence:
            if m.os_family and not seed_os and m.confidence >= 0.7:
                seed_os = m.os_family
            if m.manufacturer and not seed_vendor and m.confidence >= 0.7:
                seed_vendor = m.manufacturer
            if seed_os and seed_vendor:
                break
        if seed_os or seed_vendor:
            nmap_db_matches = lookup.lookup_nmap_os(os_name=seed_os, vendor=seed_vendor)
            for ndb_match in nmap_db_matches[:2]:
                # Slightly lower confidence — the seed wasn't from nmap -O,
                # so the cross-ref is corroborative, not authoritative.
                ndb_match.confidence = min(ndb_match.confidence, 0.75)
                evidence.append(ndb_match)
                logger.debug(f"Nmap DB cross-ref (banner-seeded): {ndb_match.os_family}")

    # === 8b'. Windows build-number resolution ===
    # Walks SMB / nmap-OS / banner strings for Windows build numbers and
    # resolves them to friendly version names (e.g. 17763 → Server 2019).
    # Runs after step 8 so nmap_os_matches is populated.
    for win_match in _extract_windows_build_evidence(
        smb_info=getattr(result, "smb_info", None),
        nmap_os_matches=nmap_os_matches,
        services=services,
        extra_texts=_collect_ntlm_build_texts(host),
    ):
        evidence.append(win_match)
        logger.debug(
            f"Windows build match: {win_match.os_version} -> "
            f"{win_match.raw_data.get('resolved_name')}"
        )

    # === 8c. TCP/IP Stack Fingerprinting ===
    tcp_sig = _extract_tcp_signature(host)
    if tcp_sig:
        tcp_match = await lookup.lookup_tcp(tcp_sig)
        if tcp_match:
            evidence.append(tcp_match)
            logger.debug(f"TCP signature match: {tcp_match.os_family}")

    # === 9. TTL-based OS Detection (low confidence fallback) ===
    ttl = _extract_ttl(host)
    if ttl:
        os_guess = _guess_os_from_ttl(ttl)
        if os_guess:
            evidence.append(FingerprintMatch(
                source="ttl",
                match_type="heuristic",
                confidence=0.4,  # Low confidence for TTL-based detection
                os_family=os_guess,
                raw_data={"ttl": ttl}
            ))

    # === NEW: UPnP/SSDP Evidence ===
    upnp_matches = _extract_upnp_info(host)
    evidence.extend(upnp_matches)

    # === NEW: SNMP Evidence ===
    snmp_matches = _extract_snmp_info(host)
    evidence.extend(snmp_matches)

    # === NEW: WS-Discovery Evidence ===
    wsd_matches = _extract_ws_discovery(host)
    evidence.extend(wsd_matches)

    # === NEW: SIP Evidence ===
    sip_matches = _extract_sip_ua(host, lookup)
    evidence.extend(sip_matches)
    # Also try Satori SIP lookup for SIP UAs
    for sip_m in sip_matches:
        sip_ua = sip_m.raw_data.get("sip_ua")
        if sip_ua:
            satori_sip_match = await lookup.lookup_satori_sip(sip_ua)
            if satori_sip_match:
                evidence.append(satori_sip_match)

    # === 9b. Cross-source Huginn enrichment ===
    # If the evidence so far names a manufacturer, OS family, or device type,
    # ask Huginn for a matching product profile. This is the killer feature:
    # we already know "Linux + Cisco + switch" — Huginn returns a confirming
    # device record so the UI can show the specific product family.
    if evidence:
        consolidated = _summarize_partial(evidence)
        if any((consolidated.get("manufacturer"), consolidated.get("os_family"), consolidated.get("device_type"))):
            try:
                hits = lookup.cache.search_huginn_devices(
                    os_family=consolidated.get("os_family"),
                    manufacturer=consolidated.get("manufacturer"),
                    device_type=consolidated.get("device_type"),
                    limit=3,
                )
                from .huginn_normalize import normalize_huginn_record
                for hit in hits:
                    norm = normalize_huginn_record(hit)
                    if not any((norm.get("device_type"), norm.get("manufacturer"), norm.get("os_family"))):
                        continue
                    evidence.append(FingerprintMatch(
                        source="huginn_device",
                        match_type="cross_source_search",
                        # Lower confidence than direct hostname/ID matches —
                        # this is correlation, not exact identification.
                        confidence=0.65,
                        device_type=norm["device_type"],
                        device_category=norm["device_category"],
                        manufacturer=norm["manufacturer"],
                        model=norm["model"],
                        os_family=norm["os_family"],
                        os_vendor=norm["os_vendor"],
                        raw_data={
                            "huginn_name": hit.get("name"),
                            "hierarchy": hit.get("hierarchy"),
                            "search_inputs": consolidated,
                        },
                    ))
                    logger.debug(f"Huginn cross-ref: {hit.get('name')} ← search({consolidated})")
            except Exception as e:
                logger.debug(f"Huginn cross-source search failed: {e}")

    # === 10. Aggregate All Evidence with Validation ===
    if evidence:
        from .verdict import VerdictEngine
        engine = VerdictEngine()
        verdict = engine.compute(evidence)

        # Convert Verdict to the dict format expected by downstream code
        aggregated = {
            "device_type": verdict.device_type,
            "device_category": verdict.device_category,
            "manufacturer": verdict.manufacturer,
            "os_family": verdict.os_family,
            "os_name": verdict.os_name,
            "os_version": verdict.os_version,
            "confidence": verdict.overall_certainty,
            "evidence": [e.to_dict() for e in verdict.evidence_chain],
            # Store per-field certainty for DeviceInfo
            "device_type_certainty": verdict.device_type_certainty,
            "manufacturer_certainty": verdict.manufacturer_certainty,
            "os_family_certainty": verdict.os_family_certainty,
        }

        result.device_type = aggregated.get("device_type", "Unknown")
        result.device_category = aggregated.get("device_category", "Unknown")
        result.manufacturer = aggregated.get("manufacturer")
        result.confidence = aggregated.get("confidence", 0.0)
        result.evidence = [e.to_dict() for e in evidence]

        # Extract unique sources that contributed
        result.sources = list(set(e.source for e in evidence if e.source))

        # === 10b. Vendor-Specific Device Enrichment ===
        # For known vendors (Ubiquiti, MikroTik, etc.), attempt to identify specific model
        if result.manufacturer:
            # Collect banners for vendor enrichment
            vendor_banners = []
            for svc in services:
                if svc.get('banner'):
                    vendor_banners.append(svc['banner'])
                if svc.get('product'):
                    vendor_banners.append(svc['product'])

            # Collect open ports
            open_ports = [svc.get('port') for svc in services if svc.get('port')]

            # Try vendor-specific enrichment
            vendor_enrichment = enrich_vendor_device(
                manufacturer=result.manufacturer,
                mac_address=mac_address,
                banners=vendor_banners,
                hostname=hostname,
                open_ports=open_ports,
                kernel_version=aggregated.get("os_family"),  # Will extract kernel later
            )

            if vendor_enrichment and vendor_enrichment.get("confidence", 0) > 0.5:
                # Update device type if more specific
                if vendor_enrichment.get("device_type"):
                    result.device_type = vendor_enrichment["device_type"]
                    logger.debug(f"Vendor enrichment device_type: {result.device_type}")

                if vendor_enrichment.get("device_category"):
                    result.device_category = vendor_enrichment["device_category"]

                # Store model info
                if vendor_enrichment.get("model"):
                    result.model = vendor_enrichment["model"]
                    logger.debug(f"Vendor enrichment model: {result.model}")

                # Add vendor enrichment as evidence source
                if "vendor_enrichment" not in result.sources:
                    result.sources.append("vendor_enrichment")

        # === 11. Huginn-Muninn Device Enrichment ===
        # Enrich generic device types (like "general purpose") with more specific categories
        if result.device_type in ("Unknown", "general purpose", None):
            # Try to get a more specific device category from Huginn-Muninn
            os_family = aggregated.get("os_family")
            enriched_type = lookup.cache.get_huginn_device_category(
                os_family=os_family,
                nmap_type=result.device_type
            )
            if enriched_type:
                result.device_type = enriched_type
                logger.debug(f"Enriched device_type from Huginn: {enriched_type}")

                # Also update device_category based on the enriched type
                if enriched_type == "Computer":
                    result.device_category = "Computing"
                elif enriched_type in ("Smartphone", "Smartphone/Tablet", "Tablet"):
                    result.device_category = "Mobile Device"
                elif enriched_type == "Embedded Device":
                    result.device_category = "IoT/Embedded"
                elif enriched_type == "Network Device":
                    result.device_category = "Network Infrastructure"

        # === OS Detection: combine weighted-voting + distro-specific extractors ===
        # Two aggregators run in parallel:
        #   - aggregate_evidence() does weighted voting across every source
        #     (Huginn, Satori, nmap_os, banners, TTL, ...). Best for os_family
        #     identification — Huginn correctly emits iOS/Android/macOS that
        #     the distro-specific extractors below can't see.
        #   - _aggregate_os_info() runs distro-specific regex extraction
        #     (Ubuntu/CentOS/Debian from SSH banners and HTTP Server headers).
        #     Best for os_name and os_version, where it can pull "Ubuntu 22.04"
        #     out of strings that the voting aggregator only sees as "Linux".
        os_info = _aggregate_os_info(
            evidence, nmap_os_matches, smb_info, ssl_certs, services
        )
        # os_family: weighted voting wins. The distro-extractor's view is a
        # fallback for hosts where voting found nothing.
        result.os_family = aggregated.get("os_family") or os_info.get('os_family')
        # os_name + version: distro extractor wins. It's the more specific
        # source ("Ubuntu" vs voting's "Linux") for the cases it covers.
        result.os_name = os_info.get('os_name') or aggregated.get("os_name")
        # os_version must stay consistent with os_name. When the distro
        # extractor identified a specific distro (e.g. "Debian") but no version,
        # do NOT borrow the voting layer's version -- that value is the raw nmap
        # osmatch string (e.g. "OpenWrt 21.02 (Linux 5.4)") and pairing it with
        # "Debian" produces a self-contradicting "Debian / OpenWrt" result.
        if os_info.get('os_name'):
            result.os_version = os_info.get('os_version')
        else:
            result.os_version = aggregated.get("os_version")
        # Kernel + free-form full string come exclusively from the distro
        # extractor — voting doesn't compute these.
        result.os_kernel = os_info.get('os_kernel')
        result.os_full = os_info.get('os_full')

        # Store raw Nmap OS detection
        if nmap_os_matches:
            result.nmap_os_raw = nmap_os_matches[0].get('name')

        # === Enhanced OS Inference ===
        # Collect service banners for firmware inference
        service_banners = []
        for svc in services:
            if svc.get('banner'):
                service_banners.append(svc['banner'])
            if svc.get('product'):
                service_banners.append(svc['product'])

        # Infer OS from kernel version
        inferred_distros = None
        if result.os_kernel:
            inferred_distros = infer_os_from_kernel(result.os_kernel)

        # Infer firmware for IoT/embedded devices
        inferred_fw = None
        if result.manufacturer:
            inferred_fw = infer_firmware_from_manufacturer(
                result.manufacturer,
                result.device_type,
                result.os_kernel,
                service_banners,
                result.os_family  # Pass OS family to skip firmware inference for desktop OSes
            )

        # Set inferred fields
        if inferred_fw and inferred_fw.get("firmware_name"):
            fw_name = inferred_fw["firmware_name"]
            fw_version = inferred_fw.get("version", "")
            if fw_version:
                result.inferred_firmware = f"{fw_name} ({fw_version})"
            else:
                result.inferred_firmware = fw_name

        if inferred_distros:
            distro_strs = [f"{d['distro']} {d['version']}" for d in inferred_distros[:3]]
            result.inferred_os = " / ".join(distro_strs)

        # === Enhanced Validation Logic ===
        validation_status, validation_reason, agreeing_sources, plausibility_score = \
            _enhanced_validate_fingerprint(
                evidence=evidence,
                os_family=result.os_family,
                device_type=result.device_type,
                manufacturer=result.manufacturer,
                kernel_version=result.os_kernel,
                nmap_os_raw=result.nmap_os_raw
            )

        result.validation_status = validation_status.value
        result.validation_reason = validation_reason
        result.validation_sources = agreeing_sources
        result.plausibility_score = plausibility_score
        result.validated = validation_status in (ValidationStatus.VALIDATED, ValidationStatus.PLAUSIBLE)

        # Adjust confidence based on validation status
        if validation_status == ValidationStatus.VALIDATED:
            result.confidence = min(1.0, result.confidence * 1.20)
        elif validation_status == ValidationStatus.PLAUSIBLE:
            result.confidence = min(1.0, result.confidence * 1.10)
        elif validation_status == ValidationStatus.SUSPECT:
            result.confidence = result.confidence * 0.75  # Penalize suspect detections

    return result


def _enhanced_validate_fingerprint(
    evidence: List[FingerprintMatch],
    os_family: Optional[str],
    device_type: str,
    manufacturer: Optional[str],
    kernel_version: Optional[str],
    nmap_os_raw: Optional[str]
) -> Tuple[ValidationStatus, str, int, float]:
    """
    Enhanced validation that checks both consensus AND plausibility.

    Combines source agreement with device type/manufacturer plausibility checks
    to provide more accurate validation status.

    Args:
        evidence: List of fingerprint matches from various sources
        os_family: Detected OS family
        device_type: Detected device type
        manufacturer: Device manufacturer from OUI/other sources
        kernel_version: Detected kernel version
        nmap_os_raw: Raw Nmap OS detection string

    Returns:
        Tuple of (validation_status, reason, agreeing_sources, plausibility_score)
    """
    # Step 1: Count consensus (existing logic)
    os_votes = {}
    for e in evidence:
        if e.os_family:
            normalized = _normalize_os_family(e.os_family)
            os_votes[normalized] = os_votes.get(normalized, 0) + 1

    device_votes = {}
    for e in evidence:
        if e.device_type:
            device_votes[e.device_type] = device_votes.get(e.device_type, 0) + 1

    max_os_votes = max(os_votes.values()) if os_votes else 0
    max_device_votes = max(device_votes.values()) if device_votes else 0
    agreeing_sources = max(max_os_votes, max_device_votes)
    has_consensus = agreeing_sources >= 2

    # Step 2: Check plausibility
    detected_os = os_family or nmap_os_raw
    is_plausible, plausibility_reason, plausibility_score = check_os_plausibility(
        detected_os_family=detected_os,
        manufacturer=manufacturer,
        device_type=device_type,
        kernel_version=kernel_version
    )

    # Step 3: Determine validation status
    if not detected_os and device_type == "Unknown":
        return ValidationStatus.UNKNOWN, "Insufficient OS/device information", 0, 0.0

    if has_consensus and is_plausible:
        return (
            ValidationStatus.VALIDATED,
            f"Consensus ({agreeing_sources} sources) + {plausibility_reason}",
            agreeing_sources,
            plausibility_score
        )
    elif has_consensus and not is_plausible:
        return (
            ValidationStatus.SUSPECT,
            f"Consensus ({agreeing_sources} sources) but {plausibility_reason}",
            agreeing_sources,
            plausibility_score
        )
    elif not has_consensus and is_plausible:
        return (
            ValidationStatus.PLAUSIBLE,
            f"Single source, {plausibility_reason}",
            agreeing_sources,
            plausibility_score
        )
    else:
        return (
            ValidationStatus.UNKNOWN,
            f"Single source, {plausibility_reason}",
            agreeing_sources,
            plausibility_score
        )


def _validate_fingerprint(
    evidence: List[FingerprintMatch],
    os_family: Optional[str],
    device_type: str
) -> Tuple[bool, int]:
    """
    Validate fingerprint by checking if multiple sources agree.

    NOTE: This is the legacy validation function, kept for backward compatibility.
    New code should use _enhanced_validate_fingerprint() instead.

    Returns:
        Tuple of (is_validated, number_of_agreeing_sources)
    """
    if not os_family and device_type == "Unknown":
        return False, 0

    # Count sources that agree on OS family
    os_votes = {}
    for e in evidence:
        if e.os_family:
            # Normalize OS family names for comparison
            normalized = _normalize_os_family(e.os_family)
            os_votes[normalized] = os_votes.get(normalized, 0) + 1

    # Count sources that agree on device type
    device_votes = {}
    for e in evidence:
        if e.device_type:
            device_votes[e.device_type] = device_votes.get(e.device_type, 0) + 1

    # Check if we have consensus (2+ sources agree)
    max_os_votes = max(os_votes.values()) if os_votes else 0
    max_device_votes = max(device_votes.values()) if device_votes else 0

    agreeing_sources = max(max_os_votes, max_device_votes)
    validated = agreeing_sources >= 2

    return validated, agreeing_sources


def _normalize_os_family(os_family: str) -> str:
    """Normalize OS family names for comparison."""
    os_lower = os_family.lower()

    if 'windows' in os_lower:
        return 'Windows'
    elif 'linux' in os_lower or 'ubuntu' in os_lower or 'debian' in os_lower or 'centos' in os_lower or 'rhel' in os_lower or 'fedora' in os_lower:
        return 'Linux'
    elif 'mac' in os_lower or 'darwin' in os_lower or 'osx' in os_lower:
        return 'macOS'
    elif 'ios' in os_lower or 'iphone' in os_lower or 'ipad' in os_lower:
        return 'iOS'
    elif 'android' in os_lower:
        return 'Android'
    elif 'freebsd' in os_lower or 'openbsd' in os_lower or 'netbsd' in os_lower:
        return 'BSD'
    elif 'cisco' in os_lower or 'ios' in os_lower:
        # Careful - "IOS" could be Apple iOS or Cisco IOS
        if 'cisco' in os_lower:
            return 'Cisco IOS'
        return os_family
    elif 'routeros' in os_lower or 'mikrotik' in os_lower:
        return 'RouterOS'
    elif 'fortios' in os_lower:
        return 'FortiOS'
    elif 'junos' in os_lower:
        return 'JunOS'

    return os_family


def _analyze_hostname(hostname: str) -> Optional[FingerprintMatch]:
    """Analyze hostname for device hints."""
    if not hostname:
        return None

    # First, check for high-confidence domain-based matches
    # FQDNs with manufacturer domains are highly reliable identifiers
    domain_result = _check_hostname_domain(hostname)
    if domain_result:
        return domain_result

    for pattern, device_type, manufacturer, os_family in HOSTNAME_PATTERNS:
        if re.search(pattern, hostname, re.IGNORECASE):
            # Higher confidence for domain patterns (ending with .com, etc.)
            confidence = 0.85 if pattern.endswith('$') and '\\.' in pattern else 0.65
            return FingerprintMatch(
                source="hostname",
                match_type="pattern",
                confidence=confidence,
                device_type=device_type,
                manufacturer=manufacturer,
                os_family=os_family,
                raw_data={"hostname": hostname, "pattern": pattern}
            )

    return None


# Domain-to-manufacturer mappings for FQDN-based detection
# These are HIGH CONFIDENCE matches - if a device reports to these domains,
# it's almost certainly from that manufacturer
HOSTNAME_DOMAIN_PATTERNS = {
    # Audio / Consumer Electronics
    "harman.com": ("smart_speaker", "Harman", "Linux"),
    "devices.harman.com": ("smart_speaker", "Harman", "Linux"),
    "jbl.com": ("speaker", "JBL", None),
    "bose.com": ("smart_speaker", "Bose", None),
    "sonos.com": ("smart_speaker", "Sonos", "Sonos OS"),
    "bang-olufsen.com": ("speaker", "Bang & Olufsen", None),
    "denon.com": ("av_receiver", "Denon", None),

    # Smart Home
    "philips-hue.com": ("smart_home", "Philips", None),
    "meethue.com": ("smart_home", "Philips", None),
    "ring.com": ("doorbell", "Ring", None),
    "nest.com": ("thermostat", "Google", None),
    "ecobee.com": ("thermostat", "ecobee", None),
    "smartthings.com": ("home_hub", "Samsung", None),

    # Network Equipment
    "ubnt.com": ("access_point", "Ubiquiti", None),
    "ui.com": ("access_point", "Ubiquiti", None),
    "amplifi.com": ("mesh_router", "Ubiquiti", None),
    "eero.com": ("mesh_router", "eero", "eeroOS"),
    "mikrotik.com": ("router", "MikroTik", "RouterOS"),
    "cisco.com": ("switch", "Cisco", None),
    "meraki.com": ("access_point", "Cisco Meraki", None),
    "aruba.com": ("access_point", "Aruba", None),
    "fortinet.com": ("firewall", "Fortinet", "FortiOS"),
    "netgear.com": ("router", "Netgear", None),
    "linksys.com": ("router", "Linksys", None),
    "tplinkwifi.net": ("router", "TP-Link", None),
    "asusrouter.com": ("router", "ASUS", None),

    # Storage
    "synology.com": ("nas", "Synology", "DSM"),
    "qnap.com": ("nas", "QNAP", "QTS"),

    # Cameras
    "hikvision.com": ("ip_camera", "Hikvision", None),
    "dahua.com": ("ip_camera", "Dahua", None),
    "axis.com": ("ip_camera", "Axis", None),

    # Gaming
    "playstation.net": ("game_console", "Sony", "PlayStation"),
    "xbox.com": ("game_console", "Microsoft", "Xbox"),
    "nintendo.net": ("game_console", "Nintendo", None),

    # Apple
    "apple.com": ("computer", "Apple", "macOS"),
    "icloud.com": ("computer", "Apple", None),

    # Printers
    "hp.com": ("printer", "HP", None),
    "canon.com": ("printer", "Canon", None),
    "epson.com": ("printer", "Epson", None),
    "brother.com": ("printer", "Brother", None),
    "xerox.com": ("printer", "Xerox", None),
}


def _check_hostname_domain(hostname: str) -> Optional[FingerprintMatch]:
    """
    Check if hostname contains a known manufacturer domain.

    Domain-based detection is HIGH CONFIDENCE (0.90) because:
    - Devices reporting to manufacturer domains are definitively from that manufacturer
    - This overrides MAC OUI which can be wrong due to chipset vendors
    - This overrides kernel fingerprinting which is generic (many devices run Linux 4.19)

    Example: jbl-bar300-0000000000.devices.harman.com -> JBL/Harman speaker
    """
    if not hostname or '.' not in hostname:
        return None

    hostname_lower = hostname.lower()

    # Check for domain matches (most specific first)
    for domain, (device_type, manufacturer, os_family) in HOSTNAME_DOMAIN_PATTERNS.items():
        if domain in hostname_lower:
            return FingerprintMatch(
                source="hostname_domain",
                match_type="domain",
                confidence=0.90,  # HIGH confidence - domain is authoritative
                device_type=device_type,
                manufacturer=manufacturer,
                os_family=os_family,
                raw_data={
                    "hostname": hostname,
                    "matched_domain": domain,
                    "detection_note": "FQDN contains manufacturer domain - high confidence identification"
                }
            )

    return None


def _analyze_user_agent(user_agent: str) -> Optional[FingerprintMatch]:
    """Analyze HTTP User-Agent for OS and device hints."""
    if not user_agent:
        return None

    for pattern, device_type, manufacturer, os_family in USER_AGENT_PATTERNS:
        if re.search(pattern, user_agent, re.IGNORECASE):
            return FingerprintMatch(
                source="http_ua",
                match_type="pattern",
                confidence=0.7,  # User-Agent is fairly reliable
                device_type=device_type,
                manufacturer=manufacturer,
                os_family=os_family,
                raw_data={"user_agent": user_agent, "pattern": pattern}
            )

    return None


def _extract_user_agent_from_headers(headers_output: str) -> Optional[str]:
    """Extract User-Agent from http-headers script output."""
    # Look for User-Agent or Server header
    for line in headers_output.split('\n'):
        line = line.strip()
        if line.lower().startswith('user-agent:'):
            return line[11:].strip()
        if line.lower().startswith('server:'):
            # Server header can also give hints
            return line[7:].strip()
    return None


def _analyze_http_title(title: str) -> Optional[FingerprintMatch]:
    """Analyze HTTP title for device hints."""
    if not title:
        return None

    title_lower = title.lower()

    # Known device login pages / dashboards
    patterns = [
        (r'synology', 'nas', 'Synology', 'DSM'),
        (r'qnap', 'nas', 'QNAP', 'QTS'),
        (r'mikrotik|routeros', 'router', 'MikroTik', 'RouterOS'),
        (r'ubiquiti|unifi', 'access_point', 'Ubiquiti', None),
        (r'fortigate|fortios', 'firewall', 'Fortinet', 'FortiOS'),
        (r'pfsense', 'firewall', 'Netgate', 'pfSense'),
        (r'opnsense', 'firewall', None, 'OPNsense'),
        (r'proxmox', 'server', 'Proxmox', 'Proxmox VE'),
        (r'esxi|vmware|vcenter', 'server', 'VMware', 'ESXi'),
        (r'idrac|dell', 'server', 'Dell', None),
        (r'ilo|hp|hpe', 'server', 'HPE', None),
        (r'hikvision', 'camera', 'Hikvision', None),
        (r'dahua', 'camera', 'Dahua', None),
        (r'axis.*camera', 'camera', 'Axis', None),
        (r'printer|laserjet|officejet', 'printer', None, None),
        (r'nas|network.*storage', 'nas', None, None),
        (r'router|gateway', 'router', None, None),
    ]

    for pattern, device_type, manufacturer, os_family in patterns:
        if re.search(pattern, title_lower):
            return FingerprintMatch(
                source="http_title",
                match_type="pattern",
                confidence=0.65,
                device_type=device_type,
                manufacturer=manufacturer,
                os_family=os_family,
                raw_data={"title": title}
            )

    return None


def _extract_dhcp_from_scripts(host) -> Optional[Dict[str, Any]]:
    """Extract DHCP options from Nmap script results."""
    dhcp_data = {}

    if not hasattr(host, 'scripts_results'):
        return None

    for script in host.scripts_results:
        script_id = script.get('id', '')
        output = script.get('output', '')

        if script_id == 'dhcp-discover':
            # Parse dhcp-discover output
            # Example output:
            # DHCP Message Type: DHCPOFFER
            # Server Identifier: 192.168.1.1
            # IP Address Offered: 192.168.1.100
            # Subnet Mask: 255.255.255.0
            # Router: 192.168.1.1
            # ...

            # Extract Vendor Class Identifier (Option 60)
            vendor_match = re.search(r'Vendor.*?[Cc]lass.*?:\s*(.+?)(?:\n|$)', output)
            if vendor_match:
                dhcp_data['option_60'] = vendor_match.group(1).strip()

            # Extract hostname
            hostname_match = re.search(r'Host[nN]ame:\s*(.+?)(?:\n|$)', output)
            if hostname_match:
                dhcp_data['hostname'] = hostname_match.group(1).strip()

            # Option 55 is typically not directly exposed in output,
            # but we can infer device type from the response

        elif script_id == 'broadcast-dhcp-discover':
            # Similar parsing for broadcast version
            vendor_match = re.search(r'Vendor.*?[Cc]lass.*?:\s*(.+?)(?:\n|$)', output)
            if vendor_match:
                dhcp_data['option_60'] = vendor_match.group(1).strip()

    return dhcp_data if dhcp_data else None


# =============================================================================
# Enhanced OS Detection Functions
# =============================================================================

def _extract_distro_from_ssh(banner: str) -> Optional[Dict[str, Any]]:
    """
    Extract Linux distribution from SSH version banner.

    Example banners:
    - "OpenSSH 4.7p1 Debian 8ubuntu1" → Ubuntu
    - "OpenSSH 7.9p1 Debian 10+deb10u2" → Debian 10
    - "OpenSSH 8.4p1 Ubuntu 18.04" → Ubuntu 18.04
    """
    if not banner:
        return None

    result = {}

    for pattern, distro, version_pattern in SSH_DISTRO_PATTERNS:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            result['distro'] = distro

            # Try to extract version
            if version_pattern:
                version_match = re.search(version_pattern, banner, re.IGNORECASE)
                if version_match:
                    result['distro_version'] = version_match.group(1)

            # Special case: "8ubuntu1" means Ubuntu, based on Debian 8
            # The number after 'ubuntu' is the Ubuntu package revision
            if distro == 'Ubuntu' and 'Debian' in banner:
                debian_match = re.search(r'Debian[_\s-]*(\d+)', banner, re.IGNORECASE)
                if debian_match:
                    result['debian_base'] = debian_match.group(1)

            return result

    return None


def _extract_distro_from_http_server(server_header: str) -> Optional[Dict[str, Any]]:
    """
    Extract Linux distribution from HTTP Server header.

    Example headers:
    - "Apache/2.2.8 (Ubuntu) DAV/2" → Ubuntu
    - "Apache/2.4.6 (CentOS)" → CentOS
    - "nginx/1.14.0 (Ubuntu)" → Ubuntu
    """
    if not server_header:
        return None

    result = {}

    for pattern, distro, version_pattern in HTTP_SERVER_OS_PATTERNS:
        match = re.search(pattern, server_header, re.IGNORECASE)
        if match:
            result['distro'] = distro

            # Extract web server version for context
            apache_ver = re.search(r'Apache/([\d.]+)', server_header)
            if apache_ver:
                result['apache_version'] = apache_ver.group(1)

            nginx_ver = re.search(r'nginx/([\d.]+)', server_header)
            if nginx_ver:
                result['nginx_version'] = nginx_ver.group(1)

            return result

    return None


def _extract_os_from_ssl_cn(cn: str) -> Optional[Dict[str, Any]]:
    """
    Extract OS info from SSL certificate CommonName.

    Example CNs:
    - "ubuntu804-base.localdomain" → Ubuntu 8.04
    - "debian10.example.com" → Debian 10
    - "centos7-server" → CentOS 7
    """
    if not cn:
        return None

    cn_lower = cn.lower()
    result = {}

    for pattern, distro, version_extractor in SSL_CN_PATTERNS:
        match = re.search(pattern, cn_lower)
        if match:
            result['distro'] = distro

            if callable(version_extractor):
                result['os_full'] = version_extractor(match)
            elif version_extractor:
                version_match = re.search(version_extractor, cn_lower)
                if version_match:
                    result['version'] = version_match.group(1)

            return result

    return None


def _extract_smb_info(host) -> Optional[Dict[str, Any]]:
    """
    Extract detailed SMB/NetBIOS information from host scripts.

    Parses smb-os-discovery and nbstat script results to extract:
    - OS version
    - Computer name (NetBIOS name)
    - Domain/workgroup
    - Samba version (if Linux)
    """
    if not hasattr(host, 'scripts_results'):
        return None

    smb_info = {}

    for script in host.scripts_results:
        script_id = script.get('id', '')
        output = script.get('output', '')

        if script_id == 'smb-os-discovery':
            # Extract OS
            os_match = re.search(r'OS:\s*([^\n]+)', output)
            if os_match:
                smb_info['os'] = os_match.group(1).strip()

            # Extract computer name
            name_match = re.search(r'Computer name:\s*([^\n]+)', output)
            if name_match:
                smb_info['computer_name'] = name_match.group(1).strip()

            # Extract Samba version (indicates Linux)
            samba_match = re.search(r'Samba\s*([\d.]+)', output)
            if samba_match:
                smb_info['samba_version'] = samba_match.group(1)
                smb_info['is_samba'] = True

            # Extract domain
            domain_match = re.search(r'Domain name:\s*([^\n]+)', output)
            if domain_match:
                smb_info['domain'] = domain_match.group(1).strip()

            # Extract FQDN
            fqdn_match = re.search(r'FQDN:\s*([^\n]+)', output)
            if fqdn_match:
                smb_info['fqdn'] = fqdn_match.group(1).strip()

            # Extract LAN Manager string (e.g. "Samba 4.5.16-Debian",
            # "Windows Server 2019 Standard 6.3"). Satori's SMB DB keys
            # by both native_os AND lanman, so passing both improves the
            # hit rate for Windows Server families.
            lanman_match = re.search(r'(?:LAN\s*Manager|Lanman):\s*([^\n]+)', output, re.IGNORECASE)
            if lanman_match:
                smb_info['lanman'] = lanman_match.group(1).strip()

        elif script_id == 'nbstat':
            # Extract NetBIOS name
            nbname_match = re.search(r'NetBIOS name:\s*([^,\n]+)', output)
            if nbname_match:
                smb_info['netbios_name'] = nbname_match.group(1).strip()

    return smb_info if smb_info else None


def _extract_ssl_certs(host) -> List[Dict[str, Any]]:
    """
    Extract SSL/TLS certificate information from service scripts.

    Returns list of certificates with:
    - commonName (CN)
    - subject details
    - validity dates
    """
    certs = []

    for service in host.services:
        if not hasattr(service, 'scripts_results'):
            continue

        for script in service.scripts_results:
            if script.get('id') == 'ssl-cert':
                cert_info = {
                    'port': service.port,
                    'service': service.service,
                }

                output = script.get('output', '')

                # Extract CommonName
                cn_match = re.search(r'commonName=([^\n/]+)', output)
                if cn_match:
                    cert_info['cn'] = cn_match.group(1).strip()

                # Extract organization
                org_match = re.search(r'organizationName=([^\n/]+)', output)
                if org_match:
                    cert_info['org'] = org_match.group(1).strip()

                # Extract email (often root@hostname)
                email_match = re.search(r'emailAddress=([^\n/]+)', output)
                if email_match:
                    cert_info['email'] = email_match.group(1).strip()

                # Extract validity
                valid_before = re.search(r'Not valid before:\s*([^\n]+)', output)
                if valid_before:
                    cert_info['not_before'] = valid_before.group(1).strip()

                valid_after = re.search(r'Not valid after:\s*([^\n]+)', output)
                if valid_after:
                    cert_info['not_after'] = valid_after.group(1).strip()

                if cert_info.get('cn'):
                    certs.append(cert_info)

    return certs


def _aggregate_os_info(
    evidence: List[FingerprintMatch],
    nmap_os_matches: List[Dict[str, Any]],
    smb_info: Optional[Dict[str, Any]],
    ssl_certs: List[Dict[str, Any]],
    services: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Aggregate OS information from all sources to determine the most likely OS.

    Priority order for distro detection:
    1. SSL certificate CN (often contains exact version, e.g., "ubuntu804")
    2. HTTP Server header (e.g., "Apache (Ubuntu)")
    3. SSH banner (e.g., "Debian 8ubuntu1")
    4. SMB OS discovery
    5. Nmap OS detection (kernel version)

    Returns dict with: os_family, os_name, os_version, os_kernel, os_full
    """
    result = {
        'os_family': None,
        'os_name': None,
        'os_version': None,
        'os_kernel': None,
        'os_full': None,
    }

    distro_hints = []  # Collect all distro hints with confidence

    # 1. Check SSL certificates for OS hints
    for cert in ssl_certs:
        cn = cert.get('cn', '')
        os_info = _extract_os_from_ssl_cn(cn)
        if os_info:
            distro_hints.append({
                'source': 'ssl_cert',
                'confidence': 0.90,  # High confidence - explicit version
                **os_info
            })

    # 2. Check HTTP Server headers
    for svc in services:
        if svc.get('service') in ('http', 'https', 'http-alt'):
            banner = svc.get('extracted_banner', '') or svc.get('banner', '')
            os_info = _extract_distro_from_http_server(banner)
            if os_info:
                distro_hints.append({
                    'source': 'http_server',
                    'confidence': 0.85,
                    **os_info
                })

    # 3. Check SSH banners
    for svc in services:
        if svc.get('service') == 'ssh':
            banner = svc.get('extracted_banner', '') or svc.get('version', '')
            os_info = _extract_distro_from_ssh(banner)
            if os_info:
                distro_hints.append({
                    'source': 'ssh_banner',
                    'confidence': 0.85,
                    **os_info
                })

    # 4. Check SMB discovery
    if smb_info:
        if smb_info.get('is_samba'):
            distro_hints.append({
                'source': 'smb_discovery',
                'confidence': 0.80,
                'distro': 'Linux',  # Samba indicates Linux/Unix
                'samba_version': smb_info.get('samba_version'),
            })

    # 5. Get kernel version from Nmap OS detection
    kernel_version = None
    nmap_os_family = None
    if nmap_os_matches:
        best_match = nmap_os_matches[0]  # Highest accuracy first
        nmap_os_name = best_match.get('name', '')

        # Extract kernel version (e.g., "Linux 2.6.9 - 2.6.33")
        kernel_match = re.search(r'Linux\s+([\d.]+(?:\s*-\s*[\d.]+)?)', nmap_os_name)
        if kernel_match:
            kernel_version = kernel_match.group(1)

        nmap_os_family = best_match.get('osfamily')
        result['os_kernel'] = kernel_version

        # macOS: promote the nmap osmatch ("Apple macOS 13 (Ventura)",
        # "Apple Mac OS X 10.13", or a Darwin uname) into a clean
        # "macOS 14 (Sonoma)" with codename, mirroring the Debian/Windows paths.
        if (nmap_os_family in ('Mac OS X', 'macOS', 'Apple macOS')
                or re.search(r'mac\s*os|macos|darwin|os\s*x', nmap_os_name, re.IGNORECASE)):
            from .os_intelligence import macos_release_from_text
            mac_full = macos_release_from_text(nmap_os_name)
            if mac_full:
                distro_hints.append({
                    'source': 'nmap_macos',
                    'confidence': 0.82,
                    'distro': 'macOS',
                    'os_full': mac_full,
                })

    # 5b. Pull resolved Windows-build evidence (source="windows_build") —
    # it's the highest-precision Windows version source we have.
    win_build_hint = None
    for ev in evidence:
        if ev.source == "windows_build" and ev.raw_data:
            win_build_hint = ev.raw_data.get("resolved_name")
            if win_build_hint:
                distro_hints.append({
                    "source": "windows_build",
                    "confidence": 0.95,
                    "distro": "Windows",
                    "os_full": win_build_hint,
                    "distro_version": ev.os_version,
                })
                break

    # Determine best distro from hints
    if distro_hints:
        # Sort by confidence
        distro_hints.sort(key=lambda x: x.get('confidence', 0), reverse=True)
        best_hint = distro_hints[0]

        result['os_name'] = best_hint.get('distro')

        # Try to get version
        if best_hint.get('os_full'):
            result['os_full'] = best_hint['os_full']
            # Parse version from os_full (e.g., "Ubuntu 8.04")
            ver_match = re.search(r'([\d.]+)', best_hint['os_full'])
            if ver_match:
                result['os_version'] = ver_match.group(1)
        elif best_hint.get('distro_version'):
            result['os_version'] = best_hint['distro_version']

    # Set OS family
    if result['os_name']:
        if result['os_name'] in ('Ubuntu', 'Debian', 'CentOS', 'RHEL', 'Fedora',
                                  'SUSE', 'openSUSE', 'Arch Linux', 'Alpine Linux',
                                  'Gentoo', 'Raspberry Pi OS', 'Linux'):
            result['os_family'] = 'Linux'
        elif result['os_name'] == 'Windows':
            result['os_family'] = 'Windows'
        elif result['os_name'] == 'FreeBSD':
            result['os_family'] = 'FreeBSD'
    elif nmap_os_family:
        result['os_family'] = nmap_os_family

    # Build full OS string if not already set
    if not result['os_full'] and result['os_name']:
        parts = [result['os_name']]
        if result['os_version']:
            codename = _distro_codename(result['os_name'], result['os_version'])
            parts.append(f"{result['os_version']} ({codename})" if codename else result['os_version'])
        if kernel_version:
            parts.append(f"(Linux {kernel_version})")
        result['os_full'] = ' '.join(parts)
    elif result['os_full'] and kernel_version and 'Linux' not in result['os_full']:
        # Append kernel version to existing os_full if not already there
        result['os_full'] += f" (Linux {kernel_version})"
    elif not result['os_full'] and nmap_os_family:
        result['os_full'] = nmap_os_family
        if kernel_version:
            result['os_full'] += f" {kernel_version}"

    return result


def fingerprint_host_sync(
    nmap_xml_path: str,
    host_index: int = 0
) -> Optional[DeviceFingerprint]:
    """
    Synchronous wrapper for fingerprint_host().

    Use this when calling from synchronous code (e.g., ThreadPoolExecutor).

    Args:
        nmap_xml_path: Path to Nmap XML output file
        host_index: Index of host in multi-host scan

    Returns:
        DeviceFingerprint or None
    """
    import asyncio

    # Create or get event loop
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is None:
        # No running loop, create one
        return asyncio.run(fingerprint_host(nmap_xml_path, host_index=host_index))
    else:
        # Already in async context, schedule coroutine
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as pool:
            future = pool.submit(
                asyncio.run,
                fingerprint_host(nmap_xml_path, host_index=host_index)
            )
            return future.result()


def _extract_mac(host) -> Optional[str]:
    """Extract MAC address from Nmap host object."""
    # Try direct mac attribute
    if hasattr(host, 'mac') and host.mac:
        return host.mac.upper()

    # Try address list
    if hasattr(host, 'addresses'):
        for addr_type, addr_value in host.addresses.items():
            if addr_type == 'mac':
                return addr_value.upper()

    # Try hostscripts for MAC
    if hasattr(host, 'scripts_results'):
        for script in host.scripts_results:
            if 'mac' in script.get('id', '').lower():
                output = script.get('output', '')
                mac_match = re.search(
                    r'([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}',
                    output
                )
                if mac_match:
                    return mac_match.group().upper()

    return None


def _extract_banner(service) -> Optional[str]:
    """Extract service banner from Nmap service object."""
    # Try banner attribute
    if hasattr(service, 'banner') and service.banner:
        return service.banner

    # Construct banner from product/version/extrainfo
    parts = []
    if hasattr(service, 'product') and service.product:
        parts.append(service.product)
    if hasattr(service, 'version') and service.version:
        parts.append(service.version)
    if hasattr(service, 'extrainfo') and service.extrainfo:
        parts.append(f"({service.extrainfo})")

    if parts:
        return " ".join(parts)

    # Try script output for banner grabbing
    if hasattr(service, 'scripts_results'):
        for script in service.scripts_results:
            script_id = script.get('id', '')
            if script_id in ('banner', 'ssh-hostkey', 'http-server-header'):
                return script.get('output', '')[:500]  # Limit length

    return None


def _map_service_to_protocol(service_name: str, port: int) -> Optional[str]:
    """Map Nmap service name to fingerprint protocol."""
    if not service_name:
        # Fall back to port-based detection
        port_map = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'http',
            445: 'smb',
            993: 'imap',
            995: 'pop3',
            3306: 'mysql',
            5432: 'postgresql',
            8080: 'http',
            8443: 'http',
        }
        return port_map.get(port)

    service_name = service_name.lower()

    # Direct mappings
    protocol_map = {
        'ssh': 'ssh',
        'http': 'http',
        'https': 'http',
        'http-proxy': 'http',
        'http-alt': 'http',
        'ftp': 'ftp',
        'smb': 'smb',
        'microsoft-ds': 'smb',
        'netbios-ssn': 'smb',
        'telnet': 'telnet',
        'smtp': 'smtp',
        'mysql': 'mysql',
        'postgresql': 'postgresql',
        'vnc': 'vnc',
        'rdp': 'rdp',
        'ms-wbt-server': 'rdp',
    }

    return protocol_map.get(service_name)


def _extract_os_matches(host) -> List[Dict[str, Any]]:
    """Extract OS detection results from Nmap host object."""
    os_matches = []

    if not hasattr(host, 'os') or not host.os:
        return os_matches

    os_obj = host.os

    # Get OS matches
    if hasattr(os_obj, 'osmatches') and os_obj.osmatches:
        for osmatch in os_obj.osmatches:
            match_info = {
                "name": osmatch.name if hasattr(osmatch, 'name') else None,
                "accuracy": osmatch.accuracy if hasattr(osmatch, 'accuracy') else 0,
            }

            # Get OS class info
            if hasattr(osmatch, 'osclasses') and osmatch.osclasses:
                osclass = osmatch.osclasses[0]
                match_info.update({
                    "vendor": osclass.vendor if hasattr(osclass, 'vendor') else None,
                    "osfamily": osclass.osfamily if hasattr(osclass, 'osfamily') else None,
                    "osgen": osclass.osgen if hasattr(osclass, 'osgen') else None,
                    "type": osclass.type if hasattr(osclass, 'type') else None,
                })

            os_matches.append(match_info)

    # Also check for smb-os-discovery script results
    if hasattr(host, 'scripts_results'):
        for script in host.scripts_results:
            if script.get('id') == 'smb-os-discovery':
                output = script.get('output', '')
                # Parse SMB OS discovery output
                if 'Windows' in output:
                    os_matches.append({
                        "name": _extract_windows_version(output),
                        "accuracy": 95,  # SMB OS discovery is highly reliable
                        "vendor": "Microsoft",
                        "osfamily": "Windows",
                        "type": "general purpose",
                        "source": "smb-os-discovery",
                    })
                elif 'Samba' in output:
                    os_matches.append({
                        "name": "Samba Server",
                        "accuracy": 85,
                        "vendor": None,
                        "osfamily": "Linux",
                        "type": "server",
                        "source": "smb-os-discovery",
                    })

    return os_matches


def _extract_windows_version(smb_output: str) -> str:
    """Extract Windows version from SMB OS discovery output."""
    patterns = [
        (r'Windows Server 2022', 'Windows Server 2022'),
        (r'Windows Server 2019', 'Windows Server 2019'),
        (r'Windows Server 2016', 'Windows Server 2016'),
        (r'Windows Server 2012 R2', 'Windows Server 2012 R2'),
        (r'Windows Server 2012', 'Windows Server 2012'),
        (r'Windows Server 2008 R2', 'Windows Server 2008 R2'),
        (r'Windows Server 2008', 'Windows Server 2008'),
        (r'Windows 11', 'Windows 11'),
        (r'Windows 10', 'Windows 10'),
        (r'Windows 8\.1', 'Windows 8.1'),
        (r'Windows 8', 'Windows 8'),
        (r'Windows 7', 'Windows 7'),
        (r'Windows Vista', 'Windows Vista'),
        (r'Windows XP', 'Windows XP'),
    ]

    for pattern, version in patterns:
        if re.search(pattern, smb_output, re.IGNORECASE):
            return version

    return "Windows"


def _extract_ttl(host) -> Optional[int]:
    """Extract TTL from Nmap host object."""
    # Try distance attribute
    if hasattr(host, 'distance') and host.distance:
        # Nmap distance is hops, we can estimate TTL
        # Common initial TTLs: 64 (Linux/macOS), 128 (Windows), 255 (network devices)
        return None  # Can't reliably determine initial TTL from distance

    # TTL might be in host scripts or traceroute data
    if hasattr(host, 'scripts_results'):
        for script in host.scripts_results:
            output = script.get('output', '')
            ttl_match = re.search(r'TTL[:\s]+(\d+)', output, re.IGNORECASE)
            if ttl_match:
                return int(ttl_match.group(1))

    return None


def _guess_os_from_ttl(ttl: int) -> Optional[str]:
    """Guess OS family from TTL value."""
    # Common initial TTL values:
    # 64 - Linux, macOS, FreeBSD, iOS, Android
    # 128 - Windows
    # 255 - Cisco IOS, Solaris, network devices

    if ttl <= 64:
        return "Linux/Unix"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Network Device"


async def fingerprint_nmap_results(
    nmap_xml_path: str,
    lookup: FingerprintLookup = None
) -> List[DeviceFingerprint]:
    """
    Fingerprint all hosts in an Nmap XML file.

    Args:
        nmap_xml_path: Path to Nmap XML output file
        lookup: Optional FingerprintLookup instance

    Returns:
        List of DeviceFingerprint objects
    """
    if not os.path.exists(nmap_xml_path):
        logger.warning(f"Nmap XML file not found: {nmap_xml_path}")
        return []

    try:
        report = NmapParser.parse_fromfile(nmap_xml_path)
    except NmapParserException as e:
        logger.error(f"Failed to parse Nmap XML: {e}")
        return []

    if lookup is None:
        lookup = FingerprintLookup()

    results = []
    for i, host in enumerate(report.hosts):
        result = await fingerprint_host(nmap_xml_path, lookup, host_index=i)
        if result:
            results.append(result)

    return results
