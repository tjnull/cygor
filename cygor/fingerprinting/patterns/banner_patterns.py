"""
Built-in service banner patterns for device/OS identification.

Each pattern is a tuple:
(regex, product, vendor, os_family, version_regex, confidence)

- regex: Pattern to match against banner
- product: Detected product name
- vendor: Product vendor
- os_family: Detected OS family (if determinable)
- version_regex: Regex to extract version (capture group 1)
- confidence: Match confidence 0-100
"""

import re
from typing import Optional, Dict, Tuple, List

# =============================================================================
# SSH Banner Patterns
# =============================================================================

SSH_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # ==========================================================================
    # Security / Penetration Testing Distributions (HIGH PRIORITY)
    # ==========================================================================

    # Kali Linux
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*[Kk]ali", "OpenSSH", "Kali", "Kali Linux", r"([\d.p]+)", 95),
    (r"SSH-2\.0-OpenSSH.*kali-rolling", "OpenSSH", "Kali", "Kali Linux", None, 95),

    # Parrot Security OS
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*[Pp]arrot", "OpenSSH", "Parrot", "Parrot Security OS", r"([\d.p]+)", 95),

    # BlackArch Linux
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*[Bb]lack[Aa]rch", "OpenSSH", None, "BlackArch Linux", r"([\d.p]+)", 95),

    # BackBox Linux
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*[Bb]ack[Bb]ox", "OpenSSH", None, "BackBox Linux", r"([\d.p]+)", 95),

    # Pentoo Linux
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*[Pp]entoo", "OpenSSH", None, "Pentoo Linux", r"([\d.p]+)", 95),

    # ArchStrike
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*[Aa]rch[Ss]trike", "OpenSSH", None, "ArchStrike", r"([\d.p]+)", 95),

    # ==========================================================================
    # Digital Forensics Distributions
    # ==========================================================================

    # CAINE
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*CAINE", "OpenSSH", None, "CAINE", r"([\d.p]+)", 95),

    # DEFT Linux
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*DEFT", "OpenSSH", None, "DEFT Linux", r"([\d.p]+)", 95),

    # Tsurugi Linux
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*[Tt]surugi", "OpenSSH", None, "Tsurugi Linux", r"([\d.p]+)", 95),

    # SIFT Workstation
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*SIFT", "OpenSSH", "SANS", "SIFT Workstation", r"([\d.p]+)", 95),

    # ==========================================================================
    # Malware Analysis Distributions
    # ==========================================================================

    # REMnux
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*REMnux", "OpenSSH", None, "REMnux", r"([\d.p]+)", 95),

    # ==========================================================================
    # Privacy / Anonymity Distributions
    # ==========================================================================

    # Tails OS
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*[Tt]ails", "OpenSSH", None, "Tails OS", r"([\d.p]+)", 95),

    # Whonix
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*[Ww]honix", "OpenSSH", None, "Whonix", r"([\d.p]+)", 95),

    # ==========================================================================
    # Standard Linux Distributions
    # ==========================================================================

    # OpenSSH variants with OS hints
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*Ubuntu", "OpenSSH", "Canonical", "Linux (Ubuntu)", r"([\d.p]+)", 90),
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*Debian", "OpenSSH", None, "Linux (Debian)", r"([\d.p]+)", 90),
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*FreeBSD", "OpenSSH", None, "FreeBSD", r"([\d.p]+)", 90),
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*CentOS", "OpenSSH", None, "Linux (CentOS)", r"([\d.p]+)", 90),
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*Red Hat", "OpenSSH", None, "Linux (RHEL)", r"([\d.p]+)", 90),
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*Rocky", "OpenSSH", None, "Linux (Rocky)", r"([\d.p]+)", 90),
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*AlmaLinux", "OpenSSH", None, "Linux (AlmaLinux)", r"([\d.p]+)", 90),
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*SUSE", "OpenSSH", None, "Linux (SUSE)", r"([\d.p]+)", 90),
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+).*Fedora", "OpenSSH", None, "Linux (Fedora)", r"([\d.p]+)", 90),
    (r"SSH-2\.0-OpenSSH[_-]?([\d.p]+)", "OpenSSH", None, "Linux", r"([\d.p]+)", 75),

    # Cisco
    (r"SSH-2\.0-Cisco[_-]?([\d.]+)?", "Cisco SSH", "Cisco", "IOS", r"([\d.]+)", 95),
    (r"SSH-1\.99-Cisco", "Cisco SSH", "Cisco", "IOS", None, 90),

    # Windows
    (r"SSH-2\.0-.*Windows", "Windows SSH", "Microsoft", "Windows", None, 85),
    (r"SSH-2\.0-.*OpenSSH.*Windows", "OpenSSH", "Microsoft", "Windows", None, 90),

    # Dropbear (embedded systems)
    (r"SSH-2\.0-dropbear[_-]?([\d.]+)", "Dropbear", None, "Linux (Embedded)", r"([\d.]+)", 80),

    # MikroTik
    (r"SSH-2\.0-.*MikroTik.*RouterOS[_-]?([\d.]+)?", "MikroTik SSH", "MikroTik", "RouterOS", r"([\d.]+)", 95),
    (r"SSH-2\.0-.*MikroTik", "MikroTik SSH", "MikroTik", "RouterOS", None, 90),

    # FortiOS
    (r"SSH-2\.0-.*FortiOS", "FortiSSH", "Fortinet", "FortiOS", None, 95),

    # Juniper
    (r"SSH-2\.0-.*Juniper", "Juniper SSH", "Juniper", "JunOS", None, 95),

    # HP/HPE
    (r"SSH-2\.0-.*HP.*ProCurve", "HP SSH", "HP", "ProCurve", None, 90),
    (r"SSH-2\.0-.*Comware", "Comware SSH", "HPE", "Comware", None, 90),

    # VMware
    (r"SSH-2\.0-.*ESXi", "ESXi SSH", "VMware", "ESXi", None, 95),
    (r"SSH-2\.0-.*vSphere", "vSphere SSH", "VMware", "vSphere", None, 90),

    # Palo Alto
    (r"SSH-2\.0-.*PAN-OS", "PAN-OS SSH", "Palo Alto", "PAN-OS", None, 95),

    # ASUS routers
    (r"SSH-2\.0-.*ASUSWRT", "ASUSWRT SSH", "ASUS", "ASUSWRT", None, 90),

    # Synology
    (r"SSH-2\.0-.*DSM", "DSM SSH", "Synology", "DSM", None, 90),

    # QNAP
    (r"SSH-2\.0-.*QNAP", "QTS SSH", "QNAP", "QTS", None, 90),
]

# =============================================================================
# HTTP Server Patterns
# =============================================================================

HTTP_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # ==========================================================================
    # Security Distributions (HIGH PRIORITY)
    # ==========================================================================
    (r"Apache/([\d.]+).*[Kk]ali", "Apache", "Apache", "Kali Linux", r"([\d.]+)", 95),
    (r"Apache/([\d.]+).*[Pp]arrot", "Apache", "Apache", "Parrot Security OS", r"([\d.]+)", 95),
    (r"Apache/([\d.]+).*[Bb]lack[Aa]rch", "Apache", "Apache", "BlackArch Linux", r"([\d.]+)", 95),
    (r"Apache/([\d.]+).*[Bb]ack[Bb]ox", "Apache", "Apache", "BackBox Linux", r"([\d.]+)", 95),
    (r"Apache/([\d.]+).*REMnux", "Apache", "Apache", "REMnux", r"([\d.]+)", 95),
    (r"Apache/([\d.]+).*CAINE", "Apache", "Apache", "CAINE", r"([\d.]+)", 95),
    (r"Apache/([\d.]+).*DEFT", "Apache", "Apache", "DEFT Linux", r"([\d.]+)", 95),
    (r"Apache/([\d.]+).*[Tt]surugi", "Apache", "Apache", "Tsurugi Linux", r"([\d.]+)", 95),

    # ==========================================================================
    # Standard Distributions
    # ==========================================================================
    # Apache variants
    (r"Apache/([\d.]+).*Ubuntu", "Apache", "Apache", "Linux (Ubuntu)", r"([\d.]+)", 90),
    (r"Apache/([\d.]+).*Debian", "Apache", "Apache", "Linux (Debian)", r"([\d.]+)", 90),
    (r"Apache/([\d.]+).*CentOS", "Apache", "Apache", "Linux (CentOS)", r"([\d.]+)", 90),
    (r"Apache/([\d.]+).*Red Hat", "Apache", "Apache", "Linux (RHEL)", r"([\d.]+)", 90),
    (r"Apache/([\d.]+).*Rocky", "Apache", "Apache", "Linux (Rocky)", r"([\d.]+)", 90),
    (r"Apache/([\d.]+).*AlmaLinux", "Apache", "Apache", "Linux (AlmaLinux)", r"([\d.]+)", 90),
    (r"Apache/([\d.]+).*Win64", "Apache", "Apache", "Windows", r"([\d.]+)", 90),
    (r"Apache/([\d.]+).*Win32", "Apache", "Apache", "Windows", r"([\d.]+)", 90),
    (r"Apache/([\d.]+)", "Apache", "Apache", None, r"([\d.]+)", 75),

    # nginx
    (r"nginx/([\d.]+)", "nginx", "nginx", None, r"([\d.]+)", 75),

    # Microsoft IIS
    (r"Microsoft-IIS/([\d.]+)", "IIS", "Microsoft", "Windows Server", r"([\d.]+)", 90),

    # lighttpd
    (r"lighttpd/([\d.]+)", "lighttpd", None, None, r"([\d.]+)", 70),

    # LiteSpeed
    (r"LiteSpeed", "LiteSpeed", "LiteSpeed", None, None, 70),

    # Caddy
    (r"Caddy", "Caddy", None, None, None, 70),

    # Network devices
    (r"Hikvision-Webs", "Hikvision", "Hikvision", None, None, 95),
    (r"DNVRS-Webs", "Dahua", "Dahua", None, None, 95),
    (r"Dahua", "Dahua", "Dahua", None, None, 90),

    # NAS devices
    (r"Synology", "DSM", "Synology", "DSM", None, 95),
    (r"QNAP", "QTS", "QNAP", "QTS", None, 95),
    (r"WD My Cloud", "WD My Cloud", "Western Digital", None, None, 90),

    # Routers/Firewalls
    (r"MikroTik", "RouterOS", "MikroTik", "RouterOS", None, 90),
    (r"DD-WRT", "DD-WRT", None, "DD-WRT", None, 90),
    (r"OpenWrt", "OpenWrt", None, "OpenWrt", None, 90),
    (r"pfSense", "pfSense", "Netgate", "pfSense", None, 90),
    (r"OPNsense", "OPNsense", "OPNsense", "OPNsense", None, 90),
    (r"UniFi", "UniFi", "Ubiquiti", None, None, 90),

    # Printers
    (r"HP-ChaiSOE", "HP Printer", "HP", None, None, 90),
    (r"EPSON[_ ]HTTP", "Epson Printer", "Epson", None, None, 90),
    (r"Brother", "Brother Printer", "Brother", None, None, 85),
    (r"CANON HTTP", "Canon Printer", "Canon", None, None, 85),
    (r"Xerox", "Xerox Printer", "Xerox", None, None, 85),

    # Smart home / IoT
    (r"Philips-hue", "Hue Bridge", "Philips", None, None, 95),
    (r"Samsung SmartTV", "Samsung Smart TV", "Samsung", "Tizen", None, 90),
    (r"Roku", "Roku", "Roku", None, None, 90),

    # Python frameworks
    (r"Werkzeug/([\d.]+)", "Flask", None, None, r"([\d.]+)", 70),
    (r"gunicorn/([\d.]+)", "Gunicorn", None, None, r"([\d.]+)", 70),
    (r"uvicorn", "Uvicorn", None, None, None, 70),

    # Java
    (r"Jetty\(([\d.]+)\)", "Jetty", "Eclipse", None, r"([\d.]+)", 70),
    (r"Apache-Coyote/([\d.]+)", "Tomcat", "Apache", None, r"([\d.]+)", 75),

    # Node.js
    (r"Express", "Express.js", None, None, None, 65),
]

# =============================================================================
# SMB Patterns
# =============================================================================

SMB_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    (r"Windows Server 2022", "Windows Server 2022", "Microsoft", "Windows Server 2022", None, 95),
    (r"Windows Server 2019", "Windows Server 2019", "Microsoft", "Windows Server 2019", None, 95),
    (r"Windows Server 2016", "Windows Server 2016", "Microsoft", "Windows Server 2016", None, 95),
    (r"Windows Server 2012", "Windows Server 2012", "Microsoft", "Windows Server 2012", None, 95),
    (r"Windows 11", "Windows 11", "Microsoft", "Windows 11", None, 90),
    (r"Windows 10", "Windows 10", "Microsoft", "Windows 10", None, 90),
    (r"Windows 8\.1", "Windows 8.1", "Microsoft", "Windows 8.1", None, 90),
    (r"Windows 8", "Windows 8", "Microsoft", "Windows 8", None, 90),
    (r"Windows 7", "Windows 7", "Microsoft", "Windows 7", None, 90),
    (r"Samba ([\d.]+)", "Samba", None, "Linux", r"([\d.]+)", 85),
    (r"Mac OS X", "macOS SMB", "Apple", "macOS", None, 85),
    (r"QNAP", "QTS", "QNAP", "QTS", None, 90),
    (r"Synology", "DSM", "Synology", "DSM", None, 90),
]

# =============================================================================
# FTP Patterns
# =============================================================================

FTP_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    (r"vsftpd ([\d.]+)", "vsftpd", None, "Linux", r"([\d.]+)", 85),
    (r"ProFTPD ([\d.]+)", "ProFTPD", None, "Linux", r"([\d.]+)", 85),
    (r"Pure-FTPd", "Pure-FTPd", None, "Linux", None, 80),
    (r"FileZilla Server ([\d.]+)", "FileZilla Server", None, "Windows", r"([\d.]+)", 85),
    (r"Microsoft FTP Service", "Microsoft FTP", "Microsoft", "Windows", None, 90),
    (r"220-Welcome to (.*) FTP", None, None, None, None, 50),  # Generic
    # Additional FTP servers
    (r"NcFTPd Server \(licensed copy\)", "NcFTPd", None, None, None, 75),
    (r"VxWorks FTP", "VxWorks FTP", "Wind River", "VxWorks", None, 90),
    (r"Serv-U FTP", "Serv-U", "SolarWinds", "Windows", None, 85),
    (r"Gene6 FTP Server", "Gene6 FTP", None, "Windows", None, 80),
    (r"CrushFTP", "CrushFTP", None, None, None, 80),
    (r"WS_FTP Server", "WS_FTP", "Ipswitch", "Windows", None, 85),
    (r"GlobalSCAPE", "GlobalSCAPE EFT", "GlobalSCAPE", "Windows", None, 85),
    (r"CompleteFTP", "CompleteFTP", None, "Windows", None, 80),
    (r"Cerberus FTP", "Cerberus FTP", None, "Windows", None, 80),
    (r"Core FTP", "Core FTP", None, "Windows", None, 75),
    (r"Titan FTP", "Titan FTP", "South River", "Windows", None, 80),
    (r"BFTPD", "bftpd", None, "Linux", None, 75),
    (r"glFTPd", "glFTPd", None, "Linux", None, 75),
    (r"pyftpdlib", "pyftpdlib", None, None, None, 70),
    (r"Twisted.*FTP", "Twisted FTP", None, "Linux", None, 70),
]

# =============================================================================
# SMTP/Mail Server Patterns
# =============================================================================

SMTP_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # Postfix
    (r"Postfix", "Postfix", None, "Linux", None, 85),
    (r"ESMTP Postfix.*Ubuntu", "Postfix", "Canonical", "Linux (Ubuntu)", None, 90),
    (r"ESMTP Postfix.*Debian", "Postfix", None, "Linux (Debian)", None, 90),

    # Sendmail
    (r"Sendmail ([\d.]+)", "Sendmail", None, "Linux", r"([\d.]+)", 85),
    (r"Sendmail.*AIX", "Sendmail", "IBM", "AIX", None, 90),

    # Exim
    (r"Exim ([\d.]+)", "Exim", None, "Linux", r"([\d.]+)", 85),
    (r"Exim.*Debian", "Exim", None, "Linux (Debian)", None, 90),

    # Microsoft Exchange
    (r"Microsoft ESMTP MAIL Service", "Exchange", "Microsoft", "Windows Server", None, 95),
    (r"Microsoft Exchange", "Exchange", "Microsoft", "Windows Server", None, 95),
    (r"Exchange Server", "Exchange", "Microsoft", "Windows Server", None, 90),

    # qmail
    (r"qmail", "qmail", None, "Linux", None, 80),

    # hMailServer
    (r"hMailServer", "hMailServer", None, "Windows", None, 85),

    # Zimbra
    (r"Zimbra", "Zimbra", "Synacor", "Linux", None, 90),

    # Dovecot (IMAP/POP but sometimes in SMTP)
    (r"Dovecot", "Dovecot", None, "Linux", None, 85),

    # Courier
    (r"Courier", "Courier", None, "Linux", None, 80),

    # Haraka
    (r"Haraka", "Haraka", None, None, None, 75),

    # MailEnable
    (r"MailEnable", "MailEnable", "MailEnable", "Windows", None, 85),

    # MDaemon
    (r"MDaemon", "MDaemon", "MDaemon", "Windows", None, 85),

    # IceWarp
    (r"IceWarp", "IceWarp", "IceWarp", None, None, 85),

    # Kerio
    (r"Kerio", "Kerio Connect", "GFI", None, None, 85),

    # Axigen
    (r"Axigen", "Axigen", "Axigen", None, None, 80),

    # OpenSMTPD
    (r"OpenSMTPD", "OpenSMTPD", "OpenBSD", "OpenBSD", None, 85),

    # Lotus Domino
    (r"Lotus Domino", "Lotus Domino", "IBM", None, None, 90),
    (r"Domino SMTP", "Lotus Domino", "IBM", None, None, 85),

    # GroupWise
    (r"GroupWise", "GroupWise", "Micro Focus", None, None, 85),

    # Mimecast
    (r"Mimecast", "Mimecast", "Mimecast", None, None, 85),

    # Proofpoint
    (r"Proofpoint", "Proofpoint", "Proofpoint", None, None, 90),

    # Barracuda
    (r"Barracuda", "Barracuda ESG", "Barracuda", None, None, 90),
]

# =============================================================================
# IMAP/POP3 Patterns
# =============================================================================

IMAP_POP_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # Dovecot
    (r"Dovecot.*ready", "Dovecot", None, "Linux", None, 85),
    (r"Dovecot \(([\d.]+)\)", "Dovecot", None, "Linux", r"([\d.]+)", 90),

    # Cyrus IMAP
    (r"Cyrus IMAP", "Cyrus IMAP", "CMU", "Linux", None, 85),
    (r"Cyrus timsieved", "Cyrus", "CMU", "Linux", None, 80),

    # Courier
    (r"Courier-IMAP", "Courier-IMAP", None, "Linux", None, 85),
    (r"Courier-POP3", "Courier-POP3", None, "Linux", None, 85),

    # UW-IMAP
    (r"UW IMAP", "UW-IMAP", "University of Washington", "Linux", None, 80),

    # Microsoft Exchange
    (r"Microsoft Exchange", "Exchange IMAP", "Microsoft", "Windows Server", None, 95),
    (r"The Microsoft Exchange POP3", "Exchange POP3", "Microsoft", "Windows Server", None, 95),

    # Zimbra
    (r"Zimbra IMAP", "Zimbra", "Synacor", "Linux", None, 90),

    # hMailServer
    (r"hMailServer.*POP3", "hMailServer", None, "Windows", None, 85),
    (r"hMailServer.*IMAP", "hMailServer", None, "Windows", None, 85),

    # Gmail
    (r"Gimap", "Gmail IMAP", "Google", None, None, 90),

    # Pstranger IMAP
    (r"pstranger IMAP", "Pstranger IMAP", None, None, None, 70),
]

# =============================================================================
# Telnet Patterns
# =============================================================================

TELNET_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # Cisco
    (r"User Access Verification", "Cisco Telnet", "Cisco", "IOS", None, 90),
    (r"Cisco IOS", "Cisco IOS", "Cisco", "IOS", None, 95),

    # Juniper
    (r"Juniper Networks", "JunOS Telnet", "Juniper", "JunOS", None, 95),

    # HP/Aruba
    (r"ProCurve", "ProCurve", "HP", None, None, 90),
    (r"Aruba", "Aruba", "HPE", "ArubaOS", None, 90),

    # MikroTik
    (r"MikroTik", "RouterOS", "MikroTik", "RouterOS", None, 95),

    # Linux
    (r"Linux.*telnetd", "Linux Telnet", None, "Linux", None, 80),
    (r"Ubuntu.*login:", "Linux Telnet", "Canonical", "Linux (Ubuntu)", None, 85),
    (r"Debian.*login:", "Linux Telnet", None, "Linux (Debian)", None, 85),

    # FreeBSD
    (r"FreeBSD", "FreeBSD Telnet", None, "FreeBSD", None, 85),

    # BusyBox
    (r"BusyBox", "BusyBox", None, "Linux (Embedded)", None, 85),

    # VxWorks
    (r"VxWorks", "VxWorks Telnet", "Wind River", "VxWorks", None, 90),

    # Embedded devices
    (r"TP-LINK", "TP-Link", "TP-Link", None, None, 90),
    (r"D-Link", "D-Link", "D-Link", None, None, 90),
    (r"NETGEAR", "Netgear", "Netgear", None, None, 90),
    (r"Linksys", "Linksys", "Linksys", None, None, 90),
    (r"ASUS.*login", "ASUS", "ASUS", None, None, 85),
    (r"ZyXEL", "ZyXEL", "ZyXEL", None, None, 90),
    (r"Huawei", "Huawei", "Huawei", None, None, 90),
    (r"ZTE", "ZTE", "ZTE", None, None, 85),

    # Printers
    (r"HP.*JetDirect", "HP JetDirect", "HP", None, None, 95),
    (r"RICOH", "Ricoh", "Ricoh", None, None, 90),
    (r"KYOCERA", "Kyocera", "Kyocera", None, None, 90),

    # SCADA/ICS
    (r"Siemens", "Siemens", "Siemens", None, None, 85),
    (r"Schneider", "Schneider Electric", "Schneider Electric", None, None, 85),
]

# =============================================================================
# DNS Server Patterns
# =============================================================================

DNS_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # BIND
    (r"BIND ([\d.]+)", "BIND", "ISC", None, r"([\d.]+)", 90),
    (r"named ([\d.]+)", "BIND", "ISC", None, r"([\d.]+)", 85),

    # Microsoft DNS
    (r"Microsoft DNS", "Microsoft DNS", "Microsoft", "Windows Server", None, 95),

    # Unbound
    (r"unbound ([\d.]+)", "Unbound", "NLnet Labs", None, r"([\d.]+)", 85),

    # PowerDNS
    (r"PowerDNS", "PowerDNS", "PowerDNS", None, None, 85),

    # dnsmasq
    (r"dnsmasq-([\d.]+)", "dnsmasq", None, "Linux", r"([\d.]+)", 85),

    # Knot DNS
    (r"Knot DNS", "Knot DNS", "CZ.NIC", None, None, 80),

    # NSD
    (r"NSD ([\d.]+)", "NSD", "NLnet Labs", None, r"([\d.]+)", 80),

    # CoreDNS
    (r"CoreDNS", "CoreDNS", "CNCF", None, None, 85),

    # Pi-hole
    (r"Pi-hole", "Pi-hole", None, "Linux", None, 90),

    # AdGuard
    (r"AdGuard", "AdGuard Home", "AdGuard", None, None, 85),
]

# =============================================================================
# LDAP/Directory Patterns
# =============================================================================

LDAP_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # OpenLDAP
    (r"OpenLDAP", "OpenLDAP", None, "Linux", None, 85),
    (r"slapd", "OpenLDAP", None, "Linux", None, 80),

    # Microsoft Active Directory
    (r"Microsoft.*Active.*Directory", "Active Directory", "Microsoft", "Windows Server", None, 95),
    (r"Microsoft.*LDAP", "Active Directory", "Microsoft", "Windows Server", None, 90),

    # 389 Directory Server
    (r"389-Directory", "389 Directory", "Red Hat", "Linux", None, 85),
    (r"Fedora-Directory", "389 Directory", "Red Hat", "Linux", None, 85),

    # FreeIPA
    (r"FreeIPA", "FreeIPA", "Red Hat", "Linux", None, 90),

    # OpenDJ
    (r"OpenDJ", "OpenDJ", "ForgeRock", None, None, 85),

    # ApacheDS
    (r"ApacheDS", "ApacheDS", "Apache", None, None, 80),

    # Oracle Directory
    (r"Oracle.*Directory", "Oracle Directory", "Oracle", None, None, 90),
    (r"OID", "Oracle Directory", "Oracle", None, None, 85),

    # Novell eDirectory
    (r"eDirectory", "eDirectory", "Micro Focus", None, None, 90),
    (r"NDS", "Novell NDS", "Micro Focus", None, None, 85),

    # IBM Directory
    (r"IBM.*Directory", "IBM Directory", "IBM", None, None, 90),
]

# =============================================================================
# SNMP Patterns (from sysDescr)
# =============================================================================

SNMP_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # Cisco
    (r"Cisco IOS.*Version ([\d.]+)", "Cisco IOS", "Cisco", "IOS", r"Version ([\d.]+)", 95),
    (r"Cisco IOS XE.*Version ([\d.]+)", "Cisco IOS XE", "Cisco", "IOS XE", r"Version ([\d.]+)", 95),
    (r"Cisco NX-OS", "Cisco NX-OS", "Cisco", "NX-OS", None, 95),
    (r"Cisco Adaptive Security Appliance", "Cisco ASA", "Cisco", "ASA", None, 95),
    (r"Cisco Firepower", "Cisco Firepower", "Cisco", None, None, 95),
    (r"Cisco.*Catalyst", "Cisco Catalyst", "Cisco", "IOS", None, 90),
    (r"Cisco.*Nexus", "Cisco Nexus", "Cisco", "NX-OS", None, 90),
    (r"Cisco.*WLC", "Cisco WLC", "Cisco", None, None, 90),
    (r"Cisco AIR-", "Cisco Aironet", "Cisco", None, None, 90),

    # Juniper
    (r"Juniper.*JUNOS ([\d.]+)", "JunOS", "Juniper", "JunOS", r"([\d.]+)", 95),
    (r"Juniper.*SRX", "Juniper SRX", "Juniper", "JunOS", None, 90),
    (r"Juniper.*MX", "Juniper MX", "Juniper", "JunOS", None, 90),
    (r"Juniper.*EX", "Juniper EX", "Juniper", "JunOS", None, 90),

    # HPE/Aruba
    (r"HP.*ProCurve", "HP ProCurve", "HP", None, None, 90),
    (r"Aruba.*Controller", "Aruba Controller", "HPE", "ArubaOS", None, 95),
    (r"ArubaOS", "ArubaOS", "HPE", "ArubaOS", None, 90),
    (r"HPE.*Comware", "HPE Comware", "HPE", "Comware", None, 90),

    # Fortinet
    (r"Fortinet.*FortiGate", "FortiGate", "Fortinet", "FortiOS", None, 95),
    (r"FortiOS.*v([\d.]+)", "FortiOS", "Fortinet", "FortiOS", r"v([\d.]+)", 95),
    (r"Fortinet.*FortiSwitch", "FortiSwitch", "Fortinet", None, None, 90),
    (r"Fortinet.*FortiAP", "FortiAP", "Fortinet", None, None, 90),

    # Palo Alto
    (r"Palo Alto.*PAN-OS ([\d.]+)", "PAN-OS", "Palo Alto", "PAN-OS", r"([\d.]+)", 95),
    (r"Palo Alto", "Palo Alto Firewall", "Palo Alto", "PAN-OS", None, 90),

    # Linux
    (r"Linux.*Ubuntu", "Ubuntu", "Canonical", "Linux (Ubuntu)", None, 90),
    (r"Linux.*Debian", "Debian", None, "Linux (Debian)", None, 90),
    (r"Linux.*CentOS", "CentOS", None, "Linux (CentOS)", None, 90),
    (r"Linux.*Red Hat", "RHEL", "Red Hat", "Linux (RHEL)", None, 90),
    (r"Linux.*([\d.]+)", "Linux", None, "Linux", r"Linux ([\d.]+)", 75),

    # Windows
    (r"Windows Server 2022", "Windows Server 2022", "Microsoft", "Windows Server 2022", None, 95),
    (r"Windows Server 2019", "Windows Server 2019", "Microsoft", "Windows Server 2019", None, 95),
    (r"Windows Server 2016", "Windows Server 2016", "Microsoft", "Windows Server 2016", None, 95),
    (r"Windows.*Version ([\d.]+)", "Windows", "Microsoft", "Windows", r"Version ([\d.]+)", 85),

    # VMware
    (r"VMware ESXi ([\d.]+)", "ESXi", "VMware", "ESXi", r"([\d.]+)", 95),
    (r"VMware vCenter", "vCenter", "VMware", "vCenter", None, 95),

    # Dell/EMC
    (r"Dell.*PowerConnect", "Dell PowerConnect", "Dell", None, None, 90),
    (r"Dell.*PowerSwitch", "Dell PowerSwitch", "Dell", None, None, 90),
    (r"Dell.*iDRAC", "Dell iDRAC", "Dell", None, None, 95),
    (r"Dell EMC", "Dell EMC", "Dell EMC", None, None, 85),

    # Extreme
    (r"Extreme.*EXOS", "Extreme EXOS", "Extreme", "EXOS", None, 90),
    (r"Extreme Networks", "Extreme", "Extreme", None, None, 85),

    # Brocade
    (r"Brocade.*FabricOS", "Brocade FabricOS", "Brocade", "FabricOS", None, 90),
    (r"Brocade.*ICX", "Brocade ICX", "Brocade", None, None, 90),

    # Ubiquiti
    (r"Ubiquiti.*EdgeSwitch", "EdgeSwitch", "Ubiquiti", None, None, 90),
    (r"Ubiquiti.*EdgeRouter", "EdgeRouter", "Ubiquiti", "EdgeOS", None, 90),
    (r"UniFi", "UniFi", "Ubiquiti", None, None, 90),

    # MikroTik
    (r"RouterOS ([\d.]+)", "RouterOS", "MikroTik", "RouterOS", r"([\d.]+)", 95),
    (r"MikroTik", "MikroTik", "MikroTik", "RouterOS", None, 90),

    # Printers
    (r"HP.*LaserJet", "HP LaserJet", "HP", None, None, 95),
    (r"HP.*OfficeJet", "HP OfficeJet", "HP", None, None, 95),
    (r"RICOH", "Ricoh", "Ricoh", None, None, 90),
    (r"Canon.*iR", "Canon", "Canon", None, None, 90),
    (r"Xerox", "Xerox", "Xerox", None, None, 90),
    (r"KYOCERA", "Kyocera", "Kyocera", None, None, 90),
    (r"Brother", "Brother", "Brother", None, None, 90),
    (r"Lexmark", "Lexmark", "Lexmark", None, None, 90),

    # UPS
    (r"APC.*Smart-UPS", "APC Smart-UPS", "APC", None, None, 95),
    (r"APC.*Symmetra", "APC Symmetra", "APC", None, None, 95),
    (r"Eaton", "Eaton UPS", "Eaton", None, None, 90),
    (r"Liebert", "Liebert", "Vertiv", None, None, 90),
    (r"CyberPower", "CyberPower", "CyberPower", None, None, 85),
    (r"Tripp Lite", "Tripp Lite", "Tripp Lite", None, None, 85),

    # Storage
    (r"NetApp.*ONTAP", "NetApp ONTAP", "NetApp", "ONTAP", None, 95),
    (r"NetApp", "NetApp", "NetApp", None, None, 90),
    (r"Synology.*DSM", "Synology DSM", "Synology", "DSM", None, 95),
    (r"QNAP.*QTS", "QNAP QTS", "QNAP", "QTS", None, 95),
    (r"EMC.*VNX", "EMC VNX", "Dell EMC", None, None, 90),
    (r"Pure Storage", "Pure Storage", "Pure Storage", None, None, 90),

    # IPMI/BMC
    (r"IPMI", "IPMI BMC", None, None, None, 80),
    (r"iLO.*HP", "HP iLO", "HP", None, None, 95),
    (r"iDRAC", "Dell iDRAC", "Dell", None, None, 95),
    (r"ASUS.*ASMB", "ASUS ASMB", "ASUS", None, None, 85),
    (r"Supermicro", "Supermicro IPMI", "Supermicro", None, None, 85),
]

# =============================================================================
# RDP/VNC Patterns
# =============================================================================

RDP_VNC_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # VNC variants
    (r"RFB 003\.008", "VNC", None, None, None, 75),
    (r"RFB 003\.007", "VNC", None, None, None, 75),
    (r"RFB 003\.003", "VNC", None, None, None, 75),
    (r"TightVNC", "TightVNC", None, None, None, 85),
    (r"RealVNC", "RealVNC", "RealVNC", None, None, 85),
    (r"UltraVNC", "UltraVNC", None, "Windows", None, 85),
    (r"TigerVNC", "TigerVNC", None, "Linux", None, 85),
    (r"x11vnc", "x11vnc", None, "Linux", None, 80),
    (r"Apple Remote Desktop", "Apple Remote Desktop", "Apple", "macOS", None, 90),

    # xrdp
    (r"xrdp", "xrdp", None, "Linux", None, 85),

    # Windows RDP
    (r"Microsoft.*Terminal.*Services", "Windows RDP", "Microsoft", "Windows", None, 90),
]

# =============================================================================
# SIP/VoIP Patterns
# =============================================================================

SIP_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # Asterisk
    (r"Asterisk PBX ([\d.]+)", "Asterisk", "Sangoma", None, r"([\d.]+)", 90),
    (r"Asterisk", "Asterisk", "Sangoma", None, None, 85),

    # FreePBX/Sangoma
    (r"FreePBX", "FreePBX", "Sangoma", None, None, 85),
    (r"Sangoma", "Sangoma PBX", "Sangoma", None, None, 85),

    # Cisco
    (r"Cisco.*CUCM", "Cisco CUCM", "Cisco", None, None, 95),
    (r"Cisco.*CallManager", "Cisco CallManager", "Cisco", None, None, 95),
    (r"Cisco.*SPA", "Cisco SPA", "Cisco", None, None, 90),

    # 3CX
    (r"3CX", "3CX", "3CX", None, None, 85),

    # Avaya
    (r"Avaya", "Avaya", "Avaya", None, None, 90),

    # Mitel
    (r"Mitel", "Mitel", "Mitel", None, None, 85),

    # Polycom
    (r"Polycom", "Polycom", "Poly", None, None, 90),

    # Yealink
    (r"Yealink", "Yealink", "Yealink", None, None, 90),

    # Grandstream
    (r"Grandstream", "Grandstream", "Grandstream", None, None, 85),

    # Kamailio
    (r"Kamailio", "Kamailio", None, "Linux", None, 85),

    # OpenSIPS
    (r"OpenSIPS", "OpenSIPS", None, "Linux", None, 85),

    # FreeSWITCH
    (r"FreeSWITCH", "FreeSWITCH", None, "Linux", None, 85),

    # Twilio
    (r"Twilio", "Twilio", "Twilio", None, None, 85),
]

# =============================================================================
# NTP Patterns
# =============================================================================

NTP_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    (r"ntpd ([\d.]+)", "ntpd", None, None, r"([\d.]+)", 80),
    (r"NTP.*openntpd", "OpenNTPD", "OpenBSD", None, None, 85),
    (r"chrony ([\d.]+)", "chrony", None, "Linux", r"([\d.]+)", 85),
    (r"Windows.*NTP", "Windows Time", "Microsoft", "Windows", None, 85),
    (r"Cisco.*NTP", "Cisco NTP", "Cisco", "IOS", None, 90),
]

# =============================================================================
# MQTT/IoT Protocol Patterns
# =============================================================================

MQTT_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    (r"Mosquitto ([\d.]+)", "Mosquitto", "Eclipse", None, r"([\d.]+)", 90),
    (r"Mosquitto", "Mosquitto", "Eclipse", None, None, 85),
    (r"EMQ X", "EMQ X", "EMQ", None, None, 85),
    (r"HiveMQ", "HiveMQ", "HiveMQ", None, None, 85),
    (r"VerneMQ", "VerneMQ", None, None, None, 80),
    (r"RabbitMQ.*MQTT", "RabbitMQ MQTT", "VMware", None, None, 85),
    (r"AWS IoT", "AWS IoT", "Amazon", None, None, 90),
    (r"Azure.*IoT", "Azure IoT Hub", "Microsoft", None, None, 90),
]

# =============================================================================
# Printer Protocol Patterns (IPP, PJL, etc.)
# =============================================================================

PRINTER_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # HP
    (r"HP.*LaserJet ([\w]+)", "HP LaserJet", "HP", None, None, 95),
    (r"HP.*OfficeJet", "HP OfficeJet", "HP", None, None, 95),
    (r"HP.*PageWide", "HP PageWide", "HP", None, None, 90),
    (r"HP.*DesignJet", "HP DesignJet", "HP", None, None, 90),
    (r"HP.*Color.*LaserJet", "HP Color LaserJet", "HP", None, None, 95),
    (r"HP Universal Printing", "HP UPD", "HP", None, None, 85),
    (r"@PJL.*HP", "HP Printer", "HP", None, None, 90),

    # Xerox
    (r"Xerox.*WorkCentre", "Xerox WorkCentre", "Xerox", None, None, 95),
    (r"Xerox.*Phaser", "Xerox Phaser", "Xerox", None, None, 95),
    (r"Xerox.*AltaLink", "Xerox AltaLink", "Xerox", None, None, 95),
    (r"Xerox.*VersaLink", "Xerox VersaLink", "Xerox", None, None, 95),
    (r"Fuji Xerox", "Fuji Xerox", "Fuji Xerox", None, None, 90),

    # Canon
    (r"Canon.*imageRUNNER", "Canon imageRUNNER", "Canon", None, None, 95),
    (r"Canon.*imageCLASS", "Canon imageCLASS", "Canon", None, None, 95),
    (r"Canon.*PIXMA", "Canon PIXMA", "Canon", None, None, 90),
    (r"Canon.*LBP", "Canon LBP", "Canon", None, None, 90),

    # Ricoh
    (r"RICOH.*Aficio", "Ricoh Aficio", "Ricoh", None, None, 95),
    (r"RICOH.*MP", "Ricoh MP", "Ricoh", None, None, 95),
    (r"RICOH.*SP", "Ricoh SP", "Ricoh", None, None, 90),

    # Konica Minolta
    (r"KONICA MINOLTA.*bizhub", "Konica Minolta bizhub", "Konica Minolta", None, None, 95),
    (r"KONICA MINOLTA", "Konica Minolta", "Konica Minolta", None, None, 90),

    # Brother
    (r"Brother.*MFC", "Brother MFC", "Brother", None, None, 95),
    (r"Brother.*HL", "Brother HL", "Brother", None, None, 95),
    (r"Brother.*DCP", "Brother DCP", "Brother", None, None, 90),

    # Epson
    (r"EPSON.*WorkForce", "Epson WorkForce", "Epson", None, None, 95),
    (r"EPSON.*EcoTank", "Epson EcoTank", "Epson", None, None, 90),
    (r"EPSON.*Expression", "Epson Expression", "Epson", None, None, 90),

    # Kyocera
    (r"KYOCERA.*TASKalfa", "Kyocera TASKalfa", "Kyocera", None, None, 95),
    (r"KYOCERA.*ECOSYS", "Kyocera ECOSYS", "Kyocera", None, None, 95),

    # Lexmark
    (r"Lexmark.*MS\d+", "Lexmark MS Series", "Lexmark", None, None, 90),
    (r"Lexmark.*MX\d+", "Lexmark MX Series", "Lexmark", None, None, 90),
    (r"Lexmark.*CS\d+", "Lexmark CS Series", "Lexmark", None, None, 90),
    (r"Lexmark.*CX\d+", "Lexmark CX Series", "Lexmark", None, None, 90),

    # Sharp
    (r"Sharp.*MX", "Sharp MX", "Sharp", None, None, 95),
    (r"Sharp.*BP", "Sharp BP", "Sharp", None, None, 90),

    # Toshiba
    (r"TOSHIBA.*e-STUDIO", "Toshiba e-STUDIO", "Toshiba", None, None, 95),

    # Dell
    (r"Dell.*Laser", "Dell Laser", "Dell", None, None, 90),
    (r"Dell.*Color", "Dell Color Printer", "Dell", None, None, 90),

    # OKI
    (r"OKI.*MC\d+", "OKI MC Series", "OKI", None, None, 90),
    (r"OKI.*C\d+", "OKI C Series", "OKI", None, None, 90),
]

# =============================================================================
# Gaming/Media Patterns
# =============================================================================

GAMING_MEDIA_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # Gaming consoles
    (r"PlayStation.*4", "PlayStation 4", "Sony", "PlayStation", None, 95),
    (r"PlayStation.*5", "PlayStation 5", "Sony", "PlayStation", None, 95),
    (r"Xbox.*One", "Xbox One", "Microsoft", "Xbox", None, 95),
    (r"Xbox.*Series", "Xbox Series X/S", "Microsoft", "Xbox", None, 95),
    (r"Nintendo.*Switch", "Nintendo Switch", "Nintendo", None, None, 95),

    # Streaming devices
    (r"Roku", "Roku", "Roku", None, None, 95),
    (r"Apple.*TV", "Apple TV", "Apple", "tvOS", None, 95),
    (r"Chromecast", "Chromecast", "Google", None, None, 95),
    (r"Fire.*TV", "Fire TV", "Amazon", "Fire OS", None, 95),
    (r"NVIDIA.*Shield", "NVIDIA Shield", "NVIDIA", "Android TV", None, 95),

    # Smart TVs
    (r"Samsung.*Smart.*TV", "Samsung Smart TV", "Samsung", "Tizen", None, 95),
    (r"LG.*Smart.*TV", "LG Smart TV", "LG", "webOS", None, 95),
    (r"Sony.*Bravia", "Sony Bravia", "Sony", "Android TV", None, 90),
    (r"Vizio", "Vizio", "Vizio", "SmartCast", None, 90),
    (r"TCL.*Roku", "TCL Roku TV", "TCL", "Roku", None, 90),
    (r"Hisense", "Hisense", "Hisense", None, None, 85),

    # Media servers
    (r"Plex Media Server", "Plex", None, None, None, 95),
    (r"Emby", "Emby", None, None, None, 90),
    (r"Jellyfin", "Jellyfin", None, None, None, 90),
    (r"Kodi", "Kodi", None, None, None, 90),
    (r"Universal Media Server", "Universal Media Server", None, None, None, 85),
    (r"Serviio", "Serviio", None, None, None, 80),

    # Audio
    (r"Sonos", "Sonos", "Sonos", None, None, 95),
    (r"HEOS", "Denon HEOS", "Denon", None, None, 90),
    (r"Bose", "Bose", "Bose", None, None, 90),
    (r"Harman.*Kardon", "Harman Kardon", "Harman", None, None, 85),
    (r"JBL.*Link", "JBL", "JBL", None, None, 85),
]

# =============================================================================
# Network Infrastructure Patterns (additional)
# =============================================================================

NETWORK_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # Access Points
    (r"Ubiquiti.*UniFi.*AP", "UniFi AP", "Ubiquiti", None, None, 95),
    (r"Aruba.*AP", "Aruba AP", "HPE", "ArubaOS", None, 95),
    (r"Cisco.*AIR-", "Cisco Aironet", "Cisco", None, None, 95),
    (r"Cisco.*Meraki.*MR", "Meraki AP", "Cisco Meraki", None, None, 95),
    (r"Ruckus", "Ruckus", "CommScope", None, None, 90),
    (r"Cambium", "Cambium", "Cambium", None, None, 85),
    (r"EnGenius", "EnGenius", "EnGenius", None, None, 85),

    # Routers (additional)
    (r"ASUS.*Router", "ASUS Router", "ASUS", "ASUSWRT", None, 90),
    (r"TP-Link.*Archer", "TP-Link Archer", "TP-Link", None, None, 90),
    (r"Netgear.*Nighthawk", "Netgear Nighthawk", "Netgear", None, None, 90),
    (r"Linksys.*Velop", "Linksys Velop", "Linksys", None, None, 90),
    (r"eero", "eero", "Amazon", None, None, 90),
    (r"Google.*Wifi", "Google Wifi", "Google", None, None, 90),
    (r"Orbi", "Netgear Orbi", "Netgear", None, None, 90),

    # Switches (additional)
    (r"Netgear.*GS\d+", "Netgear Switch", "Netgear", None, None, 90),
    (r"TP-Link.*TL-SG", "TP-Link Switch", "TP-Link", None, None, 85),
    (r"D-Link.*DGS", "D-Link Switch", "D-Link", None, None, 85),
    (r"ZyXEL.*GS\d+", "ZyXEL Switch", "ZyXEL", None, None, 85),

    # Load Balancers/ADC
    (r"Citrix.*NetScaler", "Citrix ADC", "Citrix", None, None, 95),
    (r"F5.*BIG-IP", "F5 BIG-IP", "F5", None, None, 95),
    (r"A10.*Thunder", "A10 Thunder", "A10", None, None, 95),
    (r"Kemp", "Kemp LoadMaster", "Kemp", None, None, 90),
    (r"HAProxy", "HAProxy", None, None, None, 85),
    (r"Nginx.*Plus", "NGINX Plus", "F5", None, None, 90),

    # SD-WAN
    (r"Viptela", "Cisco Viptela", "Cisco", None, None, 95),
    (r"VeloCloud", "VMware SD-WAN", "VMware", None, None, 95),
    (r"Silver Peak", "Silver Peak", "HPE", None, None, 90),
    (r"Meraki.*MX", "Meraki MX", "Cisco Meraki", None, None, 95),
]

# =============================================================================
# Storage System Patterns (additional)
# =============================================================================

STORAGE_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # Enterprise Storage
    (r"NetApp.*FAS", "NetApp FAS", "NetApp", "ONTAP", None, 95),
    (r"NetApp.*AFF", "NetApp AFF", "NetApp", "ONTAP", None, 95),
    (r"Dell EMC.*Unity", "Dell EMC Unity", "Dell EMC", None, None, 95),
    (r"Dell EMC.*PowerStore", "Dell EMC PowerStore", "Dell EMC", None, None, 95),
    (r"Dell EMC.*VNX", "Dell EMC VNX", "Dell EMC", None, None, 95),
    (r"Pure Storage.*FlashArray", "Pure FlashArray", "Pure Storage", None, None, 95),
    (r"HPE.*Nimble", "HPE Nimble", "HPE", None, None, 95),
    (r"HPE.*Primera", "HPE Primera", "HPE", None, None, 95),
    (r"HPE.*3PAR", "HPE 3PAR", "HPE", None, None, 95),
    (r"IBM.*FlashSystem", "IBM FlashSystem", "IBM", None, None, 95),
    (r"IBM.*Storwize", "IBM Storwize", "IBM", None, None, 95),
    (r"Hitachi.*VSP", "Hitachi VSP", "Hitachi", None, None, 95),

    # NAS (additional)
    (r"Synology.*DS\d+", "Synology DiskStation", "Synology", "DSM", None, 95),
    (r"Synology.*RS\d+", "Synology RackStation", "Synology", "DSM", None, 95),
    (r"QNAP.*TS-\d+", "QNAP TurboNAS", "QNAP", "QTS", None, 95),
    (r"QNAP.*TVS", "QNAP TurboNAS", "QNAP", "QTS", None, 95),
    (r"Buffalo.*TeraStation", "Buffalo TeraStation", "Buffalo", None, None, 90),
    (r"Asustor", "Asustor NAS", "Asustor", "ADM", None, 90),
    (r"Drobo", "Drobo", "Drobo", None, None, 85),
    (r"ReadyNAS", "Netgear ReadyNAS", "Netgear", None, None, 90),
    (r"WD.*My.*Cloud", "WD My Cloud", "Western Digital", None, None, 90),
    (r"Seagate.*NAS", "Seagate NAS", "Seagate", None, None, 85),

    # TrueNAS/FreeNAS
    (r"TrueNAS.*SCALE", "TrueNAS SCALE", "iXsystems", "TrueNAS SCALE", None, 95),
    (r"TrueNAS.*CORE", "TrueNAS CORE", "iXsystems", "TrueNAS CORE", None, 95),
    (r"FreeNAS", "FreeNAS", "iXsystems", "FreeNAS", None, 90),

    # Unraid
    (r"Unraid", "Unraid", "Lime Technology", "Unraid", None, 90),

    # OpenMediaVault
    (r"OpenMediaVault", "OpenMediaVault", None, "Linux (Debian)", None, 85),
]

# =============================================================================
# Backup/DR Patterns
# =============================================================================

BACKUP_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # Veeam
    (r"Veeam", "Veeam", "Veeam", "Windows", None, 95),

    # Commvault
    (r"Commvault", "Commvault", "Commvault", None, None, 95),

    # Veritas/Symantec
    (r"Veritas.*NetBackup", "Veritas NetBackup", "Veritas", None, None, 95),
    (r"Veritas.*Backup Exec", "Veritas Backup Exec", "Veritas", "Windows", None, 95),

    # Dell EMC
    (r"Dell EMC.*Avamar", "Dell EMC Avamar", "Dell EMC", None, None, 95),
    (r"Dell EMC.*Data Domain", "Dell EMC Data Domain", "Dell EMC", None, None, 95),

    # IBM
    (r"IBM.*Spectrum.*Protect", "IBM Spectrum Protect", "IBM", None, None, 95),
    (r"Tivoli Storage Manager", "IBM TSM", "IBM", None, None, 90),

    # Rubrik
    (r"Rubrik", "Rubrik", "Rubrik", None, None, 95),

    # Cohesity
    (r"Cohesity", "Cohesity", "Cohesity", None, None, 95),

    # Acronis
    (r"Acronis", "Acronis", "Acronis", None, None, 90),

    # Nakivo
    (r"NAKIVO", "Nakivo", "Nakivo", None, None, 90),

    # Altaro (now Hornetsecurity)
    (r"Altaro", "Altaro", "Hornetsecurity", None, None, 85),

    # QNAP/Synology Backup
    (r"Hyper Backup", "Synology Hyper Backup", "Synology", "DSM", None, 90),
    (r"QNAP.*Backup", "QNAP Backup", "QNAP", "QTS", None, 85),

    # Barracuda
    (r"Barracuda.*Backup", "Barracuda Backup", "Barracuda", None, None, 90),

    # Datto
    (r"Datto", "Datto", "Kaseya", None, None, 90),

    # Zerto
    (r"Zerto", "Zerto", "HPE", None, None, 95),

    # Proxmox Backup
    (r"Proxmox.*Backup", "Proxmox Backup Server", "Proxmox", "Linux", None, 90),
]

# =============================================================================
# IoT Device Patterns
# =============================================================================

IOT_HTTP_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int, str]] = [
    # IP Cameras
    (r"Hikvision-Webs", "Hikvision Camera", "Hikvision", None, None, 95, "ip_camera"),
    (r"DNVRS-Webs", "Dahua Camera", "Dahua", None, None, 95, "ip_camera"),
    (r"Dahua", "Dahua Camera", "Dahua", None, None, 90, "ip_camera"),
    (r"AXIS", "Axis Camera", "Axis", None, None, 90, "ip_camera"),
    (r"Foscam", "Foscam Camera", "Foscam", None, None, 90, "ip_camera"),
    (r"Amcrest", "Amcrest Camera", "Amcrest", None, None, 90, "ip_camera"),
    (r"Reolink", "Reolink Camera", "Reolink", None, None, 90, "ip_camera"),
    (r"Vivotek", "Vivotek Camera", "Vivotek", None, None, 90, "ip_camera"),
    (r"Ubiquiti.*UniFi.*Video", "UniFi Video", "Ubiquiti", None, None, 90, "ip_camera"),
    (r"FLIR", "FLIR Camera", "FLIR", None, None, 85, "ip_camera"),
    (r"Mobotix", "Mobotix Camera", "Mobotix", None, None, 90, "ip_camera"),
    (r"Avigilon", "Avigilon Camera", "Avigilon", None, None, 90, "ip_camera"),
    (r"Hanwha.*Wisenet", "Hanwha Camera", "Hanwha", None, None, 90, "ip_camera"),
    (r"Bosch.*Video", "Bosch Camera", "Bosch", None, None, 85, "ip_camera"),

    # Smart Home Hubs
    (r"Philips-hue", "Hue Bridge", "Philips", None, None, 95, "smart_home"),
    (r"SmartThings", "SmartThings Hub", "Samsung", None, None, 90, "home_hub"),
    (r"Home Assistant", "Home Assistant", None, None, None, 90, "home_automation"),
    (r"OpenHAB", "openHAB", None, None, None, 90, "home_automation"),
    (r"Domoticz", "Domoticz", None, None, None, 85, "home_automation"),
    (r"Vera", "Vera Controller", "Vera", None, None, 85, "home_hub"),
    (r"Hubitat", "Hubitat Elevation", "Hubitat", None, None, 90, "home_hub"),
    (r"Wink", "Wink Hub", "Wink", None, None, 85, "home_hub"),
    (r"Insteon", "Insteon Hub", "Insteon", None, None, 85, "home_hub"),
    (r"Homey", "Homey", "Athom", None, None, 85, "home_hub"),

    # Smart Thermostats
    (r"ecobee", "ecobee Thermostat", "ecobee", None, None, 90, "thermostat"),
    (r"Nest", "Nest Thermostat", "Google", None, None, 90, "thermostat"),
    (r"Honeywell.*thermostat", "Honeywell Thermostat", "Honeywell", None, None, 85, "thermostat"),
    (r"Emerson.*Sensi", "Sensi Thermostat", "Emerson", None, None, 85, "thermostat"),

    # Smart Doorbells
    (r"Ring", "Ring Doorbell", "Ring", None, None, 90, "doorbell"),
    (r"Nest.*Hello", "Nest Hello", "Google", None, None, 90, "doorbell"),
    (r"Eufy.*Doorbell", "Eufy Doorbell", "Anker", None, None, 85, "doorbell"),
    (r"Arlo.*Doorbell", "Arlo Doorbell", "Arlo", None, None, 85, "doorbell"),

    # Smart Speakers
    (r"Amazon.*Echo", "Amazon Echo", "Amazon", None, None, 90, "smart_speaker"),
    (r"Google.*Home", "Google Home", "Google", None, None, 90, "smart_speaker"),
    (r"Sonos", "Sonos Speaker", "Sonos", None, None, 90, "smart_speaker"),
    (r"HomePod", "HomePod", "Apple", None, None, 90, "smart_speaker"),
    (r"Bose.*SoundTouch", "Bose SoundTouch", "Bose", None, None, 85, "smart_speaker"),

    # IoT Gateways
    (r"MultiTech", "MultiTech Gateway", "MultiTech", None, None, 85, "iot_gateway"),
    (r"Digi", "Digi Gateway", "Digi", None, None, 85, "iot_gateway"),
    (r"Sierra.*Wireless", "Sierra Wireless Gateway", "Sierra Wireless", None, None, 85, "iot_gateway"),
    (r"Kerlink", "Kerlink Gateway", "Kerlink", None, None, 85, "iot_gateway"),
    (r"RAK.*Wireless", "RAK Gateway", "RAKwireless", None, None, 80, "iot_gateway"),

    # Smart Plugs / Power
    (r"TP-Link.*Kasa", "Kasa Smart Plug", "TP-Link", None, None, 85, "smart_plug"),
    (r"Wemo", "Wemo", "Belkin", None, None, 85, "smart_plug"),
    (r"Tasmota", "Tasmota", None, None, None, 80, "smart_plug"),
    (r"Shelly", "Shelly", "Shelly", None, None, 85, "smart_plug"),
    (r"Tuya", "Tuya Device", "Tuya", None, None, 80, "iot"),

    # Smart Lighting
    (r"LIFX", "LIFX Light", "LIFX", None, None, 85, "smart_lighting"),
    (r"Nanoleaf", "Nanoleaf", "Nanoleaf", None, None, 85, "smart_lighting"),
    (r"Lutron", "Lutron", "Lutron", None, None, 85, "smart_lighting"),
    (r"Yeelight", "Yeelight", "Yeelight", None, None, 80, "smart_lighting"),

    # Smart Locks
    (r"August", "August Lock", "August", None, None, 85, "smart_lock"),
    (r"Schlage.*Connect", "Schlage Connect", "Schlage", None, None, 85, "smart_lock"),
    (r"Yale.*Smart", "Yale Smart Lock", "Yale", None, None, 85, "smart_lock"),
    (r"Kwikset.*Smart", "Kwikset Smart Lock", "Kwikset", None, None, 85, "smart_lock"),
]

# =============================================================================
# SCADA/ICS Patterns (Industrial Control Systems)
# =============================================================================

SCADA_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int, str]] = [
    # Siemens
    (r"Siemens.*S7", "Siemens S7 PLC", "Siemens", None, None, 95, "plc"),
    (r"Siemens.*SIMATIC", "Siemens SIMATIC", "Siemens", None, None, 95, "plc"),
    (r"Siemens.*SCALANCE", "Siemens SCALANCE", "Siemens", None, None, 90, "industrial_switch"),
    (r"Siemens.*WinCC", "Siemens WinCC", "Siemens", "Windows", None, 95, "hmi"),
    (r"Siemens.*TIA.*Portal", "TIA Portal", "Siemens", "Windows", None, 90, "scada_server"),
    (r"RUGGEDCOM", "Siemens RUGGEDCOM", "Siemens", None, None, 90, "industrial_router"),
    (r"Siemens.*SINEMA", "Siemens SINEMA", "Siemens", None, None, 85, "scada_server"),

    # Schneider Electric
    (r"Schneider.*Modicon", "Schneider Modicon PLC", "Schneider Electric", None, None, 95, "plc"),
    (r"Schneider.*M340", "Schneider M340", "Schneider Electric", None, None, 95, "plc"),
    (r"Schneider.*M580", "Schneider M580", "Schneider Electric", None, None, 95, "plc"),
    (r"Schneider.*Unity.*Pro", "Unity Pro", "Schneider Electric", "Windows", None, 90, "scada_server"),
    (r"Schneider.*Vijeo", "Vijeo HMI", "Schneider Electric", None, None, 90, "hmi"),
    (r"Schneider.*Citect", "CitectSCADA", "Schneider Electric", "Windows", None, 95, "scada_server"),
    (r"Schneider.*ClearSCADA", "ClearSCADA", "Schneider Electric", "Windows", None, 95, "scada_server"),
    (r"Wonderware", "Wonderware", "Schneider Electric", "Windows", None, 95, "scada_server"),
    (r"ION.*Meter", "ION Power Meter", "Schneider Electric", None, None, 85, "power_meter"),

    # Rockwell/Allen-Bradley
    (r"Allen-Bradley", "Allen-Bradley PLC", "Rockwell", None, None, 95, "plc"),
    (r"Rockwell.*ControlLogix", "ControlLogix", "Rockwell", None, None, 95, "plc"),
    (r"Rockwell.*CompactLogix", "CompactLogix", "Rockwell", None, None, 95, "plc"),
    (r"Rockwell.*MicroLogix", "MicroLogix", "Rockwell", None, None, 95, "plc"),
    (r"FactoryTalk", "FactoryTalk", "Rockwell", "Windows", None, 90, "scada_server"),
    (r"RSView", "RSView", "Rockwell", "Windows", None, 90, "hmi"),
    (r"RSLinx", "RSLinx", "Rockwell", "Windows", None, 85, "scada_server"),
    (r"Studio.*5000", "Studio 5000", "Rockwell", "Windows", None, 90, "scada_server"),
    (r"Stratix", "Stratix Switch", "Rockwell", None, None, 85, "industrial_switch"),

    # ABB
    (r"ABB.*AC500", "ABB AC500 PLC", "ABB", None, None, 95, "plc"),
    (r"ABB.*AC800", "ABB AC800", "ABB", None, None, 95, "dcs"),
    (r"ABB.*Freelance", "ABB Freelance", "ABB", None, None, 90, "dcs"),
    (r"ABB.*Symphony", "ABB Symphony", "ABB", None, None, 90, "dcs"),
    (r"ABB.*800xA", "ABB 800xA", "ABB", "Windows", None, 95, "dcs"),
    (r"ABB.*Ability", "ABB Ability", "ABB", None, None, 85, "scada_server"),

    # GE
    (r"GE.*Fanuc", "GE Fanuc PLC", "GE", None, None, 95, "plc"),
    (r"GE.*PACSystems", "GE PACSystems", "GE", None, None, 95, "plc"),
    (r"GE.*iFIX", "GE iFIX", "GE", "Windows", None, 95, "scada_server"),
    (r"GE.*Cimplicity", "GE Cimplicity", "GE", "Windows", None, 95, "hmi"),
    (r"GE.*Proficy", "GE Proficy", "GE", "Windows", None, 90, "scada_server"),
    (r"GE.*Mark.*VI", "GE Mark VI", "GE", None, None, 90, "dcs"),

    # Honeywell
    (r"Honeywell.*Experion", "Honeywell Experion", "Honeywell", "Windows", None, 95, "dcs"),
    (r"Honeywell.*TDC", "Honeywell TDC", "Honeywell", None, None, 95, "dcs"),
    (r"Honeywell.*HC900", "Honeywell HC900", "Honeywell", None, None, 90, "plc"),
    (r"Honeywell.*Uniformance", "Honeywell Uniformance", "Honeywell", "Windows", None, 90, "scada_server"),

    # Emerson/Fisher
    (r"Emerson.*DeltaV", "Emerson DeltaV", "Emerson", "Windows", None, 95, "dcs"),
    (r"Emerson.*Ovation", "Emerson Ovation", "Emerson", "Windows", None, 95, "dcs"),
    (r"Fisher.*ROC", "Fisher ROC", "Emerson", None, None, 90, "rtu"),
    (r"Emerson.*ROC", "Emerson ROC RTU", "Emerson", None, None, 90, "rtu"),

    # Yokogawa
    (r"Yokogawa.*CENTUM", "Yokogawa CENTUM", "Yokogawa", None, None, 95, "dcs"),
    (r"Yokogawa.*ProSafe", "Yokogawa ProSafe", "Yokogawa", None, None, 95, "plc"),
    (r"Yokogawa.*STARDOM", "Yokogawa STARDOM", "Yokogawa", None, None, 90, "rtu"),

    # Mitsubishi
    (r"Mitsubishi.*MELSEC", "Mitsubishi MELSEC", "Mitsubishi", None, None, 95, "plc"),
    (r"Mitsubishi.*iQ-R", "Mitsubishi iQ-R", "Mitsubishi", None, None, 95, "plc"),
    (r"Mitsubishi.*GOT", "Mitsubishi GOT HMI", "Mitsubishi", None, None, 90, "hmi"),
    (r"Mitsubishi.*MC.*Protocol", "Mitsubishi MC Protocol", "Mitsubishi", None, None, 85, "plc"),

    # Omron
    (r"Omron.*NX", "Omron NX PLC", "Omron", None, None, 95, "plc"),
    (r"Omron.*NJ", "Omron NJ PLC", "Omron", None, None, 95, "plc"),
    (r"Omron.*CJ", "Omron CJ PLC", "Omron", None, None, 95, "plc"),
    (r"Omron.*Sysmac", "Omron Sysmac", "Omron", None, None, 90, "plc"),

    # Beckhoff
    (r"Beckhoff.*TwinCAT", "Beckhoff TwinCAT", "Beckhoff", "Windows", None, 95, "plc"),
    (r"Beckhoff.*CX", "Beckhoff CX", "Beckhoff", None, None, 90, "plc"),
    (r"Beckhoff.*EtherCAT", "Beckhoff EtherCAT", "Beckhoff", None, None, 85, "plc"),

    # Phoenix Contact
    (r"Phoenix.*Contact.*PLCnext", "Phoenix PLCnext", "Phoenix Contact", None, None, 90, "plc"),
    (r"Phoenix.*Contact.*ILC", "Phoenix ILC", "Phoenix Contact", None, None, 90, "plc"),

    # WAGO
    (r"WAGO.*PFC", "WAGO PFC", "WAGO", None, None, 90, "plc"),
    (r"WAGO.*750", "WAGO 750 Series", "WAGO", None, None, 85, "plc"),

    # Building Automation
    (r"BACnet", "BACnet Controller", None, None, None, 80, "building_automation"),
    (r"Tridium.*Niagara", "Tridium Niagara", "Tridium", None, None, 90, "building_automation"),
    (r"Johnson.*Controls.*Metasys", "Metasys", "Johnson Controls", None, None, 90, "building_automation"),
    (r"Schneider.*TAC", "TAC Vista", "Schneider Electric", None, None, 85, "building_automation"),
    (r"Carrier.*i-Vu", "Carrier i-Vu", "Carrier", None, None, 85, "building_automation"),
    (r"Trane.*Tracer", "Trane Tracer", "Trane", None, None, 85, "building_automation"),
    (r"KNX", "KNX Controller", None, None, None, 80, "building_automation"),
    (r"LON", "LonWorks Controller", None, None, None, 75, "building_automation"),

    # Industrial Switches
    (r"Moxa", "Moxa Industrial", "Moxa", None, None, 90, "industrial_switch"),
    (r"Hirschmann", "Hirschmann Switch", "Hirschmann", None, None, 90, "industrial_switch"),
    (r"Belden.*Industrial", "Belden Industrial", "Belden", None, None, 85, "industrial_switch"),
    (r"Westermo", "Westermo", "Westermo", None, None, 85, "industrial_switch"),
    (r"Red Lion", "Red Lion", "Red Lion", None, None, 85, "industrial_switch"),
    (r"Advantech.*EKI", "Advantech EKI", "Advantech", None, None, 85, "industrial_switch"),

    # Motor Drives / VFD
    (r"ABB.*ACS", "ABB Drive", "ABB", None, None, 85, "motor_drive"),
    (r"Siemens.*SINAMICS", "Siemens SINAMICS", "Siemens", None, None, 90, "motor_drive"),
    (r"Schneider.*Altivar", "Schneider Altivar", "Schneider Electric", None, None, 85, "motor_drive"),
    (r"Danfoss.*VLT", "Danfoss VLT", "Danfoss", None, None, 85, "motor_drive"),
    (r"Yaskawa.*Drive", "Yaskawa Drive", "Yaskawa", None, None, 85, "motor_drive"),

    # Power Meters / Energy
    (r"SEL.*Relay", "SEL Relay", "SEL", None, None, 90, "ied"),
    (r"GE.*Multilin", "GE Multilin", "GE", None, None, 90, "ied"),
    (r"ABB.*Relion", "ABB Relion", "ABB", None, None, 90, "ied"),
]

# =============================================================================
# Virtualization Patterns
# =============================================================================

VIRTUALIZATION_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int, str]] = [
    # VMware
    (r"VMware.*ESXi[/ ]?([\d.]+)?", "VMware ESXi", "VMware", "ESXi", r"([\d.]+)", 95, "esxi"),
    (r"vCenter.*Server", "vCenter Server", "VMware", "vCenter", None, 95, "vcenter"),
    (r"vSphere.*Client", "vSphere Client", "VMware", "vSphere", None, 90, "vcenter"),
    (r"VMware.*Workstation", "VMware Workstation", "VMware", "Windows", None, 85, "hypervisor"),
    (r"VMware.*Fusion", "VMware Fusion", "VMware", "macOS", None, 85, "hypervisor"),
    (r"VMware.*vRealize", "vRealize Suite", "VMware", None, None, 85, "vcenter"),
    (r"VMware.*NSX", "VMware NSX", "VMware", None, None, 90, "virtual_machine"),
    (r"VMware.*Horizon", "VMware Horizon", "VMware", None, None, 85, "vcenter"),

    # Proxmox
    (r"Proxmox.*VE[/ ]?([\d.]+)?", "Proxmox VE", "Proxmox", "Proxmox VE", r"([\d.]+)", 95, "proxmox"),
    (r"pve-manager", "Proxmox VE", "Proxmox", "Proxmox VE", None, 90, "proxmox"),
    (r"Proxmox.*Backup", "Proxmox Backup Server", "Proxmox", "Proxmox", None, 85, "backup_appliance"),

    # Microsoft Hyper-V
    (r"Hyper-V", "Hyper-V", "Microsoft", "Windows Server", None, 95, "hyper_v"),
    (r"Windows.*Virtual.*Machine", "Hyper-V VM", "Microsoft", "Windows", None, 80, "virtual_machine"),
    (r"SCVMM", "System Center VMM", "Microsoft", "Windows Server", None, 90, "hyper_v"),

    # Citrix
    (r"Citrix.*XenServer", "Citrix XenServer", "Citrix", "XenServer", None, 95, "xen"),
    (r"Citrix.*Hypervisor", "Citrix Hypervisor", "Citrix", "XenServer", None, 95, "xen"),
    (r"XenProject", "Xen Hypervisor", "Xen Project", "Xen", None, 90, "xen"),
    (r"Citrix.*Virtual.*Apps", "Citrix Virtual Apps", "Citrix", None, None, 85, "hypervisor"),

    # Oracle
    (r"Oracle.*VirtualBox", "VirtualBox", "Oracle", None, None, 85, "hypervisor"),
    (r"Oracle.*VM.*Server", "Oracle VM Server", "Oracle", "Oracle Linux", None, 90, "hypervisor"),

    # KVM/QEMU
    (r"QEMU", "QEMU/KVM", None, "Linux", None, 80, "kvm_host"),
    (r"libvirt", "libvirt", None, "Linux", None, 80, "kvm_host"),
    (r"virt-manager", "virt-manager", None, "Linux", None, 75, "kvm_host"),
    (r"oVirt", "oVirt", "Red Hat", "Linux", None, 85, "kvm_host"),
    (r"Red Hat.*Virtualization", "RHV", "Red Hat", "RHEL", None, 90, "kvm_host"),

    # Nutanix
    (r"Nutanix.*AHV", "Nutanix AHV", "Nutanix", "AHV", None, 95, "hypervisor"),
    (r"Nutanix.*Prism", "Nutanix Prism", "Nutanix", None, None, 90, "hypervisor"),

    # OpenStack
    (r"OpenStack", "OpenStack", None, "Linux", None, 85, "kvm_host"),
    (r"Nova", "OpenStack Nova", None, "Linux", None, 80, "kvm_host"),
]

# =============================================================================
# Container & Orchestration Patterns
# =============================================================================

CONTAINER_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int, str]] = [
    # Docker
    (r"Docker[/ ]?([\d.]+)?", "Docker", "Docker", None, r"([\d.]+)", 90, "docker_host"),
    (r"docker-engine", "Docker Engine", "Docker", None, None, 85, "docker_host"),
    (r"containerd", "containerd", None, None, None, 80, "container_host"),
    (r"Portainer", "Portainer", "Portainer", None, None, 85, "docker_host"),
    (r"Rancher[/ ]?([\d.]+)?", "Rancher", "SUSE", None, r"([\d.]+)", 90, "container_host"),

    # Kubernetes
    (r"Kubernetes", "Kubernetes", "CNCF", None, None, 90, "kubernetes_node"),
    (r"kube-apiserver", "Kubernetes API Server", "CNCF", None, None, 95, "kubernetes_master"),
    (r"kubelet", "Kubernetes Node", "CNCF", None, None, 90, "kubernetes_node"),
    (r"kubectl", "kubectl", "CNCF", None, None, 80, "kubernetes_master"),
    (r"etcd", "etcd", "CNCF", None, None, 85, "kubernetes_master"),
    (r"Helm", "Helm", "CNCF", None, None, 75, "kubernetes_master"),

    # OpenShift
    (r"OpenShift", "OpenShift", "Red Hat", None, None, 90, "openshift"),
    (r"OKD", "OKD", "Red Hat", None, None, 85, "openshift"),

    # Container Registries
    (r"Harbor[/ ]?([\d.]+)?", "Harbor Registry", "VMware", None, r"([\d.]+)", 90, "container_registry"),
    (r"Docker.*Registry", "Docker Registry", "Docker", None, None, 85, "container_registry"),
    (r"Nexus.*Repository", "Nexus Repository", "Sonatype", None, None, 85, "container_registry"),
    (r"Artifactory", "JFrog Artifactory", "JFrog", None, None, 85, "container_registry"),
    (r"Quay", "Quay Registry", "Red Hat", None, None, 85, "container_registry"),
    (r"GitLab.*Container.*Registry", "GitLab Registry", "GitLab", None, None, 80, "container_registry"),

    # Service Mesh
    (r"Istio", "Istio", "CNCF", None, None, 85, "container"),
    (r"Envoy", "Envoy Proxy", "CNCF", None, None, 80, "container"),
    (r"Linkerd", "Linkerd", "CNCF", None, None, 80, "container"),

    # Container Runtimes
    (r"CRI-O", "CRI-O", "CNCF", None, None, 85, "container_host"),
    (r"runc", "runc", None, None, None, 75, "container_host"),
    (r"Podman", "Podman", "Red Hat", None, None, 85, "container_host"),
    (r"LXC", "LXC", None, "Linux", None, 80, "container_host"),
    (r"LXD", "LXD", "Canonical", "Linux", None, 85, "container_host"),

    # Container Management
    (r"Nomad", "HashiCorp Nomad", "HashiCorp", None, None, 85, "container_host"),
    (r"Docker.*Swarm", "Docker Swarm", "Docker", None, None, 85, "docker_host"),
    (r"Mesos", "Apache Mesos", "Apache", None, None, 80, "container_host"),
    (r"Marathon", "Marathon", "Mesosphere", None, None, 80, "container_host"),
]

# =============================================================================
# Web Application & Service Patterns
# =============================================================================

WEBAPP_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int, str]] = [
    # Application Servers
    (r"Apache.*Tomcat[/ ]?([\d.]+)?", "Apache Tomcat", "Apache", None, r"([\d.]+)", 85, "application_server"),
    (r"JBoss[/ ]?([\d.]+)?", "JBoss/WildFly", "Red Hat", None, r"([\d.]+)", 85, "application_server"),
    (r"WildFly[/ ]?([\d.]+)?", "WildFly", "Red Hat", None, r"([\d.]+)", 85, "application_server"),
    (r"GlassFish", "GlassFish", "Eclipse", None, None, 80, "application_server"),
    (r"WebLogic", "WebLogic Server", "Oracle", None, None, 90, "application_server"),
    (r"WebSphere", "WebSphere", "IBM", None, None, 90, "application_server"),
    (r"Jetty[/ ]?([\d.]+)?", "Jetty", "Eclipse", None, r"([\d.]+)", 80, "application_server"),
    (r"Undertow", "Undertow", "Red Hat", None, None, 75, "application_server"),
    (r"Payara", "Payara Server", "Payara", None, None, 80, "application_server"),

    # Reverse Proxy / Load Balancer
    (r"HAProxy[/ ]?([\d.]+)?", "HAProxy", "HAProxy", None, r"([\d.]+)", 90, "load_balancer"),
    (r"Traefik[/ ]?([\d.]+)?", "Traefik", "Traefik Labs", None, r"([\d.]+)", 85, "reverse_proxy"),
    (r"Envoy", "Envoy Proxy", "CNCF", None, None, 80, "reverse_proxy"),
    (r"Varnish", "Varnish Cache", "Varnish", None, None, 85, "reverse_proxy"),
    (r"Squid[/ ]?([\d.]+)?", "Squid Proxy", None, None, r"([\d.]+)", 85, "proxy"),
    (r"F5.*BIG-IP", "F5 BIG-IP", "F5", None, None, 95, "load_balancer"),
    (r"Citrix.*ADC", "Citrix ADC", "Citrix", None, None, 95, "load_balancer"),
    (r"NetScaler", "NetScaler", "Citrix", None, None, 95, "load_balancer"),
    (r"A10.*Thunder", "A10 Thunder", "A10 Networks", None, None, 90, "load_balancer"),
    (r"Kemp", "Kemp LoadMaster", "Kemp", None, None, 85, "load_balancer"),

    # API Gateways
    (r"Kong[/ ]?([\d.]+)?", "Kong Gateway", "Kong", None, r"([\d.]+)", 90, "api_gateway"),
    (r"Tyk", "Tyk Gateway", "Tyk", None, None, 85, "api_gateway"),
    (r"Apigee", "Apigee", "Google", None, None, 90, "api_gateway"),
    (r"AWS.*API.*Gateway", "AWS API Gateway", "Amazon", None, None, 85, "api_gateway"),
    (r"Azure.*API.*Management", "Azure API Management", "Microsoft", None, None, 85, "api_gateway"),
    (r"MuleSoft", "MuleSoft", "Salesforce", None, None, 85, "api_gateway"),
    (r"WSO2", "WSO2 Gateway", "WSO2", None, None, 80, "api_gateway"),
    (r"3scale", "3scale", "Red Hat", None, None, 80, "api_gateway"),

    # Web Application Firewalls
    (r"ModSecurity", "ModSecurity WAF", None, None, None, 85, "waf"),
    (r"Cloudflare", "Cloudflare WAF", "Cloudflare", None, None, 90, "waf"),
    (r"AWS.*WAF", "AWS WAF", "Amazon", None, None, 85, "waf"),
    (r"Imperva.*WAF", "Imperva WAF", "Imperva", None, None, 90, "waf"),
    (r"Akamai.*Kona", "Akamai Kona WAF", "Akamai", None, None, 90, "waf"),
    (r"Barracuda.*WAF", "Barracuda WAF", "Barracuda", None, None, 85, "waf"),
    (r"Fortinet.*FortiWeb", "FortiWeb WAF", "Fortinet", None, None, 90, "waf"),

    # Python Frameworks
    (r"Django[/ ]?([\d.]+)?", "Django", None, None, r"([\d.]+)", 80, "web_server"),
    (r"Flask[/ ]?([\d.]+)?", "Flask", None, None, r"([\d.]+)", 75, "web_server"),
    (r"FastAPI", "FastAPI", None, None, None, 75, "web_server"),
    (r"Tornado", "Tornado", None, None, None, 70, "web_server"),
    (r"Sanic", "Sanic", None, None, None, 70, "web_server"),

    # Ruby
    (r"Puma[/ ]?([\d.]+)?", "Puma", None, None, r"([\d.]+)", 75, "web_server"),
    (r"Unicorn", "Unicorn", None, None, None, 70, "web_server"),
    (r"Passenger", "Phusion Passenger", "Phusion", None, None, 75, "web_server"),

    # Node.js
    (r"Express[/ ]?([\d.]+)?", "Express.js", None, None, r"([\d.]+)", 70, "web_server"),
    (r"Fastify", "Fastify", None, None, None, 70, "web_server"),
    (r"Koa", "Koa.js", None, None, None, 70, "web_server"),
    (r"NestJS", "NestJS", None, None, None, 75, "web_server"),
    (r"Next\.js", "Next.js", "Vercel", None, None, 75, "web_server"),
    (r"Nuxt", "Nuxt.js", None, None, None, 75, "web_server"),

    # PHP
    (r"PHP[/ ]?([\d.]+)?", "PHP", None, None, r"([\d.]+)", 70, "web_server"),
    (r"Laravel", "Laravel", None, None, None, 70, "web_server"),
    (r"Symfony", "Symfony", None, None, None, 70, "web_server"),
    (r"WordPress", "WordPress", "Automattic", None, None, 80, "web_server"),
    (r"Drupal", "Drupal", None, None, None, 75, "web_server"),
    (r"Joomla", "Joomla", None, None, None, 75, "web_server"),
    (r"Magento", "Magento", "Adobe", None, None, 80, "web_server"),

    # .NET
    (r"ASP\.NET[/ ]?([\d.]+)?", "ASP.NET", "Microsoft", "Windows", r"([\d.]+)", 85, "web_server"),
    (r"Kestrel", "Kestrel", "Microsoft", None, None, 80, "web_server"),

    # Go
    (r"Go-http-client", "Go HTTP", None, None, None, 65, "web_server"),
    (r"Gin", "Gin Framework", None, None, None, 70, "web_server"),
    (r"Echo", "Echo Framework", None, None, None, 70, "web_server"),

    # CDN
    (r"Akamai", "Akamai CDN", "Akamai", None, None, 85, "cdn_node"),
    (r"CloudFront", "Amazon CloudFront", "Amazon", None, None, 85, "cdn_node"),
    (r"Fastly", "Fastly CDN", "Fastly", None, None, 85, "cdn_node"),
    (r"Cloudflare", "Cloudflare CDN", "Cloudflare", None, None, 85, "cdn_node"),
    (r"Azure.*CDN", "Azure CDN", "Microsoft", None, None, 80, "cdn_node"),
    (r"Google.*Cloud.*CDN", "Google Cloud CDN", "Google", None, None, 80, "cdn_node"),
]

# =============================================================================
# Database Patterns
# =============================================================================

DATABASE_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int, str]] = [
    # Relational Databases
    (r"MySQL[/ ]?([\d.]+)?", "MySQL", "Oracle", None, r"([\d.]+)", 90, "database_server"),
    (r"MariaDB[/ ]?([\d.]+)?", "MariaDB", "MariaDB", None, r"([\d.]+)", 90, "database_server"),
    (r"PostgreSQL[/ ]?([\d.]+)?", "PostgreSQL", "PostgreSQL", None, r"([\d.]+)", 90, "database_server"),
    (r"Microsoft.*SQL.*Server", "SQL Server", "Microsoft", "Windows", None, 95, "database_server"),
    (r"Oracle.*Database", "Oracle Database", "Oracle", None, None, 95, "database_server"),
    (r"IBM.*Db2", "IBM Db2", "IBM", None, None, 90, "database_server"),
    (r"SQLite", "SQLite", None, None, None, 75, "database_server"),
    (r"CockroachDB", "CockroachDB", "Cockroach Labs", None, None, 85, "database_server"),
    (r"TimescaleDB", "TimescaleDB", "Timescale", None, None, 80, "database_server"),

    # NoSQL Databases
    (r"MongoDB[/ ]?([\d.]+)?", "MongoDB", "MongoDB", None, r"([\d.]+)", 90, "database_server"),
    (r"Cassandra", "Apache Cassandra", "Apache", None, None, 85, "database_server"),
    (r"CouchDB", "CouchDB", "Apache", None, None, 80, "database_server"),
    (r"Couchbase", "Couchbase", "Couchbase", None, None, 85, "database_server"),
    (r"Neo4j", "Neo4j", "Neo4j", None, None, 85, "database_server"),
    (r"ArangoDB", "ArangoDB", "ArangoDB", None, None, 80, "database_server"),
    (r"RethinkDB", "RethinkDB", "RethinkDB", None, None, 75, "database_server"),
    (r"InfluxDB", "InfluxDB", "InfluxData", None, None, 85, "database_server"),
    (r"Prometheus", "Prometheus", "CNCF", None, None, 85, "database_server"),
    (r"Elasticsearch", "Elasticsearch", "Elastic", None, None, 90, "database_server"),
    (r"OpenSearch", "OpenSearch", "Amazon", None, None, 85, "database_server"),

    # Cache / In-Memory
    (r"Redis[/ ]?([\d.]+)?", "Redis", "Redis", None, r"([\d.]+)", 90, "cache_server"),
    (r"Memcached[/ ]?([\d.]+)?", "Memcached", None, None, r"([\d.]+)", 85, "cache_server"),
    (r"Hazelcast", "Hazelcast", "Hazelcast", None, None, 80, "cache_server"),
    (r"Apache.*Ignite", "Apache Ignite", "Apache", None, None, 80, "cache_server"),

    # Message Queues
    (r"RabbitMQ[/ ]?([\d.]+)?", "RabbitMQ", "VMware", None, r"([\d.]+)", 90, "database_server"),
    (r"Apache.*Kafka", "Apache Kafka", "Apache", None, None, 90, "database_server"),
    (r"ActiveMQ", "ActiveMQ", "Apache", None, None, 85, "database_server"),
    (r"Apache.*Pulsar", "Apache Pulsar", "Apache", None, None, 80, "database_server"),
    (r"NATS", "NATS", "Synadia", None, None, 80, "database_server"),
]

# =============================================================================
# Security Appliance Patterns
# =============================================================================

SECURITY_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int, str]] = [
    # Firewalls (already have some, adding more)
    (r"Palo.*Alto.*PAN-OS", "Palo Alto Firewall", "Palo Alto", "PAN-OS", None, 95, "firewall"),
    (r"Fortinet.*FortiGate", "FortiGate", "Fortinet", "FortiOS", None, 95, "firewall"),
    (r"Check.*Point", "Check Point Firewall", "Check Point", None, None, 90, "firewall"),
    (r"Cisco.*ASA", "Cisco ASA", "Cisco", None, None, 95, "firewall"),
    (r"Cisco.*Firepower", "Cisco Firepower", "Cisco", None, None, 95, "firewall"),
    (r"SonicWall", "SonicWall", "SonicWall", None, None, 90, "firewall"),
    (r"WatchGuard", "WatchGuard", "WatchGuard", None, None, 90, "firewall"),
    (r"Sophos.*XG", "Sophos XG", "Sophos", None, None, 90, "firewall"),
    (r"Sophos.*UTM", "Sophos UTM", "Sophos", None, None, 85, "firewall"),
    (r"Juniper.*SRX", "Juniper SRX", "Juniper", None, None, 90, "firewall"),
    (r"Barracuda.*Firewall", "Barracuda Firewall", "Barracuda", None, None, 85, "firewall"),
    (r"Untangle", "Untangle", "Untangle", None, None, 80, "firewall"),
    (r"Stormshield", "Stormshield", "Stormshield", None, None, 80, "firewall"),

    # IDS/IPS
    (r"Snort", "Snort", "Cisco", None, None, 85, "ids_ips"),
    (r"Suricata", "Suricata", "OISF", None, None, 85, "ids_ips"),
    (r"Zeek", "Zeek/Bro", None, None, None, 80, "ids_ips"),
    (r"OSSEC", "OSSEC", None, None, None, 80, "ids_ips"),
    (r"Wazuh", "Wazuh", "Wazuh", None, None, 85, "ids_ips"),
    (r"Security.*Onion", "Security Onion", None, None, None, 85, "ids_ips"),

    # SIEM
    (r"Splunk", "Splunk", "Splunk", None, None, 90, "siem"),
    (r"Elastic.*Security", "Elastic Security", "Elastic", None, None, 85, "siem"),
    (r"QRadar", "IBM QRadar", "IBM", None, None, 90, "siem"),
    (r"ArcSight", "ArcSight", "Micro Focus", None, None, 90, "siem"),
    (r"LogRhythm", "LogRhythm", "LogRhythm", None, None, 85, "siem"),
    (r"AlienVault", "AlienVault", "AT&T", None, None, 85, "siem"),
    (r"Graylog", "Graylog", "Graylog", None, None, 80, "siem"),

    # Authentication / Identity
    (r"Active.*Directory", "Active Directory", "Microsoft", "Windows", None, 90, "authentication_server"),
    (r"FreeIPA", "FreeIPA", "Red Hat", "Linux", None, 85, "authentication_server"),
    (r"Keycloak", "Keycloak", "Red Hat", None, None, 85, "authentication_server"),
    (r"Okta", "Okta", "Okta", None, None, 85, "authentication_server"),
    (r"Auth0", "Auth0", "Okta", None, None, 80, "authentication_server"),
    (r"OpenLDAP", "OpenLDAP", None, None, None, 80, "authentication_server"),
    (r"389.*Directory", "389 Directory", "Red Hat", "Linux", None, 80, "authentication_server"),
    (r"Shibboleth", "Shibboleth", None, None, None, 75, "authentication_server"),
    (r"SimpleSAMLphp", "SimpleSAMLphp", None, None, None, 75, "authentication_server"),

    # VPN
    (r"OpenVPN", "OpenVPN", "OpenVPN", None, None, 85, "vpn_gateway"),
    (r"WireGuard", "WireGuard", None, None, None, 85, "vpn_gateway"),
    (r"Cisco.*AnyConnect", "Cisco AnyConnect", "Cisco", None, None, 90, "vpn_gateway"),
    (r"GlobalProtect", "GlobalProtect", "Palo Alto", None, None, 90, "vpn_gateway"),
    (r"Pulse.*Secure", "Pulse Secure", "Ivanti", None, None, 85, "vpn_gateway"),
    (r"Fortinet.*SSL.*VPN", "FortiGate SSL VPN", "Fortinet", None, None, 90, "vpn_gateway"),
    (r"Citrix.*Gateway", "Citrix Gateway", "Citrix", None, None, 90, "vpn_gateway"),
]

# =============================================================================
# Communication Patterns
# =============================================================================

COMMUNICATION_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int, str]] = [
    # VoIP/PBX
    (r"Asterisk", "Asterisk PBX", "Sangoma", None, None, 90, "pbx"),
    (r"FreePBX", "FreePBX", "Sangoma", None, None, 90, "pbx"),
    (r"Cisco.*CallManager", "Cisco CallManager", "Cisco", None, None, 95, "pbx"),
    (r"Cisco.*CUCM", "Cisco CUCM", "Cisco", None, None, 95, "pbx"),
    (r"3CX", "3CX PBX", "3CX", None, None, 85, "pbx"),
    (r"Avaya", "Avaya", "Avaya", None, None, 90, "pbx"),
    (r"Mitel", "Mitel", "Mitel", None, None, 85, "pbx"),
    (r"Polycom", "Polycom", "Poly", None, None, 85, "voip_phone"),
    (r"Yealink", "Yealink", "Yealink", None, None, 85, "voip_phone"),
    (r"Grandstream", "Grandstream", "Grandstream", None, None, 85, "voip_phone"),
    (r"Cisco.*SPA", "Cisco SPA Phone", "Cisco", None, None, 85, "voip_phone"),
    (r"Snom", "Snom Phone", "Snom", None, None, 85, "voip_phone"),

    # Video Conferencing
    (r"Zoom.*Rooms", "Zoom Rooms", "Zoom", None, None, 90, "video_conferencing"),
    (r"Cisco.*Webex", "Cisco Webex", "Cisco", None, None, 90, "video_conferencing"),
    (r"Microsoft.*Teams.*Room", "Teams Room", "Microsoft", None, None, 90, "video_conferencing"),
    (r"Polycom.*Video", "Polycom Video", "Poly", None, None, 85, "video_conferencing"),
    (r"Tandberg", "Cisco TelePresence", "Cisco", None, None, 85, "video_conferencing"),
    (r"Lifesize", "Lifesize", "Lifesize", None, None, 80, "video_conferencing"),
    (r"Logitech.*Rally", "Logitech Rally", "Logitech", None, None, 80, "video_conferencing"),

    # SIP
    (r"Kamailio", "Kamailio SIP", None, None, None, 85, "sip_gateway"),
    (r"OpenSIPS", "OpenSIPS", None, None, None, 85, "sip_gateway"),
    (r"FreeSWITCH", "FreeSWITCH", None, None, None, 85, "sip_gateway"),
    (r"SIP.*Proxy", "SIP Proxy", None, None, None, 70, "sip_gateway"),
]

# =============================================================================
# Additional Protocol Patterns
# =============================================================================

# Kerberos / Authentication Patterns (6-element)
KERBEROS_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # MIT Kerberos
    (r"MIT.*Kerberos", "MIT Kerberos", "MIT", None, r"(\d+\.\d+)", 90),
    (r"krb5kdc", "MIT Kerberos KDC", "MIT", None, None, 85),
    (r"kadmind", "MIT Kerberos Admin", "MIT", None, None, 85),
    # Heimdal Kerberos
    (r"Heimdal.*Kerberos", "Heimdal Kerberos", None, None, r"(\d+\.\d+)", 85),
    (r"heimdal", "Heimdal Kerberos", None, None, None, 80),
    # Windows Kerberos
    (r"Microsoft.*Kerberos", "Windows Kerberos", "Microsoft", "Windows", None, 90),
    # GSSAPI
    (r"GSSAPI", "GSSAPI", None, None, None, 70),
    (r"SPNEGO", "SPNEGO", "Microsoft", None, None, 75),
]

# RADIUS / TACACS Patterns (6-element)
RADIUS_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # FreeRADIUS
    (r"FreeRADIUS", "FreeRADIUS", None, None, r"(\d+\.\d+\.\d+)", 90),
    (r"radiusd", "FreeRADIUS", None, None, None, 80),
    # Cisco ISE/ACS
    (r"Cisco.*ISE", "Cisco ISE", "Cisco", None, None, 95),
    (r"Cisco.*ACS", "Cisco ACS", "Cisco", None, None, 90),
    # Microsoft NPS
    (r"Microsoft.*NPS", "Microsoft NPS", "Microsoft", "Windows Server", None, 90),
    (r"IAS", "Microsoft IAS", "Microsoft", "Windows Server", None, 85),
    # Aruba ClearPass
    (r"ClearPass", "Aruba ClearPass", "Aruba", None, None, 90),
    # TACACS+
    (r"tac_plus", "TACACS+ Server", None, None, None, 85),
    (r"TACACS", "TACACS Server", None, None, None, 80),
    # Radiator
    (r"Radiator", "Radiator RADIUS", "Open System Consultants", None, None, 80),
    # PacketFence
    (r"PacketFence", "PacketFence", None, None, None, 85),
]

# Message Queue / AMQP Patterns (6-element)
MESSAGE_QUEUE_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # RabbitMQ
    (r"RabbitMQ", "RabbitMQ", "VMware", "Erlang", r"(\d+\.\d+\.\d+)", 90),
    (r"amqp.*rabbit", "RabbitMQ", "VMware", "Erlang", None, 85),
    # Apache Kafka
    (r"Kafka", "Apache Kafka", "Apache", None, r"(\d+\.\d+)", 85),
    # Apache ActiveMQ
    (r"ActiveMQ", "Apache ActiveMQ", "Apache", None, r"(\d+\.\d+\.\d+)", 90),
    (r"Artemis", "Apache ActiveMQ Artemis", "Apache", None, None, 85),
    # ZeroMQ
    (r"ZeroMQ", "ZeroMQ", None, None, r"(\d+\.\d+)", 80),
    (r"zmq", "ZeroMQ", None, None, None, 75),
    # NATS
    (r"NATS", "NATS Server", None, None, r"(\d+\.\d+\.\d+)", 85),
    (r"nats-server", "NATS Server", None, None, None, 80),
    # NSQ
    (r"NSQ", "NSQ", None, None, None, 80),
    (r"nsqd", "NSQ Daemon", None, None, None, 80),
    # Apache Pulsar
    (r"Pulsar", "Apache Pulsar", "Apache", None, None, 85),
    # IBM MQ
    (r"IBM.*MQ", "IBM MQ", "IBM", None, None, 90),
    (r"WebSphere.*MQ", "IBM MQ", "IBM", None, None, 85),
    # TIBCO EMS
    (r"TIBCO.*EMS", "TIBCO EMS", "TIBCO", None, None, 85),
    # Solace
    (r"Solace", "Solace PubSub+", "Solace", None, None, 85),
]

# Caching Patterns (6-element)
CACHE_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # Memcached
    (r"memcached", "Memcached", None, None, r"(\d+\.\d+\.\d+)", 90),
    (r"STAT version", "Memcached", None, None, None, 85),
    # Redis (already in database patterns, but adding more)
    (r"redis_version", "Redis", "Redis", None, r"redis_version:(\d+\.\d+\.\d+)", 95),
    # Varnish
    (r"Varnish", "Varnish Cache", "Varnish", None, r"(\d+\.\d+)", 90),
    (r"X-Varnish", "Varnish Cache", "Varnish", None, None, 85),
    # Squid
    (r"Squid", "Squid Proxy", None, None, r"Squid/(\d+\.\d+)", 90),
    (r"squid", "Squid Proxy", None, None, None, 85),
    # HAProxy
    (r"HAProxy", "HAProxy", None, None, r"(\d+\.\d+)", 90),
    # Nginx caching
    (r"X-Cache.*nginx", "Nginx Cache", "Nginx", None, None, 80),
    # Apache Traffic Server
    (r"ATS", "Apache Traffic Server", "Apache", None, None, 80),
    (r"Traffic.*Server", "Apache Traffic Server", "Apache", None, None, 85),
    # KeyDB
    (r"KeyDB", "KeyDB", None, None, r"(\d+\.\d+)", 85),
    # Dragonfly
    (r"Dragonfly", "Dragonfly", None, None, None, 80),
]

# Streaming Media Patterns (6-element)
STREAMING_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # RTSP servers
    (r"RTSP/1\.\d", "RTSP Server", None, None, None, 75),
    (r"Live555", "Live555 Media Server", None, None, None, 85),
    (r"Darwin.*Streaming", "Darwin Streaming Server", "Apple", None, None, 85),
    # Wowza
    (r"Wowza", "Wowza Streaming Engine", "Wowza", None, r"(\d+\.\d+)", 90),
    # Red5
    (r"Red5", "Red5 Media Server", None, None, None, 85),
    # nginx-rtmp
    (r"nginx.*rtmp", "Nginx RTMP", "Nginx", None, None, 85),
    # Nimble Streamer
    (r"Nimble", "Nimble Streamer", "Softvelum", None, None, 80),
    # Ant Media
    (r"Ant.*Media", "Ant Media Server", "Ant Media", None, None, 85),
    # Icecast
    (r"Icecast", "Icecast", None, None, r"(\d+\.\d+\.\d+)", 85),
    # SHOUTcast
    (r"SHOUTcast", "SHOUTcast", "Nullsoft", None, None, 85),
    (r"shoutcast", "SHOUTcast", "Nullsoft", None, None, 80),
    # FFmpeg
    (r"FFmpeg", "FFmpeg", None, None, r"(\d+\.\d+)", 80),
    (r"Lavf", "FFmpeg/Libav", None, None, None, 75),
    # VLC
    (r"VLC", "VLC", "VideoLAN", None, r"(\d+\.\d+\.\d+)", 85),
    # GStreamer
    (r"GStreamer", "GStreamer", None, None, r"(\d+\.\d+)", 80),
    # Plex
    (r"Plex.*Media.*Server", "Plex Media Server", "Plex", None, r"(\d+\.\d+)", 90),
    (r"X-Plex", "Plex Media Server", "Plex", None, None, 85),
    # Jellyfin
    (r"Jellyfin", "Jellyfin", None, None, r"(\d+\.\d+)", 85),
    # Emby
    (r"Emby", "Emby Server", "Emby", None, r"(\d+\.\d+)", 85),
    # Subsonic
    (r"Subsonic", "Subsonic", None, None, None, 80),
    # Airsonic
    (r"Airsonic", "Airsonic", None, None, None, 80),
    # Navidrome
    (r"Navidrome", "Navidrome", None, None, None, 80),
    # Kodi
    (r"Kodi", "Kodi", None, None, r"(\d+\.\d+)", 85),
    (r"XBMC", "Kodi/XBMC", None, None, None, 80),
]

# Version Control Patterns (6-element)
VCS_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # Git
    (r"git.*service", "Git Server", None, None, None, 80),
    (r"git-upload-pack", "Git Server", None, None, None, 85),
    (r"git-receive-pack", "Git Server", None, None, None, 85),
    # Gitea
    (r"Gitea", "Gitea", None, None, r"(\d+\.\d+\.\d+)", 90),
    # Gogs
    (r"Gogs", "Gogs", None, None, r"(\d+\.\d+)", 85),
    # GitLab (already in cloud, adding banner variants)
    (r"gitlab-workhorse", "GitLab", "GitLab", None, None, 90),
    # Gitolite
    (r"gitolite", "Gitolite", None, None, None, 80),
    # Subversion
    (r"SVN", "Subversion", "Apache", None, None, 80),
    (r"svnserve", "Subversion", "Apache", None, None, 85),
    (r"Subversion", "Subversion", "Apache", None, r"(\d+\.\d+\.\d+)", 85),
    # Mercurial
    (r"Mercurial", "Mercurial", None, None, r"(\d+\.\d+)", 85),
    (r"hgweb", "Mercurial", None, None, None, 80),
    # Fossil
    (r"Fossil", "Fossil SCM", None, None, r"(\d+\.\d+)", 80),
    # Perforce
    (r"Perforce", "Perforce Helix", "Perforce", None, None, 90),
    (r"P4.*Server", "Perforce Helix", "Perforce", None, None, 85),
    # Bitbucket Server (self-hosted)
    (r"Bitbucket.*Server", "Bitbucket Server", "Atlassian", None, None, 90),
    # AWS CodeCommit
    (r"CodeCommit", "AWS CodeCommit", "Amazon", None, None, 85),
]

# Chat/Messaging Patterns (6-element)
CHAT_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # XMPP/Jabber
    (r"ejabberd", "ejabberd", "ProcessOne", "Erlang", r"(\d+\.\d+)", 90),
    (r"Prosody", "Prosody", None, None, r"(\d+\.\d+)", 90),
    (r"Openfire", "Openfire", "Ignite Realtime", None, r"(\d+\.\d+)", 85),
    (r"Tigase", "Tigase", None, None, None, 85),
    (r"jabber", "Jabber Server", None, None, None, 75),
    (r"xmpp", "XMPP Server", None, None, None, 70),
    # IRC
    (r"UnrealIRCd", "UnrealIRCd", None, None, r"(\d+\.\d+)", 90),
    (r"InspIRCd", "InspIRCd", None, None, r"(\d+\.\d+)", 90),
    (r"ircd-hybrid", "ircd-hybrid", None, None, None, 85),
    (r"Charybdis", "Charybdis IRCd", None, None, None, 85),
    (r"ngIRCd", "ngIRCd", None, None, None, 85),
    (r"irc\..*NOTICE", "IRC Server", None, None, None, 75),
    # Matrix
    (r"Synapse", "Matrix Synapse", "Matrix.org", None, r"(\d+\.\d+)", 90),
    (r"Dendrite", "Matrix Dendrite", "Matrix.org", None, None, 85),
    (r"Conduit", "Matrix Conduit", None, None, None, 80),
    (r"matrix", "Matrix Server", None, None, None, 70),
    # Mattermost
    (r"Mattermost", "Mattermost", "Mattermost", None, r"(\d+\.\d+)", 90),
    # Rocket.Chat
    (r"Rocket\.Chat", "Rocket.Chat", None, None, r"(\d+\.\d+)", 85),
    # Zulip
    (r"Zulip", "Zulip", None, None, None, 85),
    # Slack (self-hosted alternatives)
    (r"Slack", "Slack", "Salesforce", None, None, 80),
    # Discord (bots/bridges)
    (r"Discord", "Discord", "Discord", None, None, 80),
    # Telegram (MTProto)
    (r"MTProto", "Telegram MTProto", "Telegram", None, None, 80),
    # Element/Riot
    (r"Element", "Element", "Element", None, None, 80),
]

# WebRTC/NAT Traversal Patterns (6-element)
WEBRTC_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # STUN servers
    (r"STUN", "STUN Server", None, None, None, 75),
    (r"coturn", "coturn", None, None, r"(\d+\.\d+)", 90),
    (r"restund", "restund", None, None, None, 85),
    # TURN servers
    (r"TURN", "TURN Server", None, None, None, 75),
    # Twilio STUN/TURN
    (r"Twilio.*STUN", "Twilio STUN", "Twilio", None, None, 85),
    # Janus
    (r"Janus", "Janus WebRTC", None, None, r"(\d+\.\d+)", 90),
    # Kurento
    (r"Kurento", "Kurento Media Server", None, None, None, 85),
    # mediasoup
    (r"mediasoup", "mediasoup", None, None, None, 85),
    # Jitsi
    (r"Jitsi", "Jitsi", None, None, None, 90),
    (r"Jicofo", "Jitsi Jicofo", None, None, None, 85),
    (r"Prosody.*Jitsi", "Jitsi Prosody", None, None, None, 85),
    # BigBlueButton
    (r"BigBlueButton", "BigBlueButton", None, None, None, 90),
    # OpenVidu
    (r"OpenVidu", "OpenVidu", None, None, None, 85),
]

# Industrial / OT Additional Patterns (6-element)
INDUSTRIAL_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # Modbus
    (r"Modbus", "Modbus", None, None, None, 80),
    (r"Modbus.*TCP", "Modbus TCP", None, None, None, 85),
    # DNP3
    (r"DNP3", "DNP3", None, None, None, 85),
    (r"dnp3", "DNP3", None, None, None, 80),
    # OPC-UA
    (r"OPC.*UA", "OPC-UA", "OPC Foundation", None, None, 85),
    (r"opcua", "OPC-UA", "OPC Foundation", None, None, 80),
    # OPC-DA (classic)
    (r"OPC.*DA", "OPC-DA", "OPC Foundation", None, None, 80),
    # EtherNet/IP
    (r"EtherNet/IP", "EtherNet/IP", "ODVA", None, None, 85),
    (r"CIP", "CIP Protocol", "ODVA", None, None, 80),
    # PROFINET
    (r"PROFINET", "PROFINET", "Siemens", None, None, 85),
    # EtherCAT
    (r"EtherCAT", "EtherCAT", "Beckhoff", None, None, 85),
    # HART
    (r"HART", "HART Protocol", None, None, None, 75),
    # Foundation Fieldbus
    (r"Foundation.*Fieldbus", "Foundation Fieldbus", None, None, None, 80),
    # IEC 61850
    (r"IEC.*61850", "IEC 61850", None, None, None, 85),
    (r"MMS.*Protocol", "IEC 61850 MMS", None, None, None, 80),
    (r"GOOSE", "IEC 61850 GOOSE", None, None, None, 80),
    # IEC 60870-5-104
    (r"IEC.*104", "IEC 60870-5-104", None, None, None, 85),
    (r"IEC.*101", "IEC 60870-5-101", None, None, None, 80),
    # IEC 62351 (security)
    (r"IEC.*62351", "IEC 62351", None, None, None, 75),
    # ICCP/TASE.2
    (r"ICCP", "ICCP/TASE.2", None, None, None, 80),
    (r"TASE\.2", "ICCP/TASE.2", None, None, None, 80),
    # CAN bus
    (r"CAN.*bus", "CAN Bus", None, None, None, 75),
    (r"SocketCAN", "SocketCAN", None, "Linux", None, 80),
    # CANopen
    (r"CANopen", "CANopen", None, None, None, 80),
    # DeviceNet
    (r"DeviceNet", "DeviceNet", None, None, None, 80),
    # CC-Link
    (r"CC-Link", "CC-Link", "Mitsubishi", None, None, 80),
    # Modbus RTU
    (r"Modbus.*RTU", "Modbus RTU", None, None, None, 80),
    # MQTT-SN
    (r"MQTT.*SN", "MQTT-SN", None, None, None, 75),
    # LonWorks
    (r"LonWorks", "LonWorks", "Echelon", None, None, 80),
    (r"LON", "LonWorks", "Echelon", None, None, 70),
    # KNX
    (r"KNX", "KNX", None, None, None, 80),
    # M-Bus
    (r"M-Bus", "M-Bus", None, None, None, 75),
    # DLMS/COSEM
    (r"DLMS", "DLMS/COSEM", None, None, None, 80),
    (r"COSEM", "DLMS/COSEM", None, None, None, 80),
]

# IoT Protocol Patterns (6-element)
IOT_PROTOCOL_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # CoAP
    (r"CoAP", "CoAP", None, None, None, 80),
    (r"libcoap", "libcoap", None, None, None, 85),
    (r"Californium", "Eclipse Californium", "Eclipse", None, None, 85),
    # LwM2M
    (r"LwM2M", "LwM2M", "OMA", None, None, 80),
    (r"Leshan", "Eclipse Leshan", "Eclipse", None, None, 85),
    (r"Wakaama", "Eclipse Wakaama", "Eclipse", None, None, 80),
    # LoRaWAN
    (r"LoRaWAN", "LoRaWAN", None, None, None, 80),
    (r"ChirpStack", "ChirpStack", None, None, None, 85),
    (r"The.*Things.*Network", "The Things Network", "TTN", None, None, 90),
    (r"TTN", "The Things Network", "TTN", None, None, 75),
    # Sigfox
    (r"Sigfox", "Sigfox", "Sigfox", None, None, 85),
    # Thread
    (r"Thread", "Thread Protocol", None, None, None, 70),
    (r"OpenThread", "OpenThread", "Google", None, None, 85),
    # Matter
    (r"Matter", "Matter Protocol", "CSA", None, None, 80),
    # Zigbee
    (r"Zigbee", "Zigbee", "CSA", None, None, 80),
    (r"zigbee2mqtt", "zigbee2mqtt", None, None, None, 85),
    # Z-Wave
    (r"Z-Wave", "Z-Wave", "Silicon Labs", None, None, 85),
    (r"zwave", "Z-Wave", "Silicon Labs", None, None, 80),
    # Bluetooth/BLE
    (r"Bluetooth", "Bluetooth", None, None, None, 70),
    (r"BLE", "Bluetooth LE", None, None, None, 70),
    # EnOcean
    (r"EnOcean", "EnOcean", "EnOcean", None, None, 80),
    # Insteon
    (r"Insteon", "Insteon", None, None, None, 80),
    # HomeKit
    (r"HomeKit", "Apple HomeKit", "Apple", None, None, 85),
    # Home Assistant
    (r"Home.*Assistant", "Home Assistant", None, None, None, 90),
    (r"hass\.io", "Home Assistant", None, None, None, 85),
    # OpenHAB
    (r"openHAB", "openHAB", None, None, r"(\d+\.\d+)", 85),
    # Domoticz
    (r"Domoticz", "Domoticz", None, None, None, 85),
    # Node-RED
    (r"Node-RED", "Node-RED", None, None, r"(\d+\.\d+)", 85),
    # IFTTT
    (r"IFTTT", "IFTTT", "IFTTT", None, None, 75),
    # Tuya (local)
    (r"Tuya.*Local", "Tuya Local", "Tuya", None, None, 80),
    # Tasmota
    (r"Tasmota", "Tasmota", None, None, r"(\d+\.\d+)", 85),
    # ESPHome
    (r"ESPHome", "ESPHome", None, None, r"(\d+\.\d+)", 85),
    # Shelly
    (r"Shelly", "Shelly", "Shelly", None, None, 85),
]

# File Sync/Transfer Patterns (6-element)
FILE_SYNC_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # rsync
    (r"rsync", "rsync", None, None, r"(\d+\.\d+\.\d+)", 90),
    (r"@RSYNCD", "rsync daemon", None, None, None, 85),
    # Syncthing
    (r"Syncthing", "Syncthing", None, None, r"(\d+\.\d+)", 85),
    # Resilio Sync
    (r"Resilio", "Resilio Sync", "Resilio", None, None, 85),
    (r"BTSync", "Resilio Sync", "Resilio", None, None, 80),
    # Nextcloud
    (r"Nextcloud", "Nextcloud", "Nextcloud", None, r"(\d+\.\d+)", 90),
    # ownCloud
    (r"ownCloud", "ownCloud", "ownCloud", None, r"(\d+\.\d+)", 85),
    # Seafile
    (r"Seafile", "Seafile", None, None, r"(\d+\.\d+)", 85),
    # SFTP (already covered in SSH, adding explicit)
    (r"OpenSSH.*SFTP", "OpenSSH SFTP", "OpenBSD", None, None, 85),
    (r"SFTP", "SFTP Server", None, None, None, 70),
    # WebDAV
    (r"WebDAV", "WebDAV", None, None, None, 75),
    # Rclone
    (r"rclone", "rclone", None, None, r"(\d+\.\d+)", 80),
    # MinIO Client
    (r"MinIO.*Client", "MinIO Client", "MinIO", None, None, 80),
    # Duplicati
    (r"Duplicati", "Duplicati", None, None, None, 80),
    # Borg Backup
    (r"Borg", "Borg Backup", None, None, r"(\d+\.\d+)", 85),
    (r"borgbackup", "Borg Backup", None, None, None, 80),
    # Restic
    (r"restic", "restic", None, None, r"(\d+\.\d+)", 85),
    # Duplicity
    (r"Duplicity", "Duplicity", None, None, None, 80),
]

# API/RPC Patterns (6-element)
API_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int]] = [
    # gRPC
    (r"grpc", "gRPC", "Google", None, r"(\d+\.\d+)", 85),
    (r"grpc-status", "gRPC", "Google", None, None, 80),
    # GraphQL
    (r"GraphQL", "GraphQL", None, None, None, 80),
    (r"graphql", "GraphQL", None, None, None, 75),
    (r"Apollo.*Server", "Apollo GraphQL", "Apollo", None, None, 85),
    (r"Hasura", "Hasura GraphQL", "Hasura", None, None, 85),
    # Swagger/OpenAPI
    (r"Swagger", "Swagger/OpenAPI", None, None, None, 75),
    (r"OpenAPI", "OpenAPI", None, None, None, 75),
    # JSON-RPC
    (r"JSON-RPC", "JSON-RPC", None, None, None, 70),
    (r"jsonrpc", "JSON-RPC", None, None, None, 70),
    # XML-RPC
    (r"XML-RPC", "XML-RPC", None, None, None, 70),
    # SOAP
    (r"SOAP", "SOAP", None, None, None, 70),
    # Thrift
    (r"Thrift", "Apache Thrift", "Apache", None, None, 80),
    # Avro
    (r"Avro.*RPC", "Apache Avro", "Apache", None, None, 80),
    # Protocol Buffers
    (r"Protobuf", "Protocol Buffers", "Google", None, None, 75),
    # Cap'n Proto
    (r"Cap'n.*Proto", "Cap'n Proto", None, None, None, 75),
    # MessagePack
    (r"MessagePack", "MessagePack", None, None, None, 70),
    # CBOR
    (r"CBOR", "CBOR", None, None, None, 70),
    # tRPC
    (r"tRPC", "tRPC", None, None, None, 75),
    # Connect (Buf)
    (r"Connect.*RPC", "Connect RPC", "Buf", None, None, 75),
]


# =============================================================================
# Cloud Services Patterns
# =============================================================================

CLOUD_PATTERNS: List[Tuple[str, str, Optional[str], Optional[str], Optional[str], int, str]] = [
    # AWS - Amazon Web Services
    (r"AmazonS3", "Amazon S3", "Amazon", None, None, 90, "cloud_storage"),
    (r"x-amz-request-id", "Amazon S3", "Amazon", None, None, 85, "cloud_storage"),
    (r"Server:\s*AmazonS3", "Amazon S3", "Amazon", None, None, 90, "cloud_storage"),
    (r"AWS.*Lambda", "AWS Lambda", "Amazon", None, None, 85, "serverless"),
    (r"x-amzn-RequestId", "AWS API Gateway", "Amazon", None, None, 80, "api_gateway"),
    (r"Amazon.*EC2", "Amazon EC2", "Amazon", "Amazon Linux", None, 90, "cloud_compute"),
    (r"AWS.*EC2", "Amazon EC2", "Amazon", "Amazon Linux", None, 85, "cloud_compute"),
    (r"AWS.*ECS", "Amazon ECS", "Amazon", None, None, 85, "container_service"),
    (r"Amazon.*EKS", "Amazon EKS", "Amazon", None, None, 85, "kubernetes_service"),
    (r"AWS.*Elastic.*Beanstalk", "AWS Elastic Beanstalk", "Amazon", None, None, 80, "paas"),
    (r"Amazon.*RDS", "Amazon RDS", "Amazon", None, None, 85, "cloud_database"),
    (r"Amazon.*Aurora", "Amazon Aurora", "Amazon", None, None, 90, "cloud_database"),
    (r"Amazon.*DynamoDB", "Amazon DynamoDB", "Amazon", None, None, 85, "cloud_database"),
    (r"Amazon.*ElastiCache", "Amazon ElastiCache", "Amazon", None, None, 85, "cloud_cache"),
    (r"Amazon.*Redshift", "Amazon Redshift", "Amazon", None, None, 85, "data_warehouse"),
    (r"AWS.*CloudFront", "Amazon CloudFront", "Amazon", None, None, 90, "cdn"),
    (r"x-amz-cf-id", "Amazon CloudFront", "Amazon", None, None, 85, "cdn"),
    (r"Amazon.*SQS", "Amazon SQS", "Amazon", None, None, 80, "message_queue"),
    (r"Amazon.*SNS", "Amazon SNS", "Amazon", None, None, 80, "notification_service"),
    (r"AWS.*Cognito", "AWS Cognito", "Amazon", None, None, 85, "identity_service"),
    (r"Amazon.*Route.*53", "Amazon Route 53", "Amazon", None, None, 85, "dns_service"),
    (r"AWS.*WAF", "AWS WAF", "Amazon", None, None, 85, "waf"),
    (r"AWS.*Shield", "AWS Shield", "Amazon", None, None, 85, "ddos_protection"),
    (r"Amazon.*Kinesis", "Amazon Kinesis", "Amazon", None, None, 80, "streaming_service"),
    (r"Amazon.*EMR", "Amazon EMR", "Amazon", None, None, 80, "data_processing"),
    (r"AWS.*Glue", "AWS Glue", "Amazon", None, None, 80, "etl_service"),
    (r"Amazon.*Athena", "Amazon Athena", "Amazon", None, None, 80, "query_service"),
    (r"AWS.*Step.*Functions", "AWS Step Functions", "Amazon", None, None, 75, "orchestration"),
    (r"Amazon.*SageMaker", "Amazon SageMaker", "Amazon", None, None, 85, "ml_platform"),
    (r"Amazon.*Lightsail", "Amazon Lightsail", "Amazon", None, None, 80, "vps"),
    (r"AWS.*Fargate", "AWS Fargate", "Amazon", None, None, 85, "serverless_container"),
    (r"Amazon.*ECR", "Amazon ECR", "Amazon", None, None, 80, "container_registry"),
    (r"AWS.*AppRunner", "AWS App Runner", "Amazon", None, None, 80, "paas"),
    (r"Amazon.*MQ", "Amazon MQ", "Amazon", None, None, 80, "message_broker"),
    (r"AWS.*Amplify", "AWS Amplify", "Amazon", None, None, 80, "paas"),
    (r"Amazon.*DocumentDB", "Amazon DocumentDB", "Amazon", None, None, 85, "cloud_database"),
    (r"Amazon.*Neptune", "Amazon Neptune", "Amazon", None, None, 80, "graph_database"),
    (r"Amazon.*Keyspaces", "Amazon Keyspaces", "Amazon", None, None, 80, "cloud_database"),
    (r"Amazon.*OpenSearch", "Amazon OpenSearch", "Amazon", None, None, 85, "search_service"),
    (r"AWS.*Transfer", "AWS Transfer Family", "Amazon", None, None, 75, "file_transfer"),
    (r"Amazon.*FSx", "Amazon FSx", "Amazon", None, None, 80, "cloud_filesystem"),
    (r"Amazon.*EFS", "Amazon EFS", "Amazon", None, None, 80, "cloud_filesystem"),
    (r"AWS.*Backup", "AWS Backup", "Amazon", None, None, 75, "backup_service"),
    (r"Amazon.*WorkSpaces", "Amazon WorkSpaces", "Amazon", None, None, 85, "virtual_desktop"),
    (r"AWS.*AppSync", "AWS AppSync", "Amazon", None, None, 80, "graphql_service"),
    (r"AWS.*IoT.*Core", "AWS IoT Core", "Amazon", None, None, 85, "iot_platform"),
    (r"Amazon.*Timestream", "Amazon Timestream", "Amazon", None, None, 80, "timeseries_db"),
    (r"Amazon.*QLDB", "Amazon QLDB", "Amazon", None, None, 75, "ledger_database"),
    (r"AWS.*Secrets.*Manager", "AWS Secrets Manager", "Amazon", None, None, 80, "secrets_management"),
    (r"AWS.*Systems.*Manager", "AWS Systems Manager", "Amazon", None, None, 80, "management_service"),
    (r"Amazon.*Inspector", "Amazon Inspector", "Amazon", None, None, 80, "security_service"),
    (r"Amazon.*GuardDuty", "Amazon GuardDuty", "Amazon", None, None, 85, "threat_detection"),
    (r"AWS.*Security.*Hub", "AWS Security Hub", "Amazon", None, None, 80, "security_service"),
    (r"Amazon.*Macie", "Amazon Macie", "Amazon", None, None, 80, "data_protection"),
    (r"Amazon.*Detective", "Amazon Detective", "Amazon", None, None, 75, "security_analytics"),
    (r"AWS.*Config", "AWS Config", "Amazon", None, None, 75, "compliance_service"),
    (r"AWS.*CloudTrail", "AWS CloudTrail", "Amazon", None, None, 80, "audit_service"),
    (r"Amazon.*CloudWatch", "Amazon CloudWatch", "Amazon", None, None, 85, "monitoring"),
    (r"AWS.*X-Ray", "AWS X-Ray", "Amazon", None, None, 80, "tracing_service"),
    (r"Amazon.*EventBridge", "Amazon EventBridge", "Amazon", None, None, 80, "event_bus"),

    # Microsoft Azure
    (r"Microsoft-Azure-Application-Gateway", "Azure Application Gateway", "Microsoft", None, None, 90, "load_balancer"),
    (r"x-ms-request-id", "Azure Service", "Microsoft", None, None, 75, "cloud_service"),
    (r"Azure.*Blob", "Azure Blob Storage", "Microsoft", None, None, 90, "cloud_storage"),
    (r"Azure.*Files", "Azure Files", "Microsoft", None, None, 85, "cloud_filesystem"),
    (r"Azure.*Functions", "Azure Functions", "Microsoft", None, None, 85, "serverless"),
    (r"Azure.*App.*Service", "Azure App Service", "Microsoft", None, None, 90, "paas"),
    (r"Azure.*Kubernetes", "Azure Kubernetes Service", "Microsoft", None, None, 90, "kubernetes_service"),
    (r"Azure.*Container.*Instances", "Azure Container Instances", "Microsoft", None, None, 85, "container_service"),
    (r"Azure.*Container.*Registry", "Azure Container Registry", "Microsoft", None, None, 80, "container_registry"),
    (r"Azure.*SQL", "Azure SQL Database", "Microsoft", None, None, 90, "cloud_database"),
    (r"Azure.*Cosmos.*DB", "Azure Cosmos DB", "Microsoft", None, None, 90, "cloud_database"),
    (r"Azure.*Cache.*Redis", "Azure Cache for Redis", "Microsoft", None, None, 85, "cloud_cache"),
    (r"Azure.*Database.*MySQL", "Azure Database for MySQL", "Microsoft", None, None, 85, "cloud_database"),
    (r"Azure.*Database.*PostgreSQL", "Azure Database for PostgreSQL", "Microsoft", None, None, 85, "cloud_database"),
    (r"Azure.*Database.*MariaDB", "Azure Database for MariaDB", "Microsoft", None, None, 80, "cloud_database"),
    (r"Azure.*Synapse", "Azure Synapse Analytics", "Microsoft", None, None, 85, "data_warehouse"),
    (r"Azure.*Data.*Lake", "Azure Data Lake", "Microsoft", None, None, 85, "data_lake"),
    (r"Azure.*Databricks", "Azure Databricks", "Microsoft", None, None, 85, "data_processing"),
    (r"Azure.*HDInsight", "Azure HDInsight", "Microsoft", None, None, 80, "data_processing"),
    (r"Azure.*Stream.*Analytics", "Azure Stream Analytics", "Microsoft", None, None, 80, "streaming_service"),
    (r"Azure.*Event.*Hubs", "Azure Event Hubs", "Microsoft", None, None, 85, "event_streaming"),
    (r"Azure.*Service.*Bus", "Azure Service Bus", "Microsoft", None, None, 85, "message_queue"),
    (r"Azure.*Logic.*Apps", "Azure Logic Apps", "Microsoft", None, None, 80, "orchestration"),
    (r"Azure.*API.*Management", "Azure API Management", "Microsoft", None, None, 90, "api_gateway"),
    (r"Azure.*Front.*Door", "Azure Front Door", "Microsoft", None, None, 90, "cdn"),
    (r"Azure.*CDN", "Azure CDN", "Microsoft", None, None, 85, "cdn"),
    (r"Azure.*Traffic.*Manager", "Azure Traffic Manager", "Microsoft", None, None, 85, "load_balancer"),
    (r"Azure.*Load.*Balancer", "Azure Load Balancer", "Microsoft", None, None, 85, "load_balancer"),
    (r"Azure.*Virtual.*Network", "Azure Virtual Network", "Microsoft", None, None, 75, "cloud_network"),
    (r"Azure.*ExpressRoute", "Azure ExpressRoute", "Microsoft", None, None, 80, "cloud_network"),
    (r"Azure.*VPN.*Gateway", "Azure VPN Gateway", "Microsoft", None, None, 85, "vpn_gateway"),
    (r"Azure.*Firewall", "Azure Firewall", "Microsoft", None, None, 90, "firewall"),
    (r"Azure.*WAF", "Azure WAF", "Microsoft", None, None, 85, "waf"),
    (r"Azure.*DDoS.*Protection", "Azure DDoS Protection", "Microsoft", None, None, 85, "ddos_protection"),
    (r"Azure.*Active.*Directory", "Azure Active Directory", "Microsoft", None, None, 95, "identity_service"),
    (r"Azure.*AD.*B2C", "Azure AD B2C", "Microsoft", None, None, 85, "identity_service"),
    (r"Azure.*Key.*Vault", "Azure Key Vault", "Microsoft", None, None, 90, "secrets_management"),
    (r"Azure.*Security.*Center", "Azure Security Center", "Microsoft", None, None, 85, "security_service"),
    (r"Azure.*Sentinel", "Microsoft Sentinel", "Microsoft", None, None, 90, "siem"),
    (r"Azure.*Defender", "Microsoft Defender", "Microsoft", None, None, 90, "security_service"),
    (r"Azure.*Monitor", "Azure Monitor", "Microsoft", None, None, 85, "monitoring"),
    (r"Azure.*Log.*Analytics", "Azure Log Analytics", "Microsoft", None, None, 85, "logging_service"),
    (r"Azure.*Application.*Insights", "Azure Application Insights", "Microsoft", None, None, 85, "apm"),
    (r"Azure.*DevOps", "Azure DevOps", "Microsoft", None, None, 90, "devops_service"),
    (r"Azure.*Repos", "Azure Repos", "Microsoft", None, None, 80, "source_control"),
    (r"Azure.*Pipelines", "Azure Pipelines", "Microsoft", None, None, 85, "ci_cd"),
    (r"Azure.*Machine.*Learning", "Azure Machine Learning", "Microsoft", None, None, 85, "ml_platform"),
    (r"Azure.*Cognitive.*Services", "Azure Cognitive Services", "Microsoft", None, None, 85, "ai_service"),
    (r"Azure.*Bot.*Service", "Azure Bot Service", "Microsoft", None, None, 80, "bot_service"),
    (r"Azure.*IoT.*Hub", "Azure IoT Hub", "Microsoft", None, None, 90, "iot_platform"),
    (r"Azure.*IoT.*Central", "Azure IoT Central", "Microsoft", None, None, 85, "iot_platform"),
    (r"Azure.*Digital.*Twins", "Azure Digital Twins", "Microsoft", None, None, 80, "iot_platform"),
    (r"Azure.*Virtual.*Desktop", "Azure Virtual Desktop", "Microsoft", None, None, 85, "virtual_desktop"),
    (r"Power.*Platform", "Microsoft Power Platform", "Microsoft", None, None, 80, "low_code_platform"),
    (r"Power.*Apps", "Microsoft Power Apps", "Microsoft", None, None, 80, "low_code_platform"),
    (r"Power.*Automate", "Microsoft Power Automate", "Microsoft", None, None, 80, "workflow_automation"),
    (r"Power.*BI", "Microsoft Power BI", "Microsoft", None, None, 85, "bi_service"),

    # Google Cloud Platform (GCP)
    (r"Google.*Cloud.*Storage", "Google Cloud Storage", "Google", None, None, 90, "cloud_storage"),
    (r"X-GUploader-UploadID", "Google Cloud Storage", "Google", None, None, 80, "cloud_storage"),
    (r"Google.*Compute.*Engine", "Google Compute Engine", "Google", None, None, 90, "cloud_compute"),
    (r"Google.*Kubernetes.*Engine", "Google Kubernetes Engine", "Google", None, None, 90, "kubernetes_service"),
    (r"GKE", "Google Kubernetes Engine", "Google", None, None, 75, "kubernetes_service"),
    (r"Google.*Cloud.*Run", "Google Cloud Run", "Google", None, None, 90, "serverless_container"),
    (r"Google.*Cloud.*Functions", "Google Cloud Functions", "Google", None, None, 85, "serverless"),
    (r"Google.*App.*Engine", "Google App Engine", "Google", None, None, 90, "paas"),
    (r"Google.*Cloud.*SQL", "Google Cloud SQL", "Google", None, None, 90, "cloud_database"),
    (r"Google.*Cloud.*Spanner", "Google Cloud Spanner", "Google", None, None, 90, "cloud_database"),
    (r"Google.*Firestore", "Google Firestore", "Google", None, None, 85, "cloud_database"),
    (r"Google.*Bigtable", "Google Cloud Bigtable", "Google", None, None, 85, "cloud_database"),
    (r"Google.*BigQuery", "Google BigQuery", "Google", None, None, 90, "data_warehouse"),
    (r"Google.*Dataflow", "Google Cloud Dataflow", "Google", None, None, 85, "data_processing"),
    (r"Google.*Dataproc", "Google Cloud Dataproc", "Google", None, None, 80, "data_processing"),
    (r"Google.*Pub/Sub", "Google Cloud Pub/Sub", "Google", None, None, 85, "message_queue"),
    (r"Google.*Cloud.*CDN", "Google Cloud CDN", "Google", None, None, 85, "cdn"),
    (r"Google.*Cloud.*Load.*Balancing", "Google Cloud Load Balancing", "Google", None, None, 85, "load_balancer"),
    (r"Google.*Cloud.*Armor", "Google Cloud Armor", "Google", None, None, 90, "waf"),
    (r"Google.*Cloud.*DNS", "Google Cloud DNS", "Google", None, None, 85, "dns_service"),
    (r"Google.*Cloud.*VPN", "Google Cloud VPN", "Google", None, None, 85, "vpn_gateway"),
    (r"Google.*Cloud.*NAT", "Google Cloud NAT", "Google", None, None, 80, "cloud_network"),
    (r"Google.*Cloud.*IAM", "Google Cloud IAM", "Google", None, None, 85, "identity_service"),
    (r"Google.*Secret.*Manager", "Google Secret Manager", "Google", None, None, 85, "secrets_management"),
    (r"Google.*Cloud.*KMS", "Google Cloud KMS", "Google", None, None, 85, "encryption_service"),
    (r"Google.*Security.*Command.*Center", "Google Security Command Center", "Google", None, None, 85, "security_service"),
    (r"Google.*Cloud.*Logging", "Google Cloud Logging", "Google", None, None, 85, "logging_service"),
    (r"Google.*Cloud.*Monitoring", "Google Cloud Monitoring", "Google", None, None, 85, "monitoring"),
    (r"Google.*Cloud.*Trace", "Google Cloud Trace", "Google", None, None, 80, "tracing_service"),
    (r"Google.*Cloud.*Build", "Google Cloud Build", "Google", None, None, 85, "ci_cd"),
    (r"Google.*Container.*Registry", "Google Container Registry", "Google", None, None, 80, "container_registry"),
    (r"Google.*Artifact.*Registry", "Google Artifact Registry", "Google", None, None, 85, "artifact_registry"),
    (r"Google.*Cloud.*Deploy", "Google Cloud Deploy", "Google", None, None, 80, "cd_service"),
    (r"Google.*Vertex.*AI", "Google Vertex AI", "Google", None, None, 85, "ml_platform"),
    (r"Google.*AI.*Platform", "Google AI Platform", "Google", None, None, 85, "ml_platform"),
    (r"Google.*Cloud.*Vision", "Google Cloud Vision", "Google", None, None, 85, "ai_service"),
    (r"Google.*Cloud.*Speech", "Google Cloud Speech", "Google", None, None, 85, "ai_service"),
    (r"Google.*Cloud.*Translation", "Google Cloud Translation", "Google", None, None, 85, "ai_service"),
    (r"Google.*Cloud.*Natural.*Language", "Google Cloud Natural Language", "Google", None, None, 80, "ai_service"),
    (r"Google.*Cloud.*IoT.*Core", "Google Cloud IoT Core", "Google", None, None, 85, "iot_platform"),
    (r"Google.*Anthos", "Google Anthos", "Google", None, None, 85, "hybrid_cloud"),
    (r"Google.*Apigee", "Google Apigee", "Google", None, None, 90, "api_gateway"),
    (r"Firebase", "Firebase", "Google", None, None, 85, "backend_service"),
    (r"Google.*Looker", "Google Looker", "Google", None, None, 80, "bi_service"),
    (r"Google.*Data.*Studio", "Google Data Studio", "Google", None, None, 75, "bi_service"),
    (r"Chronicle", "Google Chronicle", "Google", None, None, 85, "siem"),

    # Oracle Cloud Infrastructure (OCI)
    (r"Oracle.*Cloud", "Oracle Cloud Infrastructure", "Oracle", None, None, 85, "cloud_compute"),
    (r"oraclecloud\.com", "Oracle Cloud Infrastructure", "Oracle", None, None, 80, "cloud_service"),
    (r"Oracle.*Autonomous.*Database", "Oracle Autonomous Database", "Oracle", None, None, 90, "cloud_database"),
    (r"Oracle.*Database.*Cloud", "Oracle Database Cloud", "Oracle", None, None, 85, "cloud_database"),
    (r"Oracle.*Container.*Engine", "Oracle Container Engine", "Oracle", None, None, 80, "kubernetes_service"),
    (r"Oracle.*Functions", "Oracle Functions", "Oracle", None, None, 80, "serverless"),
    (r"Oracle.*API.*Gateway", "Oracle API Gateway", "Oracle", None, None, 80, "api_gateway"),
    (r"Oracle.*Integration.*Cloud", "Oracle Integration Cloud", "Oracle", None, None, 80, "integration_service"),
    (r"Oracle.*Analytics.*Cloud", "Oracle Analytics Cloud", "Oracle", None, None, 80, "bi_service"),

    # IBM Cloud
    (r"IBM.*Cloud", "IBM Cloud", "IBM", None, None, 85, "cloud_service"),
    (r"Bluemix", "IBM Cloud", "IBM", None, None, 80, "cloud_service"),
    (r"IBM.*Cloud.*Kubernetes", "IBM Cloud Kubernetes", "IBM", None, None, 85, "kubernetes_service"),
    (r"IBM.*Cloud.*Functions", "IBM Cloud Functions", "IBM", None, None, 80, "serverless"),
    (r"IBM.*Cloud.*Object.*Storage", "IBM Cloud Object Storage", "IBM", None, None, 85, "cloud_storage"),
    (r"IBM.*Db2.*Cloud", "IBM Db2 on Cloud", "IBM", None, None, 85, "cloud_database"),
    (r"IBM.*Watson", "IBM Watson", "IBM", None, None, 90, "ai_service"),
    (r"IBM.*Cloud.*Pak", "IBM Cloud Pak", "IBM", None, None, 85, "paas"),

    # Alibaba Cloud
    (r"Alibaba.*Cloud", "Alibaba Cloud", "Alibaba", None, None, 85, "cloud_service"),
    (r"Aliyun", "Alibaba Cloud", "Alibaba", None, None, 85, "cloud_service"),
    (r"alicdn\.com", "Alibaba Cloud CDN", "Alibaba", None, None, 80, "cdn"),
    (r"Alibaba.*ECS", "Alibaba Cloud ECS", "Alibaba", None, None, 85, "cloud_compute"),
    (r"Alibaba.*OSS", "Alibaba Cloud OSS", "Alibaba", None, None, 85, "cloud_storage"),
    (r"Alibaba.*RDS", "Alibaba Cloud RDS", "Alibaba", None, None, 85, "cloud_database"),
    (r"Alibaba.*Container.*Service", "Alibaba Container Service", "Alibaba", None, None, 80, "kubernetes_service"),

    # DigitalOcean
    (r"DigitalOcean", "DigitalOcean", "DigitalOcean", None, None, 85, "cloud_service"),
    (r"DigitalOcean.*Droplet", "DigitalOcean Droplet", "DigitalOcean", None, None, 85, "vps"),
    (r"DigitalOcean.*Spaces", "DigitalOcean Spaces", "DigitalOcean", None, None, 85, "cloud_storage"),
    (r"DigitalOcean.*Kubernetes", "DigitalOcean Kubernetes", "DigitalOcean", None, None, 85, "kubernetes_service"),
    (r"DigitalOcean.*App.*Platform", "DigitalOcean App Platform", "DigitalOcean", None, None, 80, "paas"),
    (r"DigitalOcean.*Managed.*Database", "DigitalOcean Managed Database", "DigitalOcean", None, None, 80, "cloud_database"),

    # Linode (Akamai)
    (r"Linode", "Linode", "Akamai", None, None, 85, "cloud_service"),
    (r"Linode.*Kubernetes.*Engine", "Linode Kubernetes Engine", "Akamai", None, None, 80, "kubernetes_service"),
    (r"Linode.*Object.*Storage", "Linode Object Storage", "Akamai", None, None, 80, "cloud_storage"),

    # Vultr
    (r"Vultr", "Vultr", "Vultr", None, None, 85, "cloud_service"),
    (r"Vultr.*Kubernetes", "Vultr Kubernetes", "Vultr", None, None, 80, "kubernetes_service"),
    (r"Vultr.*Object.*Storage", "Vultr Object Storage", "Vultr", None, None, 80, "cloud_storage"),

    # Hetzner
    (r"Hetzner", "Hetzner Cloud", "Hetzner", None, None, 85, "cloud_service"),
    (r"Hetzner.*Cloud", "Hetzner Cloud", "Hetzner", None, None, 85, "vps"),

    # OVHcloud
    (r"OVH", "OVHcloud", "OVH", None, None, 80, "cloud_service"),
    (r"OVHcloud", "OVHcloud", "OVH", None, None, 85, "cloud_service"),

    # Scaleway
    (r"Scaleway", "Scaleway", "Scaleway", None, None, 80, "cloud_service"),

    # Cloudflare (CDN/Edge)
    (r"Cloudflare", "Cloudflare", "Cloudflare", None, None, 90, "cdn"),
    (r"CF-RAY", "Cloudflare", "Cloudflare", None, None, 85, "cdn"),
    (r"Cloudflare.*Workers", "Cloudflare Workers", "Cloudflare", None, None, 85, "serverless"),
    (r"Cloudflare.*Pages", "Cloudflare Pages", "Cloudflare", None, None, 80, "static_hosting"),
    (r"Cloudflare.*R2", "Cloudflare R2", "Cloudflare", None, None, 80, "cloud_storage"),
    (r"Cloudflare.*D1", "Cloudflare D1", "Cloudflare", None, None, 75, "cloud_database"),
    (r"Cloudflare.*Zero.*Trust", "Cloudflare Zero Trust", "Cloudflare", None, None, 85, "security_service"),
    (r"Cloudflare.*Access", "Cloudflare Access", "Cloudflare", None, None, 85, "identity_service"),
    (r"Cloudflare.*Tunnel", "Cloudflare Tunnel", "Cloudflare", None, None, 80, "tunnel_service"),
    (r"Cloudflare.*Stream", "Cloudflare Stream", "Cloudflare", None, None, 80, "video_streaming"),

    # Fastly
    (r"Fastly", "Fastly", "Fastly", None, None, 85, "cdn"),
    (r"x-served-by.*cache", "Fastly CDN", "Fastly", None, None, 80, "cdn"),
    (r"Fastly.*Compute", "Fastly Compute@Edge", "Fastly", None, None, 80, "serverless"),

    # Akamai
    (r"Akamai", "Akamai", "Akamai", None, None, 90, "cdn"),
    (r"akamaiedge", "Akamai Edge", "Akamai", None, None, 85, "cdn"),
    (r"Akamai.*EdgeWorkers", "Akamai EdgeWorkers", "Akamai", None, None, 80, "serverless"),
    (r"Akamai.*Kona", "Akamai Kona WAF", "Akamai", None, None, 85, "waf"),
    (r"Akamai.*Prolexic", "Akamai Prolexic", "Akamai", None, None, 85, "ddos_protection"),

    # Vercel
    (r"Vercel", "Vercel", "Vercel", None, None, 85, "paas"),
    (r"x-vercel", "Vercel", "Vercel", None, None, 80, "paas"),
    (r"Vercel.*Edge", "Vercel Edge Functions", "Vercel", None, None, 80, "serverless"),

    # Netlify
    (r"Netlify", "Netlify", "Netlify", None, None, 85, "static_hosting"),
    (r"x-nf-request-id", "Netlify", "Netlify", None, None, 80, "static_hosting"),
    (r"Netlify.*Functions", "Netlify Functions", "Netlify", None, None, 80, "serverless"),
    (r"Netlify.*Edge", "Netlify Edge Functions", "Netlify", None, None, 75, "serverless"),

    # Render
    (r"Render", "Render", "Render", None, None, 80, "paas"),
    (r"render\.com", "Render", "Render", None, None, 75, "paas"),

    # Railway
    (r"Railway", "Railway", "Railway", None, None, 75, "paas"),

    # Fly.io
    (r"Fly\.io", "Fly.io", "Fly.io", None, None, 80, "paas"),
    (r"fly-request-id", "Fly.io", "Fly.io", None, None, 75, "paas"),

    # Heroku
    (r"Heroku", "Heroku", "Salesforce", None, None, 85, "paas"),
    (r"heroku\.com", "Heroku", "Salesforce", None, None, 80, "paas"),

    # Platform.sh
    (r"Platform\.sh", "Platform.sh", "Platform.sh", None, None, 75, "paas"),

    # Red Hat OpenShift
    (r"OpenShift", "Red Hat OpenShift", "Red Hat", None, None, 90, "kubernetes_service"),
    (r"OpenShift.*Dedicated", "OpenShift Dedicated", "Red Hat", None, None, 85, "kubernetes_service"),
    (r"OpenShift.*Online", "OpenShift Online", "Red Hat", None, None, 80, "kubernetes_service"),
    (r"ROSA", "Red Hat OpenShift on AWS", "Red Hat", None, None, 85, "kubernetes_service"),
    (r"ARO", "Azure Red Hat OpenShift", "Red Hat", None, None, 85, "kubernetes_service"),

    # VMware Cloud
    (r"VMware.*Cloud", "VMware Cloud", "VMware", None, None, 85, "hybrid_cloud"),
    (r"VMware.*Tanzu", "VMware Tanzu", "VMware", None, None, 85, "kubernetes_service"),
    (r"VMware.*vRealize", "VMware vRealize", "VMware", None, None, 80, "cloud_management"),
    (r"VMC.*on.*AWS", "VMware Cloud on AWS", "VMware", None, None, 85, "hybrid_cloud"),

    # HashiCorp Cloud Platform
    (r"HashiCorp.*Cloud", "HashiCorp Cloud Platform", "HashiCorp", None, None, 80, "cloud_service"),
    (r"HCP.*Vault", "HCP Vault", "HashiCorp", None, None, 85, "secrets_management"),
    (r"HCP.*Consul", "HCP Consul", "HashiCorp", None, None, 85, "service_mesh"),
    (r"Terraform.*Cloud", "Terraform Cloud", "HashiCorp", None, None, 85, "iac_service"),

    # Snowflake
    (r"Snowflake", "Snowflake", "Snowflake", None, None, 90, "data_warehouse"),

    # Databricks
    (r"Databricks", "Databricks", "Databricks", None, None, 85, "data_processing"),

    # MongoDB Atlas
    (r"MongoDB.*Atlas", "MongoDB Atlas", "MongoDB", None, None, 90, "cloud_database"),

    # Elastic Cloud
    (r"Elastic.*Cloud", "Elastic Cloud", "Elastic", None, None, 85, "search_service"),

    # Redis Cloud
    (r"Redis.*Cloud", "Redis Cloud", "Redis", None, None, 85, "cloud_cache"),
    (r"Redis.*Enterprise.*Cloud", "Redis Enterprise Cloud", "Redis", None, None, 85, "cloud_cache"),

    # Confluent Cloud (Kafka)
    (r"Confluent.*Cloud", "Confluent Cloud", "Confluent", None, None, 85, "event_streaming"),
    (r"Confluent.*Kafka", "Confluent Cloud Kafka", "Confluent", None, None, 85, "message_queue"),

    # PlanetScale
    (r"PlanetScale", "PlanetScale", "PlanetScale", None, None, 80, "cloud_database"),

    # Supabase
    (r"Supabase", "Supabase", "Supabase", None, None, 80, "backend_service"),

    # Neon
    (r"Neon", "Neon", "Neon", None, None, 75, "cloud_database"),

    # CockroachDB Cloud
    (r"CockroachDB.*Cloud", "CockroachDB Cloud", "Cockroach Labs", None, None, 80, "cloud_database"),
    (r"Cockroach.*Cloud", "CockroachDB Cloud", "Cockroach Labs", None, None, 80, "cloud_database"),

    # Upstash
    (r"Upstash", "Upstash", "Upstash", None, None, 75, "serverless_database"),

    # Backblaze
    (r"Backblaze.*B2", "Backblaze B2", "Backblaze", None, None, 80, "cloud_storage"),

    # Wasabi
    (r"Wasabi", "Wasabi", "Wasabi", None, None, 80, "cloud_storage"),

    # MinIO (Self-hosted S3-compatible)
    (r"MinIO", "MinIO", "MinIO", None, None, 85, "object_storage"),

    # Ceph
    (r"Ceph.*RGW", "Ceph RADOS Gateway", "Red Hat", None, None, 80, "object_storage"),

    # GitHub (Microsoft)
    (r"GitHub.*Actions", "GitHub Actions", "Microsoft", None, None, 85, "ci_cd"),
    (r"GitHub.*Codespaces", "GitHub Codespaces", "Microsoft", None, None, 80, "cloud_ide"),
    (r"GitHub.*Packages", "GitHub Packages", "Microsoft", None, None, 80, "artifact_registry"),

    # GitLab
    (r"GitLab", "GitLab", "GitLab", None, None, 85, "devops_service"),
    (r"GitLab.*CI", "GitLab CI/CD", "GitLab", None, None, 85, "ci_cd"),
    (r"GitLab.*Runner", "GitLab Runner", "GitLab", None, None, 80, "ci_cd"),

    # Bitbucket
    (r"Bitbucket", "Bitbucket", "Atlassian", None, None, 85, "source_control"),
    (r"Bitbucket.*Pipelines", "Bitbucket Pipelines", "Atlassian", None, None, 80, "ci_cd"),

    # CircleCI
    (r"CircleCI", "CircleCI", "CircleCI", None, None, 80, "ci_cd"),

    # Travis CI
    (r"Travis.*CI", "Travis CI", "Travis CI", None, None, 75, "ci_cd"),

    # Jenkins X
    (r"Jenkins.*X", "Jenkins X", "CloudBees", None, None, 75, "ci_cd"),

    # Datadog
    (r"Datadog", "Datadog", "Datadog", None, None, 90, "monitoring"),
    (r"dd-trace", "Datadog APM", "Datadog", None, None, 85, "apm"),

    # New Relic
    (r"New.*Relic", "New Relic", "New Relic", None, None, 85, "monitoring"),
    (r"newrelic", "New Relic", "New Relic", None, None, 80, "apm"),

    # Dynatrace
    (r"Dynatrace", "Dynatrace", "Dynatrace", None, None, 85, "monitoring"),

    # AppDynamics
    (r"AppDynamics", "AppDynamics", "Cisco", None, None, 85, "apm"),

    # Sentry
    (r"Sentry", "Sentry", "Sentry", None, None, 80, "error_tracking"),

    # PagerDuty
    (r"PagerDuty", "PagerDuty", "PagerDuty", None, None, 80, "incident_management"),

    # Opsgenie
    (r"Opsgenie", "Opsgenie", "Atlassian", None, None, 80, "incident_management"),

    # Twilio
    (r"Twilio", "Twilio", "Twilio", None, None, 85, "communication_api"),

    # SendGrid
    (r"SendGrid", "SendGrid", "Twilio", None, None, 85, "email_service"),

    # Auth0
    (r"Auth0", "Auth0", "Okta", None, None, 85, "identity_service"),

    # Okta
    (r"Okta", "Okta", "Okta", None, None, 90, "identity_service"),

    # Stripe
    (r"Stripe", "Stripe", "Stripe", None, None, 85, "payment_service"),

    # Segment
    (r"Segment", "Segment", "Twilio", None, None, 80, "analytics_service"),

    # LaunchDarkly
    (r"LaunchDarkly", "LaunchDarkly", "LaunchDarkly", None, None, 80, "feature_flags"),

    # Split
    (r"Split\.io", "Split", "Split", None, None, 75, "feature_flags"),

    # Contentful
    (r"Contentful", "Contentful", "Contentful", None, None, 80, "headless_cms"),

    # Sanity
    (r"Sanity", "Sanity", "Sanity", None, None, 75, "headless_cms"),

    # Prismic
    (r"Prismic", "Prismic", "Prismic", None, None, 75, "headless_cms"),

    # Algolia
    (r"Algolia", "Algolia", "Algolia", None, None, 85, "search_service"),

    # Meilisearch Cloud
    (r"Meilisearch.*Cloud", "Meilisearch Cloud", "Meilisearch", None, None, 75, "search_service"),

    # Typesense Cloud
    (r"Typesense.*Cloud", "Typesense Cloud", "Typesense", None, None, 75, "search_service"),

    # Pinecone
    (r"Pinecone", "Pinecone", "Pinecone", None, None, 80, "vector_database"),

    # Weaviate Cloud
    (r"Weaviate", "Weaviate", "Weaviate", None, None, 75, "vector_database"),

    # Qdrant Cloud
    (r"Qdrant", "Qdrant", "Qdrant", None, None, 75, "vector_database"),

    # Milvus Cloud (Zilliz)
    (r"Zilliz", "Zilliz Cloud", "Zilliz", None, None, 75, "vector_database"),

    # Hugging Face
    (r"Hugging.*Face", "Hugging Face", "Hugging Face", None, None, 80, "ml_platform"),

    # Replicate
    (r"Replicate", "Replicate", "Replicate", None, None, 75, "ml_platform"),

    # Modal
    (r"Modal", "Modal", "Modal", None, None, 70, "serverless"),

    # Deno Deploy
    (r"Deno.*Deploy", "Deno Deploy", "Deno", None, None, 75, "serverless"),

    # Bun
    (r"Bun.*Cloud", "Bun Cloud", "Bun", None, None, 70, "serverless"),

    # Upbound
    (r"Upbound", "Upbound", "Upbound", None, None, 75, "control_plane"),

    # Pulumi Cloud
    (r"Pulumi.*Cloud", "Pulumi Cloud", "Pulumi", None, None, 75, "iac_service"),

    # Spacelift
    (r"Spacelift", "Spacelift", "Spacelift", None, None, 75, "iac_service"),

    # env0
    (r"env0", "env0", "env0", None, None, 70, "iac_service"),

    # Teleport Cloud
    (r"Teleport", "Teleport", "Teleport", None, None, 80, "access_management"),

    # Tailscale
    (r"Tailscale", "Tailscale", "Tailscale", None, None, 85, "mesh_vpn"),

    # Ngrok
    (r"ngrok", "ngrok", "ngrok", None, None, 80, "tunnel_service"),

    # Cloudflare Spectrum
    (r"Cloudflare.*Spectrum", "Cloudflare Spectrum", "Cloudflare", None, None, 80, "tcp_proxy"),

    # Zscaler
    (r"Zscaler", "Zscaler", "Zscaler", None, None, 85, "security_service"),

    # Netskope
    (r"Netskope", "Netskope", "Netskope", None, None, 85, "security_service"),

    # Palo Alto Prisma
    (r"Prisma.*Cloud", "Prisma Cloud", "Palo Alto", None, None, 85, "cloud_security"),

    # Wiz
    (r"Wiz\.io", "Wiz", "Wiz", None, None, 80, "cloud_security"),

    # Lacework
    (r"Lacework", "Lacework", "Lacework", None, None, 80, "cloud_security"),

    # Orca Security
    (r"Orca.*Security", "Orca Security", "Orca Security", None, None, 80, "cloud_security"),

    # Snyk
    (r"Snyk", "Snyk", "Snyk", None, None, 85, "security_service"),

    # SonarCloud
    (r"SonarCloud", "SonarCloud", "SonarSource", None, None, 80, "code_analysis"),

    # Checkmarx
    (r"Checkmarx", "Checkmarx", "Checkmarx", None, None, 80, "code_analysis"),

    # Veracode
    (r"Veracode", "Veracode", "Veracode", None, None, 80, "code_analysis"),

    # CrowdStrike Falcon
    (r"CrowdStrike", "CrowdStrike Falcon", "CrowdStrike", None, None, 90, "endpoint_security"),
    (r"Falcon", "CrowdStrike Falcon", "CrowdStrike", None, None, 75, "endpoint_security"),

    # SentinelOne
    (r"SentinelOne", "SentinelOne", "SentinelOne", None, None, 85, "endpoint_security"),

    # Carbon Black
    (r"Carbon.*Black", "Carbon Black", "VMware", None, None, 85, "endpoint_security"),

    # Rapid7
    (r"Rapid7", "Rapid7", "Rapid7", None, None, 85, "security_service"),
    (r"InsightVM", "Rapid7 InsightVM", "Rapid7", None, None, 85, "vulnerability_management"),

    # Tenable
    (r"Tenable", "Tenable", "Tenable", None, None, 85, "vulnerability_management"),
    (r"Nessus.*Cloud", "Tenable Nessus", "Tenable", None, None, 85, "vulnerability_scanner"),

    # Qualys
    (r"Qualys", "Qualys", "Qualys", None, None, 85, "vulnerability_management"),

    # 1Password
    (r"1Password", "1Password", "1Password", None, None, 80, "password_management"),

    # LastPass
    (r"LastPass", "LastPass", "GoTo", None, None, 80, "password_management"),

    # Bitwarden
    (r"Bitwarden", "Bitwarden", "Bitwarden", None, None, 80, "password_management"),

    # Keeper
    (r"Keeper.*Security", "Keeper", "Keeper", None, None, 75, "password_management"),

    # Doppler
    (r"Doppler", "Doppler", "Doppler", None, None, 75, "secrets_management"),

    # Vault (HashiCorp)
    (r"HashiCorp.*Vault", "HashiCorp Vault", "HashiCorp", None, None, 90, "secrets_management"),

    # Conjur
    (r"Conjur", "Conjur", "CyberArk", None, None, 80, "secrets_management"),

    # CyberArk
    (r"CyberArk", "CyberArk", "CyberArk", None, None, 85, "privileged_access"),

    # BeyondTrust
    (r"BeyondTrust", "BeyondTrust", "BeyondTrust", None, None, 80, "privileged_access"),

    # Thycotic
    (r"Thycotic", "Thycotic", "Delinea", None, None, 80, "privileged_access"),

    # Delinea
    (r"Delinea", "Delinea", "Delinea", None, None, 80, "privileged_access"),

    # Tencent Cloud
    (r"Tencent.*Cloud", "Tencent Cloud", "Tencent", None, None, 85, "cloud_service"),
    (r"TencentCloud", "Tencent Cloud", "Tencent", None, None, 85, "cloud_service"),

    # Huawei Cloud
    (r"Huawei.*Cloud", "Huawei Cloud", "Huawei", None, None, 80, "cloud_service"),

    # Baidu Cloud
    (r"Baidu.*Cloud", "Baidu Cloud", "Baidu", None, None, 80, "cloud_service"),

    # NTT Cloud
    (r"NTT.*Cloud", "NTT Cloud", "NTT", None, None, 75, "cloud_service"),

    # Rackspace
    (r"Rackspace", "Rackspace", "Rackspace", None, None, 80, "cloud_service"),

    # Equinix Metal
    (r"Equinix.*Metal", "Equinix Metal", "Equinix", None, None, 80, "bare_metal_cloud"),
    (r"Packet", "Equinix Metal", "Equinix", None, None, 75, "bare_metal_cloud"),

    # phoenixNAP
    (r"phoenixNAP", "phoenixNAP", "phoenixNAP", None, None, 70, "bare_metal_cloud"),

    # UpCloud
    (r"UpCloud", "UpCloud", "UpCloud", None, None, 75, "cloud_service"),

    # Exoscale
    (r"Exoscale", "Exoscale", "Exoscale", None, None, 75, "cloud_service"),

    # Kamatera
    (r"Kamatera", "Kamatera", "Kamatera", None, None, 70, "cloud_service"),

    # IONOS
    (r"IONOS", "IONOS Cloud", "IONOS", None, None, 75, "cloud_service"),

    # Contabo
    (r"Contabo", "Contabo", "Contabo", None, None, 70, "vps"),
]


# =============================================================================
# Matching Functions
# =============================================================================

def _match_extended_patterns(banner: str, patterns: list) -> Optional[Dict]:
    """
    Match against extended pattern format (7 elements with device_type).

    Args:
        banner: Service banner string
        patterns: List of extended pattern tuples

    Returns:
        Dict with match info including device_type, or None
    """
    for pattern_tuple in patterns:
        pattern, product, vendor, os_family, version_regex, confidence, device_type = pattern_tuple
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            version = None
            if version_regex:
                version_match = re.search(version_regex, banner, re.IGNORECASE)
                if version_match:
                    version = version_match.group(1)

            return {
                "product": product,
                "vendor": vendor,
                "os_family": os_family,
                "version": version,
                "confidence": confidence,
                "device_type": device_type,
                "matched_pattern": pattern,
            }
    return None


def match_banner(
    protocol: str,
    banner: str
) -> Optional[Dict]:
    """
    Match a service banner against patterns.

    Args:
        protocol: Service protocol (ssh, http, smb, ftp)
        banner: Service banner string

    Returns:
        Dict with match info or None
    """
    if not banner:
        return None

    protocol_lower = protocol.lower()

    # First try extended patterns (IoT, SCADA, Container, etc.) - they have device_type (7 elements)
    # Order matters: more specific patterns first to avoid false positives
    extended_pattern_lists = [
        # Cloud services first (high priority, avoid false positives with IoT)
        CLOUD_PATTERNS,
        # SCADA/ICS (critical infrastructure)
        SCADA_PATTERNS,
        # Virtualization & Containers
        VIRTUALIZATION_PATTERNS,
        CONTAINER_PATTERNS,
        # Security appliances
        SECURITY_PATTERNS,
        # Web services & databases
        WEBAPP_PATTERNS,
        DATABASE_PATTERNS,
        # Communication devices
        COMMUNICATION_PATTERNS,
        # IoT last (has broad patterns that can cause false positives)
        IOT_HTTP_PATTERNS,
    ]

    for pattern_list in extended_pattern_lists:
        result = _match_extended_patterns(banner, pattern_list)
        if result:
            return result

    # Fall back to basic patterns (6 elements without device_type)
    patterns = []
    if protocol_lower in ("ssh", "ssh-2.0"):
        patterns = SSH_PATTERNS
    elif protocol_lower in ("http", "https", "http-proxy"):
        patterns = HTTP_PATTERNS
    elif protocol_lower in ("smb", "microsoft-ds", "netbios-ssn"):
        patterns = SMB_PATTERNS
    elif protocol_lower == "ftp":
        patterns = FTP_PATTERNS
    elif protocol_lower in ("smtp", "smtps", "submission"):
        patterns = SMTP_PATTERNS
    elif protocol_lower in ("imap", "imaps", "pop3", "pop3s"):
        patterns = IMAP_POP_PATTERNS
    elif protocol_lower == "telnet":
        patterns = TELNET_PATTERNS
    elif protocol_lower in ("dns", "domain"):
        patterns = DNS_PATTERNS
    elif protocol_lower in ("ldap", "ldaps"):
        patterns = LDAP_PATTERNS
    elif protocol_lower == "snmp":
        patterns = SNMP_PATTERNS
    elif protocol_lower in ("rdp", "ms-wbt-server", "vnc", "rfb"):
        patterns = RDP_VNC_PATTERNS
    elif protocol_lower in ("sip", "sips", "h323"):
        patterns = SIP_PATTERNS
    elif protocol_lower == "ntp":
        patterns = NTP_PATTERNS
    elif protocol_lower == "mqtt":
        patterns = MQTT_PATTERNS
    elif protocol_lower in ("ipp", "jetdirect", "printer"):
        patterns = PRINTER_PATTERNS
    elif protocol_lower in ("kerberos", "krb5", "kpasswd"):
        patterns = KERBEROS_PATTERNS
    elif protocol_lower in ("radius", "tacacs"):
        patterns = RADIUS_PATTERNS
    elif protocol_lower in ("amqp", "stomp"):
        patterns = MESSAGE_QUEUE_PATTERNS
    elif protocol_lower in ("memcache", "memcached"):
        patterns = CACHE_PATTERNS
    elif protocol_lower in ("rtsp", "rtmp", "rtp"):
        patterns = STREAMING_PATTERNS
    elif protocol_lower in ("git", "svn", "hg"):
        patterns = VCS_PATTERNS
    elif protocol_lower in ("xmpp", "jabber", "irc"):
        patterns = CHAT_PATTERNS
    elif protocol_lower in ("stun", "turn"):
        patterns = WEBRTC_PATTERNS
    elif protocol_lower in ("modbus", "dnp3", "bacnet", "opcua"):
        patterns = INDUSTRIAL_PATTERNS
    elif protocol_lower in ("coap", "lwm2m"):
        patterns = IOT_PROTOCOL_PATTERNS
    elif protocol_lower == "rsync":
        patterns = FILE_SYNC_PATTERNS
    elif protocol_lower in ("grpc", "graphql"):
        patterns = API_PATTERNS
    else:
        # Try all basic patterns for unknown protocols
        patterns = (SSH_PATTERNS + HTTP_PATTERNS + SMB_PATTERNS + FTP_PATTERNS +
                   SMTP_PATTERNS + IMAP_POP_PATTERNS + TELNET_PATTERNS + DNS_PATTERNS +
                   LDAP_PATTERNS + SNMP_PATTERNS + RDP_VNC_PATTERNS + SIP_PATTERNS +
                   NTP_PATTERNS + MQTT_PATTERNS + PRINTER_PATTERNS + GAMING_MEDIA_PATTERNS +
                   NETWORK_PATTERNS + STORAGE_PATTERNS + BACKUP_PATTERNS +
                   KERBEROS_PATTERNS + RADIUS_PATTERNS + MESSAGE_QUEUE_PATTERNS +
                   CACHE_PATTERNS + STREAMING_PATTERNS + VCS_PATTERNS + CHAT_PATTERNS +
                   WEBRTC_PATTERNS + INDUSTRIAL_PATTERNS + IOT_PROTOCOL_PATTERNS +
                   FILE_SYNC_PATTERNS + API_PATTERNS)

    for pattern, product, vendor, os_family, version_regex, confidence in patterns:
        match = re.search(pattern, banner, re.IGNORECASE)
        if match:
            # Extract version if version_regex provided
            version = None
            if version_regex:
                version_match = re.search(version_regex, banner, re.IGNORECASE)
                if version_match:
                    version = version_match.group(1)

            return {
                "product": product,
                "vendor": vendor,
                "os_family": os_family,
                "version": version,
                "confidence": confidence,
                "matched_pattern": pattern,
            }

    return None


def match_banner_extended(banner: str) -> Optional[Dict]:
    """
    Match a banner against all extended pattern lists for device type identification.

    This function is specifically for identifying IoT, SCADA, containers,
    virtualization, and other specialized device types.

    Args:
        banner: Service banner or HTTP response to match

    Returns:
        Dict with product, vendor, os_family, version, confidence, device_type
    """
    if not banner:
        return None

    # Try all extended patterns in priority order (7-element tuples with device_type)
    # Order matters: more specific patterns first to avoid false positives
    pattern_lists = [
        # Cloud services first (high priority, avoid false positives with IoT)
        CLOUD_PATTERNS,
        # SCADA/ICS (critical infrastructure)
        SCADA_PATTERNS,
        # Virtualization & Containers
        VIRTUALIZATION_PATTERNS,
        CONTAINER_PATTERNS,
        # Security appliances
        SECURITY_PATTERNS,
        # Web services & databases
        WEBAPP_PATTERNS,
        DATABASE_PATTERNS,
        # Communication devices
        COMMUNICATION_PATTERNS,
        # IoT last (has broad patterns that can cause false positives)
        IOT_HTTP_PATTERNS,
    ]

    for pattern_list in pattern_lists:
        result = _match_extended_patterns(banner, pattern_list)
        if result:
            return result

    return None
