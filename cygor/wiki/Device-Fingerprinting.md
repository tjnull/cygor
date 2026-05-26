# Device Fingerprinting

Comprehensive guide to Cygor's passive device fingerprinting and identification capabilities.

## Overview

Cygor passively identifies devices on the network by correlating multiple data sources including MAC addresses, DHCP options, service banners, TCP/IP stack behavior, and mDNS advertisements. Rather than relying on a single technique, Cygor combines results from several open-source fingerprint databases to produce a confidence-scored device profile that includes manufacturer, device type, OS family, and model information.

The fingerprinting system uses a file-based JSON cache with no database dependency. All fingerprint databases are downloaded on demand and stored locally for offline use.

## Data Sources and Tiers

Fingerprint databases are organized into two tiers based on coverage and specificity.

### Tier 1: Huginn-Muninn Databases

The primary source for device identification is [Huginn-Muninn](https://github.com/Ringmast4r/Huginn-Muninn), an actively maintained OSINT database with millions of fingerprint records.

| Database | Records | Description |
|---|---|---|
| Huginn-Muninn Devices | 116K | Device profiles with hierarchical classification |
| Huginn-Muninn DHCP Signatures | 368K | DHCP Option 55 fingerprints for device identification |
| Huginn-Muninn DHCP Vendors | 425K | DHCP vendor class identifiers |
| Huginn-Muninn DHCPv6 Signatures | 1.6K | DHCPv6 option request patterns for IPv6 devices |
| Huginn-Muninn DHCPv6 Enterprise | 58K | DHCPv6 enterprise IDs for IPv6 vendor identification |
| Huginn-Muninn MAC Vendors | 10.1M | MAC vendor mappings (31 JSON files, ~1.5GB total) |
| Huginn-Muninn DHCP Combinations | - | Combined DHCP option fingerprints |
| OUI Master Database | 86K+ | MAC OUI lookup with device type classifications (IEEE+Wireshark+Nmap) |
| p0f TCP/IP Fingerprints | - | Passive OS detection from TCP/IP stack behavior |

### Tier 2: Satori and Standard Tools

Supplementary databases from the Satori project provide protocol-level fingerprinting.

| Database | Records | Description |
|---|---|---|
| Satori User-Agent | 899 | HTTP User-Agent string fingerprints |
| Satori DHCP | 481 | DHCP fingerprints |
| Satori SMB | 89 | SMB protocol fingerprints |
| Satori SSH | 67 | SSH banner fingerprints |
| Satori HTTP | 67 | HTTP server header fingerprints |
| Satori SIP | 25 | SIP protocol fingerprints |
| Cygor Built-in Patterns | - | Built-in banner patterns for SSH, HTTP, SMB, and FTP |

Additionally, Cygor ships with hardcoded vendor MAC prefix tables for over 30 manufacturers (Cisco, Ubiquiti, MikroTik, Aruba, Fortinet, Apple, Samsung, Dell, HPE, Synology, QNAP, Hikvision, Dahua, Axis, Palo Alto, and others). These provide fast, high-confidence matches without requiring a database download.

## Syncing Fingerprint Databases

### From the Web UI

Navigate to **Settings** in the web UI to sync fingerprint databases. The settings page lets you trigger a full sync or sync individual sources. Progress is reported in real time as each database downloads.

### Sync Order

Databases sync from fastest to slowest to give you usable data as quickly as possible:

1. `ieee_oui` -- OUI Master Database (~5MB)
2. `p0f` -- TCP/IP stack fingerprints
3. `cygor_patterns` -- Built-in banner patterns (local, instant)
4. `huginn_devices` -- Device profiles (~55MB)
5. `huginn_dhcp` -- DHCP signatures (~89MB)
6. `huginn_dhcp_vendor` -- DHCP vendor IDs (~62MB)
7. `huginn_dhcpv6` -- DHCPv6 signatures
8. `huginn_dhcpv6_enterprise` -- DHCPv6 enterprise IDs
9. `huginn_mac_vendors` -- MAC vendors (~1.5GB across 31 files)
10. `satori_ssh`, `satori_smb`, `satori_http`, `satori_useragent`, `satori_dhcp`, `satori_sip`
11. `huginn_combinations` -- DHCP combination fingerprints

The MAC vendors database is the largest at approximately 1.5GB. It downloads as 31 separate JSON files with a 10-minute timeout per file. A stable internet connection is recommended for this source.

### OUI Fallback

The OUI database has a primary source (OUI-Master-Database with device type classifications) and an automatic fallback to the standard IEEE OUI file if the primary is unavailable. The IEEE fallback has fewer entries (43K vs 86K+) and does not include device type information.

### Environment Variables

| Variable | Description |
|---|---|
| `CYGOR_FINGERPRINT_CACHE` | Override the default cache directory path |

## How Fingerprinting Works During Scans

When Cygor runs a scan, the fingerprinting engine processes collected data through multiple lookup methods in sequence:

1. **MAC Address (OUI) Lookup** -- The device's MAC address is checked against hardcoded vendor prefix tables first (35+ manufacturers, confidence 0.88), then against the OUI Master Database for manufacturer and device type.

2. **TCP/IP Stack Analysis (p0f)** -- Passive analysis of TCP/IP stack characteristics (TTL, window size, options) to identify the OS family without sending additional probes.

3. **Service Banner Matching** -- SSH version strings, HTTP server headers, SMB dialect negotiations, and FTP banners are matched against Satori and Cygor's built-in pattern databases.

4. **DHCP Fingerprinting** -- DHCP Option 55 (parameter request list) and Option 60 (vendor class identifier) are matched against the Huginn-Muninn DHCP databases for device type and OS identification. DHCPv6 options are also checked for IPv6 environments.

5. **mDNS Service Discovery** -- Advertised mDNS services are matched to identify device types (printers, media players, IoT devices).

Each lookup produces a `FingerprintMatch` with:

- **source** -- Which method produced the match (oui, tcp, banner, mdns, dhcp, nmap_os, ttl, hostname, http_ua)
- **match_type** -- How precise the match is (exact, pattern, partial, heuristic)
- **confidence** -- Score from 0.0 to 1.0
- **device_type** / **device_category** -- Classification (router, switch, phone, camera, IoT, etc.)
- **manufacturer** / **model** -- Hardware vendor and model when available
- **os_family** / **os_version** / **os_vendor** -- Operating system details

Results from all methods are combined. When multiple sources agree on a device type or manufacturer, the confidence in the final identification increases.

## Cache Directory Structure

All fingerprint data is stored as JSON files under the user's cache directory:

```
~/.cache/cygor/fingerprints/
    oui.json                    # MAC OUI manufacturer lookup
    tcpip.json                  # TCP/IP stack fingerprints (p0f)
    banners.json                # Service banner patterns
    sync_status.json            # Sync status for all sources
    huginn_devices.json         # Huginn-Muninn device profiles
    huginn_dhcp.json            # DHCP Option 55 fingerprints
    huginn_dhcp_vendor.json     # DHCP vendor class IDs
    huginn_dhcpv6.json          # DHCPv6 signatures
    huginn_dhcpv6_enterprise.json  # DHCPv6 enterprise IDs
    huginn_mac_vendors.json     # MAC vendor mappings (merged from 31 source files)
    huginn_combinations.json    # DHCP combination fingerprints
    satori_ssh.json             # Satori SSH fingerprints
    satori_smb.json             # Satori SMB fingerprints
    satori_http.json            # Satori HTTP server fingerprints
    satori_useragent.json       # Satori User-Agent fingerprints
    satori_dhcp.json            # Satori DHCP fingerprints
    satori_sip.json             # Satori SIP fingerprints
    nmap_os_db.json             # Nmap OS fingerprints
```

When running with `sudo`, Cygor automatically resolves the original user's home directory via `SUDO_USER` so that databases downloaded as a normal user are reused rather than re-downloaded into root's cache.

Cache files are lazy-loaded into memory on first use and kept in memory for the duration of the process. There is no expiration -- re-sync from the web UI whenever you want updated databases.

## Web UI Device Info Views

After a scan completes, fingerprinting results are displayed in the web UI alongside port and service data. For each discovered host you can see:

- **Manufacturer** and **device type** derived from MAC OUI and DHCP data
- **OS family** and **version** from banner analysis, p0f, and Nmap OS detection
- **Confidence score** indicating how certain the identification is
- **Match sources** showing which databases contributed to the identification

This information helps prioritize targets during an assessment -- for example, quickly filtering for network infrastructure devices, IoT equipment, or specific operating systems.

## Troubleshooting

### Databases Not Syncing

1. Check your internet connection
2. Verify you can reach `raw.githubusercontent.com`
3. Large databases (MAC vendors) may time out on slow connections -- retry from the settings page
4. Check `sync_status.json` for error details

### No Fingerprint Results

1. Ensure databases have been synced at least once (check the Settings page)
2. MAC-based identification requires Layer 2 visibility (same broadcast domain)
3. DHCP fingerprinting requires captured DHCP traffic
4. Banner matching requires service detection to have run (not discovery-only scans)

### Custom Cache Location

```bash
export CYGOR_FINGERPRINT_CACHE=/path/to/custom/cache
```

## Next Steps

- [Scanning Guide](Scanning-Guide.md)
- [Web UI Quick Start](Web-UI-Quick-Start.md)
- [Common Issues](Common-Issues.md)
