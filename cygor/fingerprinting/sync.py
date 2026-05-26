"""
FingerprintDB JSON Sync Engine.

Simplified sync engine that writes directly to JSON files.
No SQLite dependency - just downloads, parses, and saves to ~/.cache/cygor/fingerprints/

This is a drop-in replacement for the SQLite-based sync engine.

Data Sources
============
Primary source: Huginn-Muninn (https://github.com/Ringmast4r/Huginn-Muninn)
An internet-crowdsourced OSINT database for device identification with 11.5M+ records.

Source Quality Tiers & Priority
================================
Sources are organized by data quality, comprehensiveness, and uniqueness.
Higher-tier sources should be preferred; lower-tier sources are complementary.

TIER 1 - Primary Sources (Large curated databases, high accuracy):
  - huginn_devices (116K): Hierarchical device profiles from Huginn-Muninn
  - huginn_dhcp_vendor (425K): DHCP Option 60 vendor class IDs
  - huginn_dhcp (368K): DHCP Option 55 fingerprints
  - huginn_dhcpv6 (1.6K): DHCPv6 signatures for IPv6 device fingerprinting
  - huginn_dhcpv6_enterprise (58K): DHCPv6 enterprise IDs for IPv6 vendor identification
  - huginn_mac_vendors (10.1M): Extended MAC vendor database for research/validation
  - ieee_oui/OUI-Master (86K): MAC vendor + device type classification

TIER 2 - Standard Tools (Validated, specialized):
  - p0f: TCP/IP stack fingerprints (de facto standard for passive OS detection)
  - cygor_patterns: Built-in banner patterns (SSH, HTTP, SMB, FTP)

Note: Nmap OS detection uses `nmap -O` which has its own bundled database.

Recommended Sync Strategy:
  - Full sync: All sources for comprehensive coverage
  - Quick sync: Tier 1 only (Huginn-Muninn + OUI)
  - OS detection: p0f + cygor_patterns + nmap -O (active scan)
  - IPv6 networks: Include huginn_dhcpv6 and huginn_dhcpv6_enterprise
"""

import asyncio
import csv
import json
import logging
import re
from datetime import datetime
from io import StringIO
from pathlib import Path
from typing import Optional, Callable, List, Dict, Any, Tuple

import aiohttp

from .cache import get_cache, FingerprintCache

logger = logging.getLogger(__name__)

# Try to import rich for TUI progress bars
try:
    from rich.progress import Progress, TaskID, BarColumn, TextColumn, TimeElapsedColumn, DownloadColumn, TransferSpeedColumn
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    logger.debug("rich library not available, falling back to basic progress output")

# Local p0f fingerprint paths (Kali, Debian, etc.)
P0F_LOCAL_PATHS = [
    "/usr/share/p0f/p0f.fp",      # Kali Linux, Debian
    "/usr/local/share/p0f/p0f.fp", # FreeBSD, manual install
    "/opt/p0f/p0f.fp",             # Custom install
    "/etc/p0f/p0f.fp",             # Alternative location
]

# OUI pattern for parsing IEEE file
OUI_PATTERN = re.compile(r"^([0-9A-F]{2}-[0-9A-F]{2}-[0-9A-F]{2})\s+\(hex\)\s+(.+)$", re.MULTILINE)


class JSONSyncEngine:
    """
    Sync fingerprint databases directly to JSON files.

    No SQLite, no SQLAlchemy - just downloads and JSON.
    Files are stored in ~/.cache/cygor/fingerprints/
    """

    # Sync order (fastest to slowest)
    # Focus on device/OS identification - no JA3/JA4 (those identify TLS clients, not servers)
    # Note: Nmap OS detection uses nmap -O which has its own bundled database
    SYNC_ORDER = [
        "ieee_oui",              # ~5MB, MAC vendor lookup - high value (OUI-Master)
        "p0f",                   # TCP/IP stack fingerprints - OS identification
        "cygor_patterns",        # Built-in banner patterns (SSH, HTTP, SMB, FTP)
        "huginn_devices",        # ~55MB, 116K device profiles from Huginn-Muninn
        "huginn_dhcp",           # ~89MB, 368K DHCP fingerprints from Huginn-Muninn
        "huginn_dhcp_vendor",    # ~62MB, 425K DHCP vendor IDs from Huginn-Muninn
        "huginn_dhcpv6",         # ~1.6K DHCPv6 signatures for IPv6 device identification
        "huginn_dhcpv6_enterprise",  # ~58K DHCPv6 enterprise IDs for IPv6 vendor identification
        "huginn_mac_vendors",    # ~1.5GB, 10.1M MAC vendor mappings from Huginn-Muninn (31 JSON files)
        "satori_ssh",
        "satori_smb",
        "satori_http",
        "satori_useragent",
        "satori_dhcp",
        "satori_sip",
        "huginn_combinations",
        # ── Cloud-provider IP ranges ──
        # These don't go through the URL-download pipeline below — each one
        # has its own parser inside ``cloud_ipranges`` and is dispatched
        # separately by ``sync_fingerprints``. Names use a ``cloud_`` prefix
        # so the dispatch can identify them.
        "cloud_aws",             # AWS published IP ranges (~15K prefixes)
        "cloud_gcp",             # GCP published IP ranges (~900 prefixes)
        "cloud_azure",           # Azure ServiceTags (~100K prefixes; portal scrape)
        "cloud_cloudflare",      # Cloudflare edge IP ranges (~22 prefixes)
        "cloud_digitalocean",    # DigitalOcean published ranges (~1.2K prefixes)
        "cloud_oracle",          # Oracle Cloud published ranges (~1K prefixes)
        "cloud_linode",          # Linode RFC8805 geofeed (~5K prefixes)
        "cloud_hetzner",         # Hetzner via RIPE BGP (AS24940, ~92 prefixes)
        "cloud_ovh",             # OVH via RIPE BGP (AS16276, ~700 prefixes)
        "cloud_vultr",           # Vultr via RIPE BGP (AS20473, ~4K prefixes)
        "cloud_scaleway",        # Scaleway via RIPE BGP (AS12876, ~30 prefixes)
        "cloud_alibaba",         # Alibaba Cloud via RIPE BGP (AS37963 + AS45102, ~2K prefixes)
        "cloud_ibm",             # IBM Cloud / SoftLayer via RIPE BGP (AS36351, ~400 prefixes)
        "cloud_tencent",         # Tencent Cloud via RIPE BGP (AS132203 + AS45090, ~3.4K prefixes)
        "cloud_fastly",          # Fastly via RIPE BGP (AS54113, ~1.7K prefixes)
        "cloud_akamai",          # Akamai via RIPE BGP (AS20940 + AS63949, ~5K prefixes)
    ]

    # Default headers to avoid blocking
    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    # Source URLs - focused on device identification
    # Primary source: Huginn-Muninn (https://github.com/Ringmast4r/Huginn-Muninn)
    SOURCE_URLS = {
        "ieee_oui": {
            # Primary: OUI-Master-Database with device type classifications (86K+ entries)
            "url": "https://raw.githubusercontent.com/Ringmast4r/OUI-Master-Database/master/LISTS/master_oui.csv",
            # Fallback: Standard IEEE OUI file (43K entries, no device type)
            "fallback_url": "https://standards-oui.ieee.org/oui/oui.txt",
            "timeout": 120,
        },
        "p0f": {
            "url": "https://raw.githubusercontent.com/p0f/p0f/master/p0f.fp",
            "timeout": 60,
        },
        # Huginn-Muninn databases (https://github.com/Ringmast4r/Huginn-Muninn)
        # JSON format for easier parsing, actively maintained OSINT database
        "huginn_devices": {
            # 116K device profiles with hierarchical classification
            "url": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Devices/json/device.json",
            "timeout": 300,
            "format": "json",
        },
        "huginn_dhcp": {
            # DHCP Option 55 fingerprints. Upstream split this into part files;
            # they are downloaded and merged into one list before parsing.
            "url_base": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/DHCP_Signatures/json/",
            "files": ["dhcp_fingerprint_part01.json", "dhcp_fingerprint_part02.json"],
            "timeout": 300,
            "format": "json_parts",
        },
        "huginn_dhcp_vendor": {
            # DHCP vendor class identifiers. Upstream split this into part files.
            "url_base": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/DHCP_Vendors/json/",
            "files": ["dhcp_vendor_part01.json", "dhcp_vendor_part02.json"],
            "timeout": 300,
            "format": "json_parts",
        },
        # DHCPv6 databases for IPv6 device identification
        "huginn_dhcpv6": {
            # ~1.6K DHCPv6 signatures (IPv6 option request patterns)
            "url": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/DHCPv6_Signatures/json/dhcpv6_signature.json",
            "timeout": 120,
            "format": "json",
        },
        "huginn_dhcpv6_enterprise": {
            # ~58K DHCPv6 enterprise IDs (vendor identification for IPv6)
            "url": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/DHCPv6_Enterprise/json/dhcpv6_enterprise.json",
            "timeout": 120,
            "format": "json",
        },
        # Satori fingerprint databases (https://github.com/Ringmast4r/Huginn-Muninn/tree/main/Satori_Fingerprints)
        "satori_ssh": {
            "url": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/ssh.json",
            "timeout": 60,
            "format": "json",
        },
        "satori_smb": {
            "url": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/smb.json",
            "timeout": 60,
            "format": "json",
        },
        "satori_http": {
            "url": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/web.json",
            "timeout": 60,
            "format": "json",
        },
        "satori_useragent": {
            "url": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/webuseragent.json",
            "timeout": 60,
            "format": "json",
        },
        "satori_dhcp": {
            "url": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/dhcp.json",
            "timeout": 60,
            "format": "json",
        },
        "satori_sip": {
            "url": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Satori_Fingerprints/json/sip.json",
            "timeout": 60,
            "format": "json",
        },
        # Huginn-Muninn DHCP Combinations
        "huginn_combinations": {
            "url": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/Combinations/json/dhcp_combinations.json",
            "timeout": 120,
            "format": "json",
        },
        # MAC Vendors - 10.1M records split across 31 JSON files (~1.5GB total)
        "huginn_mac_vendors": {
            "url_base": "https://raw.githubusercontent.com/Ringmast4r/Huginn-Muninn/main/MAC_Vendors/json/",
            "files": [
                "mac_vendor_part01.json", "mac_vendor_part02.json", "mac_vendor_part03.json",
                "mac_vendor_part04.json", "mac_vendor_part05.json", "mac_vendor_part06.json",
                "mac_vendor_part07.json", "mac_vendor_part08.json", "mac_vendor_part09.json",
                "mac_vendor_part10.json", "mac_vendor_part11.json", "mac_vendor_part12.json",
                "mac_vendor_part13.json", "mac_vendor_part14.json", "mac_vendor_part15.json",
                "mac_vendor_part16.json", "mac_vendor_part17.json", "mac_vendor_part18.json",
                "mac_vendor_part19.json", "mac_vendor_part20.json", "mac_vendor_part21.json",
                "mac_vendor_part22.json", "mac_vendor_part23.json", "mac_vendor_part24.json",
                "mac_vendor_part25.json", "mac_vendor_part26.json", "mac_vendor_part27.json",
                "mac_vendor_part28.json", "mac_vendor_part29.json", "mac_vendor_part30.json",
                "mac_vendor_part31.json", "mac_vendor_part32.json", "mac_vendor_part33.json",
                "mac_vendor_part34.json",
            ],
            "timeout": 600,  # 10 minutes per file
            "format": "json_multifile",
        },
    }

    # Source display names
    SOURCE_NAMES = {
        "ieee_oui": "OUI Master Database (IEEE+Wireshark+Nmap)",
        "p0f": "p0f TCP/IP Fingerprints",
        "cygor_patterns": "Cygor Built-in Patterns",
        "huginn_devices": "Huginn-Muninn Devices (116K)",
        "huginn_dhcp": "Huginn-Muninn DHCP Signatures (448K)",
        "huginn_dhcp_vendor": "Huginn-Muninn DHCP Vendors (444K)",
        "huginn_dhcpv6": "Huginn-Muninn DHCPv6 Signatures (1.6K)",
        "huginn_dhcpv6_enterprise": "Huginn-Muninn DHCPv6 Enterprise (58K)",
        "huginn_mac_vendors": "Huginn-Muninn MAC Vendors (10.1M)",
        "satori_ssh": "Satori SSH Fingerprints (67)",
        "satori_smb": "Satori SMB Fingerprints (89)",
        "satori_http": "Satori HTTP Server Fingerprints (67)",
        "satori_useragent": "Satori User-Agent Fingerprints (899)",
        "satori_dhcp": "Satori DHCP Fingerprints (481)",
        "satori_sip": "Satori SIP Fingerprints (25)",
        "huginn_combinations": "Huginn-Muninn DHCP Combinations",
        "cloud_aws":          "AWS Published IP Ranges",
        "cloud_gcp":          "GCP Published IP Ranges",
        "cloud_azure":        "Azure ServiceTags (portal scrape)",
        "cloud_cloudflare":   "Cloudflare Edge IP Ranges",
        "cloud_digitalocean": "DigitalOcean Published IP Ranges",
        "cloud_oracle":       "Oracle Cloud Published IP Ranges",
        "cloud_linode":       "Linode RFC8805 Geofeed",
        "cloud_hetzner":      "Hetzner BGP Prefixes (RIPE AS24940)",
        "cloud_ovh":          "OVH BGP Prefixes (RIPE AS16276)",
        "cloud_vultr":        "Vultr BGP Prefixes (RIPE AS20473)",
        "cloud_scaleway":     "Scaleway BGP Prefixes (RIPE AS12876)",
        "cloud_alibaba":      "Alibaba Cloud BGP Prefixes (RIPE AS37963 + AS45102)",
        "cloud_ibm":          "IBM Cloud / SoftLayer BGP Prefixes (RIPE AS36351)",
        "cloud_tencent":      "Tencent Cloud BGP Prefixes (RIPE AS132203 + AS45090)",
        "cloud_fastly":       "Fastly BGP Prefixes (RIPE AS54113)",
        "cloud_akamai":       "Akamai BGP Prefixes (RIPE AS20940 + AS63949)",
    }

    def __init__(self):
        self.cache = get_cache()
        self._http_session: Optional[aiohttp.ClientSession] = None

    @staticmethod
    def find_local_p0f() -> Optional[Path]:
        """Check if p0f fingerprint file exists locally."""
        for path_str in P0F_LOCAL_PATHS:
            path = Path(path_str)
            if path.exists() and path.is_file():
                try:
                    content = path.read_text()
                    if len(content) > 1000 and "label" in content:
                        logger.info(f"Found local p0f fingerprints at {path}")
                        return path
                except Exception as e:
                    logger.debug(f"Could not read {path}: {e}")
        return None

    async def sync_all(
        self,
        force: bool = False,
        sources: List[str] = None,
        use_rich: bool = True
    ) -> Dict[str, int]:
        """
        Sync all fingerprint sources to JSON files.

        Args:
            force: Re-download even if recently synced
            sources: Only sync these sources (None = all)
            use_rich: Use rich TUI progress bars if available

        Returns:
            Dict of source -> record count
        """
        sources_to_sync = sources or self.SYNC_ORDER

        if use_rich and RICH_AVAILABLE:
            return await self._sync_with_rich_progress(sources_to_sync, force)
        else:
            return await self._sync_basic(sources_to_sync, force)

    async def _sync_with_rich_progress(
        self,
        sources: List[str],
        force: bool
    ) -> Dict[str, int]:
        """Sync with rich TUI progress bars."""
        console = Console()
        results = {}

        # Separate download sources from local sources
        download_sources = [s for s in sources if s in self.SOURCE_URLS]
        local_sources = [s for s in sources if s not in self.SOURCE_URLS]

        # Check for local p0f
        local_p0f_path = self.find_local_p0f()
        if local_p0f_path and "p0f" in download_sources:
            console.print(f"[green][+][/green] Using local p0f fingerprints: {local_p0f_path}")
            download_sources.remove("p0f")
            local_sources.append("p0f")

        # Check which sources need sync
        sources_to_download = []
        for source in download_sources:
            if force or self._needs_sync(source):
                sources_to_download.append(source)
            else:
                status = self.cache.get_source_status(source)
                if status:
                    results[source] = status.get("record_count", 0)
                    console.print(f"[dim][i] {self.SOURCE_NAMES.get(source, source)}: cached ({status.get('record_count', 0):,} records)[/dim]")

        if not sources_to_download and not local_sources:
            console.print("[green][+][/green] All sources up to date")
            return results

        # Phase 1: Download
        downloaded_data = {}
        if sources_to_download:
            console.print(f"\n[bold cyan]Phase 1:[/bold cyan] Downloading {len(sources_to_download)} sources...")

            with Progress(
                TextColumn("[bold blue]{task.description}"),
                BarColumn(bar_width=30),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                tasks = {}
                for source in sources_to_download:
                    name = self.SOURCE_NAMES.get(source, source)
                    tasks[source] = progress.add_task(f"[cyan]{name}", total=None)

                connector = aiohttp.TCPConnector(limit=10, limit_per_host=2)
                async with aiohttp.ClientSession(connector=connector) as http:
                    self._http_session = http

                    # Separate multi-file sources from regular sources
                    regular_sources = [s for s in sources_to_download
                                       if self.SOURCE_URLS[s].get("format") != "json_multifile"]
                    multifile_sources = [s for s in sources_to_download
                                         if self.SOURCE_URLS[s].get("format") == "json_multifile"]

                    async def download_one(source: str) -> Tuple[str, Optional[str], Optional[str]]:
                        config = self.SOURCE_URLS[source]
                        content, error = await self._download_with_progress(
                            source, config, progress, tasks[source]
                        )
                        return (source, content, error)

                    # Download regular sources in parallel
                    download_results = await asyncio.gather(
                        *[download_one(s) for s in regular_sources],
                        return_exceptions=True
                    )

                    # Handle multi-file sources sequentially (too large for parallel)
                    for source in multifile_sources:
                        config = self.SOURCE_URLS[source]
                        name = self.SOURCE_NAMES.get(source, source)
                        try:
                            count = await self._download_and_process_multifile_with_progress(
                                source, config, progress, tasks[source], console
                            )
                            # Mark as special "multifile_processed" so we skip in phase 2
                            downloaded_data[source] = ("__multifile_processed__", None)
                            results[source] = count
                            progress.update(tasks[source], description=f"[green][+] {name}")
                        except Exception as e:
                            logger.error(f"Failed to sync multi-file source {source}: {e}")
                            downloaded_data[source] = (None, str(e))
                            progress.update(tasks[source], description=f"[red][x] {name}")

                    self._http_session = None

                    # Process regular download results
                    download_results = list(download_results)  # Convert from tuple

                for result in download_results:
                    if isinstance(result, Exception):
                        logger.error(f"Download exception: {result}")
                        continue
                    source, content, error = result
                    name = self.SOURCE_NAMES.get(source, source)
                    if error:
                        progress.update(tasks[source], description=f"[red][x] {name}")
                        downloaded_data[source] = (None, error)
                    else:
                        progress.update(tasks[source], description=f"[green][+] {name}")
                        downloaded_data[source] = (content, None)

        # Handle local p0f
        if "p0f" in local_sources and local_p0f_path:
            try:
                content = local_p0f_path.read_text()
                downloaded_data["p0f"] = (content, None)
            except Exception as e:
                downloaded_data["p0f"] = (None, str(e))

        # Phase 2: Processing
        console.print(f"\n[bold cyan]Phase 2:[/bold cyan] Processing and saving to JSON...")

        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("|"),
            TextColumn("{task.fields[records]:,} records"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            for source in list(downloaded_data.keys()) + [s for s in local_sources if s not in downloaded_data]:
                name = self.SOURCE_NAMES.get(source, source)
                task = progress.add_task(f"[yellow][~] {name}", total=100, records=0)

                try:
                    if source in downloaded_data:
                        content, error = downloaded_data[source]
                        if error:
                            results[source] = -1
                            progress.update(task, completed=100, description=f"[red][x] {name}", records=0)
                            continue

                        # Skip multi-file sources that were already processed in phase 1
                        if content == "__multifile_processed__":
                            count = results.get(source, 0)
                            progress.update(task, completed=100, description=f"[green][+] {name}", records=count)
                            continue

                        count = self._process_and_save(source, content)
                        results[source] = count
                        progress.update(task, completed=100, description=f"[green][+] {name}", records=count)
                    elif source == "cygor_patterns":
                        count = self._save_builtin_patterns()
                        results[source] = count
                        progress.update(task, completed=100, description=f"[green][+] {name}", records=count)

                except Exception as e:
                    logger.error(f"Failed to process {source}: {e}")
                    results[source] = -1
                    progress.update(task, completed=100, description=f"[red][x] {name}", records=0)

        # Summary table
        console.print("\n")
        table = Table(title="Fingerprint Database Sync Summary")
        table.add_column("Source", style="cyan")
        table.add_column("Records", justify="right", style="green")
        table.add_column("Status", style="bold")

        total = 0
        for source in self.SYNC_ORDER:
            if source in results:
                count = results[source]
                name = self.SOURCE_NAMES.get(source, source)
                if count >= 0:
                    table.add_row(name, f"{count:,}", "[green][+] Success")
                    total += count
                else:
                    table.add_row(name, "-", "[red][x] Failed")

        table.add_row("", "", "")
        table.add_row("[bold]Total", f"[bold]{total:,}", "")

        console.print(table)

        return results

    async def _sync_basic(
        self,
        sources: List[str],
        force: bool
    ) -> Dict[str, int]:
        """Basic sync without rich progress bars (used by web UI background tasks)."""
        results = {}

        connector = aiohttp.TCPConnector(limit=10, limit_per_host=2)
        async with aiohttp.ClientSession(connector=connector) as http:
            self._http_session = http

            for source in sources:
                # Yield before processing each source to keep server responsive
                await asyncio.sleep(0)

                if source not in self.SOURCE_URLS:
                    if source == "cygor_patterns":
                        count = self._save_builtin_patterns()
                        results[source] = count
                        logger.info(f"[+] {self.SOURCE_NAMES.get(source, source)}: {count:,} built-in patterns")
                    else:
                        logger.warning(f"Source {source} not found in SOURCE_URLS")
                    continue

                needs_sync = self._needs_sync(source)
                if not force and not needs_sync:
                    status = self.cache.get_source_status(source)
                    results[source] = status.get("record_count", 0) if status else 0
                    logger.info(f"[i] {self.SOURCE_NAMES.get(source, source)}: cached (skipped, {results[source]:,} records)")
                    continue

                logger.info(f"[*] {self.SOURCE_NAMES.get(source, source)}: needs_sync={needs_sync}, force={force}")

                config = self.SOURCE_URLS[source]
                try:
                    # Handle multi-file sources (like huginn_mac_vendors)
                    if config.get("format") == "json_multifile":
                        logger.info(f"Downloading {source} ({len(config['files'])} files)...")
                        count = await self._download_and_process_multifile(source, config)
                        results[source] = count
                        if count >= 0:
                            logger.info(f"[+] {self.SOURCE_NAMES.get(source, source)}: {count:,} records")
                        else:
                            logger.warning(f"[x] {self.SOURCE_NAMES.get(source, source)}: download failed")
                    else:
                        logger.info(f"Downloading {source}...")
                        content = await self._download_with_yields(source, config)
                        if content:
                            logger.info(f"Processing {source} ({len(content):,} bytes)...")
                            # Use async processing for large files
                            count = await self._process_and_save_async(source, content)
                            results[source] = count
                            logger.info(f"[+] {self.SOURCE_NAMES.get(source, source)}: {count:,} records")
                        else:
                            results[source] = -1
                            logger.warning(f"[x] {self.SOURCE_NAMES.get(source, source)}: download failed")
                except Exception as e:
                    logger.error(f"Failed to sync {source}: {e}")
                    results[source] = -1

            self._http_session = None

        return results

    async def _download_with_progress(
        self,
        source: str,
        config: Dict,
        progress: "Progress",
        task_id: "TaskID"
    ) -> Tuple[Optional[str], Optional[str]]:
        """Download with rich progress updates."""
        # Part-file sources: fetch + merge into one JSON list, then process normally.
        if config.get("format") == "json_parts":
            content = await self._fetch_and_merge_parts(source, config)
            if content is None:
                return (None, f"{source}: failed to download part files")
            try:
                progress.update(task_id, completed=100)
            except Exception:
                pass
            return (content, None)

        urls = [config["url"]]
        if "fallback_url" in config:
            urls.append(config["fallback_url"])

        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 120))
        headers = {**self.DEFAULT_HEADERS, **config.get("headers", {})}

        for url in urls:
            try:
                async with self._http_session.get(url, timeout=timeout, headers=headers) as resp:
                    resp.raise_for_status()

                    total = resp.content_length
                    if total:
                        progress.update(task_id, total=total)

                    chunks = []
                    downloaded = 0
                    async for chunk in resp.content.iter_chunked(8192):
                        chunks.append(chunk)
                        downloaded += len(chunk)
                        progress.update(task_id, completed=downloaded)

                    content = b"".join(chunks).decode("utf-8", errors="ignore")
                    return (content, None)

            except asyncio.TimeoutError:
                logger.warning(f"{source}: Timeout")
            except aiohttp.ClientError as e:
                logger.warning(f"{source}: HTTP error: {e}")
            except Exception as e:
                logger.warning(f"{source}: Error: {e}")

        return (None, "Download failed")

    async def _download_simple(self, source: str, config: Dict) -> Optional[str]:
        """Simple download without progress."""
        urls = [config["url"]]
        if "fallback_url" in config:
            urls.append(config["fallback_url"])

        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 120))
        headers = {**self.DEFAULT_HEADERS, **config.get("headers", {})}

        for url in urls:
            try:
                async with self._http_session.get(url, timeout=timeout, headers=headers) as resp:
                    resp.raise_for_status()
                    return await resp.text()
            except Exception as e:
                logger.warning(f"{source}: {e}")

        return None

    async def _download_with_yields(self, source: str, config: Dict) -> Optional[str]:
        """
        Download with periodic yields to prevent blocking the event loop.

        This method reads data in chunks and yields control to the event loop
        periodically, ensuring the server remains responsive during large downloads.
        """
        # Sources split across part files (same JSON-list structure) are fetched
        # and merged into one list so the normal single-file parser can run.
        if config.get("format") == "json_parts":
            return await self._fetch_and_merge_parts(source, config)

        urls = [config["url"]]
        if "fallback_url" in config:
            urls.append(config["fallback_url"])

        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 300))
        headers = {**self.DEFAULT_HEADERS, **config.get("headers", {})}

        for url in urls:
            try:
                async with self._http_session.get(url, timeout=timeout, headers=headers) as resp:
                    resp.raise_for_status()

                    # Read in chunks with periodic yields
                    chunks = []
                    downloaded = 0
                    chunk_count = 0

                    async for chunk in resp.content.iter_chunked(65536):  # 64KB chunks
                        chunks.append(chunk)
                        downloaded += len(chunk)
                        chunk_count += 1

                        # Yield control every 10 chunks (~640KB)
                        if chunk_count % 10 == 0:
                            await asyncio.sleep(0)

                    content = b"".join(chunks).decode("utf-8", errors="ignore")
                    logger.info(f"{source}: Downloaded {downloaded:,} bytes")
                    return content

            except asyncio.TimeoutError:
                logger.warning(f"{source}: Timeout downloading from {url}")
            except aiohttp.ClientError as e:
                logger.warning(f"{source}: HTTP error: {e}")
            except Exception as e:
                logger.warning(f"{source}: Error: {e}")

        return None

    async def _fetch_and_merge_parts(self, source: str, config: Dict) -> Optional[str]:
        """Download a JSON-list source split across multiple part files and merge
        them into a single JSON array string.

        Upstream (Huginn-Muninn) split some datasets (DHCP signatures/vendors)
        across ``*_partNN.json`` files that share the original item structure.
        Each part is concatenated so the existing single-file parser for the
        source can process the combined result unchanged.
        """
        url_base = config["url_base"]
        files = config["files"]
        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 300), connect=60)
        headers = self.DEFAULT_HEADERS

        merged = []
        for i, filename in enumerate(files):
            url = f"{url_base}{filename}"
            logger.info(f"{source}: downloading part {i+1}/{len(files)}: {filename}")
            try:
                async with self._http_session.get(url, timeout=timeout, headers=headers) as resp:
                    resp.raise_for_status()
                    chunks = []
                    async for chunk in resp.content.iter_chunked(65536):
                        chunks.append(chunk)
                        await asyncio.sleep(0)
                    data = json.loads(b"".join(chunks).decode("utf-8", errors="ignore"))
                if isinstance(data, list):
                    merged.extend(data)
                else:
                    merged.append(data)
                await asyncio.sleep(0)
            except Exception as e:
                logger.error(f"{source}: failed to download/parse {filename}: {e}")
                return None

        logger.info(f"{source}: merged {len(merged):,} records from {len(files)} part files")
        return json.dumps(merged)

    async def _download_and_process_multifile(
        self,
        source: str,
        config: Dict
    ) -> int:
        """
        Download and process multi-file sources (like huginn_mac_vendors).

        Downloads files one at a time to manage memory, processes each file,
        and merges results into a single cache file.
        """
        url_base = config["url_base"]
        files = config["files"]
        # Increase timeout for large files (each file can be ~50MB)
        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 900), connect=60)
        headers = self.DEFAULT_HEADERS

        all_entries = {}
        total_files = len(files)
        failed_files = []

        for i, filename in enumerate(files):
            url = f"{url_base}{filename}"
            logger.info(f"{source}: Downloading file {i+1}/{total_files}: {filename}")

            # Retry logic with exponential backoff for transient errors
            max_retries = 5
            base_delay = 5  # seconds
            file_success = False

            for attempt in range(max_retries):
                retry_delay = base_delay * (2 ** attempt)  # Exponential backoff: 5, 10, 20, 40, 80 seconds

                try:
                    async with self._http_session.get(url, timeout=timeout, headers=headers) as resp:
                        resp.raise_for_status()

                        # Read in chunks with yields
                        chunks = []
                        async for chunk in resp.content.iter_chunked(65536):
                            chunks.append(chunk)
                            await asyncio.sleep(0)

                        content = b"".join(chunks).decode("utf-8", errors="ignore")

                        # Parse JSON and merge entries
                        data = json.loads(content)
                        for item in data:
                            mac = item.get("mac", "").lower()
                            if mac and len(mac) == 6:
                                all_entries[mac] = {
                                    "name": item.get("name", ""),
                                    "device_id": item.get("device_id", "0"),
                                }

                        logger.info(f"{source}: Processed {filename}, total entries: {len(all_entries):,}")

                        # Yield and clear content from memory
                        del content
                        del data
                        await asyncio.sleep(0)
                        file_success = True
                        break  # Success, exit retry loop

                except asyncio.TimeoutError:
                    if attempt < max_retries - 1:
                        logger.warning(f"{source}: Timeout downloading {filename} (attempt {attempt+1}/{max_retries}), retrying in {retry_delay}s...")
                        await asyncio.sleep(retry_delay)
                    else:
                        logger.error(f"{source}: Timeout downloading {filename} after {max_retries} attempts")
                        failed_files.append(filename)
                except aiohttp.ClientError as e:
                    error_str = str(e)
                    # Retry on 5xx errors, rate limits (429), or connection errors
                    should_retry = "50" in error_str or "429" in error_str or "Connection" in error_str
                    if attempt < max_retries - 1 and should_retry:
                        logger.warning(f"{source}: HTTP error for {filename} (attempt {attempt+1}/{max_retries}): {e}, retrying in {retry_delay}s...")
                        await asyncio.sleep(retry_delay)
                    else:
                        logger.error(f"{source}: HTTP error for {filename}: {e}")
                        failed_files.append(filename)
                        break
                except json.JSONDecodeError as e:
                    logger.error(f"{source}: JSON parse error for {filename}: {e}")
                    failed_files.append(filename)
                    break
                except Exception as e:
                    logger.error(f"{source}: Error processing {filename}: {e}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(retry_delay)
                    else:
                        failed_files.append(filename)
                        break

        # Log summary
        if failed_files:
            logger.warning(f"{source}: Failed to download {len(failed_files)}/{total_files} files: {failed_files}")

        if not all_entries:
            logger.error(f"{source}: No entries loaded, sync failed")
            return -1

        # Save to cache even if some files failed (partial data is better than none)
        start_time = datetime.utcnow()
        self.cache.save_huginn_mac_vendors(all_entries)
        duration = (datetime.utcnow() - start_time).total_seconds()
        self.cache.save_sync_status(source, "success", len(all_entries), duration)

        logger.info(f"{source}: Successfully synced {len(all_entries):,} entries from {total_files - len(failed_files)}/{total_files} files")

        return len(all_entries)

    async def _download_and_process_multifile_with_progress(
        self,
        source: str,
        config: Dict,
        progress: "Progress",
        task_id: "TaskID",
        console: "Console"
    ) -> int:
        """
        Download and process multi-file sources with rich progress display.
        """
        url_base = config["url_base"]
        files = config["files"]
        # Increase timeout for large files
        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 900), connect=60)
        headers = self.DEFAULT_HEADERS

        all_entries = {}
        total_files = len(files)
        failed_files = []
        name = self.SOURCE_NAMES.get(source, source)

        # Update progress to show file count
        progress.update(task_id, total=total_files, completed=0,
                        description=f"[cyan]{name} (0/{total_files})")

        for i, filename in enumerate(files):
            url = f"{url_base}{filename}"

            # Retry logic with exponential backoff for transient errors
            max_retries = 5
            base_delay = 5

            for attempt in range(max_retries):
                retry_delay = base_delay * (2 ** attempt)  # Exponential backoff

                try:
                    async with self._http_session.get(url, timeout=timeout, headers=headers) as resp:
                        resp.raise_for_status()

                        chunks = []
                        async for chunk in resp.content.iter_chunked(65536):
                            chunks.append(chunk)

                        content = b"".join(chunks).decode("utf-8", errors="ignore")

                        # Parse JSON and merge entries
                        data = json.loads(content)
                        for item in data:
                            mac = item.get("mac", "").lower()
                            if mac and len(mac) == 6:
                                all_entries[mac] = {
                                    "name": item.get("name", ""),
                                    "device_id": item.get("device_id", "0"),
                                }

                        del content
                        del data
                        break  # Success

                except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                    error_str = str(e)
                    should_retry = "50" in error_str or "429" in error_str or isinstance(e, asyncio.TimeoutError)
                    if attempt < max_retries - 1 and should_retry:
                        logger.warning(f"{source}: Error for {filename} (attempt {attempt+1}/{max_retries}), retrying in {retry_delay}s...")
                        await asyncio.sleep(retry_delay)
                    else:
                        logger.error(f"{source}: Error processing {filename}: {e}")
                        failed_files.append(filename)
                        break
                except Exception as e:
                    logger.error(f"{source}: Error processing {filename}: {e}")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(retry_delay)
                    else:
                        failed_files.append(filename)
                        break

            # Update progress after each file
            progress.update(task_id, completed=i+1,
                            description=f"[cyan]{name} ({i+1}/{total_files})")
            await asyncio.sleep(0)

        # Log summary
        if failed_files:
            console.print(f"[yellow][!] {source}: Failed to download {len(failed_files)}/{total_files} files[/yellow]")

        if not all_entries:
            return -1

        # Save to cache even if some files failed
        start_time = datetime.utcnow()
        self.cache.save_huginn_mac_vendors(all_entries)
        duration = (datetime.utcnow() - start_time).total_seconds()
        self.cache.save_sync_status(source, "success", len(all_entries), duration)

        return len(all_entries)

    def _needs_sync(self, source: str) -> bool:
        """Check if source needs syncing based on age."""
        # Max age in hours for each source
        max_age_hours = {
            "ieee_oui": 168,              # 7 days (updates monthly)
            "p0f": 168,                   # 7 days (rarely changes)
            # Huginn-Muninn sources - actively maintained, sync every 14 days
            "huginn_devices": 336,        # 14 days (stable dataset)
            "huginn_dhcp": 336,           # 14 days (stable dataset)
            "huginn_dhcp_vendor": 336,    # 14 days (stable dataset)
            "huginn_dhcpv6": 336,         # 14 days (stable dataset)
            "huginn_dhcpv6_enterprise": 336,  # 14 days (stable dataset)
            "huginn_mac_vendors": 672,    # 28 days (large dataset, less frequent updates)
        }

        status = self.cache.get_source_status(source)
        if not status or status.get("status") != "success":
            return True

        last_sync = status.get("last_sync")
        if not last_sync:
            return True

        try:
            last_sync_dt = datetime.fromisoformat(last_sync)
            age_hours = (datetime.utcnow() - last_sync_dt).total_seconds() / 3600
            return age_hours >= max_age_hours.get(source, 24)
        except Exception:
            return True

    def _process_and_save(self, source: str, content: str) -> int:
        """Process downloaded content and save to JSON."""
        start_time = datetime.utcnow()

        if source == "ieee_oui":
            count = self._process_oui(content)
        elif source == "p0f":
            count = self._process_p0f(content)
        elif source == "huginn_devices":
            count = self._process_huginn_devices(content)
        elif source == "huginn_dhcp":
            count = self._process_huginn_dhcp(content)
        elif source == "huginn_dhcp_vendor":
            count = self._process_huginn_dhcp_vendor(content)
        elif source == "huginn_dhcpv6":
            count = self._process_huginn_dhcpv6(content)
        elif source == "huginn_dhcpv6_enterprise":
            count = self._process_huginn_dhcpv6_enterprise(content)
        elif source == "huginn_mac_vendors":
            # MAC vendors uses multi-file format, content is already merged
            count = self._process_huginn_mac_vendors(content)
        elif source in ("satori_ssh", "satori_smb", "satori_http",
                        "satori_useragent", "satori_dhcp", "satori_sip"):
            count = self._process_satori_json(source, content)
        elif source == "huginn_combinations":
            count = self._process_huginn_combinations(content)
        else:
            logger.warning(f"Unknown source: {source}")
            return 0

        duration = (datetime.utcnow() - start_time).total_seconds()
        self.cache.save_sync_status(source, "success", count, duration)

        return count

    async def _process_and_save_async(self, source: str, content: str) -> int:
        """
        Process downloaded content and save to JSON with async yields.

        This version yields control back to the event loop periodically
        to prevent blocking during large file processing.
        """
        start_time = datetime.utcnow()

        if source == "ieee_oui":
            count = await self._process_oui_async(content)
        elif source == "p0f":
            count = self._process_p0f(content)  # Small file, no async needed
        elif source == "huginn_devices":
            count = await self._process_huginn_devices_async(content)
        elif source == "huginn_dhcp":
            count = await self._process_huginn_dhcp_async(content)
        elif source == "huginn_dhcp_vendor":
            count = await self._process_huginn_dhcp_vendor_async(content)
        elif source == "huginn_dhcpv6":
            count = await self._process_huginn_dhcpv6_async(content)
        elif source == "huginn_dhcpv6_enterprise":
            count = await self._process_huginn_dhcpv6_enterprise_async(content)
        elif source == "huginn_mac_vendors":
            # MAC vendors uses multi-file format, handled specially
            count = await self._process_huginn_mac_vendors_async(content)
        elif source in ("satori_ssh", "satori_smb", "satori_http",
                        "satori_useragent", "satori_dhcp", "satori_sip"):
            count = self._process_satori_json(source, content)
        elif source == "huginn_combinations":
            count = self._process_huginn_combinations(content)
        else:
            logger.warning(f"Unknown source: {source}")
            return 0

        duration = (datetime.utcnow() - start_time).total_seconds()
        self.cache.save_sync_status(source, "success", count, duration)

        return count

    def _process_oui(self, content: str) -> int:
        """
        Parse OUI data and save to JSON.

        Supports two formats:
        1. OUI-Master CSV (primary): oui,manufacturer,registry,short_name,device_type,...
        2. IEEE OUI text (fallback): XX-XX-XX   (hex)   Vendor Name
        """
        entries = {}

        # Detect format by checking for CSV header
        if content.startswith("oui,manufacturer"):
            # OUI-Master CSV format (86K+ entries with device types)
            entries = self._parse_oui_master_csv(content)
            source_name = "oui_master"
        else:
            # Fallback: IEEE OUI text format
            entries = self._parse_ieee_oui_txt(content)
            source_name = "ieee_oui"

        metadata = {"source": source_name}
        self.cache.save_oui(entries, metadata)
        return len(entries)

    def _parse_oui_master_csv(self, content: str) -> Dict[str, Dict]:
        """
        Parse OUI-Master-Database CSV format.

        CSV columns: oui,manufacturer,registry,short_name,device_type,registered_date,address,sources
        """
        entries = {}

        try:
            reader = csv.DictReader(StringIO(content))

            for row in reader:
                oui_raw = row.get("oui", "").strip()
                if not oui_raw:
                    continue

                # Normalize OUI to colon format (input: 28:6F:B9 or 286FB9)
                oui = oui_raw.upper().replace("-", ":").replace(".", ":")
                if len(oui) == 6:
                    # Format: 286FB9 -> 28:6F:B9
                    oui = f"{oui[0:2]}:{oui[2:4]}:{oui[4:6]}"

                vendor = row.get("manufacturer", "").strip()
                short_name = row.get("short_name", "").strip()
                device_type = row.get("device_type", "").strip()
                registry = row.get("registry", "").strip()
                sources = row.get("sources", "").strip()

                # Use provided short_name or abbreviate
                vendor_short = short_name if short_name else self._abbreviate_vendor(vendor)

                entry = {
                    "vendor": vendor,
                    "vendor_short": vendor_short,
                }

                # Add device_type if present (key feature of OUI-Master)
                if device_type:
                    entry["device_type"] = device_type

                # Add registry type if present
                if registry:
                    entry["registry"] = registry

                # Add sources if present
                if sources:
                    entry["sources"] = sources

                entries[oui] = entry

            logger.info(f"Parsed {len(entries)} OUI entries from OUI-Master CSV")

        except Exception as e:
            logger.error(f"Failed to parse OUI-Master CSV: {e}")

        return entries

    def _parse_ieee_oui_txt(self, content: str) -> Dict[str, Dict]:
        """Parse IEEE OUI text file format (fallback)."""
        entries = {}

        for match in OUI_PATTERN.finditer(content):
            oui_raw = match.group(1)
            vendor = match.group(2).strip()

            # Normalize OUI to colon format
            oui = oui_raw.replace("-", ":").upper()

            # Create abbreviated vendor name
            vendor_short = self._abbreviate_vendor(vendor)

            entries[oui] = {
                "vendor": vendor,
                "vendor_short": vendor_short,
            }

        logger.info(f"Parsed {len(entries)} OUI entries from IEEE OUI text")
        return entries

    async def _process_oui_async(self, content: str) -> int:
        """
        Parse OUI data and save to JSON with async yields.
        """
        entries = {}

        # Detect format by checking for CSV header
        if content.startswith("oui,manufacturer"):
            # OUI-Master CSV format (86K+ entries with device types)
            entries = await self._parse_oui_master_csv_async(content)
            source_name = "oui_master"
        else:
            # Fallback: IEEE OUI text format (smaller, use sync version)
            entries = self._parse_ieee_oui_txt(content)
            source_name = "ieee_oui"

        metadata = {"source": source_name}
        self.cache.save_oui(entries, metadata)
        return len(entries)

    async def _parse_oui_master_csv_async(self, content: str) -> Dict[str, Dict]:
        """
        Parse OUI-Master-Database CSV format with async yields.
        """
        entries = {}
        yield_interval = 5000  # Yield every 5000 rows

        try:
            reader = csv.DictReader(StringIO(content))
            count = 0

            for row in reader:
                oui_raw = row.get("oui", "").strip()
                if not oui_raw:
                    continue

                # Normalize OUI to colon format (input: 28:6F:B9 or 286FB9)
                oui = oui_raw.upper().replace("-", ":").replace(".", ":")
                if len(oui) == 6:
                    # Format: 286FB9 -> 28:6F:B9
                    oui = f"{oui[0:2]}:{oui[2:4]}:{oui[4:6]}"

                vendor = row.get("manufacturer", "").strip()
                short_name = row.get("short_name", "").strip()
                device_type = row.get("device_type", "").strip()
                registry = row.get("registry", "").strip()
                sources = row.get("sources", "").strip()

                # Use provided short_name or abbreviate
                vendor_short = short_name if short_name else self._abbreviate_vendor(vendor)

                entry = {
                    "vendor": vendor,
                    "vendor_short": vendor_short,
                }

                # Add device_type if present (key feature of OUI-Master)
                if device_type:
                    entry["device_type"] = device_type

                # Add registry type if present
                if registry:
                    entry["registry"] = registry

                # Add sources if present
                if sources:
                    entry["sources"] = sources

                entries[oui] = entry
                count += 1

                # Yield control to event loop periodically
                if count % yield_interval == 0:
                    await asyncio.sleep(0)

            logger.info(f"Parsed {len(entries)} OUI entries from OUI-Master CSV")

        except Exception as e:
            logger.error(f"Failed to parse OUI-Master CSV: {e}")

        return entries

    def _abbreviate_vendor(self, vendor: str) -> str:
        """Create abbreviated vendor name."""
        # Common abbreviations
        abbrevs = {
            "Cisco Systems, Inc": "Cisco",
            "Apple, Inc.": "Apple",
            "Dell Inc.": "Dell",
            "Hewlett Packard": "HP",
            "Intel Corporate": "Intel",
            "Microsoft Corporation": "Microsoft",
            "Samsung Electronics Co.,Ltd": "Samsung",
            "VMware, Inc.": "VMware",
            "Ubiquiti Inc": "Ubiquiti",
            "TP-LINK TECHNOLOGIES CO.,LTD.": "TP-Link",
            "Raspberry Pi Foundation": "Raspberry Pi",
        }

        for full, short in abbrevs.items():
            if full.lower() in vendor.lower():
                return short

        # Truncate long names
        if len(vendor) > 30:
            return vendor[:27] + "..."

        return vendor

    def _process_p0f(self, content: str) -> int:
        """Parse p0f fingerprint file and save to cache."""
        entries = []
        current_class = None
        current_label = None

        for line in content.split("\n"):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith(";"):
                continue

            # Class directive
            if line.startswith("[") and line.endswith("]"):
                current_class = line[1:-1]
                continue

            # Label directive
            if line.startswith("label"):
                parts = line.split("=", 1)
                if len(parts) == 2:
                    current_label = parts[1].strip()
                continue

            # Signature line
            if line.startswith("sig"):
                parts = line.split("=", 1)
                if len(parts) == 2:
                    sig = parts[1].strip()

                    # Parse the signature
                    entry = self._parse_p0f_sig(sig, current_class, current_label)
                    if entry:
                        entries.append(entry)

        self.cache.save_tcpip(entries)
        return len(entries)

    def _parse_p0f_sig(self, sig: str, sig_class: str, label: str) -> Optional[Dict]:
        """Parse a p0f signature line."""
        # p0f signature format: ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
        parts = sig.split(":")

        if len(parts) < 6:
            return None

        try:
            # Extract components
            ttl = None
            if parts[1] != "*":
                ttl_str = parts[1].lstrip("s")  # Remove 's' suffix
                if ttl_str.isdigit():
                    ttl = int(ttl_str)

            mss = None
            if parts[3] != "*":
                mss = int(parts[3]) if parts[3].isdigit() else None

            # Parse window size
            wsize_parts = parts[4].split(",")
            window_size = None
            if wsize_parts[0] != "*" and wsize_parts[0].isdigit():
                window_size = int(wsize_parts[0])

            # Parse OS info from label
            os_family = None
            os_version = None
            if label:
                if ":" in label:
                    parts_label = label.split(":")
                    os_family = parts_label[0]
                    os_version = parts_label[1] if len(parts_label) > 1 else None
                else:
                    os_family = label

            return {
                "signature": sig,
                "class": sig_class,
                "label": label or "Unknown",
                "ttl": ttl,
                "window_size": window_size,
                "mss": mss,
                "options": parts[5] if len(parts) > 5 else None,
                "quirks": parts[6] if len(parts) > 6 else None,
                "os_family": os_family,
                "os_version": os_version,
                "confidence": 80,
            }

        except Exception as e:
            logger.debug(f"Failed to parse p0f sig: {sig} - {e}")
            return None

    def _save_builtin_patterns(self) -> int:
        """Save built-in banner patterns to cache."""
        from .patterns import BASIC_PATTERN_LISTS, EXTENDED_PATTERN_LISTS

        entries = []

        # Convert 6-element pattern tuples to dict format
        # Tuple format: (regex, product, vendor, os_family, version_regex, confidence)
        for protocol, patterns in BASIC_PATTERN_LISTS:
            for pattern_tuple in patterns:
                regex, product, vendor, os_family, version_regex, confidence = pattern_tuple
                entries.append({
                    "protocol": protocol,
                    "pattern": regex,
                    "pattern_type": "regex",
                    "product": product,
                    "vendor": vendor,
                    "os_family": os_family,
                    "version_regex": version_regex,
                    "confidence": confidence,
                })

        # Convert 7-element extended pattern tuples to dict format
        # Tuple format: (regex, product, vendor, os_family, version_regex, confidence, device_type)
        for protocol, patterns in EXTENDED_PATTERN_LISTS:
            for pattern_tuple in patterns:
                regex, product, vendor, os_family, version_regex, confidence, device_type = pattern_tuple
                entries.append({
                    "protocol": protocol,
                    "pattern": regex,
                    "pattern_type": "regex",
                    "product": product,
                    "vendor": vendor,
                    "os_family": os_family,
                    "version_regex": version_regex,
                    "confidence": confidence,
                    "device_type": device_type,
                })

        self.cache.save_banners(entries)
        self.cache.save_sync_status("cygor_patterns", "success", len(entries), 0.0)

        return len(entries)

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return self.cache.get_stats()

    # =========================================================================
    # Huginn-Muninn Parsers (JSON format)
    # Source: https://github.com/Ringmast4r/Huginn-Muninn
    # =========================================================================

    def _process_huginn_devices(self, content: str) -> int:
        """
        Parse Huginn-Muninn device profiles JSON and save to cache.

        JSON format: Array of objects with id, name, parent_id, mobile, tablet, simplified_name, etc.
        Builds a hierarchical device classification tree.
        """
        entries = {}
        parent_map = {}  # id -> name for building hierarchy
        id_to_parent = {}  # id -> parent_id for hierarchy building

        try:
            data = json.loads(content)

            # First pass: build parent map and id_to_parent
            for item in data:
                device_id = str(item.get("id", ""))
                name = item.get("name", "")
                parent_id = item.get("parent_id")

                if device_id and name:
                    parent_map[device_id] = name
                    id_to_parent[device_id] = str(parent_id) if parent_id else None

            # Second pass: build entries with hierarchy
            for item in data:
                device_id = str(item.get("id", ""))
                if not device_id:
                    continue

                name = item.get("name", "")
                parent_id = item.get("parent_id")
                parent_id_str = str(parent_id) if parent_id else None

                # Build hierarchy path
                hierarchy = [name]
                current_parent = parent_id_str
                depth = 0
                while current_parent and current_parent in parent_map and depth < 10:
                    hierarchy.insert(0, parent_map[current_parent])
                    current_parent = id_to_parent.get(current_parent)
                    depth += 1

                entry = {
                    "name": name,
                    "parent_id": parent_id_str,
                    "hierarchy": hierarchy,
                    "hierarchy_str": " > ".join(hierarchy),
                    "mobile": bool(item.get("mobile", 0)),
                    "tablet": bool(item.get("tablet", 0)),
                }

                # Add optional fields if present
                if item.get("simplified_name"):
                    entry["simplified_name"] = item.get("simplified_name")
                if item.get("inherit"):
                    entry["inherit"] = bool(item.get("inherit", 0))

                entries[device_id] = entry

            logger.info(f"Parsed {len(entries)} Huginn-Muninn device profiles")

        except Exception as e:
            logger.error(f"Failed to parse Huginn-Muninn devices JSON: {e}")

        self.cache.save_huginn_devices(entries)
        return len(entries)

    def _process_huginn_dhcp(self, content: str) -> int:
        """
        Parse Huginn-Muninn DHCP signatures JSON and save to cache.

        JSON format: Array of objects with id, value (comma-separated options), ignored flag
        """
        entries = {}

        try:
            data = json.loads(content)

            for item in data:
                fp_id = str(item.get("id", ""))
                if not fp_id:
                    continue

                # Skip ignored entries
                if item.get("ignored", 0):
                    continue

                value = item.get("value", "")

                # Parse DHCP options into a list
                dhcp_options = []
                if value:
                    dhcp_options = [opt.strip() for opt in value.split(",") if opt.strip()]

                # Create a hash for quick lookup
                options_hash = self._hash_dhcp_options(value)

                entry = {
                    "value": value,
                    "options": dhcp_options,
                    "options_hash": options_hash,
                }

                entries[fp_id] = entry

            logger.info(f"Parsed {len(entries)} Huginn-Muninn DHCP signatures")

        except Exception as e:
            logger.error(f"Failed to parse Huginn-Muninn DHCP signatures JSON: {e}")

        self.cache.save_huginn_dhcp(entries)
        return len(entries)

    def _process_huginn_dhcp_vendor(self, content: str) -> int:
        """
        Parse Huginn-Muninn DHCP vendor class JSON and save to cache.

        JSON format: Array of objects with id, value (vendor class string)
        """
        entries = {}

        try:
            data = json.loads(content)

            for item in data:
                vendor_id = str(item.get("id", ""))
                if not vendor_id:
                    continue

                value = item.get("value", "")

                entry = {
                    "value": value,
                }

                # Extract vendor/product hints from value
                vendor_hint = self._extract_vendor_from_dhcp_class(value)
                if vendor_hint:
                    entry["vendor_hint"] = vendor_hint

                entries[vendor_id] = entry

            logger.info(f"Parsed {len(entries)} Huginn-Muninn DHCP vendor entries")

        except Exception as e:
            logger.error(f"Failed to parse Huginn-Muninn DHCP vendor JSON: {e}")

        self.cache.save_huginn_dhcp_vendor(entries)
        return len(entries)

    def _process_huginn_dhcpv6(self, content: str) -> int:
        """
        Parse Huginn-Muninn DHCPv6 signatures JSON and save to cache.

        JSON format: Array of objects with id, value (comma-separated DHCPv6 options)
        Used for IPv6 device fingerprinting via DHCPv6 option request patterns.
        """
        entries = {}

        try:
            data = json.loads(content)

            for item in data:
                fp_id = str(item.get("id", ""))
                if not fp_id:
                    continue

                value = item.get("value", "")

                # Parse DHCPv6 options into a list
                dhcpv6_options = []
                if value:
                    dhcpv6_options = [opt.strip() for opt in value.split(",") if opt.strip()]

                # Create a hash for quick lookup
                options_hash = self._hash_dhcp_options(value)

                entry = {
                    "value": value,
                    "options": dhcpv6_options,
                    "options_hash": options_hash,
                }

                entries[fp_id] = entry

            logger.info(f"Parsed {len(entries)} Huginn-Muninn DHCPv6 signatures")

        except Exception as e:
            logger.error(f"Failed to parse Huginn-Muninn DHCPv6 signatures JSON: {e}")

        self.cache.save_huginn_dhcpv6(entries)
        return len(entries)

    def _process_huginn_dhcpv6_enterprise(self, content: str) -> int:
        """
        Parse Huginn-Muninn DHCPv6 enterprise IDs JSON and save to cache.

        JSON format: Array of objects with id, value (enterprise number), organization
        Used for IPv6 vendor identification via DHCPv6 enterprise numbers.
        """
        entries = {}

        try:
            data = json.loads(content)

            for item in data:
                ent_id = str(item.get("id", ""))
                if not ent_id:
                    continue

                value = item.get("value", "")
                organization = item.get("organization", "")

                entry = {
                    "value": value,
                    "organization": organization,
                }

                # Also index by enterprise number for quick lookup
                entries[ent_id] = entry

            logger.info(f"Parsed {len(entries)} Huginn-Muninn DHCPv6 enterprise entries")

        except Exception as e:
            logger.error(f"Failed to parse Huginn-Muninn DHCPv6 enterprise JSON: {e}")

        self.cache.save_huginn_dhcpv6_enterprise(entries)
        return len(entries)

    def _process_huginn_mac_vendors(self, content: str) -> int:
        """
        Parse Huginn-Muninn MAC vendors JSON and save to cache.

        Note: This is a stub for consistency. MAC vendors are processed
        via _download_and_process_multifile due to the large multi-file dataset.
        """
        # This shouldn't normally be called - multi-file sources are handled specially
        entries = {}

        try:
            data = json.loads(content)

            for item in data:
                mac = item.get("mac", "").lower()
                if mac and len(mac) == 6:
                    entries[mac] = {
                        "name": item.get("name", ""),
                        "device_id": item.get("device_id", "0"),
                    }

            logger.info(f"Parsed {len(entries)} Huginn-Muninn MAC vendor entries")

        except Exception as e:
            logger.error(f"Failed to parse Huginn-Muninn MAC vendors JSON: {e}")

        self.cache.save_huginn_mac_vendors(entries)
        return len(entries)

    async def _process_huginn_mac_vendors_async(self, content: str) -> int:
        """
        Parse Huginn-Muninn MAC vendors JSON with async yields.

        Note: This is a stub for consistency. MAC vendors are processed
        via _download_and_process_multifile due to the large multi-file dataset.
        """
        # This shouldn't normally be called - multi-file sources are handled specially
        entries = {}
        yield_interval = 50000

        try:
            data = json.loads(content)
            count = 0

            for item in data:
                mac = item.get("mac", "").lower()
                if mac and len(mac) == 6:
                    entries[mac] = {
                        "name": item.get("name", ""),
                        "device_id": item.get("device_id", "0"),
                    }

                count += 1
                if count % yield_interval == 0:
                    await asyncio.sleep(0)

            logger.info(f"Parsed {len(entries)} Huginn-Muninn MAC vendor entries")

        except Exception as e:
            logger.error(f"Failed to parse Huginn-Muninn MAC vendors JSON: {e}")

        self.cache.save_huginn_mac_vendors(entries)
        return len(entries)

    # =========================================================================
    # Satori & Huginn Combinations Parsers
    # =========================================================================

    def _process_satori_json(self, source: str, content: str) -> int:
        """
        Parse a Satori fingerprint JSON file and save directly to cache.

        Satori sources are JSON arrays of fingerprint objects. We save the
        parsed array directly to the cache file for the corresponding source.
        """
        try:
            data = json.loads(content)
            if not isinstance(data, list):
                logger.warning(f"Satori {source}: expected JSON array, got {type(data).__name__}")
                data = list(data.values()) if isinstance(data, dict) else []

            filepath = self.cache.cache_dir / self.cache.CACHE_FILES[source]
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)

            # Clear the in-memory cache so it reloads from the new file
            cache_attr = f"_{source}_cache"
            if hasattr(self.cache, cache_attr):
                setattr(self.cache, cache_attr, None)

            logger.info(f"Parsed {len(data)} {source} fingerprints")
            return len(data)

        except Exception as e:
            logger.error(f"Failed to parse {source} JSON: {e}")
            return 0

    def _process_huginn_combinations(self, content: str) -> int:
        """
        Parse Huginn-Muninn DHCP combinations JSON and save to cache.

        JSON format: Array or dict of DHCP fingerprint + vendor combinations
        that map to specific device identifications.
        """
        try:
            data = json.loads(content)

            if isinstance(data, list):
                entries = {str(i): v for i, v in enumerate(data)}
            elif isinstance(data, dict):
                entries = data
            else:
                logger.warning(f"huginn_combinations: unexpected type {type(data).__name__}")
                entries = {}

            filepath = self.cache.cache_dir / self.cache.CACHE_FILES["huginn_combinations"]
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(entries, f, indent=2)

            self.cache._huginn_combinations_cache = None
            logger.info(f"Parsed {len(entries)} Huginn-Muninn DHCP combinations")
            return len(entries)

        except Exception as e:
            logger.error(f"Failed to parse huginn_combinations JSON: {e}")
            return 0

    # =========================================================================
    # Async Huginn-Muninn Parsers (with yields to prevent blocking)
    # =========================================================================

    async def _process_huginn_devices_async(self, content: str) -> int:
        """
        Parse Huginn-Muninn device profiles JSON with async yields.
        """
        entries = {}
        parent_map = {}
        id_to_parent = {}
        yield_interval = 5000

        try:
            data = json.loads(content)
            count = 0

            # First pass: build parent map
            for item in data:
                device_id = str(item.get("id", ""))
                name = item.get("name", "")
                parent_id = item.get("parent_id")

                if device_id and name:
                    parent_map[device_id] = name
                    id_to_parent[device_id] = str(parent_id) if parent_id else None

                count += 1
                if count % yield_interval == 0:
                    await asyncio.sleep(0)

            # Second pass: build entries with hierarchy
            count = 0
            for item in data:
                device_id = str(item.get("id", ""))
                if not device_id:
                    continue

                name = item.get("name", "")
                parent_id = item.get("parent_id")
                parent_id_str = str(parent_id) if parent_id else None

                # Build hierarchy path
                hierarchy = [name]
                current_parent = parent_id_str
                depth = 0
                while current_parent and current_parent in parent_map and depth < 10:
                    hierarchy.insert(0, parent_map[current_parent])
                    current_parent = id_to_parent.get(current_parent)
                    depth += 1

                entry = {
                    "name": name,
                    "parent_id": parent_id_str,
                    "hierarchy": hierarchy,
                    "hierarchy_str": " > ".join(hierarchy),
                    "mobile": bool(item.get("mobile", 0)),
                    "tablet": bool(item.get("tablet", 0)),
                }

                if item.get("simplified_name"):
                    entry["simplified_name"] = item.get("simplified_name")
                if item.get("inherit"):
                    entry["inherit"] = bool(item.get("inherit", 0))

                entries[device_id] = entry
                count += 1

                if count % yield_interval == 0:
                    await asyncio.sleep(0)

            logger.info(f"Parsed {len(entries)} Huginn-Muninn device profiles")

        except Exception as e:
            logger.error(f"Failed to parse Huginn-Muninn devices JSON: {e}")

        self.cache.save_huginn_devices(entries)
        return len(entries)

    async def _process_huginn_dhcp_async(self, content: str) -> int:
        """
        Parse Huginn-Muninn DHCP signatures JSON with async yields.
        """
        entries = {}
        yield_interval = 10000

        try:
            data = json.loads(content)
            count = 0

            for item in data:
                fp_id = str(item.get("id", ""))
                if not fp_id:
                    continue

                if item.get("ignored", 0):
                    continue

                value = item.get("value", "")
                dhcp_options = [opt.strip() for opt in value.split(",") if opt.strip()] if value else []
                options_hash = self._hash_dhcp_options(value)

                entry = {
                    "value": value,
                    "options": dhcp_options,
                    "options_hash": options_hash,
                }

                entries[fp_id] = entry
                count += 1

                if count % yield_interval == 0:
                    await asyncio.sleep(0)

            logger.info(f"Parsed {len(entries)} Huginn-Muninn DHCP signatures")

        except Exception as e:
            logger.error(f"Failed to parse Huginn-Muninn DHCP signatures JSON: {e}")

        self.cache.save_huginn_dhcp(entries)
        return len(entries)

    async def _process_huginn_dhcp_vendor_async(self, content: str) -> int:
        """
        Parse Huginn-Muninn DHCP vendor class JSON with async yields.
        """
        entries = {}
        yield_interval = 10000

        try:
            data = json.loads(content)
            count = 0

            for item in data:
                vendor_id = str(item.get("id", ""))
                if not vendor_id:
                    continue

                value = item.get("value", "")

                entry = {
                    "value": value,
                }

                vendor_hint = self._extract_vendor_from_dhcp_class(value)
                if vendor_hint:
                    entry["vendor_hint"] = vendor_hint

                entries[vendor_id] = entry
                count += 1

                if count % yield_interval == 0:
                    await asyncio.sleep(0)

            logger.info(f"Parsed {len(entries)} Huginn-Muninn DHCP vendor entries")

        except Exception as e:
            logger.error(f"Failed to parse Huginn-Muninn DHCP vendor JSON: {e}")

        self.cache.save_huginn_dhcp_vendor(entries)
        return len(entries)

    async def _process_huginn_dhcpv6_async(self, content: str) -> int:
        """
        Parse Huginn-Muninn DHCPv6 signatures JSON with async yields.
        """
        entries = {}
        yield_interval = 1000

        try:
            data = json.loads(content)
            count = 0

            for item in data:
                fp_id = str(item.get("id", ""))
                if not fp_id:
                    continue

                value = item.get("value", "")
                dhcpv6_options = [opt.strip() for opt in value.split(",") if opt.strip()] if value else []
                options_hash = self._hash_dhcp_options(value)

                entry = {
                    "value": value,
                    "options": dhcpv6_options,
                    "options_hash": options_hash,
                }

                entries[fp_id] = entry
                count += 1

                if count % yield_interval == 0:
                    await asyncio.sleep(0)

            logger.info(f"Parsed {len(entries)} Huginn-Muninn DHCPv6 signatures")

        except Exception as e:
            logger.error(f"Failed to parse Huginn-Muninn DHCPv6 signatures JSON: {e}")

        self.cache.save_huginn_dhcpv6(entries)
        return len(entries)

    async def _process_huginn_dhcpv6_enterprise_async(self, content: str) -> int:
        """
        Parse Huginn-Muninn DHCPv6 enterprise IDs JSON with async yields.
        """
        entries = {}
        yield_interval = 5000

        try:
            data = json.loads(content)
            count = 0

            for item in data:
                ent_id = str(item.get("id", ""))
                if not ent_id:
                    continue

                value = item.get("value", "")
                organization = item.get("organization", "")

                entry = {
                    "value": value,
                    "organization": organization,
                }

                entries[ent_id] = entry
                count += 1

                if count % yield_interval == 0:
                    await asyncio.sleep(0)

            logger.info(f"Parsed {len(entries)} Huginn-Muninn DHCPv6 enterprise entries")

        except Exception as e:
            logger.error(f"Failed to parse Huginn-Muninn DHCPv6 enterprise JSON: {e}")

        self.cache.save_huginn_dhcpv6_enterprise(entries)
        return len(entries)

    # =========================================================================
    # Utility Functions
    # =========================================================================

    def _hash_dhcp_options(self, options_str: str) -> str:
        """Create a hash of DHCP options for quick lookup."""
        import hashlib
        normalized = ",".join(sorted(opt.strip() for opt in options_str.split(",") if opt.strip()))
        return hashlib.md5(normalized.encode()).hexdigest()

    def _extract_vendor_from_dhcp_class(self, vendor_class: str) -> Optional[str]:
        """Extract vendor name from DHCP vendor class string."""
        if not vendor_class:
            return None

        vendor_class_lower = vendor_class.lower()

        # Common vendor class patterns
        vendor_patterns = {
            "msft": "Microsoft",
            "cisco": "Cisco",
            "apple": "Apple",
            "android": "Android",
            "linux": "Linux",
            "ubuntu": "Ubuntu",
            "debian": "Debian",
            "redhat": "Red Hat",
            "centos": "CentOS",
            "fedora": "Fedora",
            "vmware": "VMware",
            "dell": "Dell",
            "hp": "HP",
            "lenovo": "Lenovo",
            "xerox": "Xerox",
            "canon": "Canon",
            "epson": "Epson",
            "brother": "Brother",
            "samsung": "Samsung",
            "lg": "LG",
            "sony": "Sony",
            "philips": "Philips",
            "panasonic": "Panasonic",
            "honeywell": "Honeywell",
            "juniper": "Juniper",
            "fortinet": "Fortinet",
            "paloalto": "Palo Alto",
            "aruba": "Aruba",
            "ubiquiti": "Ubiquiti",
            "meraki": "Meraki",
            "synology": "Synology",
            "qnap": "QNAP",
            "netgear": "Netgear",
            "asus": "ASUS",
            "linksys": "Linksys",
            "tp-link": "TP-Link",
            "dlink": "D-Link",
            "zyxel": "ZyXEL",
            "mikrotik": "MikroTik",
            "ruckus": "Ruckus",
            "cambium": "Cambium",
        }

        for pattern, vendor in vendor_patterns.items():
            if pattern in vendor_class_lower:
                return vendor

        return None


# Cloud IP-range source name → cloud_ipranges provider key.
# Lives at module scope so the public sync_fingerprints function can resolve
# entries the JSONSyncEngine doesn't know about.
_CLOUD_SOURCE_TO_PROVIDER: Dict[str, str] = {
    "cloud_aws":          "AWS",
    "cloud_gcp":          "GCP",
    "cloud_azure":        "Azure",
    "cloud_cloudflare":   "Cloudflare",
    "cloud_digitalocean": "DigitalOcean",
    "cloud_oracle":       "Oracle Cloud",
    "cloud_linode":       "Linode",
    "cloud_hetzner":      "Hetzner",
    "cloud_ovh":          "OVH",
    "cloud_vultr":        "Vultr",
    "cloud_scaleway":     "Scaleway",
    "cloud_alibaba":      "Alibaba",
    "cloud_ibm":          "IBM Cloud",
    "cloud_tencent":      "Tencent",
    "cloud_fastly":       "Fastly",
    "cloud_akamai":       "Akamai",
}


def _is_cloud_source(name: str) -> bool:
    return name in _CLOUD_SOURCE_TO_PROVIDER


# Convenience function
async def sync_fingerprints(
    force: bool = False,
    sources: List[str] = None,
    use_rich: bool = True
) -> Dict[str, int]:
    """
    Sync fingerprint databases to JSON files.

    Splits the requested source list into two pipelines:
      - Standard fingerprint sources (Huginn / Satori / OUI / p0f / etc.)
        flow through the existing async URL-download engine.
      - Cloud-provider IP ranges (``cloud_aws`` / ``cloud_gcp`` / etc.) use
        the smaller, parser-per-provider pipeline in ``cloud_ipranges`` —
        each provider's published file has a different schema and the
        synchronous ``requests``-based fetch is plenty fast for ≤10 K
        prefixes total.

    Args:
        force: Re-download even if recently synced (cloud always re-downloads)
        sources: Only sync these sources (None = all in SYNC_ORDER)
        use_rich: Use rich TUI progress bars for the standard pipeline

    Returns:
        Dict of source -> record count. Cloud sources report prefix counts;
        a ``-1`` value means the per-provider sync raised an exception
        (typically network-related) — see logs for detail.
    """
    requested = sources or JSONSyncEngine.SYNC_ORDER

    cloud_sources = [s for s in requested if _is_cloud_source(s)]
    standard_sources = [s for s in requested if not _is_cloud_source(s)]

    results: Dict[str, int] = {}

    # Run the standard pipeline (everything except cloud).
    if standard_sources:
        engine = JSONSyncEngine()
        std_results = await engine.sync_all(
            force=force, sources=standard_sources, use_rich=use_rich,
        )
        results.update(std_results)

    # Run cloud-provider syncs through their own engine.
    if cloud_sources:
        from . import cloud_ipranges
        for source in cloud_sources:
            provider = _CLOUD_SOURCE_TO_PROVIDER[source]
            try:
                count = await asyncio.to_thread(cloud_ipranges.sync_provider, provider)
                results[source] = count
                logger.info(f"Synced {source}: {count} prefixes")
            except Exception as e:
                logger.warning(f"Cloud sync failed for {provider}: {e}")
                results[source] = -1

    return results
