"""
Cygor Enrich - Passive reconnaissance and threat intelligence enrichment

This module provides async parallel enrichment of IOCs (IPs, domains, hashes)
from multiple threat intelligence sources with configurable timeouts, retry logic,
and real-time streaming output.
"""
import argparse
import json
import os
import sys
import re
import csv
import io
import time
import asyncio
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set, Callable, Awaitable, Protocol
from urllib.parse import urlparse
import requests
from colorama import Fore, Style, init

# Async HTTP client
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

# Import proxy configuration
from cygor.proxy_config import get_requests_proxies

init(autoreset=True, strip=False)


# ----------------------------------------------------------------------
# Workspace-aware output helpers
# ----------------------------------------------------------------------
def resolve_output_dir(cli_output_dir: Optional[str] = None) -> Path:
    """
    Resolve output directory using workspace if available.

    Priority:
    1. CLI-specified output directory
    2. Active workspace + enrich/<timestamp>
    There is no implicit cwd fallback; resolution errors out if no workspace
    is configured.
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if cli_output_dir and cli_output_dir not in ("", None):
        outdir = Path(cli_output_dir)
    else:
        from cygor.workspace import require_workspace
        outdir = require_workspace() / "enrich" / ts

    outdir.mkdir(parents=True, exist_ok=True)
    return outdir


# ----------------------------------------------------------------------
# Enrichment Settings and Rate Limiting
# ----------------------------------------------------------------------
@dataclass
class EnrichmentSettings:
    """Configurable timeout and retry settings per source."""
    timeout: float = 30.0           # Default timeout in seconds
    max_retries: int = 3            # Maximum retry attempts
    base_delay: float = 2.0         # Base delay for exponential backoff
    max_delay: float = 60.0         # Cap on delay between retries
    retry_on_status: List[int] = field(default_factory=lambda: [429, 500, 502, 503, 504])


@dataclass
class RateLimitConfig:
    """Per-source rate limit configuration."""
    requests_per_minute: int
    burst_limit: int = 5            # Allow short bursts
    cooldown_on_429: float = 60.0   # Seconds to wait after 429


# Default rate limits (based on free tier limits)
RATE_LIMITS: Dict[str, RateLimitConfig] = {
    "shodan": RateLimitConfig(requests_per_minute=60),
    "virustotal": RateLimitConfig(requests_per_minute=4),   # Free tier: 4/min
    "abuseipdb": RateLimitConfig(requests_per_minute=60),
    "otx": RateLimitConfig(requests_per_minute=60),
    "urlscan": RateLimitConfig(requests_per_minute=60),
    "censys": RateLimitConfig(requests_per_minute=10),
    "greynoise": RateLimitConfig(requests_per_minute=30),
    "spur": RateLimitConfig(requests_per_minute=30),
    "dehashed": RateLimitConfig(requests_per_minute=10),
    "bazaar": RateLimitConfig(requests_per_minute=30),
    "prospeo": RateLimitConfig(requests_per_minute=30),
    "wayback": RateLimitConfig(requests_per_minute=15),     # Public API, be nice
    "commoncrawl": RateLimitConfig(requests_per_minute=10),
}

# Per-source default timeout settings
SOURCE_SETTINGS: Dict[str, EnrichmentSettings] = {
    # Fast APIs
    "abuseipdb": EnrichmentSettings(timeout=15.0, max_retries=3),
    "greynoise": EnrichmentSettings(timeout=15.0, max_retries=3),
    "spur": EnrichmentSettings(timeout=15.0, max_retries=3),
    # Standard APIs
    "shodan": EnrichmentSettings(timeout=20.0, max_retries=3),
    "virustotal": EnrichmentSettings(timeout=30.0, max_retries=3),
    "otx": EnrichmentSettings(timeout=20.0, max_retries=3),
    "urlscan": EnrichmentSettings(timeout=20.0, max_retries=3),
    "censys": EnrichmentSettings(timeout=20.0, max_retries=3),
    "bazaar": EnrichmentSettings(timeout=20.0, max_retries=3),
    "prospeo": EnrichmentSettings(timeout=20.0, max_retries=3),
    # Slow APIs (archives, large datasets)
    "dehashed": EnrichmentSettings(timeout=45.0, max_retries=2),
    "wayback": EnrichmentSettings(timeout=60.0, max_retries=2),
    "commoncrawl": EnrichmentSettings(timeout=60.0, max_retries=2),
}


class RateLimiter:
    """Sliding window rate limiter with per-source tracking."""

    def __init__(self):
        self._windows: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()

    async def acquire(self, source: str) -> None:
        """Wait until rate limit allows request."""
        config = RATE_LIMITS.get(source, RateLimitConfig(requests_per_minute=60))

        async with self._lock:
            now = time.time()
            window = self._windows.setdefault(source, [])

            # Remove requests outside 60s window
            window[:] = [t for t in window if now - t < 60]

            if len(window) >= config.requests_per_minute:
                # Wait until oldest request exits window
                sleep_time = 60 - (now - window[0]) + 0.1
                await asyncio.sleep(sleep_time)

            window.append(time.time())

    async def handle_429(self, source: str) -> None:
        """Handle rate limit response with cooldown."""
        config = RATE_LIMITS.get(source, RateLimitConfig(requests_per_minute=60))
        print(f"{Fore.YELLOW}[!] {source}: Rate limited, cooling down {config.cooldown_on_429:.0f}s{Style.RESET_ALL}")
        await asyncio.sleep(config.cooldown_on_429)


# Global rate limiter instance
_rate_limiter: Optional[RateLimiter] = None


def get_rate_limiter() -> RateLimiter:
    """Get or create global rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = RateLimiter()
    return _rate_limiter


# ----------------------------------------------------------------------
# Streaming Callback Protocol
# ----------------------------------------------------------------------
class EnrichmentCallback(Protocol):
    """Protocol for enrichment result callbacks."""

    async def on_source_start(self, source: str, ioc: str) -> None:
        """Called when a source query begins."""
        ...

    async def on_source_complete(self, source: str, result: Dict[str, Any], elapsed: float) -> None:
        """Called when a source returns results."""
        ...

    async def on_source_error(self, source: str, error: str, elapsed: float) -> None:
        """Called when a source fails/times out."""
        ...

    async def on_ioc_complete(self, ioc: str, all_results: Dict[str, Any]) -> None:
        """Called when all sources for an IOC are complete."""
        ...


class ConsoleStreamCallback:
    """Real-time console output for enrichment results with pentester-focused formatting."""

    def __init__(self):
        self._lock = asyncio.Lock()

    async def on_source_start(self, source: str, ioc: str) -> None:
        """Called when a source query begins."""
        async with self._lock:
            print(f"{Fore.CYAN}[*] {source.upper()}: Querying...{Style.RESET_ALL}")

    async def on_source_complete(self, source: str, result: Dict[str, Any], elapsed: float) -> None:
        """Called when a source returns results - formats for pentesters/blue teamers."""
        async with self._lock:
            if "error" in result:
                print(f"{Fore.YELLOW}[!] {source.upper()} ({elapsed:.1f}s): {result['error']}{Style.RESET_ALL}")
            else:
                self._print_source_result(source, result, elapsed)

    async def on_source_error(self, source: str, error: str, elapsed: float) -> None:
        """Called when a source fails/times out."""
        async with self._lock:
            print(f"{Fore.RED}[x] {source.upper()} ({elapsed:.1f}s): {error}{Style.RESET_ALL}")

    async def on_ioc_complete(self, ioc: str, all_results: Dict[str, Any]) -> None:
        """Called when all sources for an IOC are complete."""
        pass  # Summary handled separately

    def _print_source_result(self, source: str, result: Dict[str, Any], elapsed: float) -> None:
        """Format and print source-specific results with actionable intel."""
        header = f"{Fore.GREEN}[+] {source.upper()} ({elapsed:.1f}s):{Style.RESET_ALL}"

        if source == "shodan":
            self._print_shodan(header, result)
        elif source == "virustotal":
            self._print_virustotal(header, result)
        elif source == "abuseipdb":
            self._print_abuseipdb(header, result)
        elif source == "greynoise":
            self._print_greynoise(header, result)
        elif source == "spur":
            self._print_spur(header, result)
        elif source == "dehashed":
            self._print_dehashed(header, result)
        elif source == "wayback":
            self._print_wayback(header, result)
        elif source == "commoncrawl":
            self._print_commoncrawl(header, result)
        elif source == "censys":
            self._print_censys(header, result)
        elif source == "otx":
            self._print_otx(header, result)
        elif source == "urlscan":
            self._print_urlscan(header, result)
        elif source == "bazaar":
            self._print_bazaar(header, result)
        elif source == "prospeo":
            self._print_prospeo(header, result)
        else:
            print(f"{header}")
            for key, value in result.items():
                if key not in ["source", "ip", "domain"]:
                    print(f"    {key}: {value}")

    def _print_shodan(self, header: str, result: Dict[str, Any]) -> None:
        """Format Shodan results - attack surface focused."""
        print(f"{header}")

        # Check if this is domain or IP result
        if result.get("domain"):
            # Domain enrichment - show subdomains
            print(f"    {Fore.CYAN}DOMAIN INTEL:{Style.RESET_ALL}")

            subdomains = result.get("subdomains", [])
            num_subdomains = result.get("num_subdomains", len(subdomains))

            if num_subdomains > 0:
                print(f"    ├── {Fore.GREEN}{num_subdomains} subdomains discovered{Style.RESET_ALL}")
                # Show first 10 subdomains
                for i, sub in enumerate(subdomains[:10]):
                    prefix = "│   ├──" if i < min(9, len(subdomains[:10]) - 1) else "│   └──"
                    print(f"    {prefix} {sub}.{result.get('domain', '')}")
                if num_subdomains > 10:
                    print(f"    │       ... and {num_subdomains - 10} more")

            resolved_ips = result.get("resolved_ips", [])
            if resolved_ips:
                print(f"    └── Resolved IPs: {', '.join(resolved_ips[:5])}")
        else:
            # IP enrichment - show attack surface
            print(f"    {Fore.CYAN}ATTACK SURFACE:{Style.RESET_ALL}")

            # Organization & Location
            org = result.get("org", "")
            country = result.get("country", "")
            if org or country:
                loc_info = f"{org}" if org else ""
                if country:
                    loc_info += f" ({country})" if loc_info else country
                print(f"    ├── Organization: {loc_info}")

            # Ports with services
            ports = result.get("ports", [])
            services = result.get("services", [])

            if services:
                print(f"    ├── {len(services)} Open Services:")
                for i, svc in enumerate(services[:8]):  # Show up to 8 services
                    port = svc.get("port", "?")
                    transport = svc.get("transport", "tcp")
                    product = svc.get("product", "")
                    version = svc.get("version", "")
                    http_title = svc.get("http_title", "")

                    svc_str = f"{port}/{transport}"
                    if product:
                        svc_str += f" - {product}"
                        if version:
                            svc_str += f" {version}"
                    if http_title:
                        svc_str += f" [{http_title[:30]}...]" if len(http_title) > 30 else f" [{http_title}]"

                    prefix = "│   ├──" if i < min(7, len(services[:8]) - 1) else "│   └──"
                    print(f"    {prefix} {svc_str}")

                if len(services) > 8:
                    print(f"    │       ... and {len(services) - 8} more services")
            elif ports:
                print(f"    ├── Ports: {', '.join(map(str, ports[:15]))}")
                if len(ports) > 15:
                    print(f"    │       ... and {len(ports) - 15} more")

            # Vulnerabilities - critical intel
            vulns = result.get("vulns", [])
            if vulns:
                print(f"    ├── {Fore.RED}VULNERABILITIES ({len(vulns)}):{Style.RESET_ALL}")
                for i, vuln in enumerate(vulns[:5]):
                    prefix = "│   ├──" if i < min(4, len(vulns[:5]) - 1) else "│   └──"
                    print(f"    {prefix} {Fore.RED}{vuln}{Style.RESET_ALL}")
                if len(vulns) > 5:
                    print(f"    │       ... and {len(vulns) - 5} more CVEs")

            # SSL cert info
            ssl_subject = None
            ssl_expires = None
            ssl_issuer = None
            for svc in services:
                if svc.get("ssl_cert_subject"):
                    ssl_subject = svc["ssl_cert_subject"]
                    ssl_expires = svc.get("ssl_cert_expires", "")
                    ssl_issuer = svc.get("ssl_cert_issuer", "")
                    break
            if ssl_subject:
                print(f"    ├── SSL Certificate:")
                print(f"    │   ├── CN: {ssl_subject}")
                if ssl_issuer:
                    print(f"    │   ├── Issuer: {ssl_issuer}")
                if ssl_expires:
                    print(f"    │   └── Expires: {ssl_expires}")

            # Hostnames
            hostnames = result.get("hostnames", [])
            if hostnames:
                print(f"    └── Hostnames: {', '.join(hostnames[:5])}")

    def _print_virustotal(self, header: str, result: Dict[str, Any]) -> None:
        """Format VirusTotal results - reputation focused."""
        print(f"{header}")
        print(f"    {Fore.CYAN}THREAT INTELLIGENCE:{Style.RESET_ALL}")

        mal = result.get("malicious", 0)
        sus = result.get("suspicious", 0)
        harm = result.get("harmless", 0)
        total = mal + sus + harm

        # Detection status with color coding
        if mal > 0:
            print(f"    ├── {Fore.RED}Detection: {mal}/{total} engines flagged MALICIOUS{Style.RESET_ALL}")
        elif sus > 0:
            print(f"    ├── {Fore.YELLOW}Detection: {sus}/{total} engines flagged suspicious{Style.RESET_ALL}")
        else:
            print(f"    ├── {Fore.GREEN}Detection: Clean (0/{total} engines){Style.RESET_ALL}")

        # Reputation score
        rep = result.get("reputation", 0)
        if rep != 0:
            rep_color = Fore.GREEN if rep > 0 else Fore.RED
            print(f"    ├── Reputation Score: {rep_color}{rep}{Style.RESET_ALL}")

        # Categories (useful for domain classification)
        categories = result.get("categories", {})
        if categories:
            cat_list = list(categories.values())[:3]
            if cat_list:
                print(f"    ├── Categories: {', '.join(cat_list)}")

        # DNS Records - crucial for pentesters
        dns_records = result.get("last_dns_records", [])
        if dns_records:
            print(f"    ├── DNS Records ({len(dns_records)}):")
            # Group by type
            a_records = [r for r in dns_records if r.get("type") == "A"]
            mx_records = [r for r in dns_records if r.get("type") == "MX"]
            txt_records = [r for r in dns_records if r.get("type") == "TXT"]
            ns_records = [r for r in dns_records if r.get("type") == "NS"]

            if a_records:
                ips = [r.get("value", "") for r in a_records[:5]]
                print(f"    │   ├── A: {', '.join(ips)}")
            if mx_records:
                mx = [r.get("value", "") for r in mx_records[:3]]
                print(f"    │   ├── MX: {', '.join(mx)}")
            if ns_records:
                ns = [r.get("value", "") for r in ns_records[:3]]
                print(f"    │   ├── NS: {', '.join(ns)}")
            if txt_records:
                # TXT records can reveal SPF, DKIM, etc
                for txt in txt_records[:2]:
                    val = txt.get("value", "")[:60]
                    print(f"    │   ├── TXT: {val}...")

        # WHOIS info
        if result.get("registrar"):
            print(f"    ├── Registrar: {result['registrar']}")
        if result.get("creation_date"):
            print(f"    ├── Created: {result['creation_date']}")

        # Popularity ranks
        ranks = result.get("popularity_ranks", {})
        if ranks:
            rank_strs = [f"{k}: #{v.get('rank', '?')}" for k, v in list(ranks.items())[:2]]
            if rank_strs:
                print(f"    └── Rankings: {', '.join(rank_strs)}")

    def _print_abuseipdb(self, header: str, result: Dict[str, Any]) -> None:
        """Format AbuseIPDB results - reputation/abuse focused."""
        print(f"{header}")
        print(f"    {Fore.CYAN}REPUTATION:{Style.RESET_ALL}")

        confidence = result.get("abuse_confidence", 0)
        reports = result.get("total_reports", 0)

        if confidence >= 50:
            print(f"    \u251c\u2500\u2500 {Fore.RED}Confidence of Abuse: {confidence}%{Style.RESET_ALL}")
        elif confidence > 0:
            print(f"    \u251c\u2500\u2500 {Fore.YELLOW}Confidence of Abuse: {confidence}%{Style.RESET_ALL}")
        else:
            print(f"    \u251c\u2500\u2500 {Fore.GREEN}Confidence of Abuse: {confidence}%{Style.RESET_ALL}")

        print(f"    \u251c\u2500\u2500 Total Reports: {reports}")

        if result.get("isp"):
            print(f"    \u251c\u2500\u2500 ISP: {result['isp']}")

        if result.get("usage_type"):
            print(f"    \u2514\u2500\u2500 Usage Type: {result['usage_type']}")

    def _print_greynoise(self, header: str, result: Dict[str, Any]) -> None:
        """Format GreyNoise results - noise classification."""
        print(f"{header}")
        print(f"    {Fore.CYAN}NOISE CLASSIFICATION:{Style.RESET_ALL}")

        classification = result.get("classification", "unknown")
        noise = result.get("noise", False)
        riot = result.get("riot", False)

        if riot:
            print(f"    \u251c\u2500\u2500 {Fore.GREEN}RIOT: Benign service (e.g., CDN, crawler){Style.RESET_ALL}")
        elif classification == "malicious":
            print(f"    \u251c\u2500\u2500 {Fore.RED}Classification: MALICIOUS{Style.RESET_ALL}")
        elif noise:
            print(f"    \u251c\u2500\u2500 {Fore.YELLOW}Status: Internet background noise/scanner{Style.RESET_ALL}")
        else:
            print(f"    \u251c\u2500\u2500 Status: Not observed in internet noise")

        if result.get("actor"):
            print(f"    \u251c\u2500\u2500 Actor: {result['actor']}")

        if result.get("tags"):
            print(f"    \u2514\u2500\u2500 Tags: {', '.join(result['tags'][:5])}")

    def _print_spur(self, header: str, result: Dict[str, Any]) -> None:
        """Format Spur results - VPN/proxy detection."""
        print(f"{header}")
        print(f"    {Fore.CYAN}ANONYMIZATION:{Style.RESET_ALL}")

        flags = []
        if result.get("vpn"):
            flags.append(f"{Fore.YELLOW}VPN{Style.RESET_ALL}")
        if result.get("proxy"):
            flags.append(f"{Fore.YELLOW}Proxy{Style.RESET_ALL}")
        if result.get("datacenter"):
            flags.append("Datacenter")
        if result.get("tor"):
            flags.append(f"{Fore.RED}Tor{Style.RESET_ALL}")

        if flags:
            print(f"    \u251c\u2500\u2500 Detected: {', '.join(flags)}")
        else:
            print(f"    \u251c\u2500\u2500 {Fore.GREEN}No anonymization detected{Style.RESET_ALL}")

        if result.get("organization"):
            print(f"    \u2514\u2500\u2500 Organization: {result['organization']}")

    def _print_dehashed(self, header: str, result: Dict[str, Any]) -> None:
        """Format Dehashed results - credential focused."""
        print(f"{header}")
        print(f"    {Fore.CYAN}BREACH DATA / CREDENTIALS:{Style.RESET_ALL}")

        total = result.get("total_entries", result.get("retrieved_entries", 0))
        emails = result.get("unique_emails", 0)
        usernames = result.get("unique_usernames", 0)
        passwords = result.get("unique_passwords", 0)
        hashes = result.get("unique_hashes", 0)

        if total > 0:
            print(f"    ├── {Fore.YELLOW}{total:,} breach entries found{Style.RESET_ALL}")

            # Emails found
            if emails > 0:
                print(f"    ├── {emails:,} unique emails")
                sample_emails = result.get("sample_emails", [])
                if sample_emails:
                    for i, email in enumerate(sample_emails[:3]):
                        prefix = "│   ├──" if i < 2 else "│   └──"
                        print(f"    {prefix} {email}")

            # Usernames found
            if usernames > 0:
                print(f"    ├── {usernames:,} unique usernames")
                sample_usernames = result.get("sample_usernames", [])
                if sample_usernames:
                    print(f"    │   └── e.g.: {', '.join(sample_usernames[:5])}")

            # Passwords - critical for spray attacks
            if passwords > 0:
                print(f"    ├── {Fore.RED}{passwords:,} passwords found (SPRAY CANDIDATES){Style.RESET_ALL}")

            if hashes > 0:
                print(f"    ├── {hashes:,} password hashes (for cracking)")

            # Breach sources
            databases = result.get("breach_databases", result.get("databases", []))
            if databases:
                print(f"    ├── Breach Sources:")
                for i, db in enumerate(databases[:5]):
                    prefix = "│   ├──" if i < min(4, len(databases[:5]) - 1) else "│   └──"
                    print(f"    {prefix} {db}")
                if len(databases) > 5:
                    print(f"    │       ... and {len(databases) - 5} more breaches")

            # Spray list files saved
            saved_files = result.get("saved_files", {})
            if saved_files:
                print(f"    ├── {Fore.GREEN}SPRAY LISTS GENERATED:{Style.RESET_ALL}")
                if saved_files.get("emails"):
                    print(f"    │   ├── Emails: {saved_files['emails']}")
                if saved_files.get("usernames"):
                    print(f"    │   ├── Usernames: {saved_files['usernames']}")
                if saved_files.get("passwords"):
                    print(f"    │   └── Passwords: {saved_files['passwords']}")

            # API balance remaining
            balance = result.get("api_balance", 0)
            if balance > 0:
                print(f"    └── API Balance: {balance:,} credits remaining")
        else:
            print(f"    └── {Fore.GREEN}No breach data found{Style.RESET_ALL}")

    def _print_wayback(self, header: str, result: Dict[str, Any]) -> None:
        """Format Wayback results - historical recon."""
        print(f"{header}")
        print(f"    {Fore.CYAN}HISTORICAL RECON:{Style.RESET_ALL}")

        snapshots = result.get("estimated_total_snapshots", result.get("total_snapshots", 0))
        urls = result.get("unique_urls", 0)
        subdomains = result.get("subdomains", {})
        subdomain_count = subdomains.get("count", 0) if isinstance(subdomains, dict) else len(subdomains) if isinstance(subdomains, list) else 0
        subdomain_list = subdomains.get("list", []) if isinstance(subdomains, dict) else subdomains if isinstance(subdomains, list) else []

        print(f"    ├── {snapshots:,} archived snapshots")
        print(f"    ├── {urls:,} unique URLs discovered")

        # Subdomains - critical for pentesters
        if subdomain_count > 0:
            print(f"    ├── {Fore.GREEN}{subdomain_count} subdomains discovered:{Style.RESET_ALL}")
            for i, sub in enumerate(subdomain_list[:8]):
                prefix = "│   ├──" if i < min(7, len(subdomain_list[:8]) - 1) else "│   └──"
                print(f"    {prefix} {sub}")
            if subdomain_count > 8:
                print(f"    │       ... and {subdomain_count - 8} more")

        # Interesting file extensions - potential sensitive files
        extensions = result.get("file_extensions", [])
        if extensions:
            # Categorize extensions by risk
            backup_exts = [e for e in extensions if e in [".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp"]]
            config_exts = [e for e in extensions if e in [".config", ".conf", ".cfg", ".ini", ".env", ".yml", ".yaml", ".xml"]]
            data_exts = [e for e in extensions if e in [".sql", ".db", ".sqlite", ".mdb", ".json", ".csv"]]
            archive_exts = [e for e in extensions if e in [".zip", ".tar", ".gz", ".rar", ".7z", ".tar.gz"]]
            code_exts = [e for e in extensions if e in [".php", ".asp", ".aspx", ".jsp", ".cgi", ".pl"]]

            if backup_exts or config_exts or data_exts or archive_exts:
                print(f"    ├── {Fore.YELLOW}Potentially Sensitive Files:{Style.RESET_ALL}")
                if backup_exts:
                    print(f"    │   ├── Backups: {', '.join(backup_exts)}")
                if config_exts:
                    print(f"    │   ├── Configs: {', '.join(config_exts)}")
                if data_exts:
                    print(f"    │   ├── Data files: {', '.join(data_exts)}")
                if archive_exts:
                    print(f"    │   └── Archives: {', '.join(archive_exts)}")

            if code_exts:
                print(f"    ├── Server-side: {', '.join(code_exts)}")

        # Sample URLs if available
        archived_urls = result.get("archived_urls", [])
        if archived_urls:
            # Filter for interesting paths
            interesting_paths = []
            for url in archived_urls[:50]:
                path = url.lower()
                if any(p in path for p in ["/admin", "/api", "/backup", "/config", "/upload", "/login", "/dashboard", "/phpmyadmin", "/wp-admin", "/.git", "/.env"]):
                    interesting_paths.append(url)

            if interesting_paths:
                print(f"    ├── {Fore.YELLOW}Interesting Paths Found:{Style.RESET_ALL}")
                for i, path in enumerate(interesting_paths[:5]):
                    # Truncate long URLs
                    display_path = path if len(path) < 70 else path[:67] + "..."
                    prefix = "│   ├──" if i < min(4, len(interesting_paths[:5]) - 1) else "│   └──"
                    print(f"    {prefix} {display_path}")
                if len(interesting_paths) > 5:
                    print(f"    │       ... and {len(interesting_paths) - 5} more")

        # File saved location
        if result.get("subdomain_file"):
            print(f"    └── {Fore.GREEN}Subdomains saved to: {result['subdomain_file']}{Style.RESET_ALL}")

    def _print_commoncrawl(self, header: str, result: Dict[str, Any]) -> None:
        """Format CommonCrawl results."""
        print(f"{header}")
        print(f"    {Fore.CYAN}WEB CRAWL DATA:{Style.RESET_ALL}")

        urls = result.get("total_urls", result.get("urls_count", 0))
        subdomains = result.get("subdomains", {})
        subdomain_count = subdomains.get("count", 0) if isinstance(subdomains, dict) else len(subdomains) if isinstance(subdomains, list) else 0
        subdomain_list = subdomains.get("list", []) if isinstance(subdomains, dict) else subdomains if isinstance(subdomains, list) else []

        print(f"    ├── {urls:,} indexed URLs")

        if subdomain_count > 0:
            print(f"    ├── {Fore.GREEN}{subdomain_count} subdomains discovered:{Style.RESET_ALL}")
            for i, sub in enumerate(subdomain_list[:6]):
                prefix = "│   ├──" if i < min(5, len(subdomain_list[:6]) - 1) else "│   └──"
                print(f"    {prefix} {sub}")
            if subdomain_count > 6:
                print(f"    │       ... and {subdomain_count - 6} more")

        # Show crawled URLs if available
        crawled_urls = result.get("urls", [])
        if crawled_urls:
            print(f"    └── Sample URLs found: {len(crawled_urls)}")

    def _print_censys(self, header: str, result: Dict[str, Any]) -> None:
        """Format Censys results - infrastructure focused."""
        print(f"{header}")
        print(f"    {Fore.CYAN}INFRASTRUCTURE:{Style.RESET_ALL}")

        services = result.get("services", [])
        if services:
            print(f"    ├── {len(services)} services detected:")
            for i, svc in enumerate(services[:6]):
                port = svc.get("port", "?")
                service_name = svc.get("service_name", svc.get("protocol", "unknown"))
                software = svc.get("software", {})
                product = software.get("product", "") if isinstance(software, dict) else ""
                version = software.get("version", "") if isinstance(software, dict) else ""

                svc_str = f"{port} - {service_name}"
                if product:
                    svc_str += f" ({product}"
                    if version:
                        svc_str += f" {version}"
                    svc_str += ")"

                prefix = "│   ├──" if i < min(5, len(services[:6]) - 1) else "│   └──"
                print(f"    {prefix} {svc_str}")

            if len(services) > 6:
                print(f"    │       ... and {len(services) - 6} more")

        # ASN info
        asn = result.get("autonomous_system", {})
        if asn:
            asn_name = asn.get("name", "") if isinstance(asn, dict) else asn
            asn_num = asn.get("asn", "") if isinstance(asn, dict) else ""
            if asn_name or asn_num:
                print(f"    ├── ASN: {asn_num} - {asn_name}" if asn_num else f"    ├── ASN: {asn_name}")

        # Location
        location = result.get("location", {})
        if location:
            country = location.get("country", "")
            city = location.get("city", "")
            if country or city:
                loc_str = f"{city}, {country}" if city and country else country or city
                print(f"    ├── Location: {loc_str}")

        # Certificates
        certs = result.get("certificates", [])
        if certs:
            print(f"    └── {len(certs)} SSL certificates found")

    def _print_otx(self, header: str, result: Dict[str, Any]) -> None:
        """Format OTX results - threat intel."""
        print(f"{header}")
        print(f"    {Fore.CYAN}THREAT INTEL (AlienVault OTX):{Style.RESET_ALL}")

        pulses = result.get("pulse_count", result.get("pulse_info", {}).get("count", 0) if isinstance(result.get("pulse_info"), dict) else 0)

        if pulses > 0:
            print(f"    ├── {Fore.YELLOW}Referenced in {pulses} threat pulse(s){Style.RESET_ALL}")

            # Show pulse names if available
            pulse_info = result.get("pulse_info", {})
            pulse_list = pulse_info.get("pulses", []) if isinstance(pulse_info, dict) else []
            if pulse_list:
                print(f"    ├── Recent Pulses:")
                for i, pulse in enumerate(pulse_list[:3]):
                    name = pulse.get("name", "Unknown")[:50]
                    prefix = "│   ├──" if i < min(2, len(pulse_list[:3]) - 1) else "│   └──"
                    print(f"    {prefix} {name}")
        else:
            print(f"    ├── {Fore.GREEN}No threat pulses - not seen in threat reports{Style.RESET_ALL}")

        # WHOIS data if available
        whois = result.get("whois", {})
        if whois:
            registrar = whois.get("registrar", "")
            if registrar:
                print(f"    ├── Registrar: {registrar}")

        # Reputation
        rep = result.get("reputation", 0)
        if rep != 0:
            rep_color = Fore.GREEN if rep >= 0 else Fore.RED
            print(f"    └── Reputation: {rep_color}{rep}{Style.RESET_ALL}")

    def _print_urlscan(self, header: str, result: Dict[str, Any]) -> None:
        """Format URLScan results."""
        print(f"{header}")
        print(f"    {Fore.CYAN}LIVE RECON:{Style.RESET_ALL}")

        scans = result.get("total_scans", result.get("total", 0))
        print(f"    ├── {scans} recent scans found")

        # Show scan results if available
        scan_results = result.get("results", [])
        if scan_results:
            print(f"    ├── Recent Scans:")
            for i, scan in enumerate(scan_results[:4]):
                page = scan.get("page", {})
                url = page.get("url", scan.get("task", {}).get("url", ""))[:60]
                status = page.get("status", "")
                server = page.get("server", "")

                scan_info = url
                if status:
                    scan_info += f" [{status}]"
                if server:
                    scan_info += f" - {server}"

                prefix = "│   ├──" if i < min(3, len(scan_results[:4]) - 1) else "│   └──"
                print(f"    {prefix} {scan_info}")

        # Technologies detected
        if result.get("technologies"):
            techs = result["technologies"][:5]
            print(f"    ├── Technologies: {', '.join(techs)}")

        if result.get("last_scan_url"):
            print(f"    └── View latest: {result['last_scan_url'][:70]}")

    def _print_bazaar(self, header: str, result: Dict[str, Any]) -> None:
        """Format MalwareBazaar results."""
        print(f"{header}")
        print(f"    {Fore.CYAN}MALWARE INTEL:{Style.RESET_ALL}")

        samples = result.get("sample_count", result.get("query_status") == "ok")
        if samples and samples > 0:
            print(f"    ├── {Fore.RED}{samples} malware sample(s) associated{Style.RESET_ALL}")

            # Signature/family
            sig = result.get("signature", result.get("malware_family", ""))
            if sig:
                print(f"    ├── Family/Signature: {Fore.RED}{sig}{Style.RESET_ALL}")

            # File type
            file_type = result.get("file_type", "")
            if file_type:
                print(f"    ├── File Type: {file_type}")

            # First/last seen
            first_seen = result.get("first_seen", "")
            if first_seen:
                print(f"    ├── First Seen: {first_seen}")

            # Tags
            tags = result.get("tags", [])
            if tags:
                print(f"    ├── Tags: {', '.join(tags[:6])}")

            # C2 indicators
            if result.get("c2_url") or result.get("c2_ip"):
                print(f"    ├── {Fore.RED}C2 Indicators Found{Style.RESET_ALL}")

            # Hash if available
            sha256 = result.get("sha256_hash", "")
            if sha256:
                print(f"    └── SHA256: {sha256[:16]}...")
        else:
            print(f"    └── {Fore.GREEN}No malware samples associated{Style.RESET_ALL}")

    def _print_prospeo(self, header: str, result: Dict[str, Any]) -> None:
        """Format Prospeo results - email enumeration."""
        print(f"{header}")
        print(f"    {Fore.CYAN}EMAIL ENUMERATION:{Style.RESET_ALL}")

        emails_found = result.get("emails_found", result.get("email_count", 0))
        emails_list = result.get("emails", [])

        if emails_found > 0 or emails_list:
            count = emails_found or len(emails_list)
            print(f"    ├── {Fore.GREEN}{count} email addresses discovered{Style.RESET_ALL}")

            # Show sample emails
            if emails_list:
                print(f"    ├── Sample Emails:")
                for i, email in enumerate(emails_list[:5]):
                    email_str = email if isinstance(email, str) else email.get("email", "")
                    prefix = "│   ├──" if i < min(4, len(emails_list[:5]) - 1) else "│   └──"
                    print(f"    {prefix} {email_str}")
                if len(emails_list) > 5:
                    print(f"    │       ... and {len(emails_list) - 5} more")

            # Email pattern detection
            pattern = result.get("email_pattern", result.get("format", ""))
            if pattern:
                print(f"    ├── Detected Pattern: {Fore.YELLOW}{pattern}{Style.RESET_ALL}")

            # Department breakdown if available
            departments = result.get("departments", {})
            if departments:
                dept_strs = [f"{k}: {v}" for k, v in list(departments.items())[:3]]
                print(f"    └── Departments: {', '.join(dept_strs)}")
        else:
            print(f"    └── No email addresses found")


# ----------------------------------------------------------------------
# Base Async Enricher with Retry Logic
# ----------------------------------------------------------------------
class BaseAsyncEnricher:
    """
    Abstract base class for async enrichers with built-in retry logic,
    rate limiting, and exponential backoff.
    """
    source_name: str = "unknown"

    def __init__(self, api_key: Optional[str] = None, output_dir: Optional[Path] = None):
        self.api_key = api_key
        self.output_dir = output_dir
        self.settings = SOURCE_SETTINGS.get(self.source_name, EnrichmentSettings())
        self.rate_limiter = get_rate_limiter()

    def _get_proxy_connector(self) -> Optional[Any]:
        """Get aiohttp connector with proxy settings if configured."""
        proxies = get_requests_proxies()
        if proxies and HAS_AIOHTTP:
            # aiohttp doesn't support proxies in the same way, handle separately
            return None
        return None

    async def _fetch_with_retry(
        self,
        session: "aiohttp.ClientSession",
        url: str,
        settings: Optional[EnrichmentSettings] = None,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, Any]] = None,
        auth: Optional[Any] = None,
    ) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Fetch URL with exponential backoff retry.

        Returns:
            Tuple of (data, error) - one will be None
        """
        if not HAS_AIOHTTP:
            return None, "aiohttp not installed - async mode unavailable"

        if settings is None:
            settings = self.settings

        # Acquire rate limit slot before request
        await self.rate_limiter.acquire(self.source_name)

        for attempt in range(settings.max_retries):
            delay = min(
                settings.base_delay * (2 ** attempt),
                settings.max_delay
            )

            try:
                timeout = aiohttp.ClientTimeout(total=settings.timeout)

                request_kwargs = {
                    "timeout": timeout,
                    "headers": headers,
                    "params": params,
                }

                if method.upper() == "POST" and data:
                    request_kwargs["json"] = data

                if auth:
                    request_kwargs["auth"] = auth

                if method.upper() == "GET":
                    async with session.get(url, **request_kwargs) as resp:
                        return await self._handle_response(resp, settings, attempt, delay)
                else:
                    async with session.post(url, **request_kwargs) as resp:
                        return await self._handle_response(resp, settings, attempt, delay)

            except asyncio.TimeoutError:
                if attempt < settings.max_retries - 1:
                    print(f"{Fore.YELLOW}[!] {self.source_name}: Timeout, retrying ({attempt + 1}/{settings.max_retries})...{Style.RESET_ALL}")
                    await asyncio.sleep(delay)
                    continue
                return None, f"Timeout after {settings.max_retries} attempts"

            except aiohttp.ClientError as e:
                if attempt < settings.max_retries - 1:
                    print(f"{Fore.YELLOW}[!] {self.source_name}: Connection error, retrying ({attempt + 1}/{settings.max_retries})...{Style.RESET_ALL}")
                    await asyncio.sleep(delay)
                    continue
                return None, f"Connection error: {str(e)}"

            except Exception as e:
                return None, f"Unexpected error: {str(e)}"

        return None, "Max retries exceeded"

    async def _handle_response(
        self,
        resp: "aiohttp.ClientResponse",
        settings: EnrichmentSettings,
        attempt: int,
        delay: float
    ) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Handle HTTP response with status code checking."""
        if resp.status == 200:
            try:
                return await resp.json(), None
            except Exception:
                text = await resp.text()
                return {"raw_text": text}, None

        elif resp.status == 404:
            return None, "Not found (404)"

        elif resp.status == 429:
            # Rate limited
            await self.rate_limiter.handle_429(self.source_name)
            if attempt < settings.max_retries - 1:
                return None, None  # Signal to retry
            return None, "Rate limit exceeded (429)"

        elif resp.status in settings.retry_on_status:
            if attempt < settings.max_retries - 1:
                await asyncio.sleep(delay)
                return None, None  # Signal to retry
            return None, f"HTTP {resp.status} after {settings.max_retries} attempts"

        elif resp.status == 401:
            return None, "Invalid API key (401 Unauthorized)"

        elif resp.status == 402:
            return None, "Payment required (402)"

        elif resp.status == 403:
            return None, "Access forbidden (403)"

        else:
            try:
                error_data = await resp.json()
                error_msg = error_data.get("error", error_data.get("message", f"HTTP {resp.status}"))
                return None, error_msg
            except Exception:
                return None, f"HTTP {resp.status}"

    # Synchronous fallback methods for non-async mode
    def _sync_fetch(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        auth: Optional[tuple] = None,
        method: str = "GET",
        data: Optional[Dict[str, Any]] = None,
    ) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Synchronous fetch with retry for fallback mode."""
        proxies = get_requests_proxies()
        settings = self.settings

        for attempt in range(settings.max_retries):
            delay = min(settings.base_delay * (2 ** attempt), settings.max_delay)

            try:
                if method.upper() == "GET":
                    response = requests.get(
                        url,
                        headers=headers,
                        params=params,
                        auth=auth,
                        timeout=settings.timeout,
                        proxies=proxies
                    )
                else:
                    response = requests.post(
                        url,
                        headers=headers,
                        params=params,
                        auth=auth,
                        json=data,
                        timeout=settings.timeout,
                        proxies=proxies
                    )

                if response.status_code == 200:
                    try:
                        return response.json(), None
                    except Exception:
                        return {"raw_text": response.text}, None

                elif response.status_code == 404:
                    return None, "Not found (404)"

                elif response.status_code == 429:
                    if attempt < settings.max_retries - 1:
                        print(f"{Fore.YELLOW}[!] {self.source_name}: Rate limited, waiting {delay:.0f}s...{Style.RESET_ALL}")
                        time.sleep(delay)
                        continue
                    return None, "Rate limit exceeded (429)"

                elif response.status_code in settings.retry_on_status:
                    if attempt < settings.max_retries - 1:
                        time.sleep(delay)
                        continue
                    return None, f"HTTP {response.status_code} after {settings.max_retries} attempts"

                elif response.status_code == 401:
                    return None, "Invalid API key (401 Unauthorized)"

                else:
                    return None, f"HTTP {response.status_code}"

            except requests.exceptions.Timeout:
                if attempt < settings.max_retries - 1:
                    print(f"{Fore.YELLOW}[!] {self.source_name}: Timeout, retrying ({attempt + 1}/{settings.max_retries})...{Style.RESET_ALL}")
                    time.sleep(delay)
                    continue
                return None, f"Timeout after {settings.max_retries} attempts"

            except requests.exceptions.RequestException as e:
                if attempt < settings.max_retries - 1:
                    time.sleep(delay)
                    continue
                return None, f"Connection error: {str(e)}"

        return None, "Max retries exceeded"

    def _extract_subdomains(self, urls: List[str], base_domain: str) -> Set[str]:
        """Extract unique subdomains from URL list."""
        subdomains = set()
        base_domain = base_domain.lower()

        for url in urls:
            try:
                parsed = urlparse(url)
                host = parsed.netloc.lower()
                # Remove port if present
                if ':' in host:
                    host = host.split(':')[0]

                if host and host.endswith(base_domain) and host != base_domain:
                    subdomains.add(host)
            except Exception:
                continue

        return subdomains

    def _save_subdomains(self, subdomains: Set[str], domain: str) -> Optional[str]:
        """Save subdomains to file in output directory."""
        if not self.output_dir or not subdomains:
            return None

        subdomain_dir = self.output_dir / "subdomains"
        subdomain_dir.mkdir(parents=True, exist_ok=True)

        filepath = subdomain_dir / f"{domain}.txt"
        filepath.write_text("\n".join(sorted(subdomains)))
        return str(filepath)


# ----------------------------------------------------------------------
# Async Enrichment Orchestrator
# ----------------------------------------------------------------------
async def async_enrich_single_source(
    source: str,
    ioc: str,
    ioc_type: str,
    config: "EnrichmentConfig",
    callback: Optional[ConsoleStreamCallback] = None,
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Enrich a single IOC from a single source asynchronously.

    Falls back to synchronous enrichment if async not available.
    """
    start_time = time.time()

    # Notify callback of start
    if callback:
        await callback.on_source_start(source, ioc)

    try:
        # Get the enricher for this source
        result = await _get_enrichment_result(source, ioc, ioc_type, config, output_dir)
        elapsed = time.time() - start_time

        # Notify callback of completion
        if callback:
            if "error" in result:
                await callback.on_source_error(source, result["error"], elapsed)
            else:
                await callback.on_source_complete(source, result, elapsed)

        result["_elapsed"] = elapsed
        return result

    except Exception as e:
        elapsed = time.time() - start_time
        result = {"source": source, "error": str(e), "_elapsed": elapsed}
        if callback:
            await callback.on_source_error(source, str(e), elapsed)
        return result


async def _get_enrichment_result(
    source: str,
    ioc: str,
    ioc_type: str,
    config: "EnrichmentConfig",
    output_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Get enrichment result from a source, using sync fallback if needed."""

    # Map source names to enricher classes and methods
    # This uses the existing synchronous enrichers wrapped in async

    if ioc_type == "ip":
        return await _enrich_ip_from_source(source, ioc, config, output_dir)
    elif ioc_type == "domain":
        return await _enrich_domain_from_source(source, ioc, config, output_dir)
    elif ioc_type == "hash":
        return await _enrich_hash_from_source(source, ioc, config)
    else:
        return {"source": source, "error": f"Unknown IOC type: {ioc_type}"}


async def _enrich_ip_from_source(
    source: str,
    ip: str,
    config: "EnrichmentConfig",
    output_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """Enrich IP from a specific source."""

    # Run synchronous enrichers in thread pool to avoid blocking
    loop = asyncio.get_event_loop()

    if source == "shodan" and config.get("shodan"):
        enricher = ShodanEnricher(config.get("shodan"))
        return await loop.run_in_executor(None, enricher.enrich_ip, ip)

    elif source == "virustotal" and config.get("virustotal"):
        enricher = VirusTotalEnricher(config.get("virustotal"))
        return await loop.run_in_executor(None, enricher.enrich_ip, ip)

    elif source == "abuseipdb" and config.get("abuseipdb"):
        enricher = AbuseIPDBEnricher(config.get("abuseipdb"))
        return await loop.run_in_executor(None, enricher.enrich_ip, ip)

    elif source == "otx" and config.get("otx"):
        enricher = AlienVaultOTXEnricher(config.get("otx"))
        return await loop.run_in_executor(None, enricher.enrich_ip, ip)

    elif source == "urlscan" and config.get("urlscan"):
        enricher = URLScanEnricher(config.get("urlscan"))
        return await loop.run_in_executor(None, enricher.enrich_ip, ip)

    elif source == "censys" and config.get("censys"):
        enricher = CensysEnricher(config.get("censys"))
        return await loop.run_in_executor(None, enricher.enrich_ip, ip)

    elif source == "greynoise" and config.get("greynoise"):
        enricher = GreyNoiseEnricher(config.get("greynoise"))
        return await loop.run_in_executor(None, enricher.enrich_ip, ip)

    elif source == "spur" and config.get("spur"):
        enricher = SpurEnricher(config.get("spur"))
        return await loop.run_in_executor(None, enricher.enrich_ip, ip)

    elif source == "dehashed" and config.get("dehashed"):
        api_creds = config.get("dehashed")
        if ":" in api_creds:
            api_email, api_key = api_creds.split(":", 1)
            enricher = DehashedEnricher(api_email, api_key, output_dir=str(output_dir) if output_dir else None)
            return await loop.run_in_executor(None, enricher.enrich_ip, ip)
        return {"source": "dehashed", "error": "Invalid API credentials format"}

    elif source == "bazaar":
        api_key = config.get("bazaar")
        enricher = BazaarEnricher(api_key)
        return await loop.run_in_executor(None, enricher.enrich_ip, ip)

    elif source == "crt_sh":
        enricher = CrtShEnricher()
        return await loop.run_in_executor(None, enricher.enrich_ip, ip)

    else:
        return {"source": source, "error": f"Source not configured or unknown: {source}"}


async def _enrich_domain_from_source(
    source: str,
    domain: str,
    config: "EnrichmentConfig",
    output_dir: Optional[Path] = None
) -> Dict[str, Any]:
    """Enrich domain from a specific source."""

    loop = asyncio.get_event_loop()

    if source == "shodan" and config.get("shodan"):
        enricher = ShodanEnricher(config.get("shodan"))
        return await loop.run_in_executor(None, enricher.enrich_domain, domain)

    elif source == "virustotal" and config.get("virustotal"):
        enricher = VirusTotalEnricher(config.get("virustotal"))
        return await loop.run_in_executor(None, enricher.enrich_domain, domain)

    elif source == "otx" and config.get("otx"):
        enricher = AlienVaultOTXEnricher(config.get("otx"))
        return await loop.run_in_executor(None, enricher.enrich_domain, domain)

    elif source == "urlscan" and config.get("urlscan"):
        enricher = URLScanEnricher(config.get("urlscan"))
        return await loop.run_in_executor(None, enricher.enrich_domain, domain)

    elif source == "censys" and config.get("censys"):
        enricher = CensysEnricher(config.get("censys"))
        return await loop.run_in_executor(None, enricher.enrich_domain, domain)

    elif source == "wayback":
        download_responses = output_dir is not None
        enricher = WaybackMachineEnricher(
            output_dir=str(output_dir) if output_dir else None,
            download_responses=download_responses
        )
        result = await loop.run_in_executor(None, enricher.enrich_domain, domain)

        # Extract and save subdomains
        if output_dir and "unique_urls" in result:
            urls = result.get("archived_urls", [])
            if urls:
                base_enricher = BaseAsyncEnricher(output_dir=output_dir)
                subdomains = base_enricher._extract_subdomains(urls, domain)
                if subdomains:
                    subdomain_file = base_enricher._save_subdomains(subdomains, domain)
                    result["subdomains"] = {
                        "count": len(subdomains),
                        "list": sorted(list(subdomains))[:20],  # First 20 for display
                        "file": subdomain_file
                    }

        return result

    elif source == "commoncrawl":
        enricher = CommonCrawlEnricher()
        result = await loop.run_in_executor(None, enricher.enrich_domain, domain)

        # Extract and save subdomains
        if output_dir:
            urls = result.get("urls", [])
            if urls:
                base_enricher = BaseAsyncEnricher(output_dir=output_dir)
                subdomains = base_enricher._extract_subdomains(urls, domain)
                if subdomains:
                    subdomain_file = base_enricher._save_subdomains(subdomains, f"{domain}_commoncrawl")
                    result["subdomains"] = {
                        "count": len(subdomains),
                        "list": sorted(list(subdomains))[:20],
                        "file": subdomain_file
                    }

        return result

    elif source == "dehashed" and config.get("dehashed"):
        api_creds = config.get("dehashed")
        if ":" in api_creds:
            api_email, api_key = api_creds.split(":", 1)
            enricher = DehashedEnricher(api_email, api_key, output_dir=str(output_dir) if output_dir else None)
            return await loop.run_in_executor(None, enricher.enrich_domain, domain)
        return {"source": "dehashed", "error": "Invalid API credentials format"}

    elif source == "bazaar":
        api_key = config.get("bazaar")
        enricher = BazaarEnricher(api_key)
        return await loop.run_in_executor(None, enricher.enrich_domain, domain)

    elif source == "prospeo" and config.get("prospeo"):
        enricher = ProspeoEnricher(config.get("prospeo"))
        return await loop.run_in_executor(None, enricher.enrich_domain, domain)

    elif source == "crt_sh":
        # crt.sh has no API key; the source is always available.
        enricher = CrtShEnricher()
        return await loop.run_in_executor(None, enricher.enrich_domain, domain)

    else:
        return {"source": source, "error": f"Source not configured or unknown: {source}"}


async def _enrich_hash_from_source(
    source: str,
    hash_value: str,
    config: "EnrichmentConfig"
) -> Dict[str, Any]:
    """Enrich hash from a specific source."""

    loop = asyncio.get_event_loop()

    if source == "bazaar":
        api_key = config.get("bazaar")
        enricher = BazaarEnricher(api_key)
        return await loop.run_in_executor(None, enricher.enrich_hash, hash_value)

    else:
        return {"source": source, "error": f"Source doesn't support hash lookups: {source}"}


async def async_enrich_ioc(
    ioc: str,
    config: "EnrichmentConfig",
    sources: Optional[List[str]] = None,
    callback: Optional[ConsoleStreamCallback] = None,
    output_dir: Optional[Path] = None,
    extract_subdomains: bool = False,
    spray_lists: bool = False,
) -> Dict[str, Any]:
    """
    Enrich a single IOC with all specified sources in parallel.

    Args:
        ioc: The IOC to enrich (IP, domain, or hash)
        config: Configuration with API keys
        sources: List of sources to use. If None, use all configured sources.
        callback: Optional callback for streaming output
        output_dir: Optional output directory for saving files
        extract_subdomains: If True, extract subdomains from archive sources
        spray_lists: If True, generate credential spray lists from Dehashed

    Returns:
        Enrichment results dictionary
    """
    ioc = refang(ioc)
    ioc_type = classify_ioc(ioc)

    result = {
        "ioc": ioc,
        "type": ioc_type,
        "enrichments": [],
        "timestamp": datetime.now().isoformat(),
    }

    # Determine which sources to use based on IOC type
    if sources is None:
        sources = _get_default_sources_for_type(ioc_type, config)

    # Filter to only sources that support this IOC type
    valid_sources = _filter_sources_for_type(sources, ioc_type, config)

    if not valid_sources:
        result["error"] = "No valid sources configured for this IOC type"
        return result

    # Create tasks for all sources
    tasks = [
        async_enrich_single_source(source, ioc, ioc_type, config, callback, output_dir)
        for source in valid_sources
    ]

    # Run all sources in parallel
    enrichment_results = await asyncio.gather(*tasks, return_exceptions=True)

    # Collect results
    total_time = 0
    for enrichment in enrichment_results:
        if isinstance(enrichment, Exception):
            result["enrichments"].append({"source": "unknown", "error": str(enrichment)})
        else:
            result["enrichments"].append(enrichment)
            total_time = max(total_time, enrichment.get("_elapsed", 0))

    result["total_time"] = total_time
    result["sources_queried"] = len(valid_sources)
    result["sources_successful"] = sum(1 for e in result["enrichments"] if "error" not in e)

    # Consolidate subdomains if extracted
    if extract_subdomains and output_dir:
        result["consolidated_subdomains"] = _consolidate_subdomains(result, output_dir)

    # Notify callback of IOC completion
    if callback:
        await callback.on_ioc_complete(ioc, result)

    return result


def _get_default_sources_for_type(ioc_type: str, config: "EnrichmentConfig") -> List[str]:
    """Get default sources based on IOC type."""
    if ioc_type == "ip":
        return ["shodan", "virustotal", "abuseipdb", "otx", "urlscan", "censys",
                "greynoise", "spur", "dehashed", "bazaar"]
    elif ioc_type == "domain":
        return ["shodan", "virustotal", "otx", "urlscan", "censys", "wayback",
                "commoncrawl", "dehashed", "bazaar", "prospeo"]
    elif ioc_type == "hash":
        return ["bazaar"]
    return []


def _filter_sources_for_type(sources: List[str], ioc_type: str, config: "EnrichmentConfig") -> List[str]:
    """Filter sources to only those valid for the IOC type and configured."""
    valid = []

    ip_sources = {"shodan", "virustotal", "abuseipdb", "otx", "urlscan", "censys",
                  "greynoise", "spur", "dehashed", "bazaar"}
    domain_sources = {"shodan", "virustotal", "otx", "urlscan", "censys", "wayback",
                      "commoncrawl", "dehashed", "bazaar", "prospeo"}
    hash_sources = {"bazaar"}

    # Public sources that don't need API keys
    public_sources = {"wayback", "commoncrawl", "bazaar"}

    if ioc_type == "ip":
        type_sources = ip_sources
    elif ioc_type == "domain":
        type_sources = domain_sources
    elif ioc_type == "hash":
        type_sources = hash_sources
    else:
        return []

    for source in sources:
        if source not in type_sources:
            continue

        # Check if source is configured (has API key) or is public
        if source in public_sources:
            valid.append(source)
        elif config.get(source):
            valid.append(source)

    return valid


def _consolidate_subdomains(result: Dict[str, Any], output_dir: Path) -> Dict[str, Any]:
    """Consolidate subdomains from all sources into a single file."""
    all_subdomains = set()

    for enrichment in result.get("enrichments", []):
        subdomains = enrichment.get("subdomains", {})
        if isinstance(subdomains, dict):
            subdomain_list = subdomains.get("list", [])
        elif isinstance(subdomains, list):
            subdomain_list = subdomains
        else:
            subdomain_list = []

        all_subdomains.update(subdomain_list)

    if all_subdomains:
        subdomain_dir = output_dir / "subdomains"
        subdomain_dir.mkdir(parents=True, exist_ok=True)

        consolidated_file = subdomain_dir / "consolidated.txt"
        consolidated_file.write_text("\n".join(sorted(all_subdomains)))

        return {
            "count": len(all_subdomains),
            "file": str(consolidated_file)
        }

    return {}


def run_async_enrichment(
    ioc: str,
    config: "EnrichmentConfig",
    sources: Optional[List[str]] = None,
    stream: bool = False,
    output_dir: Optional[Path] = None,
    extract_subdomains: bool = False,
    spray_lists: bool = False,
) -> Dict[str, Any]:
    """
    Run async enrichment from synchronous code.

    This is the main entry point for the async enrichment system.
    """
    callback = ConsoleStreamCallback() if stream else None

    return asyncio.run(
        async_enrich_ioc(
            ioc=ioc,
            config=config,
            sources=sources,
            callback=callback,
            output_dir=output_dir,
            extract_subdomains=extract_subdomains,
            spray_lists=spray_lists,
        )
    )


# Banner
BANNER = f"""{Fore.CYAN}
 ██████╗██╗   ██╗ ██████╗  ██████╗ ██████╗     ███████╗███╗   ██╗██████╗ ██╗ ██████╗██╗  ██╗
██╔════╝╚██╗ ██╔╝██╔════╝ ██╔═══██╗██╔══██╗    ██╔════╝████╗  ██║██╔══██╗██║██╔════╝██║  ██║
██║      ╚████╔╝ ██║  ███╗██║   ██║██████╔╝    █████╗  ██╔██╗ ██║██████╔╝██║██║     ███████║
██║       ╚██╔╝  ██║   ██║██║   ██║██╔══██╗    ██╔══╝  ██║╚██╗██║██╔══██╗██║██║     ██╔══██║
╚██████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║    ███████╗██║ ╚████║██║  ██║██║╚██████╗██║  ██║
 ╚═════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝ ╚═════╝╚═╝  ╚═╝
{Style.RESET_ALL}
Passive Reconnaissance & Threat Intelligence Enrichment
"""


class EnrichmentConfig:
    """Configuration manager for API keys"""

    def __init__(self, config_path: Optional[Path] = None):
        if config_path is None:
            config_path = Path.home() / ".cygor" / "enrich_config.json"

        self.config_path = config_path
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, str]:
        """Load configuration from file or environment"""
        config = {}

        # Try to load from file
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    config = json.load(f)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Warning: Could not load config file: {e}{Style.RESET_ALL}")

        # Override with environment variables if present
        env_keys = {
            'SHODAN_API_KEY': 'shodan',
            'VIRUSTOTAL_API_KEY': 'virustotal',
            'VT_API_KEY': 'virustotal',
            'OTX_API_KEY': 'otx',
            'ABUSEIPDB_API_KEY': 'abuseipdb',
            'URLSCAN_API_KEY': 'urlscan',
            'CENSYS_API_ID': 'censys',  # Format: API_ID:SECRET
            'DEHASHED_API_KEY': 'dehashed',  # Format: email:api_key
            'GREYNOISE_API_KEY': 'greynoise',
            'SPUR_API_KEY': 'spur',
            'BAZAAR_API_KEY': 'bazaar',  # MalwareBazaar API key (optional)
            'PROSPEO_API_KEY': 'prospeo'  # Prospeo API key
        }

        for env_key, config_key in env_keys.items():
            if env_key in os.environ:
                config[config_key] = os.environ[env_key]

        return config

    def get(self, key: str) -> Optional[str]:
        """Get API key by name"""
        return self.config.get(key)

    def is_configured(self) -> bool:
        """Check if at least one API key is configured"""
        return len(self.config) > 0


def classify_ioc(entry: str) -> str:
    """Classify an IOC as IP, domain, hash, or unknown"""
    entry = entry.strip()

    # IP pattern
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    # Domain pattern
    domain_pattern = re.compile(r'^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
    # Hash patterns (MD5, SHA1, SHA256)
    hash_pattern = re.compile(r'^[a-fA-F0-9]{32,64}$')

    if ip_pattern.match(entry):
        return 'ip'
    elif hash_pattern.match(entry):
        return 'hash'
    elif domain_pattern.match(entry):
        return 'domain'

    return 'unknown'


def defang(value: str) -> str:
    """Defang an IOC for safe display"""
    if not value:
        return value
    value = value.replace(".", "[.]")
    value = value.replace("http://", "hxxp://")
    value = value.replace("https://", "hxxps://")
    return value


def refang(value: str) -> str:
    """Refang an IOC for queries"""
    if not value:
        return value
    value = value.replace("[.]", ".")
    value = value.replace("(.)", ".")
    value = value.replace("hxxp", "http")
    value = value.replace("hxxps", "https")
    return value


class ShodanEnricher:
    """Shodan API enrichment"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.shodan.io"

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with comprehensive Shodan data"""
        url = f"{self.base_url}/shodan/host/{ip}?key={self.api_key}"
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()

                # Extract general information
                result = {
                    "source": "shodan",
                    "ip": ip,
                    "hostnames": data.get("hostnames", []),
                    "domains": data.get("domains", []),
                    "org": data.get("org", ""),
                    "isp": data.get("isp", ""),
                    "asn": data.get("asn", ""),
                    "country": data.get("country_name", ""),
                    "country_code": data.get("country_code", ""),
                    "city": data.get("city", ""),
                    "region": data.get("region_code", ""),
                    "postal_code": data.get("postal_code", ""),
                    "latitude": data.get("latitude", ""),
                    "longitude": data.get("longitude", ""),
                    "os": data.get("os", ""),
                    "tags": data.get("tags", []),
                    "ports": data.get("ports", []),
                    "vulns": list(data.get("vulns", [])),
                    "last_update": data.get("last_update", ""),
                }

                # Extract detailed service information from the 'data' array
                services = []
                for service_data in data.get("data", []):
                    service_info = {
                        "port": service_data.get("port"),
                        "transport": service_data.get("transport", "tcp"),
                        "product": service_data.get("product", ""),
                        "version": service_data.get("version", ""),
                        "cpe": service_data.get("cpe", []),
                        "devicetype": service_data.get("devicetype", ""),
                        "info": service_data.get("info", ""),
                        "banner": service_data.get("data", "")[:500],  # Limit banner size
                        "timestamp": service_data.get("timestamp", ""),
                    }

                    # Extract SSL/TLS certificate information if available
                    if "ssl" in service_data:
                        ssl_info = service_data["ssl"]
                        service_info["ssl_cert_serial"] = ssl_info.get("cert", {}).get("serial", "")
                        service_info["ssl_cert_issued"] = ssl_info.get("cert", {}).get("issued", "")
                        service_info["ssl_cert_expires"] = ssl_info.get("cert", {}).get("expires", "")
                        service_info["ssl_cert_subject"] = ssl_info.get("cert", {}).get("subject", {}).get("CN", "")
                        service_info["ssl_cert_issuer"] = ssl_info.get("cert", {}).get("issuer", {}).get("CN", "")

                    # Extract HTTP information if available
                    if "http" in service_data:
                        http_info = service_data["http"]
                        service_info["http_title"] = http_info.get("title", "")
                        service_info["http_server"] = http_info.get("server", "")
                        service_info["http_status"] = http_info.get("status", "")
                        service_info["http_location"] = http_info.get("location", "")

                    # Extract vulnerability information for this service
                    if "vulns" in service_data:
                        service_info["service_vulns"] = list(service_data["vulns"].keys())

                    services.append(service_info)

                result["services"] = services
                result["num_services"] = len(services)

                # Add link to Shodan web interface
                result["link"] = f"https://www.shodan.io/host/{ip}"

                return result
            else:
                error_msg = f"HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    if "error" in error_data:
                        error_msg = f"HTTP {response.status_code}: {error_data['error']}"
                except:
                    pass
                return {"source": "shodan", "error": error_msg}
        except Exception as e:
            return {"source": "shodan", "error": str(e)}

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with Shodan DNS data"""
        url = f"{self.base_url}/dns/domain/{domain}?key={self.api_key}"
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()

                result = {
                    "source": "shodan",
                    "domain": domain,
                    "subdomains": data.get("subdomains", [])[:50],  # Limit to 50 subdomains
                    "num_subdomains": len(data.get("subdomains", [])),
                }

                # Also try to resolve domain to IP and get host info
                try:
                    resolve_url = f"{self.base_url}/dns/resolve?hostnames={domain}&key={self.api_key}"
                    resolve_response = requests.get(resolve_url, timeout=10, proxies=proxies)
                    if resolve_response.status_code == 200:
                        resolve_data = resolve_response.json()
                        ips = resolve_data.get(domain, []) if isinstance(resolve_data.get(domain), list) else [resolve_data.get(domain)]
                        result["resolved_ips"] = [ip for ip in ips if ip]
                except:
                    pass

                result["link"] = f"https://www.shodan.io/domain/{domain}"
                return result
            else:
                error_msg = f"HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    if "error" in error_data:
                        error_msg = f"HTTP {response.status_code}: {error_data['error']}"
                except:
                    pass
                return {"source": "shodan", "error": error_msg}
        except Exception as e:
            return {"source": "shodan", "error": str(e)}


class VirusTotalEnricher:
    """VirusTotal API enrichment"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with VirusTotal data"""
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, headers=self.headers, timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()
                attrs = data["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})

                return {
                    "source": "virustotal",
                    "ip": ip,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attrs.get("reputation", 0),
                    "link": f"https://www.virustotal.com/gui/ip-address/{ip}"
                }
            else:
                return {"source": "virustotal", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "virustotal", "error": str(e)}

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with VirusTotal data"""
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, headers=self.headers, timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()
                attrs = data["data"]["attributes"]
                stats = attrs.get("last_analysis_stats", {})

                result = {
                    "source": "virustotal",
                    "domain": domain,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attrs.get("reputation", 0),
                    "categories": attrs.get("categories", {}),
                    "last_dns_records": attrs.get("last_dns_records", [])[:10],  # Limit to 10 records
                    "popularity_ranks": attrs.get("popularity_ranks", {}),
                    "registrar": attrs.get("registrar", ""),
                    "creation_date": attrs.get("creation_date", ""),
                    "last_update_date": attrs.get("last_update_date", ""),
                    "link": f"https://www.virustotal.com/gui/domain/{domain}"
                }
                return result
            else:
                return {"source": "virustotal", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "virustotal", "error": str(e)}


class AbuseIPDBEnricher:
    """AbuseIPDB API enrichment"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"Accept": "application/json", "Key": api_key}

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with AbuseIPDB data"""
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()["data"]
                return {
                    "source": "abuseipdb",
                    "ip": ip,
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", ""),
                    "usage_type": data.get("usageType", ""),
                    "is_whitelisted": data.get("isWhitelisted", False),
                }
            else:
                return {"source": "abuseipdb", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "abuseipdb", "error": str(e)}

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """AbuseIPDB doesn't support domain lookups directly"""
        return {"source": "abuseipdb", "error": "Domain lookups not supported"}


class CrtShEnricher:
    """
    Certificate Transparency log lookup via crt.sh.

    Returns the most recent N certificates issued for a domain (or matching
    a hostname). No API key required; the public crt.sh endpoint is rate-
    limited but free.

    Per the enrich architectural rule, this talks only to crt.sh — never to
    the asset itself.
    """

    def __init__(self, max_recent: int = 5, include_historical: bool = False, timeout: int = 30):
        self.max_recent = max_recent
        self.include_historical = include_historical
        self.timeout = timeout

    def _fetch(self, query: str) -> List[Dict[str, Any]]:
        """Hit crt.sh JSON endpoint. Returns [] on any error (best-effort)."""
        url = f"https://crt.sh/?q={query}&output=json"
        proxies = get_requests_proxies()
        try:
            response = requests.get(
                url,
                headers={"User-Agent": "cygor/enrich"},
                timeout=self.timeout,
                proxies=proxies,
            )
            if response.status_code != 200:
                return []
            data = response.json()
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _normalize(self, raw_certs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Dedupe by serial_number, sort by not_before desc, project to a
        smaller normalized shape suitable for the EnrichmentFinding.raw blob.
        """
        seen_serials: set = set()
        normalized: List[Dict[str, Any]] = []
        for c in raw_certs:
            if not isinstance(c, dict):
                continue
            serial = c.get("serial_number") or ""
            if serial and serial in seen_serials:
                continue
            if serial:
                seen_serials.add(serial)
            normalized.append({
                "id": c.get("id"),
                "common_name": c.get("common_name", ""),
                "issuer_name": c.get("issuer_name", ""),
                "name_value": c.get("name_value", ""),  # newline-separated SANs
                "not_before": c.get("not_before", ""),
                "not_after": c.get("not_after", ""),
                "serial_number": serial,
                "entry_timestamp": c.get("entry_timestamp", ""),
            })

        # Sort by not_before descending (most recent first)
        normalized.sort(key=lambda c: c.get("not_before") or "", reverse=True)
        return normalized

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Fetch CT-log certs for a domain."""
        if not domain:
            return {"source": "crt_sh", "error": "empty domain"}

        raw = self._fetch(domain)
        if not raw:
            return {
                "source": "crt_sh",
                "domain": domain,
                "certs": [],
                "total_count": 0,
                "note": "No CT-log entries returned (or the endpoint is rate-limiting)",
            }

        normalized = self._normalize(raw)
        kept = normalized if self.include_historical else normalized[: self.max_recent]
        return {
            "source": "crt_sh",
            "domain": domain,
            "certs": kept,
            "total_count": len(normalized),
            "shown_count": len(kept),
            "include_historical": self.include_historical,
        }

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """
        crt.sh supports IP queries — useful when the asset has a cert with
        the IP in a SAN. Less commonly populated than domain queries.
        """
        if not ip:
            return {"source": "crt_sh", "error": "empty ip"}
        raw = self._fetch(ip)
        normalized = self._normalize(raw or [])
        kept = normalized if self.include_historical else normalized[: self.max_recent]
        return {
            "source": "crt_sh",
            "ip": ip,
            "certs": kept,
            "total_count": len(normalized),
            "shown_count": len(kept),
            "include_historical": self.include_historical,
        }


class AlienVaultOTXEnricher:
    """AlienVault OTX API enrichment"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"X-OTX-API-KEY": api_key}
        self.base_url = "https://otx.alienvault.com/api/v1"

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with AlienVault OTX data"""
        url = f"{self.base_url}/indicators/IPv4/{ip}/general"
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, headers=self.headers, timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()

                result = {
                    "source": "otx",
                    "ip": ip,
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [p.get("name", "") for p in data.get("pulse_info", {}).get("pulses", [])[:10]],
                    "asn": data.get("asn", ""),
                    "country": data.get("country_name", ""),
                    "city": data.get("city", ""),
                    "reputation": data.get("reputation", 0),
                    "link": f"https://otx.alienvault.com/indicator/ip/{ip}"
                }
                return result
            else:
                return {"source": "otx", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "otx", "error": str(e)}

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with AlienVault OTX data"""
        url = f"{self.base_url}/indicators/domain/{domain}/general"
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, headers=self.headers, timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()

                result = {
                    "source": "otx",
                    "domain": domain,
                    "pulse_count": data.get("pulse_info", {}).get("count", 0),
                    "pulses": [p.get("name", "") for p in data.get("pulse_info", {}).get("pulses", [])[:10]],
                    "alexa_rank": data.get("alexa", ""),
                    "whois": data.get("whois", "")[:500],  # Limit whois data
                    "link": f"https://otx.alienvault.com/indicator/domain/{domain}"
                }
                return result
            else:
                return {"source": "otx", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "otx", "error": str(e)}


class URLScanEnricher:
    """URLScan.io API enrichment"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"API-Key": api_key}
        self.base_url = "https://urlscan.io/api/v1"

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with URLScan data"""
        url = f"{self.base_url}/search/?q=ip:{ip}"
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, headers=self.headers, timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])[:5]  # Limit to 5 results

                return {
                    "source": "urlscan",
                    "ip": ip,
                    "total_scans": data.get("total", 0),
                    "recent_scans": [
                        {
                            "url": r.get("page", {}).get("url", ""),
                            "domain": r.get("page", {}).get("domain", ""),
                            "country": r.get("page", {}).get("country", ""),
                            "asn": r.get("page", {}).get("asn", ""),
                            "server": r.get("page", {}).get("server", ""),
                        }
                        for r in results
                    ],
                    "link": f"https://urlscan.io/search/#ip:{ip}"
                }
            else:
                return {"source": "urlscan", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "urlscan", "error": str(e)}

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with URLScan data"""
        url = f"{self.base_url}/search/?q=domain:{domain}"
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, headers=self.headers, timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()
                results = data.get("results", [])[:5]  # Limit to 5 results

                return {
                    "source": "urlscan",
                    "domain": domain,
                    "total_scans": data.get("total", 0),
                    "recent_scans": [
                        {
                            "url": r.get("page", {}).get("url", ""),
                            "ip": r.get("page", {}).get("ip", ""),
                            "country": r.get("page", {}).get("country", ""),
                            "asn": r.get("page", {}).get("asn", ""),
                            "server": r.get("page", {}).get("server", ""),
                            "title": r.get("page", {}).get("title", ""),
                        }
                        for r in results
                    ],
                    "link": f"https://urlscan.io/search/#domain:{domain}"
                }
            else:
                return {"source": "urlscan", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "urlscan", "error": str(e)}


class CensysEnricher:
    """Censys API enrichment"""

    def __init__(self, api_key: str):
        # Censys uses API_ID:SECRET format
        if ":" in api_key:
            self.api_id, self.api_secret = api_key.split(":", 1)
        else:
            raise ValueError("Censys API key must be in format API_ID:SECRET")
        self.base_url = "https://search.censys.io/api/v2"

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with Censys data"""
        url = f"{self.base_url}/hosts/{ip}"
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, auth=(self.api_id, self.api_secret), timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()
                result_data = data.get("result", {})

                # Extract services
                services = []
                for service_data in result_data.get("services", []):
                    service_info = {
                        "port": service_data.get("port"),
                        "transport": service_data.get("transport_protocol", "tcp"),
                        "service_name": service_data.get("service_name", ""),
                        "extended_service_name": service_data.get("extended_service_name", ""),
                        "banner": service_data.get("banner", "")[:500],
                        "timestamp": service_data.get("observed_at", ""),
                    }

                    # Extract software/version info
                    software = service_data.get("software", [])
                    if software:
                        service_info["software"] = [
                            {"vendor": s.get("vendor"), "product": s.get("product"), "version": s.get("version")}
                            for s in software
                        ]

                    # Extract TLS/SSL info
                    if "tls" in service_data:
                        tls_info = service_data["tls"]
                        cert = tls_info.get("certificates", {}).get("leaf_data", {})
                        if cert:
                            service_info["tls_subject"] = cert.get("subject", {}).get("common_name", [""])[0]
                            service_info["tls_issuer"] = cert.get("issuer", {}).get("common_name", [""])[0]
                            service_info["tls_not_after"] = cert.get("validity", {}).get("end", "")

                    # Extract HTTP info
                    if "http" in service_data:
                        http_info = service_data["http"]
                        if "response" in http_info:
                            service_info["http_status"] = http_info["response"].get("status_code")
                            service_info["http_title"] = http_info["response"].get("body_html_title", "")
                            service_info["http_server"] = http_info["response"].get("headers", {}).get("Server", "")

                    services.append(service_info)

                result = {
                    "source": "censys",
                    "ip": ip,
                    "autonomous_system": result_data.get("autonomous_system", {}),
                    "location": result_data.get("location", {}),
                    "operating_system": result_data.get("operating_system", {}).get("product", ""),
                    "dns": result_data.get("dns", {}),
                    "services": services,
                    "num_services": len(services),
                    "last_updated": result_data.get("last_updated_at", ""),
                    "link": f"https://search.censys.io/hosts/{ip}"
                }
                return result
            else:
                try:
                    error_data = response.json()
                    return {"source": "censys", "error": error_data.get("error", f"HTTP {response.status_code}")}
                except:
                    return {"source": "censys", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "censys", "error": str(e)}

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with Censys data"""
        # Search for hosts by domain name
        url = f"{self.base_url}/hosts/search"
        params = {"q": f"dns.names:{domain}", "per_page": 10}
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, auth=(self.api_id, self.api_secret), params=params, timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()
                hits = data.get("result", {}).get("hits", [])

                # Extract IPs and basic info
                resolved_ips = []
                hosts_info = []
                for hit in hits:
                    ip = hit.get("ip", "")
                    if ip:
                        resolved_ips.append(ip)
                        hosts_info.append({
                            "ip": ip,
                            "location": hit.get("location", {}),
                            "autonomous_system": hit.get("autonomous_system", {}),
                            "services": [s.get("port") for s in hit.get("services", [])]
                        })

                result = {
                    "source": "censys",
                    "domain": domain,
                    "total_hosts": data.get("result", {}).get("total", 0),
                    "resolved_ips": resolved_ips[:10],
                    "hosts": hosts_info[:5],
                    "link": f"https://search.censys.io/search?resource=hosts&q=dns.names%3A{domain}"
                }
                return result
            else:
                try:
                    error_data = response.json()
                    return {"source": "censys", "error": error_data.get("error", f"HTTP {response.status_code}")}
                except:
                    return {"source": "censys", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "censys", "error": str(e)}


class WaybackMachineEnricher:
    """Wayback Machine CDX API enrichment with response download capability"""

    def __init__(self, output_dir: Optional[str] = None, download_responses: bool = False):
        # No API key required - public API
        self.base_url = "http://web.archive.org/cdx/search/cdx"
        self.wayback_base = "https://web.archive.org/web"
        self.output_dir = output_dir
        self.download_responses = download_responses

    def _get_total_count(self, domain: str) -> int:
        """Get the total count of captures for a domain (fast query)"""
        try:
            params = {
                "url": domain,
                "matchType": "domain",  # Include all subdomains
                "showNumPages": "true",
                "pageSize": "1"
            }
            response = requests.get(self.base_url, params=params, timeout=10)
            if response.status_code == 200:
                # The response is just a number
                try:
                    num_pages = int(response.text.strip())
                    # Each page has multiple items, estimate total (conservative)
                    # CDX typically returns ~3000 items per page
                    return num_pages * 3000
                except:
                    return 0
            return 0
        except:
            return 0

    def _download_archived_response(self, url: str, timestamp: str, output_path: Path) -> bool:
        """Download an archived response from Wayback Machine

        Args:
            url: The original URL
            timestamp: The timestamp of the capture
            output_path: Where to save the response

        Returns:
            True if successful, False otherwise
        """
        try:
            # Construct Wayback URL with 'id_' flag to get raw response without Wayback headers
            wayback_url = f"{self.wayback_base}/{timestamp}id_/{url}"

            response = requests.get(wayback_url, timeout=30, stream=True)
            if response.status_code == 200:
                output_path.write_bytes(response.content)
                return True
            return False
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to download {url}: {e}{Style.RESET_ALL}")
            return False

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with Wayback Machine historical data

        This method:
        1. Gets the total count of archived snapshots
        2. Retrieves a sample of unique URLs across time
        3. Optionally downloads archived responses for analysis
        """
        proxies = get_requests_proxies()
        try:
            # First, get the total count (fast query)
            total_count = self._get_total_count(domain)

            # Try multiple query strategies to get data
            # Strategy 1: Try with wildcard for all pages
            params = {
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "timestamp,original,mimetype,statuscode,digest",
                "collapse": "urlkey",  # One result per unique URL
                "filter": "statuscode:200",
                "limit": "1000"
            }

            response = requests.get(self.base_url, params=params, timeout=30, proxies=proxies)

            # If no results, try without wildcard subdomain
            if response.status_code == 200:
                try:
                    data = response.json()
                    if len(data) <= 1:  # Only header or empty
                        # Try strategy 2: exact domain match
                        params["url"] = f"{domain}/*"
                        response = requests.get(self.base_url, params=params, timeout=30, proxies=proxies)
                        data = response.json()
                except:
                    # Try strategy 2 if parsing failed
                    params["url"] = f"{domain}/*"
                    response = requests.get(self.base_url, params=params, timeout=30, proxies=proxies)
                    data = response.json()
            else:
                # Try strategy 2 if first request failed
                params["url"] = f"{domain}/*"
                response = requests.get(self.base_url, params=params, timeout=30, proxies=proxies)
                data = response.json()

            if response.status_code == 200:

                # First row is header, rest are data
                if len(data) > 1:
                    captures = []
                    timestamps = []
                    unique_urls = set()
                    file_extensions = {}
                    paths = set()
                    parameters = set()
                    subdomains = set()

                    for row in data[1:]:  # Skip header row
                        timestamp, url, mimetype, statuscode, digest = row
                        timestamps.append(timestamp)
                        unique_urls.add(url)
                        captures.append({
                            "timestamp": timestamp,
                            "url": url,
                            "mimetype": mimetype,
                            "statuscode": statuscode,
                            "digest": digest
                        })

                        # Extract additional intelligence from URLs
                        try:
                            from urllib.parse import urlparse, parse_qs
                            parsed = urlparse(url)

                            # Extract subdomain
                            if parsed.hostname:
                                subdomain = parsed.hostname
                                if subdomain != domain and domain in subdomain:
                                    subdomains.add(subdomain)

                            # Extract path
                            if parsed.path and parsed.path != '/':
                                paths.add(parsed.path)

                            # Extract file extension
                            path = parsed.path
                            if '.' in path:
                                ext = path.rsplit('.', 1)[-1].split('/')[0].lower()
                                if ext and len(ext) <= 10:  # Reasonable extension length
                                    file_extensions[ext] = file_extensions.get(ext, 0) + 1

                            # Extract parameters
                            if parsed.query:
                                params = parse_qs(parsed.query)
                                for param in params.keys():
                                    parameters.add(param)
                        except:
                            pass

                    # Calculate first and last seen
                    first_seen = min(timestamps) if timestamps else ""
                    last_seen = max(timestamps) if timestamps else ""

                    # Get top file extensions
                    top_extensions = sorted(file_extensions.items(), key=lambda x: x[1], reverse=True)[:10]

                    # Download archived responses if requested
                    downloaded_files = []
                    if self.download_responses and self.output_dir:
                        from pathlib import Path
                        import hashlib

                        output_path = Path(self.output_dir)
                        wayback_dir = output_path / f"wayback_{domain.replace('/', '_')}"
                        wayback_dir.mkdir(parents=True, exist_ok=True)

                        print(f"{Fore.CYAN}[*] Downloading archived responses for {domain}...{Style.RESET_ALL}")

                        # Download a sample of responses (limit to avoid overwhelming)
                        download_limit = min(50, len(captures))
                        for i, capture in enumerate(captures[:download_limit]):
                            # Create filename from URL and timestamp
                            url_hash = hashlib.md5(capture['url'].encode()).hexdigest()[:8]
                            filename = f"{capture['timestamp']}_{url_hash}.html"
                            file_path = wayback_dir / filename

                            if self._download_archived_response(capture['url'], capture['timestamp'], file_path):
                                downloaded_files.append(str(file_path))

                            # Progress indicator
                            if (i + 1) % 10 == 0:
                                print(f"{Fore.CYAN}[*] Downloaded {i + 1}/{download_limit} responses...{Style.RESET_ALL}")

                        if downloaded_files:
                            print(f"{Fore.GREEN}[+] Downloaded {len(downloaded_files)} archived responses to {wayback_dir}{Style.RESET_ALL}")

                            # Create index file
                            index_file = wayback_dir / "index.txt"
                            index_content = []
                            for capture in captures[:download_limit]:
                                url_hash = hashlib.md5(capture['url'].encode()).hexdigest()[:8]
                                filename = f"{capture['timestamp']}_{url_hash}.html"
                                index_content.append(f"{filename}|{capture['url']}|{capture['timestamp']}")

                            index_file.write_text('\n'.join(index_content))

                    result = {
                        "source": "wayback",
                        "domain": domain,
                        "total_snapshots_estimated": total_count,
                        "unique_urls_found": len(unique_urls),
                        "sample_size": len(captures),
                        "first_seen": first_seen,
                        "last_seen": last_seen,
                        "subdomains_found": sorted(list(subdomains))[:20],
                        "unique_paths": len(paths),
                        "unique_parameters": sorted(list(parameters))[:30],
                        "file_extensions": dict(top_extensions),
                        "recent_captures": captures[:10],  # Most recent 10
                        "downloaded_responses": len(downloaded_files) if downloaded_files else 0,
                        "download_directory": str(wayback_dir) if downloaded_files else None,
                        "link": f"https://web.archive.org/web/*/{domain}"
                    }
                    return result
                else:
                    return {"source": "wayback", "domain": domain, "total_snapshots_estimated": total_count, "unique_urls_found": 0, "message": "No captures found"}
            else:
                return {"source": "wayback", "error": f"HTTP {response.status_code}", "total_snapshots_estimated": total_count}
        except requests.exceptions.Timeout:
            return {"source": "wayback", "error": "Request timed out - domain may have too many captures. Try a more specific subdomain."}
        except requests.exceptions.RequestException as e:
            return {"source": "wayback", "error": f"Connection error: {str(e)}"}
        except Exception as e:
            return {"source": "wayback", "error": str(e)}


class CommonCrawlEnricher:
    """Common Crawl Index enrichment"""

    def __init__(self):
        # No API key required - public API
        self.base_url = "https://index.commoncrawl.org"
        self.collections = []

    def _get_latest_collections(self, limit=3):
        """Get the latest Common Crawl collections"""
        proxies = get_requests_proxies()
        try:
            response = requests.get(f"{self.base_url}/collinfo.json", timeout=10, proxies=proxies)
            if response.status_code == 200:
                all_collections = response.json()
                # Return the latest N collections
                return [c["id"] for c in all_collections[:limit]]
            return []
        except:
            # Fallback to hardcoded recent collections if API fails
            return ["CC-MAIN-2024-51", "CC-MAIN-2024-46", "CC-MAIN-2024-42"]

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with Common Crawl index data"""
        proxies = get_requests_proxies()
        try:
            # Get latest collections
            collections = self._get_latest_collections(limit=2)

            all_urls = []
            total_results = 0

            for collection in collections:
                try:
                    # Query the index for this domain
                    url = f"{self.base_url}/{collection}-index"
                    params = {
                        "url": f"{domain}/*",
                        "output": "json",
                        "limit": "50"
                    }

                    response = requests.get(url, params=params, timeout=10, proxies=proxies)

                    if response.status_code == 200:
                        # Response is NDJSON (newline-delimited JSON)
                        for line in response.text.strip().split('\n'):
                            if line:
                                try:
                                    record = json.loads(line)
                                    all_urls.append({
                                        "url": record.get("url", ""),
                                        "timestamp": record.get("timestamp", ""),
                                        "mime": record.get("mime", ""),
                                        "status": record.get("status", ""),
                                        "collection": collection
                                    })
                                    total_results += 1
                                except:
                                    continue
                except Exception:
                    continue

            if all_urls:
                # Deduplicate URLs
                unique_urls = list({u["url"]: u for u in all_urls}.values())

                result = {
                    "source": "commoncrawl",
                    "domain": domain,
                    "total_urls": len(unique_urls),
                    "collections_searched": len(collections),
                    "urls": unique_urls[:15],  # Return top 15
                    "link": f"{self.base_url}/CC-MAIN-2024-51-index?url={domain}/*&output=json"
                }
                return result
            else:
                return {"source": "commoncrawl", "domain": domain, "total_urls": 0, "message": "No URLs found"}
        except Exception as e:
            return {"source": "commoncrawl", "error": str(e)}


class GreyNoiseEnricher:
    """GreyNoise API enrichment - Internet scanner and threat intelligence"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"key": api_key, "Accept": "application/json"}
        self.base_url = "https://api.greynoise.io/v3"

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with GreyNoise data"""
        url = f"{self.base_url}/community/{ip}"
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, headers=self.headers, timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()

                result = {
                    "source": "greynoise",
                    "ip": ip,
                    "noise": data.get("noise", False),
                    "riot": data.get("riot", False),
                    "classification": data.get("classification", "unknown"),
                    "name": data.get("name", ""),
                    "last_seen": data.get("last_seen", ""),
                    "message": data.get("message", ""),
                    "link": data.get("link", f"https://viz.greynoise.io/ip/{ip}")
                }

                # Try to get more detailed info with enterprise endpoint if available
                try:
                    context_url = f"{self.base_url}/noise/context/{ip}"
                    context_response = requests.get(context_url, headers=self.headers, timeout=10, proxies=proxies)

                    if context_response.status_code == 200:
                        context_data = context_response.json()
                        result["seen"] = context_data.get("seen", False)
                        result["tags"] = context_data.get("tags", [])
                        result["actor"] = context_data.get("actor", "")
                        result["bot"] = context_data.get("bot", False)
                        result["vpn"] = context_data.get("vpn", False)
                        result["vpn_service"] = context_data.get("vpn_service", "")
                        result["metadata"] = {
                            "asn": context_data.get("metadata", {}).get("asn", ""),
                            "organization": context_data.get("metadata", {}).get("organization", ""),
                            "city": context_data.get("metadata", {}).get("city", ""),
                            "country": context_data.get("metadata", {}).get("country", ""),
                            "country_code": context_data.get("metadata", {}).get("country_code", ""),
                            "category": context_data.get("metadata", {}).get("category", ""),
                            "os": context_data.get("metadata", {}).get("os", "")
                        }
                        result["raw_data"] = context_data.get("raw_data", {})
                except:
                    # Community API only - detailed data not available
                    pass

                return result
            elif response.status_code == 404:
                return {
                    "source": "greynoise",
                    "ip": ip,
                    "noise": False,
                    "riot": False,
                    "classification": "unknown",
                    "message": "IP not observed by GreyNoise",
                    "link": f"https://viz.greynoise.io/ip/{ip}"
                }
            else:
                error_msg = f"HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    if "message" in error_data:
                        error_msg = error_data["message"]
                except:
                    pass
                return {"source": "greynoise", "error": error_msg}
        except Exception as e:
            return {"source": "greynoise", "error": str(e)}

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """GreyNoise doesn't support domain lookups directly"""
        return {"source": "greynoise", "error": "Domain lookups not supported"}


class SpurEnricher:
    """Spur.io API enrichment - VPN/Proxy/Datacenter detection"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"Token": api_key, "Accept": "application/json"}
        self.base_url = "https://api.spur.us/v2"

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with Spur.io data"""
        url = f"{self.base_url}/context/{ip}"
        proxies = get_requests_proxies()

        try:
            response = requests.get(url, headers=self.headers, timeout=10, proxies=proxies)
            if response.status_code == 200:
                data = response.json()

                result = {
                    "source": "spur",
                    "ip": ip,
                    "anonymous": data.get("anonymous", False),
                    "vpn": data.get("vpn", False),
                    "proxy": data.get("proxy", False),
                    "datacenter": data.get("datacenter", False),
                    "tor": data.get("tor", False),
                    "relay": data.get("relay", False),
                    "infrastructure": data.get("infrastructure", "unknown"),
                }

                # Organization info
                if "organization" in data:
                    result["organization"] = data["organization"]

                # AS info
                if "as" in data:
                    result["as_number"] = data["as"].get("number", "")
                    result["as_organization"] = data["as"].get("organization", "")

                # GEO info
                if "geo" in data:
                    result["country"] = data["geo"].get("country", "")
                    result["city"] = data["geo"].get("city", "")
                    result["state"] = data["geo"].get("state", "")

                # Client info
                if "client" in data:
                    client = data["client"]
                    result["client_types"] = client.get("types", [])
                    result["client_concentration"] = client.get("concentration", {})
                    result["client_countries"] = client.get("countries", 0)
                    result["client_spread"] = client.get("spread", 0)
                    result["client_count"] = client.get("count", 0)
                    result["client_proxies"] = client.get("proxies", [])
                    result["client_behaviors"] = client.get("behaviors", [])

                # Tunnels info
                if "tunnels" in data:
                    result["tunnels"] = data["tunnels"]

                # Risk factors
                risks = []
                if result.get("vpn"):
                    risks.append("VPN")
                if result.get("proxy"):
                    risks.append("Proxy")
                if result.get("datacenter"):
                    risks.append("Datacenter")
                if result.get("tor"):
                    risks.append("Tor")
                if result.get("relay"):
                    risks.append("Relay")

                result["risk_factors"] = risks
                result["risk_score"] = len(risks)

                return result
            elif response.status_code == 404:
                return {
                    "source": "spur",
                    "ip": ip,
                    "anonymous": False,
                    "message": "IP not found in Spur database"
                }
            else:
                error_msg = f"HTTP {response.status_code}"
                try:
                    error_data = response.json()
                    if "message" in error_data:
                        error_msg = error_data["message"]
                except:
                    pass
                return {"source": "spur", "error": error_msg}
        except Exception as e:
            return {"source": "spur", "error": str(e)}

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Spur doesn't support domain lookups directly"""
        return {"source": "spur", "error": "Domain lookups not supported"}


class DehashedEnricher:
    """Dehashed API enrichment for breach data"""

    def __init__(self, api_email: str, api_key: str, output_dir: Optional[str] = None):
        # Dehashed uses email:api_key format or separate credentials
        if ":" in api_email:
            self.api_email, self.api_key = api_email.split(":", 1)
        else:
            self.api_email = api_email
            self.api_key = api_key
        self.base_url = "https://api.dehashed.com/search"
        self.output_dir = output_dir

    def _search(self, query: str, size: int = 10000) -> Dict[str, Any]:
        """Perform a Dehashed search

        Args:
            query: Search query
            size: Number of results to retrieve (max 10000 per request)
        """
        proxies = get_requests_proxies()
        try:
            params = {"query": query, "size": size}
            auth = (self.api_email, self.api_key)
            headers = {"Accept": "application/json"}

            response = requests.get(self.base_url, params=params, auth=auth, headers=headers, timeout=30, proxies=proxies)

            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}", "balance": 0, "entries": []}
        except Exception as e:
            return {"error": str(e), "balance": 0, "entries": []}

    def _process_and_save_data(self, entries: List[Dict], target: str, search_type: str) -> Dict[str, Any]:
        """Process entries and save extracted data to files

        Args:
            entries: List of Dehashed entries
            target: The search target (domain or IP)
            search_type: Type of search ('domain' or 'ip')

        Returns:
            Dictionary with processed statistics and file paths
        """
        # Extract all unique data
        emails = set()
        usernames = set()
        passwords = set()
        hashed_passwords = set()
        ip_addresses = set()
        databases = set()
        names = set()

        for entry in entries:
            # Email addresses (lowercase and deduplicate)
            if entry.get("email"):
                emails.add(entry["email"].lower().strip())

            # Usernames (lowercase and deduplicate)
            if entry.get("username"):
                usernames.add(entry["username"].lower().strip())

            # Passwords (plaintext - as-is, no lowercase to preserve)
            if entry.get("password"):
                passwords.add(entry["password"].strip())

            # Hashed passwords
            if entry.get("hashed_password"):
                hashed_passwords.add(entry["hashed_password"].strip())

            # IP addresses
            if entry.get("ip_address"):
                ip_addresses.add(entry["ip_address"].strip())

            # Database names
            if entry.get("database_name"):
                databases.add(entry["database_name"].strip())

            # Names
            if entry.get("name"):
                names.add(entry["name"].strip())

        # Sort all sets alphabetically (case-insensitive for proper alphabetical order)
        # Emails and usernames are already lowercased, so normal sort is fine
        emails_sorted = sorted(list(emails))
        usernames_sorted = sorted(list(usernames))

        # Passwords: case-insensitive sort (preserves original case but sorts alphabetically)
        passwords_sorted = sorted(list(passwords), key=str.lower)

        # Hashed passwords: case-insensitive sort
        hashes_sorted = sorted(list(hashed_passwords), key=str.lower)

        # IP addresses: special IP sorting (by octets)
        ips_sorted = sorted(list(ip_addresses), key=lambda ip: tuple(int(part) if part.isdigit() else part for part in ip.split('.')))

        # Database names and names: case-insensitive sort
        databases_sorted = sorted(list(databases), key=str.lower)
        names_sorted = sorted(list(names), key=str.lower)

        saved_files = {}

        # Save to files if output directory is specified
        if self.output_dir:
            from pathlib import Path
            output_path = Path(self.output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            # Create subdirectory for this target
            target_safe = target.replace('/', '_').replace(':', '_')
            target_dir = output_path / f"dehashed_{target_safe}"
            target_dir.mkdir(parents=True, exist_ok=True)

            # Save emails
            if emails_sorted:
                emails_file = target_dir / "emails.txt"
                emails_file.write_text('\n'.join(emails_sorted) + '\n')
                saved_files['emails'] = str(emails_file)

            # Save usernames
            if usernames_sorted:
                usernames_file = target_dir / "usernames.txt"
                usernames_file.write_text('\n'.join(usernames_sorted) + '\n')
                saved_files['usernames'] = str(usernames_file)

            # Save passwords (plaintext)
            if passwords_sorted:
                passwords_file = target_dir / "passwords.txt"
                passwords_file.write_text('\n'.join(passwords_sorted) + '\n')
                saved_files['passwords'] = str(passwords_file)

            # Save hashed passwords
            if hashes_sorted:
                hashes_file = target_dir / "hashed_passwords.txt"
                hashes_file.write_text('\n'.join(hashes_sorted) + '\n')
                saved_files['hashed_passwords'] = str(hashes_file)

            # Save IP addresses
            if ips_sorted:
                ips_file = target_dir / "ip_addresses.txt"
                ips_file.write_text('\n'.join(ips_sorted) + '\n')
                saved_files['ip_addresses'] = str(ips_file)

            # Save names
            if names_sorted:
                names_file = target_dir / "names.txt"
                names_file.write_text('\n'.join(names_sorted) + '\n')
                saved_files['names'] = str(names_file)

            # Save database sources
            if databases_sorted:
                databases_file = target_dir / "breach_databases.txt"
                databases_file.write_text('\n'.join(databases_sorted) + '\n')
                saved_files['databases'] = str(databases_file)

            # Save full JSON data for deeper analysis
            full_json_file = target_dir / "full_data.json"
            full_json_file.write_text(json.dumps(entries, indent=2))
            saved_files['full_json'] = str(full_json_file)

            # Create summary report
            summary_file = target_dir / "summary.txt"
            summary_content = f"""Dehashed Breach Data Summary
{'=' * 80}
Target: {target}
Search Type: {search_type}
Total Entries: {len(entries)}

Statistics:
  Unique Emails: {len(emails_sorted)}
  Unique Usernames: {len(usernames_sorted)}
  Unique Passwords (plaintext): {len(passwords_sorted)}
  Unique Hashed Passwords: {len(hashes_sorted)}
  Unique IP Addresses: {len(ips_sorted)}
  Unique Names: {len(names_sorted)}
  Breach Databases: {len(databases_sorted)}

Files Generated:
"""
            for file_type, file_path in saved_files.items():
                summary_content += f"  - {file_type}: {file_path}\n"

            summary_file.write_text(summary_content)
            saved_files['summary'] = str(summary_file)

        return {
            'emails': emails_sorted,
            'usernames': usernames_sorted,
            'passwords': passwords_sorted,
            'hashed_passwords': hashes_sorted,
            'ip_addresses': ips_sorted,
            'names': names_sorted,
            'databases': databases_sorted,
            'saved_files': saved_files,
            'stats': {
                'total_emails': len(emails_sorted),
                'total_usernames': len(usernames_sorted),
                'total_passwords': len(passwords_sorted),
                'total_hashes': len(hashes_sorted),
                'total_ips': len(ips_sorted),
                'total_names': len(names_sorted),
                'total_databases': len(databases_sorted)
            }
        }

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with Dehashed breach data"""
        try:
            data = self._search(f"email:@{domain}", size=10000)

            if "error" in data:
                return {"source": "dehashed", "error": data["error"]}

            entries = data.get("entries", [])
            balance = data.get("balance", 0)
            total = data.get("total", 0)

            # Process and save data
            processed_data = self._process_and_save_data(entries, domain, "domain")

            result = {
                "source": "dehashed",
                "domain": domain,
                "total_entries": total,
                "retrieved_entries": len(entries),
                "unique_emails": processed_data['stats']['total_emails'],
                "unique_usernames": processed_data['stats']['total_usernames'],
                "unique_passwords": processed_data['stats']['total_passwords'],
                "unique_hashes": processed_data['stats']['total_hashes'],
                "unique_ips": processed_data['stats']['total_ips'],
                "unique_names": processed_data['stats']['total_names'],
                "unique_databases": processed_data['stats']['total_databases'],
                "breach_databases": processed_data['databases'][:10],  # Top 10 for display
                "sample_emails": processed_data['emails'][:10],  # Top 10 for display
                "sample_usernames": processed_data['usernames'][:10],  # Top 10 for display
                "saved_files": processed_data['saved_files'],
                "api_balance": balance,
                "link": f"https://dehashed.com/search?query=email:@{domain}"
            }
            return result
        except Exception as e:
            return {"source": "dehashed", "error": str(e)}

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with Dehashed breach data"""
        try:
            data = self._search(f"ip_address:{ip}", size=10000)

            if "error" in data:
                return {"source": "dehashed", "error": data["error"]}

            entries = data.get("entries", [])
            balance = data.get("balance", 0)
            total = data.get("total", 0)

            # Process and save data
            processed_data = self._process_and_save_data(entries, ip, "ip")

            result = {
                "source": "dehashed",
                "ip": ip,
                "total_entries": total,
                "retrieved_entries": len(entries),
                "unique_emails": processed_data['stats']['total_emails'],
                "unique_usernames": processed_data['stats']['total_usernames'],
                "unique_passwords": processed_data['stats']['total_passwords'],
                "unique_hashes": processed_data['stats']['total_hashes'],
                "unique_databases": processed_data['stats']['total_databases'],
                "breach_databases": processed_data['databases'][:10],  # Top 10 for display
                "sample_emails": processed_data['emails'][:10],  # Top 10 for display
                "sample_usernames": processed_data['usernames'][:10],  # Top 10 for display
                "saved_files": processed_data['saved_files'],
                "api_balance": balance,
                "link": f"https://dehashed.com/search?query=ip_address:{ip}"
            }
            return result
        except Exception as e:
            return {"source": "dehashed", "error": str(e)}


class BazaarEnricher:
    """MalwareBazaar (abuse.ch) API enrichment - Malware sample database"""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key if api_key and api_key != "none" else None
        self.base_url = "https://mb-api.abuse.ch/api/v1/"
        self.headers = {"API-KEY": self.api_key} if self.api_key else {}

    def enrich_hash(self, hash_value: str) -> Dict[str, Any]:
        """Query MalwareBazaar by hash (MD5, SHA1, SHA256)"""
        proxies = get_requests_proxies()

        try:
            data = {"query": "get_info", "hash": hash_value}
            response = requests.post(self.base_url, data=data, headers=self.headers, timeout=10, proxies=proxies)

            if response.status_code == 200:
                result = response.json()

                if result.get("query_status") == "ok":
                    data_entry = result.get("data", [{}])[0]

                    return {
                        "source": "bazaar",
                        "hash": hash_value,
                        "found": True,
                        "file_name": data_entry.get("file_name", ""),
                        "file_type": data_entry.get("file_type", ""),
                        "file_size": data_entry.get("file_size", 0),
                        "signature": data_entry.get("signature", ""),
                        "first_seen": data_entry.get("first_seen", ""),
                        "last_seen": data_entry.get("last_seen", ""),
                        "imphash": data_entry.get("imphash", ""),
                        "ssdeep": data_entry.get("ssdeep", ""),
                        "tlsh": data_entry.get("tlsh", ""),
                        "reporter": data_entry.get("reporter", ""),
                        "tags": data_entry.get("tags", []),
                        "delivery_method": data_entry.get("delivery_method", ""),
                        "intelligence": data_entry.get("intelligence", {}),
                        "link": f"https://bazaar.abuse.ch/browse.php?search={hash_value}"
                    }
                elif result.get("query_status") == "no_results":
                    return {
                        "source": "bazaar",
                        "hash": hash_value,
                        "found": False,
                        "message": "No results found",
                        "link": f"https://bazaar.abuse.ch/browse.php?search={hash_value}"
                    }
                else:
                    return {
                        "source": "bazaar",
                        "error": result.get("query_status", "Unknown error")
                    }
            else:
                return {"source": "bazaar", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "bazaar", "error": str(e)}

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Query MalwareBazaar by IP address (C2 infrastructure)"""
        proxies = get_requests_proxies()

        try:
            # Search for samples related to this IP
            data = {"query": "get_cscb", "ip": ip}
            response = requests.post(self.base_url, data=data, headers=self.headers, timeout=10, proxies=proxies)

            if response.status_code == 200:
                result = response.json()

                if result.get("query_status") == "ok":
                    samples = result.get("data", [])

                    # Extract relevant information
                    file_types = {}
                    signatures = {}
                    tags_set = set()

                    for sample in samples:
                        file_type = sample.get("file_type", "unknown")
                        file_types[file_type] = file_types.get(file_type, 0) + 1

                        signature = sample.get("signature", "unknown")
                        signatures[signature] = signatures.get(signature, 0) + 1

                        for tag in sample.get("tags", []):
                            tags_set.add(tag)

                    return {
                        "source": "bazaar",
                        "ip": ip,
                        "found": True,
                        "total_samples": len(samples),
                        "file_types": file_types,
                        "signatures": signatures,
                        "tags": sorted(list(tags_set)),
                        "samples": samples[:10],  # First 10 samples
                        "link": f"https://bazaar.abuse.ch/browse.php?search={ip}"
                    }
                elif result.get("query_status") == "no_results":
                    return {
                        "source": "bazaar",
                        "ip": ip,
                        "found": False,
                        "message": "No C2 infrastructure found for this IP",
                        "link": f"https://bazaar.abuse.ch/browse.php?search={ip}"
                    }
                else:
                    return {
                        "source": "bazaar",
                        "error": result.get("query_status", "Unknown error")
                    }
            else:
                return {"source": "bazaar", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "bazaar", "error": str(e)}

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Query MalwareBazaar by domain (C2 infrastructure)"""
        proxies = get_requests_proxies()

        try:
            # Search for samples related to this domain
            data = {"query": "get_cscb", "domain": domain}
            response = requests.post(self.base_url, data=data, headers=self.headers, timeout=10, proxies=proxies)

            if response.status_code == 200:
                result = response.json()

                if result.get("query_status") == "ok":
                    samples = result.get("data", [])

                    # Extract relevant information
                    file_types = {}
                    signatures = {}
                    tags_set = set()

                    for sample in samples:
                        file_type = sample.get("file_type", "unknown")
                        file_types[file_type] = file_types.get(file_type, 0) + 1

                        signature = sample.get("signature", "unknown")
                        signatures[signature] = signatures.get(signature, 0) + 1

                        for tag in sample.get("tags", []):
                            tags_set.add(tag)

                    return {
                        "source": "bazaar",
                        "domain": domain,
                        "found": True,
                        "total_samples": len(samples),
                        "file_types": file_types,
                        "signatures": signatures,
                        "tags": sorted(list(tags_set)),
                        "samples": samples[:10],  # First 10 samples
                        "link": f"https://bazaar.abuse.ch/browse.php?search={domain}"
                    }
                elif result.get("query_status") == "no_results":
                    return {
                        "source": "bazaar",
                        "domain": domain,
                        "found": False,
                        "message": "No C2 infrastructure found for this domain",
                        "link": f"https://bazaar.abuse.ch/browse.php?search={domain}"
                    }
                else:
                    return {
                        "source": "bazaar",
                        "error": result.get("query_status", "Unknown error")
                    }
            else:
                return {"source": "bazaar", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "bazaar", "error": str(e)}


class ProspeoEnricher:
    """Prospeo.io API enrichment - Email and domain search"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.base_url = "https://api.prospeo.io"
        self.headers = {
            "Content-Type": "application/json",
            "X-KEY": api_key
        }

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Search for emails associated with a domain"""
        proxies = get_requests_proxies()

        try:
            url = f"{self.base_url}/domain-search"
            data = {"domain": domain}
            response = requests.post(url, json=data, headers=self.headers, timeout=30, proxies=proxies)

            if response.status_code == 200:
                result = response.json()

                emails = result.get("response", {}).get("emails", [])
                company_info = result.get("response", {}).get("company", {})

                # Extract email addresses and names
                email_list = []
                for email_entry in emails:
                    email_list.append({
                        "email": email_entry.get("email", ""),
                        "first_name": email_entry.get("first_name", ""),
                        "last_name": email_entry.get("last_name", ""),
                        "position": email_entry.get("position", ""),
                        "phone": email_entry.get("phone", ""),
                        "linkedin": email_entry.get("linkedin", ""),
                        "verified": email_entry.get("verified", False)
                    })

                return {
                    "source": "prospeo",
                    "domain": domain,
                    "total_emails": len(emails),
                    "company_name": company_info.get("name", ""),
                    "company_industry": company_info.get("industry", ""),
                    "company_size": company_info.get("size", ""),
                    "company_location": company_info.get("location", ""),
                    "emails": email_list,
                    "link": f"https://prospeo.io/dashboard"
                }
            elif response.status_code == 401:
                return {"source": "prospeo", "error": "Invalid API key (401 Unauthorized)"}
            elif response.status_code == 402:
                return {"source": "prospeo", "error": "Payment required - Check your subscription (402)"}
            elif response.status_code == 429:
                return {"source": "prospeo", "error": "Rate limit exceeded (429)"}
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get("error", error_data.get("message", f"HTTP {response.status_code}"))
                    return {"source": "prospeo", "error": error_msg}
                except:
                    return {"source": "prospeo", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "prospeo", "error": str(e)}

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Prospeo doesn't support IP lookups"""
        return {"source": "prospeo", "error": "IP lookups not supported"}


def enrich_ioc(ioc: str, config: EnrichmentConfig, sources: Optional[List[str]] = None, output_dir: Optional[str] = None) -> Dict[str, Any]:
    """Enrich a single IOC with specified or all available sources

    Args:
        ioc: The IOC to enrich
        config: Configuration with API keys
        sources: List of sources to use (e.g., ['shodan', 'virustotal']). If None, use all configured sources.
        output_dir: Optional output directory for saving processed data (used by Dehashed)
    """
    ioc = refang(ioc)
    ioc_type = classify_ioc(ioc)

    result = {
        "ioc": ioc,
        "type": ioc_type,
        "enrichments": []
    }

    # If no sources specified, use all available
    if sources is None:
        sources = ['shodan', 'virustotal', 'abuseipdb', 'otx', 'urlscan', 'greynoise', 'spur', 'bazaar', 'prospeo']

    if ioc_type == "ip":
        # Shodan
        if 'shodan' in sources and config.get("shodan"):
            enricher = ShodanEnricher(config.get("shodan"))
            result["enrichments"].append(enricher.enrich_ip(ioc))

        # VirusTotal
        if 'virustotal' in sources and config.get("virustotal"):
            enricher = VirusTotalEnricher(config.get("virustotal"))
            result["enrichments"].append(enricher.enrich_ip(ioc))

        # AbuseIPDB
        if 'abuseipdb' in sources and config.get("abuseipdb"):
            enricher = AbuseIPDBEnricher(config.get("abuseipdb"))
            result["enrichments"].append(enricher.enrich_ip(ioc))

        # AlienVault OTX
        if 'otx' in sources and config.get("otx"):
            enricher = AlienVaultOTXEnricher(config.get("otx"))
            result["enrichments"].append(enricher.enrich_ip(ioc))

        # URLScan
        if 'urlscan' in sources and config.get("urlscan"):
            enricher = URLScanEnricher(config.get("urlscan"))
            result["enrichments"].append(enricher.enrich_ip(ioc))

        # Censys
        if 'censys' in sources and config.get("censys"):
            enricher = CensysEnricher(config.get("censys"))
            result["enrichments"].append(enricher.enrich_ip(ioc))

        # GreyNoise
        if 'greynoise' in sources and config.get("greynoise"):
            enricher = GreyNoiseEnricher(config.get("greynoise"))
            result["enrichments"].append(enricher.enrich_ip(ioc))

        # Spur
        if 'spur' in sources and config.get("spur"):
            enricher = SpurEnricher(config.get("spur"))
            result["enrichments"].append(enricher.enrich_ip(ioc))

        # Dehashed
        if 'dehashed' in sources and config.get("dehashed"):
            api_creds = config.get("dehashed")
            # Split email:api_key format
            if ":" in api_creds:
                api_email, api_key = api_creds.split(":", 1)
                enricher = DehashedEnricher(api_email, api_key, output_dir=output_dir)
                result["enrichments"].append(enricher.enrich_ip(ioc))

        # Bazaar
        if 'bazaar' in sources:
            api_key = config.get("bazaar")
            enricher = BazaarEnricher(api_key)
            result["enrichments"].append(enricher.enrich_ip(ioc))

    elif ioc_type == "domain":
        # Shodan
        if 'shodan' in sources and config.get("shodan"):
            enricher = ShodanEnricher(config.get("shodan"))
            result["enrichments"].append(enricher.enrich_domain(ioc))

        # VirusTotal
        if 'virustotal' in sources and config.get("virustotal"):
            enricher = VirusTotalEnricher(config.get("virustotal"))
            result["enrichments"].append(enricher.enrich_domain(ioc))

        # AlienVault OTX
        if 'otx' in sources and config.get("otx"):
            enricher = AlienVaultOTXEnricher(config.get("otx"))
            result["enrichments"].append(enricher.enrich_domain(ioc))

        # URLScan
        if 'urlscan' in sources and config.get("urlscan"):
            enricher = URLScanEnricher(config.get("urlscan"))
            result["enrichments"].append(enricher.enrich_domain(ioc))

        # Censys
        if 'censys' in sources and config.get("censys"):
            enricher = CensysEnricher(config.get("censys"))
            result["enrichments"].append(enricher.enrich_domain(ioc))

        # Wayback Machine (no API key required)
        if 'wayback' in sources or 'all' in sources:
            # Enable response downloads if output_dir is specified
            download_responses = output_dir is not None
            enricher = WaybackMachineEnricher(output_dir=output_dir, download_responses=download_responses)
            result["enrichments"].append(enricher.enrich_domain(ioc))

        # Common Crawl (no API key required)
        if 'commoncrawl' in sources or 'all' in sources:
            enricher = CommonCrawlEnricher()
            result["enrichments"].append(enricher.enrich_domain(ioc))

        # Dehashed
        if 'dehashed' in sources and config.get("dehashed"):
            api_creds = config.get("dehashed")
            # Split email:api_key format
            if ":" in api_creds:
                api_email, api_key = api_creds.split(":", 1)
                enricher = DehashedEnricher(api_email, api_key, output_dir=output_dir)
                result["enrichments"].append(enricher.enrich_domain(ioc))

        # Bazaar
        if 'bazaar' in sources:
            api_key = config.get("bazaar")
            enricher = BazaarEnricher(api_key)
            result["enrichments"].append(enricher.enrich_domain(ioc))

        # Prospeo
        if 'prospeo' in sources and config.get("prospeo"):
            enricher = ProspeoEnricher(config.get("prospeo"))
            result["enrichments"].append(enricher.enrich_domain(ioc))

    elif ioc_type == "hash":
        # Hash enrichment - primarily Bazaar
        if 'bazaar' in sources:
            api_key = config.get("bazaar")
            enricher = BazaarEnricher(api_key)
            result["enrichments"].append(enricher.enrich_hash(ioc))

    return result


def format_results_as_csv(results: List[Dict[str, Any]]) -> str:
    """Format enrichment results as CSV"""
    output = io.StringIO()

    # Collect all unique fields across all results
    fieldnames = set(['ioc', 'type'])
    for result in results:
        for enrichment in result.get('enrichments', []):
            source = enrichment.get('source', 'unknown')
            for key in enrichment.keys():
                if key != 'source':
                    fieldnames.add(f"{source}_{key}")

    fieldnames = sorted(list(fieldnames))
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()

    # Write data rows
    for result in results:
        row = {
            'ioc': result.get('ioc', ''),
            'type': result.get('type', '')
        }

        for enrichment in result.get('enrichments', []):
            source = enrichment.get('source', 'unknown')
            for key, value in enrichment.items():
                if key != 'source':
                    # Convert lists to comma-separated strings
                    if isinstance(value, list):
                        value = ', '.join(str(v) for v in value)
                    row[f"{source}_{key}"] = value

        writer.writerow(row)

    return output.getvalue()


def format_results_as_xml(results: List[Dict[str, Any]]) -> str:
    """Format enrichment results as XML"""
    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append('<enrichment_results>')

    for result in results:
        lines.append('  <ioc>')
        lines.append(f'    <value>{result.get("ioc", "")}</value>')
        lines.append(f'    <type>{result.get("type", "")}</type>')
        lines.append('    <enrichments>')

        for enrichment in result.get('enrichments', []):
            source = enrichment.get('source', 'unknown')
            lines.append(f'      <{source}>')

            for key, value in enrichment.items():
                if key == 'source':
                    continue

                # Handle different value types
                if isinstance(value, list):
                    lines.append(f'        <{key}>')
                    for item in value:
                        lines.append(f'          <item>{item}</item>')
                    lines.append(f'        </{key}>')
                elif isinstance(value, dict):
                    lines.append(f'        <{key}>')
                    for k, v in value.items():
                        lines.append(f'          <{k}>{v}</{k}>')
                    lines.append(f'        </{key}>')
                else:
                    # Escape XML special characters
                    value_str = str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    lines.append(f'        <{key}>{value_str}</{key}>')

            lines.append(f'      </{source}>')

        lines.append('    </enrichments>')
        lines.append('  </ioc>')

    lines.append('</enrichment_results>')
    return '\n'.join(lines)


def print_enrichment_result(result: Dict[str, Any], format_type: str = "text"):
    """Print enrichment results"""
    if format_type == "json":
        print(json.dumps(result, indent=2))
        return

    ioc = result["ioc"]
    ioc_type = result["type"]

    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] IOC:{Style.RESET_ALL} {ioc} ({ioc_type})")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")

    for enrichment in result["enrichments"]:
        source = enrichment.get("source", "unknown")

        if "error" in enrichment:
            print(f"{Fore.YELLOW}[!] {source.upper()}:{Style.RESET_ALL} {enrichment['error']}")
            continue

        print(f"\n{Fore.BLUE}[*] {source.upper()}:{Style.RESET_ALL}")

        # Special formatting for Shodan results
        if source == "shodan":
            # Check if this is IP or domain enrichment
            if "ip" in enrichment:
                # IP enrichment - existing format
                print(f"\n  {Fore.CYAN}General Information:{Style.RESET_ALL}")
                for key in ["org", "isp", "asn", "os", "country", "city", "region", "postal_code"]:
                    if key in enrichment and enrichment[key]:
                        print(f"    {key}: {enrichment[key]}")

                if enrichment.get("latitude") and enrichment.get("longitude"):
                    print(f"    location: {enrichment['latitude']}, {enrichment['longitude']}")

                if enrichment.get("hostnames"):
                    print(f"    hostnames: {', '.join(enrichment['hostnames'])}")

                if enrichment.get("domains"):
                    print(f"    domains: {', '.join(enrichment['domains'])}")

                if enrichment.get("tags"):
                    print(f"    tags: {', '.join(enrichment['tags'])}")

                # Open Ports
                if enrichment.get("ports"):
                    print(f"\n  {Fore.CYAN}Open Ports ({len(enrichment['ports'])}):{Style.RESET_ALL}")
                    print(f"    {', '.join(str(p) for p in enrichment['ports'])}")

                # Vulnerabilities
                if enrichment.get("vulns"):
                    print(f"\n  {Fore.RED}Vulnerabilities ({len(enrichment['vulns'])}):{Style.RESET_ALL}")
                    for vuln in enrichment['vulns']:
                        print(f"    - {vuln}")

                # Services
                if enrichment.get("services"):
                    print(f"\n  {Fore.CYAN}Services ({enrichment.get('num_services', 0)}):{Style.RESET_ALL}")
                    for svc in enrichment["services"]:
                        port = svc.get("port", "?")
                        transport = svc.get("transport", "tcp")
                        product = svc.get("product", "unknown")
                        version = svc.get("version", "")

                        service_line = f"    Port {port}/{transport}: {product}"
                        if version:
                            service_line += f" {version}"
                        print(service_line)

                        if svc.get("info"):
                            print(f"      Info: {svc['info']}")

                        if svc.get("http_title"):
                            print(f"      HTTP Title: {svc['http_title']}")

                        if svc.get("http_server"):
                            print(f"      HTTP Server: {svc['http_server']}")

                        if svc.get("ssl_cert_subject"):
                            print(f"      SSL Subject: {svc['ssl_cert_subject']}")
                            if svc.get("ssl_cert_expires"):
                                print(f"      SSL Expires: {svc['ssl_cert_expires']}")

                        if svc.get("service_vulns"):
                            print(f"      {Fore.RED}Vulnerabilities: {', '.join(svc['service_vulns'])}{Style.RESET_ALL}")

                        if svc.get("banner"):
                            banner = svc['banner'][:200]  # Truncate for display
                            if len(svc['banner']) > 200:
                                banner += "..."
                            print(f"      Banner: {banner}")

                if enrichment.get("last_update"):
                    print(f"\n  Last Updated: {enrichment['last_update']}")

            elif "domain" in enrichment:
                # Domain enrichment
                if enrichment.get("resolved_ips"):
                    print(f"  Resolved IPs: {', '.join(enrichment['resolved_ips'])}")

                if enrichment.get("num_subdomains"):
                    print(f"  Subdomains: {enrichment['num_subdomains']}")
                    if enrichment.get("subdomains"):
                        subdomain_list = enrichment['subdomains'][:10]
                        print(f"    {', '.join(subdomain_list)}")
                        if len(enrichment['subdomains']) > 10:
                            print(f"    ... and {len(enrichment['subdomains']) - 10} more")

            # Link (common to both)
            if enrichment.get("link"):
                print(f"\n  {Fore.CYAN}More Info:{Style.RESET_ALL} {enrichment['link']}")

        elif source == "virustotal":
            # Special formatting for VirusTotal
            print(f"  Malicious: {enrichment.get('malicious', 0)}")
            print(f"  Suspicious: {enrichment.get('suspicious', 0)}")
            print(f"  Harmless: {enrichment.get('harmless', 0)}")
            print(f"  Reputation: {enrichment.get('reputation', 0)}")

            if enrichment.get("categories"):
                print(f"  Categories: {enrichment['categories']}")

            if enrichment.get("registrar"):
                print(f"  Registrar: {enrichment['registrar']}")

            if enrichment.get("creation_date"):
                print(f"  Created: {enrichment['creation_date']}")

            if enrichment.get("link"):
                print(f"  Link: {enrichment['link']}")

        elif source == "otx":
            # Special formatting for AlienVault OTX
            print(f"  Pulse Count: {enrichment.get('pulse_count', 0)}")

            if enrichment.get("pulses"):
                print(f"  Recent Pulses:")
                for pulse in enrichment['pulses'][:5]:
                    print(f"    - {pulse}")

            if enrichment.get("reputation"):
                print(f"  Reputation: {enrichment['reputation']}")

            if enrichment.get("asn"):
                print(f"  ASN: {enrichment['asn']}")

            if enrichment.get("country"):
                print(f"  Country: {enrichment['country']}")

            if enrichment.get("alexa_rank"):
                print(f"  Alexa Rank: {enrichment['alexa_rank']}")

            if enrichment.get("link"):
                print(f"  Link: {enrichment['link']}")

        elif source == "urlscan":
            # Special formatting for URLScan
            print(f"  Total Scans: {enrichment.get('total_scans', 0)}")

            if enrichment.get("recent_scans"):
                print(f"  Recent Scans:")
                for scan in enrichment['recent_scans'][:3]:
                    print(f"    URL: {scan.get('url', 'N/A')}")
                    if scan.get("ip"):
                        print(f"      IP: {scan['ip']}")
                    if scan.get("domain"):
                        print(f"      Domain: {scan['domain']}")
                    if scan.get("title"):
                        print(f"      Title: {scan['title']}")
                    if scan.get("server"):
                        print(f"      Server: {scan['server']}")

            if enrichment.get("link"):
                print(f"  Link: {enrichment['link']}")

        elif source == "censys":
            # Special formatting for Censys
            if "ip" in enrichment:
                # IP enrichment
                if enrichment.get("autonomous_system"):
                    asn_info = enrichment["autonomous_system"]
                    print(f"  ASN: {asn_info.get('asn', 'N/A')}")
                    if asn_info.get("name"):
                        print(f"  AS Name: {asn_info['name']}")

                if enrichment.get("location"):
                    loc = enrichment["location"]
                    print(f"  Location: {loc.get('city', '')}, {loc.get('country', '')}")

                if enrichment.get("operating_system"):
                    print(f"  OS: {enrichment['operating_system']}")

                if enrichment.get("services"):
                    print(f"\n  {Fore.CYAN}Services ({enrichment.get('num_services', 0)}):{Style.RESET_ALL}")
                    for svc in enrichment["services"][:5]:
                        port = svc.get("port", "?")
                        transport = svc.get("transport", "tcp")
                        service_name = svc.get("service_name", "unknown")
                        print(f"    Port {port}/{transport}: {service_name}")

                        if svc.get("software"):
                            for sw in svc["software"][:2]:
                                print(f"      Software: {sw.get('vendor', '')} {sw.get('product', '')} {sw.get('version', '')}")

                        if svc.get("http_title"):
                            print(f"      HTTP Title: {svc['http_title']}")

                        if svc.get("tls_subject"):
                            print(f"      TLS Subject: {svc['tls_subject']}")

            elif "domain" in enrichment:
                # Domain enrichment
                print(f"  Total Hosts: {enrichment.get('total_hosts', 0)}")
                if enrichment.get("resolved_ips"):
                    print(f"  Resolved IPs: {', '.join(enrichment['resolved_ips'][:5])}")
                    if len(enrichment['resolved_ips']) > 5:
                        print(f"    ... and {len(enrichment['resolved_ips']) - 5} more")

            if enrichment.get("link"):
                print(f"  Link: {enrichment['link']}")

        elif source == "wayback":
            # Special formatting for Wayback Machine
            print(f"  {Fore.YELLOW}Total Snapshots (Estimated):{Style.RESET_ALL} {enrichment.get('total_snapshots_estimated', 0):,}")
            print(f"  Unique URLs Found: {enrichment.get('unique_urls_found', 0):,}")
            print(f"  Unique Paths: {enrichment.get('unique_paths', 0):,}")
            print(f"  Sample Size: {enrichment.get('sample_size', 0)}")

            if enrichment.get("first_seen"):
                first_seen = enrichment["first_seen"]
                # Format timestamp: YYYYMMDDhhmmss -> YYYY-MM-DD
                formatted_first = f"{first_seen[:4]}-{first_seen[4:6]}-{first_seen[6:8]}"
                print(f"  First Seen: {formatted_first}")

            if enrichment.get("last_seen"):
                last_seen = enrichment["last_seen"]
                formatted_last = f"{last_seen[:4]}-{last_seen[4:6]}-{last_seen[6:8]}"
                print(f"  Last Seen: {formatted_last}")

            # Subdomains
            if enrichment.get("subdomains_found"):
                print(f"\n  {Fore.CYAN}Subdomains Discovered:{Style.RESET_ALL}")
                for subdomain in enrichment["subdomains_found"][:10]:
                    print(f"    - {subdomain}")
                if len(enrichment["subdomains_found"]) > 10:
                    print(f"    ... and {len(enrichment['subdomains_found']) - 10} more")

            # File extensions
            if enrichment.get("file_extensions"):
                print(f"\n  {Fore.CYAN}File Extensions:{Style.RESET_ALL}")
                for ext, count in list(enrichment["file_extensions"].items())[:10]:
                    print(f"    .{ext}: {count} URLs")

            # Parameters
            if enrichment.get("unique_parameters"):
                print(f"\n  {Fore.CYAN}URL Parameters Found:{Style.RESET_ALL}")
                params = enrichment["unique_parameters"][:15]
                print(f"    {', '.join(params)}")
                if len(enrichment.get("unique_parameters", [])) > 15:
                    print(f"    ... and {len(enrichment['unique_parameters']) - 15} more")

            # Downloaded responses info
            if enrichment.get("downloaded_responses", 0) > 0:
                print(f"\n  {Fore.GREEN}Downloaded Archived Responses:{Style.RESET_ALL}")
                print(f"    Count: {enrichment['downloaded_responses']}")
                print(f"    Directory: {enrichment['download_directory']}")

            if enrichment.get("recent_captures"):
                print(f"\n  {Fore.CYAN}Sample URLs:{Style.RESET_ALL}")
                for capture in enrichment["recent_captures"][:5]:
                    timestamp = capture.get("timestamp", "")
                    formatted_ts = f"{timestamp[:4]}-{timestamp[4:6]}-{timestamp[6:8]}"
                    url = capture.get("url", "")
                    # Truncate URL for display
                    url_display = url if len(url) <= 70 else url[:67] + "..."
                    print(f"    {formatted_ts}: {url_display}")

            if enrichment.get("link"):
                print(f"\n  Link: {enrichment['link']}")

        elif source == "commoncrawl":
            # Special formatting for Common Crawl
            print(f"  Total URLs: {enrichment.get('total_urls', 0)}")
            print(f"  Collections Searched: {enrichment.get('collections_searched', 0)}")

            if enrichment.get("urls"):
                print(f"\n  {Fore.CYAN}Sample URLs:{Style.RESET_ALL}")
                for url_data in enrichment["urls"][:10]:
                    url = url_data.get("url", "")
                    mime = url_data.get("mime", "unknown")
                    print(f"    {url} ({mime})")

            if enrichment.get("link"):
                print(f"  Link: {enrichment['link']}")

        elif source == "greynoise":
            # Special formatting for GreyNoise
            noise = enrichment.get("noise", False)
            riot = enrichment.get("riot", False)
            classification = enrichment.get("classification", "unknown")

            # Color code the classification
            if classification == "malicious":
                class_color = Fore.RED
            elif classification == "benign":
                class_color = Fore.GREEN
            else:
                class_color = Fore.YELLOW

            print(f"  Internet Noise: {Fore.YELLOW if noise else Fore.GREEN}{'Yes' if noise else 'No'}{Style.RESET_ALL}")
            print(f"  RIOT (Known Good): {Fore.GREEN if riot else Fore.YELLOW}{'Yes' if riot else 'No'}{Style.RESET_ALL}")
            print(f"  Classification: {class_color}{classification.upper()}{Style.RESET_ALL}")

            if enrichment.get("name"):
                print(f"  Name: {enrichment['name']}")

            if enrichment.get("last_seen"):
                print(f"  Last Seen: {enrichment['last_seen']}")

            if enrichment.get("message"):
                print(f"  Message: {enrichment['message']}")

            # Extended data if available
            if enrichment.get("tags"):
                print(f"\n  {Fore.CYAN}Tags:{Style.RESET_ALL}")
                for tag in enrichment["tags"][:10]:
                    print(f"    - {tag}")

            if enrichment.get("actor"):
                print(f"  Actor: {enrichment['actor']}")

            if enrichment.get("bot"):
                print(f"  Bot Activity: {Fore.YELLOW if enrichment['bot'] else Fore.GREEN}{'Yes' if enrichment['bot'] else 'No'}{Style.RESET_ALL}")

            if enrichment.get("vpn"):
                print(f"  VPN: {Fore.YELLOW if enrichment['vpn'] else Fore.GREEN}{'Yes' if enrichment['vpn'] else 'No'}{Style.RESET_ALL}")
                if enrichment.get("vpn_service"):
                    print(f"    VPN Service: {enrichment['vpn_service']}")

            if enrichment.get("metadata"):
                metadata = enrichment["metadata"]
                if metadata.get("organization"):
                    print(f"  Organization: {metadata['organization']}")
                if metadata.get("asn"):
                    print(f"  ASN: {metadata['asn']}")
                if metadata.get("country"):
                    print(f"  Country: {metadata['country']} ({metadata.get('country_code', '')})")
                if metadata.get("city"):
                    print(f"  City: {metadata['city']}")
                if metadata.get("category"):
                    print(f"  Category: {metadata['category']}")
                if metadata.get("os"):
                    print(f"  OS: {metadata['os']}")

            if enrichment.get("link"):
                print(f"\n  Link: {enrichment['link']}")

        elif source == "spur":
            # Special formatting for Spur
            anonymous = enrichment.get("anonymous", False)
            risk_score = enrichment.get("risk_score", 0)
            risk_factors = enrichment.get("risk_factors", [])

            # Color code based on risk
            if risk_score >= 3:
                risk_color = Fore.RED
            elif risk_score >= 1:
                risk_color = Fore.YELLOW
            else:
                risk_color = Fore.GREEN

            print(f"  Anonymous: {Fore.RED if anonymous else Fore.GREEN}{'Yes' if anonymous else 'No'}{Style.RESET_ALL}")
            print(f"  Risk Score: {risk_color}{risk_score}/5{Style.RESET_ALL}")

            if risk_factors:
                print(f"\n  {Fore.CYAN}Risk Factors:{Style.RESET_ALL}")
                for factor in risk_factors:
                    print(f"    - {factor}")

            # Infrastructure indicators
            print(f"\n  {Fore.CYAN}Infrastructure:{Style.RESET_ALL}")
            print(f"    VPN: {Fore.YELLOW if enrichment.get('vpn') else Fore.GREEN}{'Yes' if enrichment.get('vpn') else 'No'}{Style.RESET_ALL}")
            print(f"    Proxy: {Fore.YELLOW if enrichment.get('proxy') else Fore.GREEN}{'Yes' if enrichment.get('proxy') else 'No'}{Style.RESET_ALL}")
            print(f"    Datacenter: {Fore.YELLOW if enrichment.get('datacenter') else Fore.GREEN}{'Yes' if enrichment.get('datacenter') else 'No'}{Style.RESET_ALL}")
            print(f"    Tor: {Fore.RED if enrichment.get('tor') else Fore.GREEN}{'Yes' if enrichment.get('tor') else 'No'}{Style.RESET_ALL}")
            print(f"    Relay: {Fore.YELLOW if enrichment.get('relay') else Fore.GREEN}{'Yes' if enrichment.get('relay') else 'No'}{Style.RESET_ALL}")

            if enrichment.get("infrastructure") != "unknown":
                print(f"    Type: {enrichment['infrastructure']}")

            if enrichment.get("organization"):
                print(f"\n  Organization: {enrichment['organization']}")

            if enrichment.get("as_number"):
                print(f"  AS Number: {enrichment['as_number']}")
            if enrichment.get("as_organization"):
                print(f"  AS Organization: {enrichment['as_organization']}")

            if enrichment.get("country"):
                location_parts = [enrichment['country']]
                if enrichment.get("city"):
                    location_parts.insert(0, enrichment["city"])
                if enrichment.get("state"):
                    location_parts.insert(1, enrichment["state"])
                print(f"  Location: {', '.join(location_parts)}")

            # Client information
            if enrichment.get("client_types"):
                print(f"\n  {Fore.CYAN}Client Information:{Style.RESET_ALL}")
                print(f"    Types: {', '.join(enrichment['client_types'])}")
                if enrichment.get("client_count"):
                    print(f"    Client Count: {enrichment['client_count']}")
                if enrichment.get("client_countries"):
                    print(f"    Countries: {enrichment['client_countries']}")
                if enrichment.get("client_behaviors"):
                    print(f"    Behaviors: {', '.join(enrichment['client_behaviors'][:5])}")

            if enrichment.get("tunnels"):
                print(f"\n  {Fore.CYAN}Tunnels:{Style.RESET_ALL}")
                tunnels = enrichment["tunnels"]
                if isinstance(tunnels, list):
                    for tunnel in tunnels[:5]:
                        print(f"    - {tunnel}")
                elif isinstance(tunnels, dict):
                    for k, v in list(tunnels.items())[:5]:
                        print(f"    {k}: {v}")

        elif source == "dehashed":
            # Special formatting for Dehashed
            print(f"  {Fore.YELLOW}Total Entries:{Style.RESET_ALL} {enrichment.get('total_entries', 0)}")
            print(f"  Retrieved Entries: {enrichment.get('retrieved_entries', 0)}")
            print(f"  API Balance: {enrichment.get('api_balance', 'N/A')} credits")

            # Statistics
            print(f"\n  {Fore.CYAN}Unique Data Found:{Style.RESET_ALL}")
            print(f"    Emails: {enrichment.get('unique_emails', 0)}")
            print(f"    Usernames: {enrichment.get('unique_usernames', 0)}")
            print(f"    Passwords (plaintext): {enrichment.get('unique_passwords', 0)}")
            print(f"    Hashed Passwords: {enrichment.get('unique_hashes', 0)}")
            if enrichment.get('unique_ips'):
                print(f"    IP Addresses: {enrichment.get('unique_ips', 0)}")
            if enrichment.get('unique_names'):
                print(f"    Names: {enrichment.get('unique_names', 0)}")
            print(f"    Breach Databases: {enrichment.get('unique_databases', 0)}")

            # Saved files
            if enrichment.get("saved_files"):
                print(f"\n  {Fore.GREEN}Processed Data Saved:{Style.RESET_ALL}")
                saved_files = enrichment["saved_files"]
                if 'summary' in saved_files:
                    print(f"    Summary: {saved_files['summary']}")
                if 'emails' in saved_files:
                    print(f"    Emails: {saved_files['emails']}")
                if 'usernames' in saved_files:
                    print(f"    Usernames: {saved_files['usernames']}")
                if 'passwords' in saved_files:
                    print(f"    Passwords: {saved_files['passwords']}")
                if 'hashed_passwords' in saved_files:
                    print(f"    Hashed Passwords: {saved_files['hashed_passwords']}")
                if 'ip_addresses' in saved_files:
                    print(f"    IP Addresses: {saved_files['ip_addresses']}")
                if 'names' in saved_files:
                    print(f"    Names: {saved_files['names']}")
                if 'databases' in saved_files:
                    print(f"    Breach Databases: {saved_files['databases']}")
                if 'full_json' in saved_files:
                    print(f"    Full JSON Data: {saved_files['full_json']}")

            # Sample data
            if enrichment.get("breach_databases"):
                print(f"\n  {Fore.CYAN}Top Breach Databases:{Style.RESET_ALL}")
                for db in enrichment["breach_databases"][:10]:
                    print(f"    - {db}")

            if enrichment.get("sample_emails"):
                print(f"\n  {Fore.CYAN}Sample Emails:{Style.RESET_ALL}")
                for email in enrichment["sample_emails"][:5]:
                    print(f"    - {email}")

            if enrichment.get("sample_usernames"):
                print(f"\n  {Fore.CYAN}Sample Usernames:{Style.RESET_ALL}")
                for username in enrichment["sample_usernames"][:5]:
                    print(f"    - {username}")

            if enrichment.get("link"):
                print(f"\n  Link: {enrichment['link']}")

        else:
            # Default formatting for other sources
            for key, value in enrichment.items():
                if key in ["source", "ip", "domain"]:
                    continue
                print(f"  {key}: {value}")


def main(argv=None):
    # Check if first argument is "config-manager" to delegate to config management
    # Do this BEFORE parsing to avoid conflicts with argparse
    import sys
    check_argv = argv if argv is not None else sys.argv[1:]
    if check_argv and len(check_argv) > 0 and check_argv[0] == "config-manager":
        from cygor import enrich_config
        # Remove "config-manager" from argv and pass the rest
        enrich_config.main(check_argv[1:])
        return

    parser = argparse.ArgumentParser(
        prog="cygor enrich",
        description="Enrich IOCs with passive reconnaissance and threat intelligence",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cygor enrich 192.168.1.1                          # Enrich single IP with all sources
  cygor enrich iocs.txt -o results.json             # Enrich from file
  cygor enrich 192.168.1.1 --sources shodan vt      # Use only Shodan and VirusTotal
  cygor enrich iocs.txt --sources abuseipdb         # Use only AbuseIPDB
  cygor enrich config-manager list                  # Manage API keys

API Key Management:
  cygor enrich config-manager set <source> <key>    # Set an API key
  cygor enrich config-manager list                  # List all configured keys
  cygor enrich config-manager test                  # Test all configured keys
  cygor enrich config-manager --help                # Show config management help

Available sources:
  shodan       - Shodan (requires SHODAN_API_KEY)
  vt           - VirusTotal (requires VIRUSTOTAL_API_KEY or VT_API_KEY)
  virustotal   - VirusTotal (alias for 'vt')
  abuseipdb    - AbuseIPDB (requires ABUSEIPDB_API_KEY)
  otx          - LevelBlue OTX/AlienVault (requires OTX_API_KEY)
  urlscan      - URLScan.io (requires URLSCAN_API_KEY)
  censys       - Censys (requires CENSYS_API_ID in format API_ID:SECRET)
  greynoise    - GreyNoise (requires GREYNOISE_API_KEY)
  spur         - Spur (requires SPUR_API_KEY)
  bazaar       - MalwareBazaar (BAZAAR_API_KEY optional for most queries)
  prospeo      - Prospeo.io (requires PROSPEO_API_KEY for email/domain searches)
  wayback      - Wayback Machine (no API key required)
  commoncrawl  - Common Crawl (no API key required)
  dehashed     - Dehashed (requires DEHASHED_API_KEY in format email:api_key)
  all          - Use all configured sources (default)
        """
    )

    parser.add_argument("input", nargs="?", help="IOC to enrich (IP, domain, or hash), or path to file with IOCs")
    parser.add_argument("-i", "--input-file", dest="input_file", help="File containing IOCs (one per line)")
    parser.add_argument("-o", "--output", dest="output", help="Output file or directory for results")
    parser.add_argument("--format", choices=["text", "json", "csv", "xml"], default="text", help="Output format (default: text)")
    parser.add_argument("--config", dest="config", help="Path to config file with API keys")
    parser.add_argument("--sources", nargs="+", choices=["shodan", "vt", "virustotal", "abuseipdb", "otx", "urlscan", "censys", "greynoise", "spur", "bazaar", "prospeo", "wayback", "commoncrawl", "dehashed", "crt_sh", "all"],
                        help="Enrichment sources to use (default: all configured sources)")

    # Pentester feature options
    parser.add_argument("--extract-subdomains", action="store_true", dest="extract_subdomains",
                        help="Extract and save subdomains from Wayback/CommonCrawl results")
    parser.add_argument("--spray-lists", action="store_true", dest="spray_lists",
                        help="Generate credential spray lists from Dehashed for credrecon")
    parser.add_argument("--include-historical-certs", action="store_true", dest="include_historical_certs",
                        help="When using crt_sh, return all CT-log certs instead of the most recent few")
    parser.add_argument("--ai-scope", dest="ai_scope",
                        help="Run AI/MCP-targeted Shodan dorks scoped to one or more CIDRs (comma-separated)")

    # Advanced options
    parser.add_argument("--timeout", type=float, default=30.0,
                        help="Default timeout per source in seconds (default: 30)")
    parser.add_argument("--retries", type=int, default=3,
                        help="Max retry attempts per source (default: 3)")
    parser.add_argument("--sequential", action="store_true",
                        help="Use sequential (legacy) mode instead of parallel async")

    args = parser.parse_args(argv)

    # AI scope sweep mode (Mode B) — run curated Shodan dorks scoped to a
    # CIDR list and write the matches into the standard enrichment JSON
    # format so the existing ingest path picks up the AI/MCP indicators.
    if args.ai_scope:
        from .enrich_ai_scope import run_ai_scope_sweep

        config_path = Path(args.config) if args.config else None
        ai_config = EnrichmentConfig(config_path)
        shodan_key = ai_config.get("shodan")
        if not shodan_key:
            print(f"{Fore.RED}[!] --ai-scope requires the shodan API key{Style.RESET_ALL}")
            sys.exit(1)

        cidrs = [c.strip() for c in args.ai_scope.split(",") if c.strip()]
        print(f"{Fore.CYAN}[*] Running AI scope sweep across {len(cidrs)} CIDR(s){Style.RESET_ALL}")
        results = run_ai_scope_sweep(shodan_key, cidrs)
        print(f"{Fore.GREEN}[+] Found {len(results)} unique IP(s) with AI indicators{Style.RESET_ALL}")

        # Persist as a normal enrichment_results.json so the post-task hook
        # ingests it into the database.
        out_dir = resolve_output_dir(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        json_file = out_dir / "enrichment_results.json"
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{Fore.GREEN}[+] AI scope results saved to: {json_file}{Style.RESET_ALL}")
        sys.exit(0)

    # Check if user provided input - if not, show help and configuration info
    if not args.input and not args.input_file:
        print(BANNER)
        parser.print_help()
        print(f"\n{Fore.CYAN}Quick Start:{Style.RESET_ALL}")
        print(f"  1. Configure API keys:  {Fore.YELLOW}cygor enrich config-manager set shodan YOUR_KEY{Style.RESET_ALL}")
        print(f"  2. List configured keys: {Fore.YELLOW}cygor enrich config-manager list{Style.RESET_ALL}")
        print(f"  3. Test your keys:       {Fore.YELLOW}cygor enrich config-manager test{Style.RESET_ALL}")
        print(f"  4. Enrich IOCs:          {Fore.YELLOW}cygor enrich 8.8.8.8{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}For API key management, use:{Style.RESET_ALL} cygor enrich config-manager --help")
        sys.exit(0)

    # Collect IOCs
    iocs = []

    if args.input_file:
        try:
            with open(args.input_file, 'r') as f:
                iocs = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading input file: {e}{Style.RESET_ALL}")
            sys.exit(1)
    elif args.input:
        if Path(args.input).exists():
            with open(args.input, 'r') as f:
                iocs = [line.strip() for line in f if line.strip()]
        else:
            iocs = [args.input]

    # Now check for API keys only when we have IOCs to enrich
    config_path = Path(args.config) if args.config else None
    config = EnrichmentConfig(config_path)

    if not config.is_configured():
        print(f"{Fore.RED}[!] No API keys configured!{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}To configure API keys, use:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}cygor enrich config-manager set shodan YOUR_API_KEY{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}cygor enrich config-manager set virustotal YOUR_API_KEY{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Or see all options:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}cygor enrich config-manager --help{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}[*] Alternative: Set environment variables or create config file at:{Style.RESET_ALL}")
        print(f"    {Path.home() / '.cygor' / 'enrich_config.json'}")
        sys.exit(1)

    # Parse sources argument
    sources = None
    if args.sources:
        # Normalize source names (vt -> virustotal)
        normalized_sources = []
        use_all = False
        for src in args.sources:
            if src == 'all':
                use_all = True
                break
            elif src == 'vt':
                normalized_sources.append('virustotal')
            else:
                normalized_sources.append(src)

        # Set sources based on what was specified
        if use_all:
            sources = None  # Use all configured sources
        else:
            sources = normalized_sources

    # Determine output directory - use workspace-aware resolution
    if args.output:
        # User specified output - use as-is if it's a directory, or parent if it's a file
        output_path = Path(args.output)
        if output_path.suffix in ['.json', '.csv', '.xml', '.txt']:
            output_dir = output_path.parent
        else:
            output_dir = output_path
        output_dir.mkdir(parents=True, exist_ok=True)
    else:
        # Use workspace-aware output directory
        output_dir = resolve_output_dir()

    # Update default timeout/retries if specified
    if args.timeout != 30.0 or args.retries != 3:
        default_settings = EnrichmentSettings(
            timeout=args.timeout,
            max_retries=args.retries
        )
        # Update all source settings with new defaults
        for source in SOURCE_SETTINGS:
            SOURCE_SETTINGS[source] = EnrichmentSettings(
                timeout=args.timeout,
                max_retries=args.retries,
                base_delay=SOURCE_SETTINGS[source].base_delay,
                max_delay=SOURCE_SETTINGS[source].max_delay,
            )

    # Enrich IOCs - always use async parallel mode with streaming (unless --sequential)
    results = []
    use_sequential = getattr(args, 'sequential', False)

    for ioc in iocs:
        if not ioc:
            continue

        sources_str = ", ".join(sources) if sources else "all configured sources"

        if use_sequential:
            # Legacy sequential enrichment (only if explicitly requested)
            print(f"{Fore.YELLOW}[*] Enriching: {ioc} (sequential mode){Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Sources: {sources_str}{Style.RESET_ALL}")
            result = enrich_ioc(ioc, config, sources, output_dir=str(output_dir))

            if args.format == "text":
                print_enrichment_result(result, "text")
        else:
            # Default: async parallel enrichment with real-time streaming
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Enriching: {ioc}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Sources: {sources_str}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

            result = run_async_enrichment(
                ioc=ioc,
                config=config,
                sources=sources,
                stream=True,  # Always stream results
                output_dir=output_dir,
                extract_subdomains=args.extract_subdomains,
                spray_lists=args.spray_lists,
            )

            # Print summary after enrichment
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}ENRICHMENT COMPLETE: {ioc}{Style.RESET_ALL}")
            print(f"  Sources queried: {result.get('sources_queried', 0)}")
            print(f"  Successful: {result.get('sources_successful', 0)}")
            print(f"  Total time: {result.get('total_time', 0):.1f}s")
            if result.get('consolidated_subdomains', {}).get('count'):
                print(f"  Subdomains: {result['consolidated_subdomains']['count']} saved to {result['consolidated_subdomains'].get('file', 'output directory')}")
            print(f"  Results saved to: {output_dir}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

        results.append(result)

    # Always save results to output directory (workspace or specified)
    try:
        # Determine output file paths
        if args.output and Path(args.output).suffix in ['.json', '.csv', '.xml', '.txt']:
            # User specified a specific file
            output_file = Path(args.output)
        else:
            # Save to output directory with default name
            output_file = output_dir / f"enrichment_results.{args.format if args.format != 'text' else 'json'}"

        # Save JSON (always save JSON for structured data)
        json_file = output_dir / "enrichment_results.json"
        with open(json_file, 'w') as f:
            json.dump(results, f, indent=2)

        # Save in requested format if different from JSON
        if args.format == "csv":
            csv_file = output_dir / "enrichment_results.csv"
            with open(csv_file, 'w') as f:
                f.write(format_results_as_csv(results))
            print(f"{Fore.GREEN}[+] CSV saved to: {csv_file}{Style.RESET_ALL}")
        elif args.format == "xml":
            xml_file = output_dir / "enrichment_results.xml"
            with open(xml_file, 'w') as f:
                f.write(format_results_as_xml(results))
            print(f"{Fore.GREEN}[+] XML saved to: {xml_file}{Style.RESET_ALL}")
        elif args.format == "text":
            txt_file = output_dir / "enrichment_results.txt"
            with open(txt_file, 'w') as f:
                for result in results:
                    f.write(f"\n{'='*80}\n")
                    f.write(f"IOC: {result.get('ioc', '')} ({result.get('type', '')})\n")
                    f.write(f"{'='*80}\n")
                    for enrichment in result.get('enrichments', []):
                        source = enrichment.get('source', 'unknown')
                        f.write(f"\n{source.upper()}:\n")
                        for key, value in enrichment.items():
                            if key not in ['source', 'ip', 'domain', '_elapsed']:
                                f.write(f"  {key}: {value}\n")

        print(f"{Fore.GREEN}[+] JSON saved to: {json_file}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[+] Results directory: {output_dir}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}[!] Error saving results: {e}{Style.RESET_ALL}")

    # Print results to stdout for formats that need it
    # Only print if sequential mode was used (streaming already displayed results)
    if use_sequential:
        if args.format == "json":
            print(json.dumps(results, indent=2))
        elif args.format == "csv":
            print(format_results_as_csv(results))
        elif args.format == "xml":
            print(format_results_as_xml(results))


if __name__ == "__main__":
    main()
