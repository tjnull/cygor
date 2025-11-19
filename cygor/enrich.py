"""
Cygor Enrich - Passive reconnaissance and threat intelligence enrichment
"""
import argparse
import json
import os
import sys
import re
import csv
import io
from pathlib import Path
from typing import Dict, List, Optional, Any
import requests
from colorama import Fore, Style, init

init(autoreset=True)

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
            'URLSCAN_API_KEY': 'urlscan'
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

        try:
            response = requests.get(url, timeout=10)
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

        try:
            response = requests.get(url, timeout=10)
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
                    resolve_response = requests.get(resolve_url, timeout=10)
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

        try:
            response = requests.get(url, headers=self.headers, timeout=10)
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

        try:
            response = requests.get(url, headers=self.headers, timeout=10)
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

        try:
            response = requests.get(url, headers=self.headers, params=params, timeout=10)
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


class AlienVaultOTXEnricher:
    """AlienVault OTX API enrichment"""

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"X-OTX-API-KEY": api_key}
        self.base_url = "https://otx.alienvault.com/api/v1"

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP with AlienVault OTX data"""
        url = f"{self.base_url}/indicators/IPv4/{ip}/general"

        try:
            response = requests.get(url, headers=self.headers, timeout=10)
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

        try:
            response = requests.get(url, headers=self.headers, timeout=10)
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

        try:
            response = requests.get(url, headers=self.headers, timeout=10)
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

        try:
            response = requests.get(url, headers=self.headers, timeout=10)
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


def enrich_ioc(ioc: str, config: EnrichmentConfig, sources: Optional[List[str]] = None) -> Dict[str, Any]:
    """Enrich a single IOC with specified or all available sources

    Args:
        ioc: The IOC to enrich
        config: Configuration with API keys
        sources: List of sources to use (e.g., ['shodan', 'virustotal']). If None, use all configured sources.
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
        sources = ['shodan', 'virustotal', 'abuseipdb', 'otx', 'urlscan']

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
  shodan      - Shodan (requires SHODAN_API_KEY)
  vt          - VirusTotal (requires VIRUSTOTAL_API_KEY or VT_API_KEY)
  virustotal  - VirusTotal (alias for 'vt')
  abuseipdb   - AbuseIPDB (requires ABUSEIPDB_API_KEY)
  otx         - AlienVault OTX (requires OTX_API_KEY)
  urlscan     - URLScan.io (requires URLSCAN_API_KEY)
  all         - Use all configured sources (default)
        """
    )

    parser.add_argument("input", nargs="?", help="IOC to enrich (IP, domain, or hash), or path to file with IOCs")
    parser.add_argument("-i", "--input-file", dest="input_file", help="File containing IOCs (one per line)")
    parser.add_argument("-o", "--output", dest="output", help="Output file for results")
    parser.add_argument("--format", choices=["text", "json", "csv", "xml"], default="text", help="Output format (default: text)")
    parser.add_argument("--config", dest="config", help="Path to config file with API keys")
    parser.add_argument("--sources", nargs="+", choices=["shodan", "vt", "virustotal", "abuseipdb", "otx", "urlscan", "all"],
                        help="Enrichment sources to use (default: all configured sources)")

    args = parser.parse_args(argv)

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
        for src in args.sources:
            if src == 'all':
                sources = None  # Use all configured sources
                break
            elif src == 'vt':
                normalized_sources.append('virustotal')
            else:
                normalized_sources.append(src)
        if sources is not None:
            sources = normalized_sources

    # Enrich IOCs
    results = []
    for ioc in iocs:
        if not ioc:
            continue

        sources_str = ", ".join(sources) if sources else "all configured sources"
        print(f"{Fore.YELLOW}[*] Enriching: {ioc} (using {sources_str}){Style.RESET_ALL}")
        result = enrich_ioc(ioc, config, sources)
        results.append(result)

        if args.format == "text":
            print_enrichment_result(result, "text")

    # Save output if requested
    if args.output:
        try:
            with open(args.output, 'w') as f:
                if args.format == "json":
                    json.dump(results, f, indent=2)
                elif args.format == "csv":
                    f.write(format_results_as_csv(results))
                elif args.format == "xml":
                    f.write(format_results_as_xml(results))
                else:  # text format
                    for result in results:
                        f.write(f"\n{'='*80}\n")
                        f.write(f"IOC: {result.get('ioc', '')} ({result.get('type', '')})\n")
                        f.write(f"{'='*80}\n")
                        for enrichment in result.get('enrichments', []):
                            source = enrichment.get('source', 'unknown')
                            f.write(f"\n{source.upper()}:\n")
                            for key, value in enrichment.items():
                                if key not in ['source', 'ip', 'domain']:
                                    f.write(f"  {key}: {value}\n")
            print(f"\n{Fore.GREEN}[+] Results saved to: {args.output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {e}{Style.RESET_ALL}")
    elif args.format == "json":
        print(json.dumps(results, indent=2))
    elif args.format == "csv":
        print(format_results_as_csv(results))
    elif args.format == "xml":
        print(format_results_as_xml(results))


if __name__ == "__main__":
    main()
