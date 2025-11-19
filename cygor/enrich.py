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
            'URLSCAN_API_KEY': 'urlscan',
            'CENSYS_API_ID': 'censys',  # Format: API_ID:SECRET
            'DEHASHED_API_KEY': 'dehashed'  # Format: email:api_key
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

        try:
            response = requests.get(url, auth=(self.api_id, self.api_secret), timeout=10)
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

        try:
            response = requests.get(url, auth=(self.api_id, self.api_secret), params=params, timeout=10)
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

            response = requests.get(self.base_url, params=params, timeout=30)

            # If no results, try without wildcard subdomain
            if response.status_code == 200:
                try:
                    data = response.json()
                    if len(data) <= 1:  # Only header or empty
                        # Try strategy 2: exact domain match
                        params["url"] = f"{domain}/*"
                        response = requests.get(self.base_url, params=params, timeout=30)
                        data = response.json()
                except:
                    # Try strategy 2 if parsing failed
                    params["url"] = f"{domain}/*"
                    response = requests.get(self.base_url, params=params, timeout=30)
                    data = response.json()
            else:
                # Try strategy 2 if first request failed
                params["url"] = f"{domain}/*"
                response = requests.get(self.base_url, params=params, timeout=30)
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
        try:
            response = requests.get(f"{self.base_url}/collinfo.json", timeout=10)
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

                    response = requests.get(url, params=params, timeout=10)

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
        try:
            params = {"query": query, "size": size}
            auth = (self.api_email, self.api_key)
            headers = {"Accept": "application/json"}

            response = requests.get(self.base_url, params=params, auth=auth, headers=headers, timeout=30)

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

        # Censys
        if 'censys' in sources and config.get("censys"):
            enricher = CensysEnricher(config.get("censys"))
            result["enrichments"].append(enricher.enrich_ip(ioc))

        # Dehashed
        if 'dehashed' in sources and config.get("dehashed"):
            api_creds = config.get("dehashed")
            # Split email:api_key format
            if ":" in api_creds:
                api_email, api_key = api_creds.split(":", 1)
                enricher = DehashedEnricher(api_email, api_key, output_dir=output_dir)
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
  otx          - AlienVault OTX (requires OTX_API_KEY)
  urlscan      - URLScan.io (requires URLSCAN_API_KEY)
  censys       - Censys (requires CENSYS_API_ID in format API_ID:SECRET)
  wayback      - Wayback Machine (no API key required)
  commoncrawl  - Common Crawl (no API key required)
  dehashed     - Dehashed (requires DEHASHED_API_KEY in format email:api_key)
  all          - Use all configured sources (default)
        """
    )

    parser.add_argument("input", nargs="?", help="IOC to enrich (IP, domain, or hash), or path to file with IOCs")
    parser.add_argument("-i", "--input-file", dest="input_file", help="File containing IOCs (one per line)")
    parser.add_argument("-o", "--output", dest="output", help="Output file for results")
    parser.add_argument("--format", choices=["text", "json", "csv", "xml"], default="text", help="Output format (default: text)")
    parser.add_argument("--config", dest="config", help="Path to config file with API keys")
    parser.add_argument("--sources", nargs="+", choices=["shodan", "vt", "virustotal", "abuseipdb", "otx", "urlscan", "censys", "wayback", "commoncrawl", "dehashed", "all"],
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

    # Determine output directory for Dehashed processed files
    output_dir = None
    if args.output:
        output_dir = str(Path(args.output).parent)

    # Enrich IOCs
    results = []
    for ioc in iocs:
        if not ioc:
            continue

        sources_str = ", ".join(sources) if sources else "all configured sources"
        print(f"{Fore.YELLOW}[*] Enriching: {ioc} (using {sources_str}){Style.RESET_ALL}")
        result = enrich_ioc(ioc, config, sources, output_dir=output_dir)
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

    # Always print results to stdout
    # For text format: if output file was specified, print again so web UI can capture complete output
    # For other formats: always print to stdout
    if args.format == "json":
        print(json.dumps(results, indent=2))
    elif args.format == "csv":
        print(format_results_as_csv(results))
    elif args.format == "xml":
        print(format_results_as_xml(results))
    elif args.format == "text" and args.output:
        # Re-print text results to stdout for web UI capture when output file is specified
        for result in results:
            print(f"\n{'='*80}")
            print(f"IOC: {result.get('ioc', '')} ({result.get('type', '')})")
            print(f"{'='*80}")
            print_enrichment_result(result, "text")


if __name__ == "__main__":
    main()
