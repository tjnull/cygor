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
        """Enrich IP with Shodan data"""
        url = f"{self.base_url}/shodan/host/{ip}?key={self.api_key}"

        try:
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                return {
                    "source": "shodan",
                    "ip": ip,
                    "hostnames": data.get("hostnames", []),
                    "ports": data.get("ports", []),
                    "vulns": data.get("vulns", []),
                    "org": data.get("org", ""),
                    "asn": data.get("asn", ""),
                    "country": data.get("country_name", ""),
                    "city": data.get("city", ""),
                    "last_update": data.get("last_update", ""),
                }
            else:
                return {"source": "shodan", "error": f"HTTP {response.status_code}"}
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

                return {
                    "source": "virustotal",
                    "domain": domain,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": attrs.get("reputation", 0),
                    "link": f"https://www.virustotal.com/gui/domain/{domain}"
                }
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
                }
            else:
                return {"source": "abuseipdb", "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"source": "abuseipdb", "error": str(e)}


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

    elif ioc_type == "domain":
        # VirusTotal
        if 'virustotal' in sources and config.get("virustotal"):
            enricher = VirusTotalEnricher(config.get("virustotal"))
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

        for key, value in enrichment.items():
            if key in ["source", "ip", "domain"]:
                continue
            print(f"  {key}: {value}")


def main(argv=None):
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
        print(f"  1. Configure API keys:  {Fore.YELLOW}cygor enrich-config set shodan YOUR_KEY{Style.RESET_ALL}")
        print(f"  2. List configured keys: {Fore.YELLOW}cygor enrich-config list{Style.RESET_ALL}")
        print(f"  3. Test your keys:       {Fore.YELLOW}cygor enrich-config test{Style.RESET_ALL}")
        print(f"  4. Enrich IOCs:          {Fore.YELLOW}cygor enrich 8.8.8.8{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}For API key management, use:{Style.RESET_ALL} cygor enrich-config --help")
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
        print(f"  {Fore.YELLOW}cygor enrich-config set shodan YOUR_API_KEY{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}cygor enrich-config set virustotal YOUR_API_KEY{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Or see all options:{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}cygor enrich-config --help{Style.RESET_ALL}")
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
