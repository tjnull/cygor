"""
Cygor Enrich Config - CLI tool for managing enrichment API keys
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Optional
import requests
from colorama import Fore, Style, init

init(autoreset=True)

CONFIG_DIR = Path.home() / ".cygor"
CONFIG_FILE = CONFIG_DIR / "enrich_config.json"

# Source information
SOURCES = {
    "shodan": {
        "name": "Shodan",
        "env_var": "SHODAN_API_KEY",
        "url": "https://account.shodan.io/",
        "test_url": "https://api.shodan.io/api-info?key={key}"
    },
    "virustotal": {
        "name": "VirusTotal",
        "env_var": "VIRUSTOTAL_API_KEY",
        "url": "https://www.virustotal.com/gui/my-apikey",
        "test_url": "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
    },
    "abuseipdb": {
        "name": "AbuseIPDB",
        "env_var": "ABUSEIPDB_API_KEY",
        "url": "https://www.abuseipdb.com/account/api",
        "test_url": "https://api.abuseipdb.com/api/v2/check"
    },
    "otx": {
        "name": "AlienVault OTX",
        "env_var": "OTX_API_KEY",
        "url": "https://otx.alienvault.com/api",
        "test_url": "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general"
    },
    "urlscan": {
        "name": "URLScan.io",
        "env_var": "URLSCAN_API_KEY",
        "url": "https://urlscan.io/user/profile/",
        "test_url": "https://urlscan.io/api/v1/search/?q=domain:google.com"
    }
}


def ensure_config_dir():
    """Ensure config directory exists"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    """Load API key configuration"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"{Fore.RED}[!] Error loading config: {e}{Style.RESET_ALL}")
            return {}
    return {}


def save_config(config: dict):
    """Save API key configuration"""
    ensure_config_dir()
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        # Set restrictive permissions (600 - owner read/write only)
        CONFIG_FILE.chmod(0o600)
        print(f"{Fore.GREEN}[+] Configuration saved to: {CONFIG_FILE}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error saving config: {e}{Style.RESET_ALL}")
        sys.exit(1)


def test_api_key(source: str, api_key: str) -> tuple[bool, Optional[str]]:
    """Test an API key to verify it's valid

    Returns:
        tuple: (is_valid, error_message)
            - is_valid: True if key is valid, False otherwise
            - error_message: None if valid, error message string if invalid
    """
    try:
        if source == "shodan":
            url = f"https://api.shodan.io/api-info?key={api_key}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                return True, None
            try:
                error_data = response.json()
                return False, error_data.get("error", f"HTTP {response.status_code}")
            except:
                return False, f"HTTP {response.status_code}"

        elif source == "virustotal":
            url = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
            headers = {"x-apikey": api_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return True, None
            # Check for quota exceeded
            try:
                error_data = response.json()
                if "error" in error_data:
                    error_code = error_data["error"].get("code", "")
                    error_msg = error_data["error"].get("message", "")
                    if error_code == "QuotaExceededError":
                        return False, f"Quota exceeded - {error_msg}. Your API key is valid but you've reached your API quota limit. The key will still be saved and will work once your quota resets."
                    return False, f"{error_code}: {error_msg}"
                return False, f"HTTP {response.status_code}"
            except:
                return False, f"HTTP {response.status_code}"

        elif source == "abuseipdb":
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {"Accept": "application/json", "Key": api_key}
            params = {"ipAddress": "8.8.8.8", "maxAgeInDays": 90}
            response = requests.get(url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                return True, None
            try:
                error_data = response.json()
                errors = error_data.get("errors", [])
                if errors:
                    return False, str(errors[0])
                return False, f"HTTP {response.status_code}"
            except:
                return False, f"HTTP {response.status_code}"

        elif source == "otx":
            url = "https://otx.alienvault.com/api/v1/indicators/IPv4/8.8.8.8/general"
            headers = {"X-OTX-API-KEY": api_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return True, None
            try:
                error_data = response.json()
                return False, error_data.get("detail", f"HTTP {response.status_code}")
            except:
                return False, f"HTTP {response.status_code}"

        elif source == "urlscan":
            url = "https://urlscan.io/api/v1/search/?q=domain:google.com"
            headers = {"API-Key": api_key}
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                return True, None
            try:
                error_data = response.json()
                return False, error_data.get("message", f"HTTP {response.status_code}")
            except:
                return False, f"HTTP {response.status_code}"

        return False, "Unknown source"

    except requests.exceptions.Timeout:
        return False, "Request timed out"
    except requests.exceptions.RequestException as e:
        return False, f"Request error: {e}"
    except Exception as e:
        return False, f"Error testing key: {e}"


def cmd_set(args):
    """Set an API key"""
    source = args.source.lower()

    if source not in SOURCES:
        print(f"{Fore.RED}[!] Unknown source: {source}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Available sources: {', '.join(SOURCES.keys())}{Style.RESET_ALL}")
        sys.exit(1)

    api_key = args.key

    # Test key if requested
    if not args.no_test:
        print(f"{Fore.YELLOW}[*] Testing {SOURCES[source]['name']} API key...{Style.RESET_ALL}")
        is_valid, error_msg = test_api_key(source, api_key)
        if is_valid:
            print(f"{Fore.GREEN}[+] API key is valid!{Style.RESET_ALL}")
        else:
            # Validation failed - but we need to determine if we should save anyway
            should_save = False

            if error_msg:
                # Check if it's a quota error (key is valid but quota exceeded)
                if "quota" in error_msg.lower():
                    print(f"{Fore.YELLOW}[!] {error_msg}{Style.RESET_ALL}")
                    # Auto-save for quota errors since the key is valid
                    print(f"{Fore.GREEN}[+] Saving API key anyway (quota errors don't indicate invalid keys){Style.RESET_ALL}")
                    should_save = True
                else:
                    print(f"{Fore.RED}[!] API key validation failed!{Style.RESET_ALL}")
                    print(f"{Fore.YELLOW}[!] Error: {error_msg}{Style.RESET_ALL}")
                    should_save = args.force
            else:
                print(f"{Fore.RED}[!] API key validation failed!{Style.RESET_ALL}")
                should_save = args.force

            # If we shouldn't save and force is not set, exit
            if not should_save:
                print(f"{Fore.YELLOW}[*] Use --force to save anyway{Style.RESET_ALL}")
                sys.exit(1)

    # Save key
    config = load_config()
    config[source] = api_key
    save_config(config)


def cmd_get(args):
    """Get an API key"""
    source = args.source.lower()

    if source not in SOURCES:
        print(f"{Fore.RED}[!] Unknown source: {source}{Style.RESET_ALL}")
        sys.exit(1)

    config = load_config()
    key = config.get(source)

    if key:
        if args.show:
            print(key)
        else:
            # Mask key for security
            masked = f"{'*' * (len(key) - 4)}{key[-4:]}" if len(key) > 4 else "****"
            print(f"{SOURCES[source]['name']}: {masked}")
    else:
        print(f"{Fore.YELLOW}[!] No API key configured for {SOURCES[source]['name']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Get your API key from: {SOURCES[source]['url']}{Style.RESET_ALL}")
        sys.exit(1)


def cmd_list(args):
    """List all configured API keys"""
    config = load_config()

    if not config:
        print(f"{Fore.YELLOW}[!] No API keys configured{Style.RESET_ALL}")
        print(f"\n{Fore.CYAN}Available sources:{Style.RESET_ALL}")
        for source, info in SOURCES.items():
            print(f"  {source:15} - {info['name']:20} ({info['url']})")
        sys.exit(0)

    print(f"{Fore.GREEN}Configured API Keys:{Style.RESET_ALL}")
    print(f"Config file: {CONFIG_FILE}\n")

    for source, info in SOURCES.items():
        key = config.get(source)
        if key:
            if args.show:
                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {source:15} - {key}")
            else:
                masked = f"{'*' * (len(key) - 4)}{key[-4:]}" if len(key) > 4 else "****"
                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {source:15} - {masked}")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} {source:15} - Not configured")

    if not args.show:
        print(f"\n{Fore.CYAN}[*] Use --show to display full keys{Style.RESET_ALL}")


def cmd_unset(args):
    """Remove an API key"""
    source = args.source.lower()

    if source not in SOURCES:
        print(f"{Fore.RED}[!] Unknown source: {source}{Style.RESET_ALL}")
        sys.exit(1)

    config = load_config()

    if source in config:
        del config[source]
        save_config(config)
        print(f"{Fore.GREEN}[+] Removed API key for {SOURCES[source]['name']}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[!] No API key configured for {SOURCES[source]['name']}{Style.RESET_ALL}")


def cmd_test(args):
    """Test API keys"""
    config = load_config()

    if not config:
        print(f"{Fore.YELLOW}[!] No API keys configured{Style.RESET_ALL}")
        sys.exit(1)

    # Test specific source or all
    sources_to_test = [args.source.lower()] if args.source else list(config.keys())

    print(f"{Fore.CYAN}Testing API keys...{Style.RESET_ALL}\n")

    results = {}
    for source in sources_to_test:
        if source not in config:
            print(f"{Fore.YELLOW}[!] {SOURCES[source]['name']:15} - Not configured{Style.RESET_ALL}")
            continue

        print(f"{Fore.YELLOW}[*] Testing {SOURCES[source]['name']}...{Style.RESET_ALL}", end=" ")
        is_valid, error_msg = test_api_key(source, config[source])
        results[source] = is_valid

        if is_valid:
            print(f"{Fore.GREEN}✓ Valid{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}✗ Invalid{Style.RESET_ALL}")
            if error_msg:
                # Show the error message indented
                if "quota" in error_msg.lower():
                    print(f"  {Fore.YELLOW}→ {error_msg}{Style.RESET_ALL}")
                else:
                    print(f"  {Fore.RED}→ {error_msg}{Style.RESET_ALL}")

    # Summary
    print(f"\n{Fore.CYAN}Summary:{Style.RESET_ALL}")
    valid_count = sum(1 for v in results.values() if v)
    total_count = len(results)
    print(f"  Valid: {valid_count}/{total_count}")

    if valid_count < total_count:
        sys.exit(1)


def cmd_info(args):
    """Show information about sources"""
    if args.source:
        source = args.source.lower()
        if source not in SOURCES:
            print(f"{Fore.RED}[!] Unknown source: {source}{Style.RESET_ALL}")
            sys.exit(1)

        info = SOURCES[source]
        config = load_config()
        is_configured = source in config

        print(f"\n{Fore.CYAN}{info['name']}{Style.RESET_ALL}")
        print(f"  Source ID:       {source}")
        print(f"  Status:          {'✓ Configured' if is_configured else '✗ Not configured'}")
        print(f"  Environment Var: {info['env_var']}")
        print(f"  Get API Key:     {info['url']}")
        print()

    else:
        # Show all sources
        config = load_config()
        print(f"\n{Fore.CYAN}Available Enrichment Sources:{Style.RESET_ALL}\n")

        for source, info in SOURCES.items():
            is_configured = source in config
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if is_configured else f"{Fore.RED}✗{Style.RESET_ALL}"
            print(f"{status} {info['name']:20} - {info['url']}")

        print(f"\n{Fore.CYAN}[*] Use 'cygor enrich config-manager info <source>' for details{Style.RESET_ALL}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="cygor enrich config-manager",
        description="Manage enrichment API keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Set an API key (with automatic validation)
  cygor enrich config-manager set shodan YOUR_API_KEY

  # Set an API key without validation
  cygor enrich config-manager set virustotal YOUR_KEY --no-test

  # Get an API key (masked)
  cygor enrich config-manager get shodan

  # Get an API key (full)
  cygor enrich config-manager get shodan --show

  # List all configured keys
  cygor enrich config-manager list

  # List all keys (show full keys)
  cygor enrich config-manager list --show

  # Remove an API key
  cygor enrich config-manager unset shodan

  # Test all configured keys
  cygor enrich config-manager test

  # Test a specific key
  cygor enrich config-manager test shodan

  # Show available sources
  cygor enrich config-manager info

  # Show info about a specific source
  cygor enrich config-manager info virustotal

Available sources: shodan, virustotal, abuseipdb, otx, urlscan
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Set command
    set_parser = subparsers.add_parser("set", help="Set an API key")
    set_parser.add_argument("source", help="Source name (shodan, virustotal, abuseipdb, otx, urlscan)")
    set_parser.add_argument("key", help="API key")
    set_parser.add_argument("--no-test", action="store_true", help="Skip API key validation")
    set_parser.add_argument("--force", action="store_true", help="Save even if validation fails")

    # Get command
    get_parser = subparsers.add_parser("get", help="Get an API key")
    get_parser.add_argument("source", help="Source name")
    get_parser.add_argument("--show", action="store_true", help="Show full API key (default: masked)")

    # List command
    list_parser = subparsers.add_parser("list", help="List all configured API keys")
    list_parser.add_argument("--show", action="store_true", help="Show full API keys (default: masked)")

    # Unset command
    unset_parser = subparsers.add_parser("unset", help="Remove an API key")
    unset_parser.add_argument("source", help="Source name")

    # Test command
    test_parser = subparsers.add_parser("test", help="Test API keys")
    test_parser.add_argument("source", nargs="?", help="Source to test (default: all)")

    # Info command
    info_parser = subparsers.add_parser("info", help="Show information about sources")
    info_parser.add_argument("source", nargs="?", help="Source name (default: show all)")

    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Dispatch to command handler
    if args.command == "set":
        cmd_set(args)
    elif args.command == "get":
        cmd_get(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "unset":
        cmd_unset(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "info":
        cmd_info(args)


if __name__ == "__main__":
    main()
