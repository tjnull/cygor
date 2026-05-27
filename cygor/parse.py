# cygor/parse.py
# Parse Nmap scan files into categorized hostlists
import os
import sys
import argparse
import re
import json
import csv
import xml.etree.ElementTree as ET
from colorama import Fore, Style, init
from pathlib import Path

# Initialize colorama
init(autoreset=True, strip=False)

# Try to import libnmap, but allow fallback if it's not installed
try:
    from libnmap.parser import NmapParser, NmapParserException
except Exception:
    NmapParser = None
    class NmapParserException(Exception):
        pass

# --- Colorized help formatter ---
from argparse import RawTextHelpFormatter
class ColorHelpFormatter(RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    def start_section(self, heading):
        heading = f"{Fore.CYAN}{heading}{Style.RESET_ALL}"
        super().start_section(heading)
    def _format_action_invocation(self, action):
        parts = super()._format_action_invocation(action)
        return f"{Fore.YELLOW}{parts}{Style.RESET_ALL}"

# --- Banner & Examples ---
BANNER = f"""
{Fore.GREEN}{'='*60}
  CYGOR PARSE - Nmap XML & Hostlist Extraction
{'='*60}{Style.RESET_ALL}
"""

EXAMPLES = f"""
   {Fore.MAGENTA}Examples:{Style.RESET_ALL}

    {Fore.YELLOW}# Parse a directory of Nmap results and print hostlists{Style.RESET_ALL}
    cygor parse results/nmap

    {Fore.YELLOW}# Parse a single XML and write hostlists to results/parsed-hostlists{Style.RESET_ALL}
    cygor parse results/nmap/scan1.xml -o results

    {Fore.YELLOW}# Recursively parse .xml/.nmap/.gnmap files and write outputs{Style.RESET_ALL}
    cygor parse /path/to/scans --out-dir results
"""

# ---------------- Services & Fingerprints ----------------

SERVICES = {
    # Web / Admin Panels
    "http": [
        80, 81, 3000, 3333, 5000, 7001, 8000, 8008, 8080,
        8081, 8088, 8443, 8888, 9000, 9080, 10000, 10443,
        12000, 16080, 18080, 50080
    ],
    "https": [
        443, 4443, 5443, 7443, 8443, 9443, 10443, 12443, 16443, 18443
    ],

    # File sharing
    "smb": [139, 445],
    "nfs": [2049],
    "ftp": [20, 21, 2121],
    "tftp": [69],

    # Remote access
    "ssh": [22],
    "telnet": [23],
    "rdp": [3389],
    "winrm": [5985, 5986],
    "vnc": [5900, 5901, 5902, 5903, 5904, 5905],

    # Databases
    "mysql": [3306],
    "postgres": [5432],
    "mssql": [1433, 1434],
    "oracle": [1521],
    "mongodb": [27017, 27018],
    "couchdb": [5984],
    "redis": [6379],
    "elasticsearch": [9200, 9300],
    "cassandra": [9042],
    "db2": [50000],

    # Mail
    "smtp": [25, 465, 587, 2525],
    "imap": [143, 993],
    "pop3": [110, 995],

    # Directory & auth
    "ldap": [389, 636],
    "kerberos": [88, 464],
    "radius": [1812, 1813],

    # Other infra
    "dns": [53],
    "snmp": [161, 162],
    "ntp": [123],
    "ipp": [631],

    # Messaging / IoT
    "mqtt": [1883, 8883],
    "amqp": [5672, 5671],
    "stomp": [61613],
    "zeromq": [5555],
    "memcached": [11211],

    # DevOps / APIs
    "docker-api": [2375, 2376],
    "kubernetes-api": [6443],

    # Virtualization (only Proxmox + Hyper-V get their own lists)
    "proxmox": [8006],
    "hyperv": [2179],
}

FINGERPRINTS = {
    "proxmox": ["proxmox", "pve", "proxmox ve"],
    "hyperv": ["microsoft hyper-v", "hyper-v"],
    # ESXi, Xen, OpenStack handled only as web-like
    "esxi": ["vmware esxi", "vsphere", "vcenter", "vmware"],
    "xen": ["xen", "citrix hypervisor"],
    "openstack": ["openstack", "keystone", "nova", "glance", "neutron"],
}

# Web-like categories always also go into http/https
WEBLIKE_CATEGORIES = {"proxmox", "hyperv", "esxi", "xen", "openstack"}

# Per-port HTTPS hint: these are HTTPS-only by convention. When a port
# matches one of these AND the service-name lookup picks a 'weblike'
# category (proxmox 8006, hyperv 2179, ...), we should add to https only,
# not double-list into the http hostlist -- otherwise lockon/webenum
# will try plaintext HTTP against an HTTPS-only service and waste time.
# Conversely the plain 'http' ports go only to http.
_HTTPS_ONLY_PORTS = {443, 4443, 5443, 6443, 7443, 8443, 9443, 10443, 12443,
                     16443, 18443, 8006, 2179}
_HTTP_ONLY_PORTS = {80, 8000, 8080, 8081, 8088, 8888, 9000, 9080, 10000,
                    16080, 18080, 50080, 12000}


def _add_to_web_buckets(hosts: dict, target_entry: str, port: int | None) -> None:
    """Add a target to the appropriate web hostlist(s) based on port.

    HTTPS-only ports go to 'https' only. HTTP-only ports go to 'http'
    only. Anything else -- ambiguous ports, fingerprint-driven matches
    where we don't know the port shape -- gets both as a safe default
    so lockon/webenum can probe and discard.
    """
    if port in _HTTPS_ONLY_PORTS:
        hosts["https"].add(target_entry)
    elif port in _HTTP_ONLY_PORTS:
        hosts["http"].add(target_entry)
    else:
        hosts["http"].add(target_entry)
        hosts["https"].add(target_entry)

# ---------------- Parsing helpers ----------------

def parse_nmap_xml(file_path):
    hosts = {service: set() for service in SERVICES}
    for cat in FINGERPRINTS.keys():
        hosts.setdefault(cat, set())

    if NmapParser is None:
        print(f"{Fore.RED}[!] libnmap not installed — cannot parse XML file: {file_path}")
        return hosts

    try:
        nmap_report = NmapParser.parse_fromfile(file_path)
        print(f"{Fore.YELLOW}[i] Parsing XML file: {file_path}")

        for host in nmap_report.hosts:
            if not host.is_up():
                continue

            for service in host.services:
                if service.state != 'open':
                    continue

                port = getattr(service, "port", None)
                target_entry = f"{host.address}:{port}" if port else host.address

                # Port-based. SERVICES["http"] and SERVICES["https"] both
                # contain ports like 8443 (which appears in both because
                # some web servers expose both schemes there); but for the
                # http / https hostlists we want a single canonical bucket
                # per target, not double-listing. So for web services skip
                # the direct hosts[serv_name].add() and let
                # _add_to_web_buckets() route by port.
                for serv_name, ports in SERVICES.items():
                    if port in ports:
                        if serv_name in ("http", "https"):
                            # Routed below; skip the direct add to avoid
                            # leaking 8443 into the http bucket (etc.).
                            continue
                        if serv_name == "smb":
                            hosts[serv_name].add(host.address)
                        else:
                            hosts[serv_name].add(target_entry)

                        if serv_name in WEBLIKE_CATEGORIES:
                            _add_to_web_buckets(hosts, target_entry, port)

                # Dedicated http/https port routing (single canonical bucket
                # per target based on the port number).
                if (port in SERVICES.get("http", [])
                        or port in SERVICES.get("https", [])):
                    _add_to_web_buckets(hosts, target_entry, port)

                # Fingerprint-based: the banner says it's web-like, but we
                # don't know the protocol from the banner alone. Use the
                # port to pick the right bucket(s).
                combined = " ".join([
                    (getattr(service, "service", "") or "").lower(),
                    (getattr(service, "product", "") or "").lower(),
                    (getattr(service, "banner", "") or "").lower(),
                    (getattr(service, "servicefp", "") or "").lower()
                ])
                for category, keywords in FINGERPRINTS.items():
                    if any(k in combined for k in keywords):
                        if category in ("proxmox", "hyperv"):
                            hosts[category].add(target_entry)
                        _add_to_web_buckets(hosts, target_entry, port)

    except NmapParserException as e:
        # Check if this is actually a non-Nmap XML file (like from enumeration modules)
        if "Unpexpected data structure" in str(e) or "unexpected" in str(e).lower():
            # Silently skip enumeration module XML files
            pass
        else:
            print(f"{Fore.RED}[!] Error parsing {file_path}: {e}")
    except Exception as e:
        # Catch any other parsing errors
        if "enumeration-modules" in file_path:
            # Silently skip enumeration module files
            pass
        else:
            print(f"{Fore.RED}[!] Unexpected error parsing {file_path}: {e}")
    return hosts

# In a gnmap "Ports:" segment, each entry looks like
#   <port>/<state>/<proto>//<service>//<version>
# We need every (port, "open") pair on the line, not just the first.
_GNMAP_PORT_RE = re.compile(r"(\d{1,5})/open/")
# In a .nmap text body, ports are one per line like  `22/tcp   open  ssh ...`
_NMAP_PORT_LINE_RE = re.compile(r"^(\d{1,5})/(?:tcp|udp)\s+open\s")
# Validate an extracted token is an IP literal (v4 or v6). Doing the structural
# parse first and validating with the stdlib is more robust than building a
# regex that covers every legal IPv6 compressed form.
import ipaddress as _ipaddress


def _looks_like_ip(token: str) -> bool:
    if not token:
        return False
    try:
        _ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def _extract_ip_from_gnmap_host(host_segment: str) -> str | None:
    """Pull the IP from a gnmap 'Host: <ip> (<hostname>)' segment.

    gnmap always puts the IP immediately after 'Host:' and before either
    a space-paren-hostname-paren or the end of the segment. Structural
    parsing handles every legal IP form (v4 + v6 compressed) without
    fighting regex edge cases."""
    if "Host:" not in host_segment:
        return None
    after = host_segment.split("Host:", 1)[1].strip()
    # Optional "(hostname)" trailer is whitespace-separated.
    token = after.split()[0] if after else ""
    return token if _looks_like_ip(token) else None


def _extract_ip_from_scan_report(line: str) -> str | None:
    """Pull the IP from `Nmap scan report for <something>`. Handles:
        Nmap scan report for 10.0.0.1
        Nmap scan report for 2001:db8::1
        Nmap scan report for host.example.com (10.0.0.1)
        Nmap scan report for host.example.com (2001:db8::1)
    Prefers the parenthesised IP when both a name and a paren-IP are
    present (the parenthesised one is what nmap resolved).
    """
    marker = "Nmap scan report for"
    if marker not in line:
        return None
    rest = line.split(marker, 1)[1].strip()
    # Parenthesised IP takes precedence.
    if "(" in rest and ")" in rest:
        inner = rest[rest.rfind("(") + 1:rest.rfind(")")].strip()
        if _looks_like_ip(inner):
            return inner
    # Otherwise the leading token must be the IP.
    token = rest.split()[0] if rest else ""
    return token if _looks_like_ip(token) else None


def _format_target(ip: str, port: int) -> str:
    """Render `ip:port` for hostlists. IPv6 gets `[host]:port` brackets so
    the result is shell- and URL-parsable (`http://[2001:db8::1]:80`)."""
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def parse_nmap_text(file_path):
    """Parse .nmap or .gnmap output into per-service hostlists.

    Handles both formats and IPv6 in both. gnmap is line-oriented (`Host:
    <ip> ...  Ports: 22/open/tcp//ssh//, 80/open/tcp//http//`), so every
    `port/open` substring on a single Host: line is collected -- the old
    regex captured only the first and silently dropped the rest.
    .nmap is block-oriented (`Nmap scan report for <ip>` followed by
    per-line `port/proto open service`), so we track the current host
    across lines.
    """
    hosts = {service: set() for service in SERVICES}
    for cat in FINGERPRINTS.keys():
        hosts.setdefault(cat, set())

    print(f"{Fore.YELLOW}[i] Parsing text-based file: {file_path}")

    def _record(ip: str, port_num: int) -> None:
        target_entry = _format_target(ip, port_num)
        for service, ports in SERVICES.items():
            if port_num in ports:
                if service in ("http", "https"):
                    # Routed via _add_to_web_buckets below; skip direct add
                    # to avoid double-listing ports that appear in both
                    # SERVICES["http"] and SERVICES["https"] (e.g. 8443).
                    continue
                if service == "smb":
                    hosts[service].add(ip)
                else:
                    hosts[service].add(target_entry)
                if service in WEBLIKE_CATEGORIES:
                    _add_to_web_buckets(hosts, target_entry, port_num)
        if (port_num in SERVICES.get("http", [])
                or port_num in SERVICES.get("https", [])):
            _add_to_web_buckets(hosts, target_entry, port_num)

    is_gnmap = str(file_path).lower().endswith(".gnmap")
    current_ip: str | None = None

    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if is_gnmap:
                # gnmap puts host + all its ports on a single line. The
                # "Host: <ip>" segment comes before "Ports:" -- splitting
                # on Ports: avoids picking ports out of the hostname.
                if "Host:" not in line:
                    continue
                host_seg = line.split("Ports:", 1)[0]
                ip = _extract_ip_from_gnmap_host(host_seg)
                if not ip:
                    continue
                ports_seg = line.split("Ports:", 1)[1] if "Ports:" in line else ""
                for m in _GNMAP_PORT_RE.finditer(ports_seg):
                    port_num = int(m.group(1))
                    if 1 <= port_num <= 65535:
                        _record(ip, port_num)
                continue

            # .nmap text format: track the host across lines.
            if line.startswith("Nmap scan report for"):
                current_ip = _extract_ip_from_scan_report(line)
                continue
            if current_ip is None:
                continue
            m = _NMAP_PORT_LINE_RE.match(line)
            if m:
                port_num = int(m.group(1))
                if 1 <= port_num <= 65535:
                    _record(current_ip, port_num)
    return hosts

# ---------------- Writers ----------------

def _write_service_hostlist(base_dir: str, service: str, items: set[str]) -> None:
    if not items:
        return
    svc_dir_name = service
    filename = f"{service}-hostlist.txt"
    if service == "http+https":
        svc_dir_name = "http-https"
        filename = "http-https-hostlist.txt"
    svc_dir = os.path.join(base_dir, svc_dir_name)
    os.makedirs(svc_dir, exist_ok=True)
    out_file = os.path.join(svc_dir, filename)
    try:
        with open(out_file, "w") as f:
            f.write("\n".join(sorted(items)))
        print(f"{Fore.GREEN}[+] Saved: {out_file}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error writing to {out_file}: {e}")

def save_as_json(hosts, base_dir=None):
    data = {svc: sorted(list(items)) for svc, items in hosts.items() if items}
    if base_dir:
        out_file = os.path.join(base_dir, "parsed-hosts.json")
        with open(out_file, "w") as f:
            json.dump(data, f, indent=2)
        print(f"{Fore.GREEN}[+] Saved JSON: {out_file}")
    else:
        print(json.dumps(data, indent=2))

def save_as_csv(hosts, base_dir=None):
    if base_dir:
        out_file = os.path.join(base_dir, "parsed-hosts.csv")
        with open(out_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["service", "host"])
            for svc, items in sorted(hosts.items()):
                for item in sorted(items):
                    writer.writerow([svc, item])
        print(f"{Fore.GREEN}[+] Saved CSV: {out_file}")
    else:
        writer = csv.writer(sys.stdout)
        writer.writerow(["service", "host"])
        for svc, items in sorted(hosts.items()):
            for item in sorted(items):
                writer.writerow([svc, item])

def save_as_xml(hosts, base_dir=None):
    root = ET.Element("services")
    for svc, items in sorted(hosts.items()):
        svc_el = ET.SubElement(root, "service", name=svc)
        for item in sorted(items):
            ET.SubElement(svc_el, "host").text = item
    tree = ET.ElementTree(root)
    if base_dir:
        out_file = os.path.join(base_dir, "parsed-hosts.xml")
        tree.write(out_file, encoding="utf-8", xml_declaration=True)
        print(f"{Fore.GREEN}[+] Saved XML: {out_file}")
    else:
        try: ET.indent(tree, space="  ")
        except Exception: pass
        tree.write(sys.stdout, encoding="unicode", xml_declaration=True)

# ---------------- Save dispatcher ----------------

def save_results(hosts, output_dir=None, fmt="txt"):
    if output_dir:
        base_dir = os.path.abspath(os.path.expanduser(output_dir))
        leaf = os.path.basename(os.path.normpath(base_dir))
        base = base_dir if leaf == "parsed-hostlists" else os.path.join(base_dir, "parsed-hostlists")
        os.makedirs(base, exist_ok=True)
        print(f"{Fore.BLUE}\n[i] Output directory: {base}{Style.RESET_ALL}")

        if fmt in ("txt", "all"):
            for service, items in hosts.items():
                _write_service_hostlist(base, service, items)
            combined = sorted(hosts.get("http", set()).union(hosts.get("https", set())))
            if combined:
                _write_service_hostlist(base, "http+https", set(combined))
        if fmt in ("json", "all"): save_as_json(hosts, base)
        if fmt in ("csv", "all"): save_as_csv(hosts, base)
        if fmt in ("xml", "all"): save_as_xml(hosts, base)
    else:
        # No output directory specified - just print to stdout
        print(f"{Fore.BLUE}\n[i] Displaying results (no files saved - use -o to save){Style.RESET_ALL}")
        if fmt == "txt":
            for service, ips in sorted(hosts.items()):
                if ips:
                    print(f"\n{Fore.CYAN}[{service.upper()} HOSTS]{Style.RESET_ALL}")
                    for ip in sorted(ips):
                        print(f"  {Fore.GREEN}{ip}{Style.RESET_ALL}")
            # Also show combined http+https
            combined = sorted(hosts.get("http", set()).union(hosts.get("https", set())))
            if combined:
                print(f"\n{Fore.CYAN}[HTTP+HTTPS HOSTS]{Style.RESET_ALL}")
                for ip in combined:
                    print(f"  {Fore.GREEN}{ip}{Style.RESET_ALL}")
        elif fmt == "json": save_as_json(hosts)
        elif fmt == "csv": save_as_csv(hosts)
        elif fmt == "xml": save_as_xml(hosts)
        elif fmt == "all":
            print(f"{Fore.YELLOW}[!] Warning: dumping JSON, CSV, and XML all to stdout may be messy.{Style.RESET_ALL}")
            save_as_json(hosts); save_as_csv(hosts); save_as_xml(hosts)

    # Summary
    print(f"\n{Fore.MAGENTA}{'='*40}")
    print(f"{Fore.MAGENTA} Summary of Discovered Services")
    print(f"{'='*40}{Style.RESET_ALL}")
    any_found = False
    for service in sorted(hosts.keys()):
        count = len(hosts[service])
        if count > 0:
            any_found = True
            print(f"{Fore.CYAN}{service:<12}{Style.RESET_ALL}: {Fore.GREEN}{count}{Style.RESET_ALL}")
    combined_count = len(hosts.get("http", set()).union(hosts.get("https", set())))
    if combined_count > 0:
        any_found = True
        print(f"{Fore.CYAN}{'http+https':<12}{Style.RESET_ALL}: {Fore.GREEN}{combined_count}{Style.RESET_ALL}")
    if not any_found:
        print(f"{Fore.RED}[!] No open service hosts discovered.{Style.RESET_ALL}")

# ---------------- CLI entry ----------------

def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="cygor parse",
        usage="cygor parse [options] <input>",
        description=BANNER + "\nParse Nmap scan files (.xml, .nmap, .gnmap) into categorized hostlists.\n\n"
                    f"{Fore.YELLOW}Note:{Style.RESET_ALL} If you specify {Fore.CYAN}-o/--out-dir{Style.RESET_ALL}, "
                    "Cygor will create a subdirectory called "
                    f"{Fore.CYAN}parsed-hostlists/{Style.RESET_ALL}.\n",
        epilog=EXAMPLES,
        formatter_class=ColorHelpFormatter,
    )
    parser.add_argument("input", help="Path to a file or directory containing scan files")
    parser.add_argument("-o","--out-dir",dest="output",
                        help="Directory to save extracted service lists (parsed-hostlists/ created here)")
    parser.add_argument("--format", choices=["txt","json","csv","xml","all"], default="txt",
                        help="Output format (default: txt). If no -o is given, json/csv/xml print to stdout.")
    args = parser.parse_args(argv)

    input_path, output_dir, fmt = args.input, args.output, args.format
    all_hosts = {service: set() for service in SERVICES}
    for cat in FINGERPRINTS.keys(): all_hosts.setdefault(cat, set())

    files_to_parse = []
    if os.path.isdir(input_path):
        for f in Path(input_path).rglob("*"):
            # Skip enumeration module directories (they have non-Nmap XML)
            if "enumeration-modules" in str(f) or "cygor-enumeration-modules" in str(f):
                continue
            if f.suffix.lower() in (".xml",".nmap",".gnmap"):
                files_to_parse.append(str(f))
    else:
        files_to_parse.append(input_path)

    for file_path in files_to_parse:
        file_hosts = parse_nmap_xml(file_path) if file_path.endswith(".xml") else parse_nmap_text(file_path)
        for service in file_hosts: all_hosts.setdefault(service,set()).update(file_hosts[service])

    save_results(all_hosts, output_dir, fmt)

if __name__ == "__main__":
    main()
