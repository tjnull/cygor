# Auto-generated from original script to preserve logic
# Module: cygor.scan

import argparse
import concurrent.futures
import ipaddress
import os
import subprocess
import socket
import sys
import time
from libnmap.parser import NmapParser, NmapParserException, NmapService
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

from argparse import RawTextHelpFormatter

class ColorHelpFormatter(RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    def start_section(self, heading):
        heading = f"{Fore.CYAN}{heading}{Style.RESET_ALL}"
        super().start_section(heading)

    def _format_action_invocation(self, action):
        parts = super()._format_action_invocation(action)
        return f"{Fore.YELLOW}{parts}{Style.RESET_ALL}"




def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def print_time_taken(start_time, end_time, task_name):
    total_seconds = end_time - start_time
    hours = total_seconds // 3600
    minutes = (total_seconds % 3600) // 60
    seconds = total_seconds % 60
    print(f"\n{Fore.CYAN}{task_name} completed in {int(hours)} hours, {int(minutes)} minutes, and {int(seconds)} seconds.")

def get_ip_from_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"{Fore.RED}Error: Unable to resolve {domain}")
        return None

def discover_and_print_domain_ips(hosts):
    resolved_domains = []
    for host in hosts:
        if '.' in host and not any(c.isdigit() for c in host):
            ip = get_ip_from_domain(host)
            if ip:
                resolved_domains.append(f"Domain: {host} -> IP: {ip}")
        else:
            return None
    if resolved_domains:
        print('\n'.join(resolved_domains))

def resolve_domain_to_ip(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        print(f"{Fore.GREEN}Domain {domain} resolved to IP: {ip_address}")
        return ip_address
    except socket.gaierror:
        print(f"{Fore.RED}Failed to resolve domain: {domain}")
        return None

def process_hosts(hosts):
    processed_hosts = []
    for host in hosts:
        try:
            ip = ipaddress.ip_address(host)
            if ip.version == 6:
                print(f"{Fore.GREEN}IPv6 Host: {host}")
            else:
                print(f"{Fore.GREEN}IPv4 Host: {host}")
            processed_hosts.append(str(ip))
        except ValueError:
            if '.' in host and not any(c.isdigit() for c in host):
                ip = resolve_domain_to_ip(host)
                if ip:
                    processed_hosts.append(ip)
            else:
                processed_hosts.append(host)
    return processed_hosts

def parse_exclusions(exclusions):
    excluded_ips = set()
    if os.path.isfile(exclusions):
        with open(exclusions, 'r') as file:
            for line in file:
                line = line.strip()
                try:
                    if '/' in line:
                        excluded_ips.update(map(str, ipaddress.ip_network(line, strict=False)))
                    else:
                        excluded_ips.add(line)
                except ValueError:
                    print(f"{Fore.RED}Invalid exclusion entry: {line}")
    else:
        try:
            if '/' in exclusions:
                excluded_ips.update(map(str, ipaddress.ip_network(exclusions, strict=False)))
            else:
                excluded_ips.add(exclusions)
        except ValueError:
            print(f"{Fore.RED}Invalid exclusion entry: {exclusions}")
    return excluded_ips

def filter_excluded_hosts(hosts, excluded_ips):
    filtered_hosts = []
    for host in hosts:
        try:
            if '/' in host:
                cidr_ips = set(map(str, ipaddress.IPv4Network(host, strict=False)))
                if not cidr_ips.intersection(excluded_ips):
                    filtered_hosts.append(host)
            else:
                if host not in excluded_ips:
                    filtered_hosts.append(host)
        except ValueError:
            print(f"{Fore.RED}Invalid host entry: {host}")
    return filtered_hosts

def comma_separated_ips(value):
    """Allow comma-separated or space-separated IPs/CIDRs for --ips."""
    return [ip.strip() for ip in value.split(",") if ip.strip()]


def save_discovery_results(masscan_hosts, naabu_hosts, merged_hosts):
    """Save discovery results into results/discovery/ as text files."""
    outdir = "results/discovery"
    ensure_directory_exists(outdir)
    files = {
        "masscan-discovered.txt": masscan_hosts,
        "naabu-discovered.txt": naabu_hosts,
        "merged-discovered.txt": merged_hosts,
    }
    for fname, hosts in files.items():
        fpath = os.path.join(outdir, fname)
        with open(fpath, "w") as f:
            f.write("\n".join(sorted(hosts)))
        print(f"{Fore.GREEN}[+] Saved {len(hosts)} hosts to {fpath}")


def run_masscan(host, interface=None, output_dir='results/masscan', ports=None, rate=1000):
    ensure_directory_exists(output_dir)
    output_file = os.path.join(output_dir, f"masscan_{host.replace('/', '_')}.txt")
    interface_option = f"--interface {interface}" if interface else ""
    if ports:
        ports_option = f"-p {ports}"
    else:
        ports_option = "-p 21,22,23,25,80,111,135,139,443,445,1099,1433,2049,3389,4786,5900,5985,8080,9100"

    try:
        if '/' in host:
            ipaddress.ip_network(host, strict=False)
        else:
            ipaddress.ip_address(host)
    except ValueError as e:
        print(f"{Fore.RED}Invalid IP/CIDR {host}: {e}")
        return None

    command = f"masscan {host} {interface_option} {ports_option} --rate {rate} --wait 0 -oL {output_file}"
    print(f"{Fore.YELLOW}[+] Running masscan for host {host} with: {command}\n")

    try:
        subprocess.run(command, shell=True, check=True)
        print(f"{Fore.GREEN}Masscan completed for {host}\n")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running masscan for {host}: {e}")
    return output_file

def run_naabu(host, interface=None, output_dir='results/naabu', ports=None, rate=10000):
    ensure_directory_exists(output_dir)
    output_file = os.path.join(output_dir, f"naabu_{host.replace('/', '_')}.txt")
    interface_option = f"-interface {interface}" if interface else ""
    if ports:
        ports_option = f"-p {ports}"
    else:
        ports_option = "-p 80,443,21,22,23,25,53,111,135,139,445,1099,1433,2049,4786,5900,5985,3389,8080"

    command = f"naabu -host {host} {interface_option} {ports_option} -rate {rate} -o {output_file}"
    print(f"{Fore.YELLOW}Running naabu for host {host} with: {command}")

    try:
        subprocess.run(command, shell=True, check=True)
        print(f"{Fore.GREEN}Naabu completed for {host}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running naabu for {host}: {e}")
    return output_file

def ensure_nmap_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def run_nmap(ip, output_dir='results/nmap/', scan_type='top-ports', ports=None):
    scan_directory = os.path.join(output_dir, scan_type)
    ensure_nmap_directory_exists(scan_directory)
    output_file_prefix = f"{ip.replace('/', '_')}"
    ip_obj = ipaddress.ip_address(ip)
    ip_option = "-6" if ip_obj.version == 6 else ""

    if ports:
        command = f"nmap {ip_option} -Pn -sC -sV -O -T4 -p {ports} {ip} -oA {os.path.join(scan_directory, output_file_prefix)}"
    elif scan_type == 'top-ports':
        command = f"nmap {ip_option} -Pn -sC -sV -O -T4 --top-ports 1000 {ip} -oA {os.path.join(scan_directory, output_file_prefix)}"
    else:
        command = f"nmap {ip_option} -Pn -sC -sV -O -T4 -p- {ip} -oA {os.path.join(scan_directory, output_file_prefix)}"

    print(f"{Fore.YELLOW}Running nmap for host {ip} with: {command}")
    try:
        subprocess.run(command, shell=True, check=True)
        print(f"{Fore.GREEN}Nmap completed for {ip}")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running nmap for {ip}: {e}")

def run_nmap_parallel(ips, processes, scan_type='top-ports', ports=None):
    output_dir = 'results/nmap/'
    ensure_nmap_directory_exists(os.path.join(output_dir, scan_type))
    with ThreadPoolExecutor(max_workers=processes) as executor:
        executor.map(lambda ip: run_nmap(ip, output_dir, scan_type, ports=ports), ips)

def read_hosts_from_file(file_path):
    print(f"{Fore.YELLOW}[+] Reading hosts from {file_path}")
    hosts = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line:
                continue
            if '/' in line:
                try:
                    ipaddress.ip_network(line, strict=False)
                    print(f"{Fore.GREEN}Adding CIDR: {line}")
                except ValueError:
                    print(f"{Fore.RED}Invalid CIDR: {line}")
                    continue
            hosts.append(line)
    return hosts

def combine_nmap_files(scan_type, output_dir):
    scan_directory = os.path.join(output_dir, scan_type)
    combined_file = os.path.join(scan_directory, f"{scan_type}.nmap")
    with open(combined_file, 'w') as outfile:
        for file_name in os.listdir(scan_directory):
            if file_name.endswith(".nmap"):
                with open(os.path.join(scan_directory, file_name), 'r') as infile:
                    outfile.write(f"=== {file_name} ===\n")
                    outfile.write(infile.read())
                    outfile.write("\n")
    print(f"{Fore.GREEN}Combined Nmap results saved: {combined_file}")

examples = f"""
   {Fore.MAGENTA}Examples:{Style.RESET_ALL}

    {Fore.YELLOW}# 1. Run host discovery with Masscan only{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover masscan

    {Fore.YELLOW}# 2. Run host discovery with both Masscan and Naabu, then Nmap on merged results{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover masscan naabu --nmap-source merge

    {Fore.YELLOW}# 3. Discovery only (no Nmap), save results in results/discovery/{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover masscan naabu --discover-only

    {Fore.YELLOW}# 4. Reuse saved discovery results for Nmap full scan{Style.RESET_ALL}
    cygor scan --use-discovery results/discovery/merged-discovered.txt --scan-type fullscan

    {Fore.YELLOW}# 5. Run Nmap with custom ports on discovered hosts{Style.RESET_ALL}
    cygor scan --use-discovery results/discovery/masscan-discovered.txt --ports 80,443,8443

    {Fore.YELLOW}# 6. Run Nmap with 10 parallel processes on full scope{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover naabu --processes 10 --scan-type fullscan

    {Fore.YELLOW}# 7. Run Cygor to discover hosts and scan them with Nmap with a provided lists of IP Addresses or CDRs{Style.RESET_ALL}
    cygor scan -i eth0 --ips 10.10.10.1 10.10.10.5 10.10.20.0/24 --discover naabu --processes 10 --scan-type fullscan

    {Fore.YELLOW}# 8. Exclude specific subnets or hosts from scan{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --exclusions exclusions.txt --discover masscan
    """

def main():
    banner = f"""
    {Fore.GREEN}{'='*60}
      CYGOR SCANNER - Host Discovery & Enumeration
    {Fore.GREEN}{'='*60}{Style.RESET_ALL}
    """

    parser = argparse.ArgumentParser(
    prog="cygor scan",
    usage="cygor scan [--discover masscan|naabu] [--scan-type fullscan|top-ports] [options]",
    description=banner + "\nRun host discovery (masscan/naabu), feed results into Nmap, and parse findings.\n",
    epilog=examples,
    formatter_class=ColorHelpFormatter
    )


    # Input/Scope
    scope_group = parser.add_argument_group("Scope/Input")
    scope_group.add_argument("-i", "--interface", help="Network interface to use")
    scope_group.add_argument("--ips", type=comma_separated_ips, nargs="+", help="List of IPs/CIDRs (comma or space separated)")
    scope_group.add_argument("-f", "--file", help="Path to file containing host/scope list")
    scope_group.add_argument("--exclusions", help="File or CIDR(s) of IPs/ranges to exclude")

    # Discovery
    disc_group = parser.add_argument_group("Discovery")
    disc_group.add_argument(
        "--discover",
        nargs="+",
        choices=["masscan", "naabu"],
        default=["masscan"],
        help="Run host discovery with one or more tools (default: masscan)."
    )
    disc_group.add_argument(
        "--discover-only",
        action="store_true",
        help="Run discovery only, save results into results/discovery/, and skip Nmap."
    )
    disc_group.add_argument(
        "--use-discovery",
        help="Reuse a discovery results file (e.g., results/discovery/merged-discovered.txt) "
             "and feed those hosts directly into Nmap. Skips discovery phase."
    )

    # Nmap scanning
    nmap_group = parser.add_argument_group("Nmap Scanning")
    nmap_group.add_argument(
        "--scan-type",
        choices=["top-ports", "fullscan"],
        default="top-ports",
        help="Nmap scan type (default: top-ports)."
    )
    nmap_group.add_argument(
        "--ports",
        help="Custom ports for scanning (e.g., '80,443' or '1-1024'). "
             "Overrides --scan-type if provided."
    )
    nmap_group.add_argument(
        "--nmap-source",
        choices=["masscan", "naabu", "merge"],
        default="merge",
        help="Which discovery results to pass to Nmap (default: merge)."
    )
    nmap_group.add_argument(
        "--processes",
        type=int,
        default=4,
        help="Number of parallel Nmap scans (default: 4)."
    )

    # Misc
    misc_group = parser.add_argument_group("Other")
    misc_group.add_argument("-b", "--banner", action="store_true", help="Display the banner")
    misc_group.add_argument("--parse", action="store_true", help="Enable parsing of results after scanning")

    

    
    args = parser.parse_args()

    # If user provides --use-discovery, skip everything else and go straight to Nmap
    if args.use_discovery:
        if not os.path.exists(args.use_discovery):
            print(f"{Fore.RED}Discovery file not found: {args.use_discovery}")
            return
        with open(args.use_discovery, "r") as f:
            nmap_targets = [line.strip() for line in f if line.strip()]
        print(f"{Fore.CYAN}Loaded {len(nmap_targets)} hosts from discovery file: {args.use_discovery}")

    # Mutual exclusion: --discover and --use-discovery cannot be combined
    if args.use_discovery and args.discover != ["masscan"]:
        print(f"{Fore.RED}[!] Warning: --use-discovery supplied together with --discover.")
        print(f"{Fore.YELLOW}    Ignoring --discover and using --use-discovery only.\n")
        args.discover = []  # disable discovery


        if not nmap_targets:
            print(f"{Fore.RED}No hosts found in discovery file. Exiting...")
            return

        run_nmap_parallel(nmap_targets, args.processes, scan_type=args.scan_type, ports=args.ports)
        combine_nmap_files(args.scan_type, 'results/nmap/')
        print(f"{Fore.CYAN}Nmap scanned {len(nmap_targets)} hosts")
        return

    # Normal path: file or IPs
    if args.file:
        if not os.path.exists(args.file):
            print(f"{Fore.RED}Host file not found")
            return
        with open(args.file, 'r') as f:
            hosts = [line.strip() for line in f if line.strip()]
    elif args.ips:
    # flatten list of lists from comma_separated_ips + nargs="+"
      hosts = [item for sublist in args.ips for item in sublist]
    else:
        print(f"{Fore.RED}No hosts specified")
        return

    hosts = process_hosts(hosts)

    if args.exclusions:
        excluded_ips = parse_exclusions(args.exclusions)
        hosts = filter_excluded_hosts(hosts, excluded_ips)
        if not hosts:
            print(f"{Fore.RED}All hosts excluded")
            return


    overall_start_time = time.time()
    discovered_hosts_masscan, discovered_hosts_naabu = set(), set()

    if 'masscan' in args.discover:
        masscan_results = [run_masscan(h, interface=args.interface, ports=args.ports) for h in hosts]
        for f in masscan_results:
            if f and os.path.exists(f):
                with open(f, 'r') as fh:
                    discovered_hosts_masscan.update([l.split()[3] for l in fh if l.startswith('open')])
        print(f"{Fore.CYAN}Masscan discovered {len(discovered_hosts_masscan)} hosts")

    if 'naabu' in args.discover:
        naabu_results = [run_naabu(h, interface=args.interface, ports=args.ports) for h in hosts]
        for f in naabu_results:
            if f and os.path.exists(f):
                with open(f, 'r') as fh:
                    discovered_hosts_naabu.update([l.split(':')[0].strip() for l in fh if l.strip()])
        print(f"{Fore.CYAN}Naabu discovered {len(discovered_hosts_naabu)} hosts")

    discovered_hosts_merge = discovered_hosts_masscan.union(discovered_hosts_naabu)

    # --- stop after discovery if requested ---
    if args.discover_only:
        save_discovery_results(discovered_hosts_masscan, discovered_hosts_naabu, discovered_hosts_merge)
        print(f"\n{Fore.YELLOW}{'='*50}")
        print(f"{Fore.YELLOW}Discovery Summary")
        print(f"{Fore.YELLOW}{'='*50}")
        print(f"{Fore.CYAN}Masscan: {len(discovered_hosts_masscan)} hosts")
        print(f"{Fore.CYAN}Naabu:   {len(discovered_hosts_naabu)} hosts")
        print(f"{Fore.CYAN}Merged:  {len(discovered_hosts_merge)} hosts")
        print(f"{Fore.YELLOW}{'='*50}\n")
        return


    # --- Nmap phase ---
    if args.nmap_source == 'masscan':
        nmap_targets = list(discovered_hosts_masscan)
    elif args.nmap_source == 'naabu':
        nmap_targets = list(discovered_hosts_naabu)
    else:
        nmap_targets = list(discovered_hosts_merge)

    if not nmap_targets:
        print(f"{Fore.RED}No hosts to scan with Nmap")
        return

    run_nmap_parallel(nmap_targets, args.processes, scan_type=args.scan_type, ports=args.ports)
    combine_nmap_files(args.scan_type, 'results/nmap/')
    print(f"{Fore.CYAN}Nmap scanned {len(nmap_targets)} hosts")

    overall_end_time = time.time()
    print_time_taken(overall_start_time, overall_end_time, "Total scan process")

try:
    if __name__ == '__main__':
        main()
except KeyboardInterrupt:
    print(f"{Fore.RED}Interrupted by user")
    time.sleep(2)
    print(f"{Fore.RED}Exiting...")

# ---- CLI bridge ----
import sys as _cygor_sys
import argparse as _cygor_argparse
import runpy as _cygor_runpy

def add_arguments(parser: _cygor_argparse.ArgumentParser):
    parser.add_argument("args", nargs=_cygor_argparse.REMAINDER, help="Forwarded args")

def run(args):
    _cygor_sys.argv = ["scan"] + list(args.args or [])
    _cygor_runpy.run_module("cygor.scan", run_name="__main__")

def exec_argv(argv):
    modname = __name__
    prog = modname.split(".")[-1]
    _cygor_sys.argv = [f"cygor-{prog}"] + list(argv)
    try:
        del _cygor_sys.modules[modname]
    except KeyError:
        pass
    _cygor_runpy.run_module(modname, run_name="__main__", alter_sys=True)
1