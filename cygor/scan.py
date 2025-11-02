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
import tempfile
import stat
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
        os.makedirs(directory, exist_ok=True)


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
        # Only attempt domain resolution if the host looks like a domain
        if '.' in host and not any(c.isdigit() for c in host.split('.')[0]):
            ip = get_ip_from_domain(host)
            if ip:
                resolved_domains.append(f"Domain: {host} -> IP: {ip}")
        else:
            # Just skip IP or CIDR entries — don't return early
            continue

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
    """
    Parse exclusion targets from a file or single argument.
    Returns a tuple: (set_of_exact_ips, set_of_network_objects, set_of_domains)
    """
    ip_set = set()
    net_set = set()
    dom_set = set()

    if os.path.isfile(exclusions):
        lines = open(exclusions, encoding="utf-8").read().splitlines()
    else:
        lines = [exclusions]

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            if '/' in line:
                net = ipaddress.ip_network(line, strict=False)
                net_set.add(net)
            else:
                # Try as IP first
                ip = ipaddress.ip_address(line)
                ip_set.add(str(ip))
        except ValueError:
            # Not an IP/CIDR — treat as domain if it looks like one
            # (simple heuristic: contains a dot and has at least one alpha)
            if '.' in line and any(ch.isalpha() for ch in line):
                dom_set.add(line.lower())
            else:
                print(f"{Fore.RED}Invalid exclusion entry: {line}")

    # Pretty print a summary
    print(f"{Fore.YELLOW}[Exclusions Active]{Style.RESET_ALL} "
          f"{len(net_set)} networks, {len(ip_set)} IPs, {len(dom_set)} domains")
    if net_set:
        for n in sorted(net_set, key=lambda x: (x.version, str(x))):
            print(f"  {Fore.CYAN}- Network: {n}{Style.RESET_ALL}")
    if ip_set:
        for i in sorted(ip_set):
            print(f"  {Fore.CYAN}- IP:      {i}{Style.RESET_ALL}")
    if dom_set:
        for d in sorted(dom_set):
            print(f"  {Fore.CYAN}- Domain:  {d}{Style.RESET_ALL}")

    return ip_set, net_set, dom_set



def filter_excluded_hosts(hosts, exclusions):
    """
    Filter hosts against (ip_set, net_set, dom_set).
    CIDRs are only removed if fully covered by an exclusion network.
    Single IPs/domains are dropped only if they match exclusions.
    """
    ip_exclude, net_exclude, dom_exclude = exclusions
    filtered = []

    for host in hosts:
        if not host:
            continue

        # CIDR block
        if '/' in host:
            try:
                net = ipaddress.ip_network(host, strict=False)
            except ValueError:
                print(f"{Fore.RED}Invalid CIDR: {host}")
                continue

            # Skip only if an exclusion network fully covers this CIDR
            skip = False
            matched_excl = None
            for excl in net_exclude:
                # if exclusion is equal or completely covers this net
                if net == excl or net.subnet_of(excl):
                    skip = True
                    matched_excl = excl
                    break

            if skip:
                print(f"{Fore.YELLOW}[!] Skipping {host} — fully covered by an exclusion network {matched_excl}{Style.RESET_ALL}")
                continue
            filtered.append(host)
            continue

        # Single IP?
        try:
            ip_obj = ipaddress.ip_address(host)
            if str(ip_obj) in ip_exclude:
                print(f"{Fore.YELLOW}[!] Skipping {host} — directly excluded IP{Style.RESET_ALL}")
                continue
            if any(ip_obj in net for net in net_exclude):
                # find which net
                for net in net_exclude:
                    if ip_obj in net:
                        print(f"{Fore.YELLOW}[!] Skipping {host} — inside excluded network {net}{Style.RESET_ALL}")
                        break
                continue
            filtered.append(host)
            continue
        except ValueError:
            # Not an IP — treat as domain
            dom = host.lower()
            if dom in dom_exclude:
                print(f"{Fore.YELLOW}[!] Skipping {host} — excluded domain{Style.RESET_ALL}")
                continue
            filtered.append(host)

    return filtered



def comma_separated_ips(value):
    """Allow comma-separated or space-separated IPs/CIDRs for --ips."""
    parts = []
    for segment in value.split(","):
        segment = segment.strip()
        if segment:
            parts.append(segment)
    return parts


def save_discovery_results(masscan_hosts, naabu_hosts, merged_hosts, base_outdir):
    """Save discovery results into <outdir>/discovery/ as text files."""
    outdir = os.path.join(base_outdir, "discovery")
    ensure_directory_exists(outdir)
    files = {
        "masscan-discovered.txt": sorted(masscan_hosts),
        "naabu-discovered.txt": sorted(naabu_hosts),
        "merged-discovered.txt": sorted(merged_hosts),
        "all-discovered-hosts.txt": sorted(merged_hosts),  # unified hostlist
    }
    for fname, hosts in files.items():
        fpath = os.path.join(outdir, fname)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("\n".join(hosts))
        print(f"{Fore.GREEN}[+] Saved {len(hosts)} hosts to {fpath}")


def _determine_target_uid_gid():
    """
    Determine which uid:gid should own created files:
    - If running under sudo, use SUDO_UID/SUDO_GID (the real user's uid/gid)
    - Otherwise use current process uid/gid
    """
    try:
        sudo_uid = os.environ.get("SUDO_UID")
        sudo_gid = os.environ.get("SUDO_GID")
        if sudo_uid and sudo_gid:
            return int(sudo_uid), int(sudo_gid)
    except Exception:
        pass
    return os.getuid(), os.getgid()


def set_owner_recursive(path, uid=None, gid=None, ignore_errors=True):
    """
    Recursively chown path to uid:gid. If uid/gid omitted, inferred from _determine_target_uid_gid().
    Guarded with try/except to avoid crashing if permissions don't allow chown.
    """
    if uid is None or gid is None:
        uid, gid = _determine_target_uid_gid()
    try:
        # chown the root path first
        os.chown(path, uid, gid)
    except PermissionError:
        if not ignore_errors:
            raise
    except Exception:
        # best-effort - ignore other errors unless requested
        if not ignore_errors:
            raise

    for root, dirs, files in os.walk(path):
        for d in dirs:
            p = os.path.join(root, d)
            try:
                os.chown(p, uid, gid)
            except Exception:
                if not ignore_errors:
                    raise
        for f in files:
            p = os.path.join(root, f)
            try:
                os.chown(p, uid, gid)
            except Exception:
                if not ignore_errors:
                    raise


def ensure_directory_owned(directory):
    """
    Ensure directory exists and set ownership to invoking user (or SUDO_UID owner).
    Call this after ensure_directory_exists(...) when creating output dirs.
    """
    ensure_directory_exists(directory)
    uid, gid = _determine_target_uid_gid()
    # if current effective uid already equals target, skip system chown (no-op)
    try:
        if os.geteuid() == uid:
            # already owned by the running user; still ensure mode is writable
            return
    except Exception:
        pass
    # Best-effort chown
    try:
        set_owner_recursive(directory)
    except Exception as e:
        # don't crash the scan because of chown issues; print a warning
        print(f"{Fore.YELLOW}[!] Warning: couldn't chown {directory} to uid:gid {uid}:{gid}: {e}{Style.RESET_ALL}")



def run_masscan(host, interface=None, base_outdir='results', ports=None, rate=1000, exclusions=None):
    """
    Run Masscan on a single host or CIDR.
    Supports exclusions via --excludefile.
    Produces machine-readable (-oL) output and returns the output file path if scan succeeded.
    """
    output_dir = os.path.join(base_outdir, 'masscan')
    ensure_directory_exists(output_dir)
    ensure_directory_owned(output_dir)

    safe_host = host.replace('/', '_')
    output_file = os.path.join(output_dir, f"masscan_{safe_host}.txt")

    interface_option = f"--interface {interface}" if interface else ""
    ports_option = f"-p {ports}" if ports else (
    # Default discovery ports (common services)
    "-p 21,22,23,25,80,88,111,135,139,389,443,445,636,1099,1433,2049,3389,4786,5900,5985,8080,9100"
    )

    # --- NEW: exclusions support ---
    exclude_file = None
    exclude_option = ""
    if exclusions:
        ip_exclude, net_exclude, dom_exclude = exclusions
        tmp_exclude_path = os.path.join(output_dir, "masscan_exclude.txt")
        with open(tmp_exclude_path, "w", encoding="utf-8") as ef:
            for i in sorted(ip_exclude):
                ef.write(f"{i}\n")
            for n in sorted(net_exclude, key=lambda x: str(x)):
                ef.write(f"{n}\n")
        exclude_file = tmp_exclude_path
        exclude_option = f"--excludefile {exclude_file}"
    # ------------------------------

    try:
        if '/' in host:
            ipaddress.ip_network(host, strict=False)
        else:
            ipaddress.ip_address(host)
    except ValueError as e:
        print(f"{Fore.RED}Invalid IP/CIDR {host}: {e}")
        return None

    command = (
        f"masscan {host} {interface_option} {ports_option} {exclude_option} "
        f"--rate {rate} --wait 0 --open-only -oL {output_file}"
    )

    print(f"{Fore.YELLOW}[masscan] {command}{Style.RESET_ALL}\n")
    try:
        subprocess.run(command, shell=True, check=True)
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8") as fh:
                if any(line.startswith("open") for line in fh):
                    print(f"{Fore.GREEN}Masscan completed for {host}. Output: {output_file}\n")
                    return output_file
                else:
                    print(f"{Fore.YELLOW}[!] Masscan found no open ports for {host}{Style.RESET_ALL}")
                    return None
        else:
            print(f"{Fore.RED}[!] Masscan did not produce output file for {host}{Style.RESET_ALL}")
            return None
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running masscan for {host}: {e}")
        return None
    finally:
        if exclude_file and os.path.exists(exclude_file):
            try:
                os.remove(exclude_file)
            except Exception:
                pass

def run_naabu(host, interface=None, base_outdir='results', ports=None, rate=10000, exclusions=None):
    """
    Run Naabu for a given host or CIDR, writing a temporary target file and passing it with -list.
    Supports exclusions via -exclude-file.
    Returns path to validated output file or None.
    """
    output_dir = os.path.join(base_outdir, 'naabu')
    ensure_directory_owned(output_dir)
    safe_host = host.replace('/', '_')
    output_file = os.path.join(output_dir, f"naabu_{safe_host}.txt")

    interface_option = f"-interface {interface}" if interface else ""
    ports_option = f"-p {ports}" if ports else (
        "-p 21,22,23,25,80,88,111,135,139,389,443,445,636,1099,1433,2049,3389,4786,5900,5985,3389,8080,9100"
    )

    # --- NEW: exclusions support ---
    exclude_file = None
    exclude_option = ""
    if exclusions:
        ip_exclude, net_exclude, dom_exclude = exclusions
        tmp_exclude_path = os.path.join(output_dir, "naabu_exclude.txt")
        with open(tmp_exclude_path, "w", encoding="utf-8") as ef:
            for i in sorted(ip_exclude):
                ef.write(f"{i}\n")
            for n in sorted(net_exclude, key=lambda x: str(x)):
                ef.write(f"{n}\n")
        exclude_file = tmp_exclude_path
        exclude_option = f"-exclude-file {exclude_file}"
    # -------------------------------

    # Write targets to a temp file
    fd, tmp_path = tempfile.mkstemp(prefix="naabu_targets_", suffix=".txt", dir=output_dir)
    os.close(fd)
    with open(tmp_path, "w", encoding="utf-8") as tf:
        tf.write(f"{host}\n")

    print(f"{Fore.YELLOW}[naabu] Scanning target(s) from {host} -> targets file: {tmp_path}{Style.RESET_ALL}")

    try:
        command = f"naabu {interface_option} {ports_option} {exclude_option} -rate {rate} -o {output_file} -list {tmp_path}"
        subprocess.run(command, shell=True, check=True)

        # Validate and clean results
        valid_lines = []
        if os.path.exists(output_file):
            with open(output_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or ":" not in line:
                        continue
                    ip_part = line.split(":")[0].strip()
                    try:
                        ipaddress.ip_address(ip_part)
                        valid_lines.append(line)
                    except ValueError:
                        continue

            if valid_lines:
                with open(output_file, "w", encoding="utf-8") as out:
                    out.write("\n".join(sorted(set(valid_lines))) + "\n")
                print(f"{Fore.GREEN}Naabu completed for {host}. {len(valid_lines)} valid entries saved: {output_file}")
                return output_file
            else:
                print(f"{Fore.YELLOW}[!] Naabu found no valid open ports for {host}{Style.RESET_ALL}")
                try:
                    os.remove(output_file)
                except Exception:
                    pass
                return None
        else:
            print(f"{Fore.RED}[!] Naabu did not create output file for {host}{Style.RESET_ALL}")
            return None

    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running naabu for {host}: {e}")
        return None

    finally:
        # Always cleanup temporary files
        for f in [tmp_path, exclude_file]:
            if f and os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass



def ensure_nmap_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

def run_nmap(ip, base_outdir='results', scan_type='top-ports', ports=None):
    """
    Run Nmap on a single host.
    Ensures all output directories are writable and owned by the invoking user (not root),
    even if executed with sudo.
    """
    output_dir = os.path.join(base_outdir, 'nmap')
    ensure_directory_exists(output_dir)
    ensure_directory_owned(output_dir)

    scan_directory = os.path.join(output_dir, scan_type)
    ensure_directory_exists(scan_directory)
    ensure_directory_owned(scan_directory)

    safe_ip = ip.replace('/', '_')
    output_file_prefix = os.path.join(scan_directory, safe_ip)

    # Detect IPv6
    ip_option = ""
    try:
        ip_obj = ipaddress.ip_address(ip)
        ip_option = "-6" if ip_obj.version == 6 else ""
    except Exception:
        ip_option = ""

    # Choose Nmap command
    if ports:
        command = f"nmap {ip_option} -Pn -sC -sV -O -T4 -p {ports} {ip} -oA {output_file_prefix}"
    elif scan_type == 'top-ports':
        command = f"nmap {ip_option} -Pn -sC -sV -O -T4 --top-ports 1000 {ip} -oA {output_file_prefix}"
    else:
        command = f"nmap {ip_option} -Pn -sC -sV -O -T4 -p- {ip} -oA {output_file_prefix}"

    print(f"{Fore.YELLOW}[nmap] {command}{Style.RESET_ALL}")

    try:
        subprocess.run(command, shell=True, check=True)
        print(f"{Fore.GREEN}Nmap completed for {ip}.")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running nmap for {ip}: {e}")
    finally:
        # Ensure Nmap results and subdirs are owned by invoking user
        try:
            set_owner_recursive(scan_directory)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Warning: could not reset ownership on {scan_directory}: {e}{Style.RESET_ALL}")



def run_nmap_parallel(ips, processes, base_outdir='results', scan_type='top-ports', ports=None):
    output_dir = os.path.join(base_outdir, 'nmap')
    ensure_nmap_directory_exists(os.path.join(output_dir, scan_type))
    with ThreadPoolExecutor(max_workers=processes) as executor:
        executor.map(lambda ip: run_nmap(ip, base_outdir=base_outdir, scan_type=scan_type, ports=ports), ips)

def read_hosts_from_file(file_path):
    print(f"{Fore.YELLOW}[+] Reading hosts from {file_path}")
    hosts = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            try:
                # Validate CIDR or IP
                if '/' in line:
                    ipaddress.ip_network(line, strict=False)
                    print(f"{Fore.GREEN}Adding CIDR: {line}")
                else:
                    ipaddress.ip_address(line)
                    print(f"{Fore.GREEN}Adding IP: {line}")
                hosts.append(line)
            except ValueError:
                print(f"{Fore.RED}Invalid entry in scope file: {line}")
    return hosts


def combine_nmap_files(scan_type, base_outdir):
    scan_directory = os.path.join(base_outdir, 'nmap', scan_type)
    ensure_nmap_directory_exists(scan_directory)
    ensure_directory_owned(scan_directory)
    combined_file = os.path.join(scan_directory, f"{scan_type}.nmap")
    with open(combined_file, 'w', encoding="utf-8") as outfile:
        for file_name in sorted(os.listdir(scan_directory)):
            if file_name.endswith(".nmap"):
                with open(os.path.join(scan_directory, file_name), 'r', encoding="utf-8") as infile:
                    outfile.write(f"=== {file_name} ===\n")
                    outfile.write(infile.read())
                    outfile.write("\n")
    print(f"{Fore.GREEN}Combined Nmap results saved: {combined_file}")

examples = f"""
   {Fore.MAGENTA}Examples:{Style.RESET_ALL}

    {Fore.YELLOW}# 1. Run host discovery with Masscan only{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover masscan

    {Fore.YELLOW}# 2. Run discovery with custom ports for Masscan{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover masscan --masscan-ports 80,443,8443

    {Fore.YELLOW}# 3. Run discovery with custom ports for Naabu{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover naabu --naabu-ports 1-1024,8080

    {Fore.YELLOW}# 4. Discovery only (no Nmap), save hostlists in results/discovery/{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover masscan naabu --discover-only
    # ➜ Creates: masscan-discovered.txt, naabu-discovered.txt, merged-discovered.txt, all-discovered-hosts.txt

    {Fore.YELLOW}# 5. Reuse full discovered hostlist for Nmap scan{Style.RESET_ALL}
    cygor scan --use-discovery results/discovery/all-discovered-hosts.txt --scan-type fullscan

    {Fore.YELLOW}# 6. Run Nmap with custom ports on discovered hosts{Style.RESET_ALL}
    cygor scan --use-discovery results/discovery/masscan-discovered.txt --ports 80,443,8443

    {Fore.YELLOW}# 7. Run with 10 parallel Nmap processes{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover naabu --processes 10 --scan-type fullscan

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
    scope_group.add_argument("-o", "--outdir",default="results",help="Base output directory for all outputs (discovery, masscan, naabu, nmap). Default: results/")
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
    "--masscan-ports",
    help="Custom ports for Masscan discovery phase (e.g., '80,443,8080')."
    )
    disc_group.add_argument(
        "--naabu-ports",
        help="Custom ports for Naabu discovery phase (e.g., '1-1024,8080')."
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

        # ensure Nmap writes to outdir when using --use-discovery
        run_nmap_parallel(nmap_targets, args.processes, base_outdir=args.outdir, scan_type=args.scan_type, ports=args.ports)
        combine_nmap_files(args.scan_type, args.outdir)
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
        exclusions = parse_exclusions(args.exclusions)
        before = len(hosts)
        hosts = filter_excluded_hosts(hosts, exclusions)
        print(f"{Fore.YELLOW}[Exclusions Summary]{Style.RESET_ALL} kept {len(hosts)}/{before} targets after filtering")
        if not hosts:
            print(f"{Fore.RED}All hosts excluded")
            return



    overall_start_time = time.time()
    discovered_hosts_masscan, discovered_hosts_naabu = set(), set()

    # --- Discovery Phase Start ---
    print(f"\n{Fore.CYAN}[+] Starting discovery phase using: {', '.join(args.discover)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Output directory: {args.outdir}{Style.RESET_ALL}")

    if 'masscan' in args.discover:
        print(f"{Fore.CYAN}[+] Running Masscan discovery...{Style.RESET_ALL}")
        masscan_results = [run_masscan(h, interface=args.interface, base_outdir=args.outdir,ports=args.masscan_ports, ports=args.ports) for h in hosts]
        for f in masscan_results:
            if f and os.path.exists(f):
                with open(f, 'r', encoding="utf-8") as fh:
                    for line in fh:
                        parts = line.strip().split()
                        # Expected format: open <proto> <port> <ip> <latency>
                        if len(parts) >= 4 and parts[0] == "open":
                            ip_candidate = parts[3]
                            try:
                                ipaddress.ip_address(ip_candidate)
                                discovered_hosts_masscan.add(ip_candidate)
                            except ValueError:
                                continue
        # optional: show a preview of what was found
        if discovered_hosts_masscan:
            print(f"{Fore.GREEN}[Masscan] Valid hosts discovered: {len(discovered_hosts_masscan)}")
            if len(discovered_hosts_masscan) < 20:
                for ip in sorted(discovered_hosts_masscan):
                    print(f"  {ip}")
        else:
            print(f"{Fore.RED}[Masscan] No valid hosts discovered.")


    if 'naabu' in args.discover:
        print(f"{Fore.CYAN}[+] Running Naabu discovery...{Style.RESET_ALL}")
        naabu_results = [run_naabu(h,interface=args.interface,base_outdir=args.outdir,ports=args.naabu_ports,ports=args.ports,exclusions=exclusions if args.exclusions else None) for h in hosts]
        for f in naabu_results:
            if f and os.path.exists(f):
                with open(f, 'r', encoding="utf-8") as fh:
                    discovered_hosts_naabu.update([l.split(':')[0].strip() for l in fh if l.strip()])
        print(f"{Fore.CYAN}Naabu discovered {len(discovered_hosts_naabu)} hosts")

    discovered_hosts_merge = discovered_hosts_masscan.union(discovered_hosts_naabu)

    # --- stop after discovery if requested ---
    if args.discover_only:
        save_discovery_results(discovered_hosts_masscan, discovered_hosts_naabu, discovered_hosts_merge, args.outdir)
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

    # NEW: Apply exclusions again before Nmap
    if args.exclusions:
        before_nmap = len(nmap_targets)
        nmap_targets = filter_excluded_hosts(nmap_targets, exclusions)
        print(f"{Fore.YELLOW}[Exclusions Summary]{Style.RESET_ALL} kept {len(nmap_targets)}/{before_nmap} targets before Nmap")

    if not nmap_targets:
        print(f"{Fore.RED}No hosts to scan with Nmap")
        return

    print(f"\n{Fore.CYAN}[+] Starting Nmap phase on {len(nmap_targets)} targets (scan-type={args.scan_type}){Style.RESET_ALL}")

    run_nmap_parallel(nmap_targets, args.processes, base_outdir=args.outdir, scan_type=args.scan_type, ports=args.ports)
    combine_nmap_files(args.scan_type, args.outdir)
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
