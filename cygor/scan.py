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
import glob
import re
import shutil
from urllib.parse import urlparse
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
    # Validate masscan is installed
    if not shutil.which("masscan"):
        print(f"{Fore.RED}[!] Error: masscan not found in PATH. Please install masscan.{Style.RESET_ALL}")
        return None

    output_dir = os.path.join(base_outdir, 'masscan')
    ensure_directory_exists(output_dir)
    ensure_directory_owned(output_dir)

    safe_host = host.replace('/', '_').replace(':', '_')
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

    # Build command as list for safer execution
    cmd_args = ["masscan", host]
    if interface:
        cmd_args.extend(["--interface", interface])
    if ports:
        cmd_args.extend(["-p", ports])
    else:
        cmd_args.extend(["-p", "21,22,23,25,80,88,111,135,139,389,443,445,636,1099,1433,2049,3389,4786,5900,5985,8080,9100"])
    if exclude_file:
        cmd_args.extend(["--excludefile", exclude_file])
    cmd_args.extend(["--rate", str(rate), "--wait", "0", "--open-only", "-oL", output_file])

    print(f"{Fore.YELLOW}[masscan] {' '.join(cmd_args)}{Style.RESET_ALL}\n")
    try:
        subprocess.run(cmd_args, check=True)
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
    # Validate naabu is installed
    if not shutil.which("naabu"):
        print(f"{Fore.RED}[!] Error: naabu not found in PATH. Please install naabu.{Style.RESET_ALL}")
        return None

    output_dir = os.path.join(base_outdir, 'naabu')
    ensure_directory_exists(output_dir)
    ensure_directory_owned(output_dir)
    safe_host = host.replace('/', '_').replace(':', '_')
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

    # Build command as list for safer execution
    cmd_args = ["naabu"]
    if interface:
        cmd_args.extend(["-interface", interface])
    if ports:
        cmd_args.extend(["-p", ports])
    else:
        cmd_args.extend(["-p", "21,22,23,25,80,88,111,135,139,389,443,445,636,1099,1433,2049,3389,4786,5900,5985,3389,8080,9100"])
    if exclude_file:
        cmd_args.extend(["-exclude-file", exclude_file])
    cmd_args.extend(["-rate", str(rate), "-o", output_file, "-list", tmp_path])

    print(f"{Fore.YELLOW}[naabu] {' '.join(cmd_args)}{Style.RESET_ALL}")

    try:
        subprocess.run(cmd_args, check=True)

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

def run_nmap(ip, base_outdir='results', scan_type='top-ports', ports=None, nmap_options=None):
    """
    Run Nmap on a single host.
    Ensures all output directories are writable and owned by the invoking user (not root),
    even if executed with sudo.
    """
    # Validate nmap is installed
    if not shutil.which("nmap"):
        print(f"{Fore.RED}[!] Error: nmap not found in PATH. Please install nmap.{Style.RESET_ALL}")
        return

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

    # Build nmap command as list for safer execution
    cmd_args = ["nmap"]
    if ip_option:
        cmd_args.append(ip_option)
    cmd_args.extend(["-Pn", "-sC", "-sV", "-O", "-T4"])

    # Add port specification based on scan type
    if ports:
        # Custom ports override scan_type
        cmd_args.extend(["-p", ports])
    elif scan_type == 'quick':
        cmd_args.extend(["--top-ports", "100"])
    elif scan_type in ('top-ports', 'top-1000'):
        cmd_args.extend(["--top-ports", "1000"])
    elif scan_type == 'top-10000':
        cmd_args.extend(["--top-ports", "10000"])
    elif scan_type == 'fullscan':
        cmd_args.append("-p-")
    elif scan_type == 'custom':
        if not ports:
            print(f"{Fore.YELLOW}[!] Warning: scan_type is 'custom' but no --ports specified. Using top 1000 ports.{Style.RESET_ALL}")
            cmd_args.extend(["--top-ports", "1000"])
        else:
            cmd_args.extend(["-p", ports])

    # Add custom Nmap options if provided
    if nmap_options:
        # Split options string and add to command
        # Use shlex to properly handle quoted arguments
        import shlex
        try:
            custom_opts = shlex.split(nmap_options)
            cmd_args.extend(custom_opts)
            print(f"{Fore.CYAN}[i] Adding custom Nmap options: {nmap_options}{Style.RESET_ALL}")
        except ValueError as e:
            print(f"{Fore.YELLOW}[!] Warning: Failed to parse nmap-options: {e}{Style.RESET_ALL}")

    cmd_args.extend([ip, "-oA", output_file_prefix])

    print(f"{Fore.YELLOW}[nmap] {' '.join(cmd_args)}{Style.RESET_ALL}")

    try:
        subprocess.run(cmd_args, check=True)
        print(f"{Fore.GREEN}Nmap completed for {ip}.")
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running nmap for {ip}: {e}")
    finally:
        # Ensure Nmap results and subdirs are owned by invoking user
        try:
            set_owner_recursive(scan_directory)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Warning: could not reset ownership on {scan_directory}: {e}{Style.RESET_ALL}")



def run_nmap_parallel(ips, processes, base_outdir='results', scan_type='top-ports', ports=None, nmap_options=None):
    output_dir = os.path.join(base_outdir, 'nmap')
    ensure_nmap_directory_exists(os.path.join(output_dir, scan_type))
    with ThreadPoolExecutor(max_workers=processes) as executor:
        executor.map(lambda ip: run_nmap(ip, base_outdir=base_outdir, scan_type=scan_type, ports=ports, nmap_options=nmap_options), ips)

def _is_domain_like(token: str) -> bool:
    # Basic heuristic: contains a dot and at least one alpha char in the name part
    if not token or token.startswith('#'):
        return False
    token = token.strip()
    # reject pure IPs (handled elsewhere)
    try:
        ipaddress.ip_address(token)
        return False
    except ValueError:
        pass
    return '.' in token and any(ch.isalpha() for ch in token)

def _extract_host_from_line(line: str):
    """
    Given a line of text, attempt to extract a single IP/CIDR or domain/hostname.
    Returns None if nothing valid is found.
    """
    if not line:
        return None
    # Remove comments
    line = line.split('#', 1)[0].strip()
    if not line:
        return None

    # If the line looks like a URL, parse host
    if '://' in line or line.startswith('www.'):
        try:
            parsed = urlparse(line if '://' in line else 'http://' + line)
            host = parsed.hostname
            if host:
                # strip trailing colon/port
                return host.strip()
        except Exception:
            pass

    # If the token contains whitespace, take first token
    token = line.split()[0].strip().strip('"').strip("'")

    # CIDR?
    if '/' in token:
        try:
            net = ipaddress.ip_network(token, strict=False)
            return str(net)
        except ValueError:
            pass

    # IPv4/IPv6?
    try:
        ip = ipaddress.ip_address(token)
        return str(ip)
    except ValueError:
        pass

    # Domain-like?
    if _is_domain_like(token):
        return token.lower()

    # Try to find any IP or CIDR in the line (e.g., embedded in text)
    ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)', line)
    if ip_match:
        try:
            candidate = ip_match.group(1)
            if '/' in candidate:
                ipaddress.ip_network(candidate, strict=False)
            else:
                ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass

    return None


def read_hosts_from_file(file_pattern):
    """
    Read hosts/targets from:
      - a single file path
      - a directory (read all files inside)
      - a glob pattern (e.g., results/discovery/*.txt)
    Extract IPs, CIDRs, and domain names found in each file.
    Returns a list of targets (strings).
    """
    matched_files = []

    # if user passed a list (defensive) handle it
    if isinstance(file_pattern, (list, tuple)):
        patterns = file_pattern
    else:
        patterns = [file_pattern]

    for pattern in patterns:
        pattern = str(pattern)
        # If it's an existing file path, use it
        if os.path.isfile(pattern):
            matched_files.append(pattern)
            continue

        # If it's a directory, include all files inside
        if os.path.isdir(pattern):
            for entry in sorted(os.listdir(pattern)):
                path = os.path.join(pattern, entry)
                if os.path.isfile(path):
                    matched_files.append(path)
            continue

        # Treat as glob pattern
        globbed = glob.glob(pattern)
        if globbed:
            for g in sorted(globbed):
                if os.path.isfile(g):
                    matched_files.append(g)
            continue

        # Last resort: maybe the user passed a literal filename that doesn't exist
        # We'll still add it and let the later open() fail with a clear message
        matched_files.append(pattern)

    if not matched_files:
        print(f"{Fore.RED}Host file(s) not found for pattern: {file_pattern}")
        return []

    print(f"{Fore.YELLOW}[+] Reading hosts from {len(matched_files)} file(s) matching: {file_pattern}{Style.RESET_ALL}")
    targets = []
    for fp in matched_files:
        if not os.path.isfile(fp):
            print(f"{Fore.RED}Warning: not a file, skipping: {fp}")
            continue
        try:
            with open(fp, 'r', encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    line = line.strip()
                    candidate = _extract_host_from_line(line)
                    if candidate:
                        targets.append(candidate)
        except Exception as e:
            print(f"{Fore.RED}Error reading {fp}: {e}")

    # dedupe while preserving stable sort
    unique = []
    seen = set()
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)

    # show short preview
    if unique:
        print(f"{Fore.GREEN}Loaded {len(unique)} unique targets (IPs/CIDRs/domains) from files.")
        if len(unique) <= 20:
            for t in unique:
                print(f"  {t}")
    else:
        print(f"{Fore.RED}No valid targets found in provided files.")

    return unique



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

    {Fore.YELLOW}# 9. Use discovery files via glob for Nmap (works with shell expansion or as a pattern){Style.RESET_ALL}
    cygor scan --use-discovery results/discovery/*.txt --scan-type top-ports --processes 50

    {Fore.YELLOW}# 10. Provide a directory of scope files; each file can contain IPs, CIDRs, domains or URLs{Style.RESET_ALL}
    cygor scan -f path/to/scope_dir --discover masscan

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
    nargs="+",
    help="Reuse one or more discovery results files or glob patterns (e.g., results/discovery/*.txt) "
         "and feed those hosts directly into Nmap. Skips discovery phase."
    )

    # Nmap scanning
    nmap_group = parser.add_argument_group("Nmap Scanning")
    nmap_group.add_argument(
        "--scan-type",
        choices=["quick", "top-ports", "top-1000", "top-10000", "fullscan", "custom"],
        default="top-ports",
        help="Nmap scan type: quick (top 100), top-ports (top 1000), top-1000 (alias), top-10000, fullscan (all 65535), custom (use --ports). Default: top-ports."
    )
    nmap_group.add_argument(
        "--ports",
        help="Custom ports for scanning (e.g., '80,443' or '1-1024'). "
             "Required when --scan-type is 'custom', overrides scan-type otherwise."
    )
    nmap_group.add_argument(
        "--nmap-options",
        metavar="'OPTIONS'",
        help="Custom Nmap switches/options (must be quoted if multiple flags, e.g., --nmap-options '-sC -sV -T4'). "
             "These will be added to the base Nmap command. Use with caution."
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

    # Check if running with required privileges for scanning tools
    # Only required if doing actual discovery (not when using --use-discovery)
    if not args.use_discovery and args.discover:
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Error: Scanner requires root privileges (masscan/naabu/nmap need raw socket access)")
            print(f"{Fore.YELLOW}[i] Please run with: sudo cygor scan ...{Style.RESET_ALL}")
            sys.exit(1)

    # If user provides --use-discovery, skip discovery and go straight to Nmap
    if args.use_discovery:
        # args.use_discovery may be a list of paths/patterns
        discovery_patterns = args.use_discovery if isinstance(args.use_discovery, (list, tuple)) else [args.use_discovery]
        nmap_targets = []
        for pat in discovery_patterns:
            # expand glob/dir/file and parse content
            new_targets = read_hosts_from_file(pat)
            if new_targets:
                nmap_targets.extend(new_targets)

        # dedupe
        nmap_targets = sorted(set(nmap_targets))
        if not nmap_targets:
            print(f"{Fore.RED}No hosts loaded from discovery patterns: {discovery_patterns}")
            return

        print(f"{Fore.CYAN}Loaded {len(nmap_targets)} hosts from discovery patterns: {discovery_patterns}")
        # ensure Nmap writes to outdir when using --use-discovery
        run_nmap_parallel(nmap_targets, args.processes, base_outdir=args.outdir, scan_type=args.scan_type, ports=args.ports, nmap_options=getattr(args, 'nmap_options', None))
        combine_nmap_files(args.scan_type, args.outdir)
        print(f"{Fore.CYAN}Nmap scanned {len(nmap_targets)} hosts")
        return

    # Normal path: file or IPs
    if args.file:
        hosts = read_hosts_from_file(args.file)
        if not hosts:
            print(f"{Fore.RED}No valid hosts loaded from {args.file}")
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
        # Masscan discovery
        masscan_results = [
            run_masscan(
                h,
                interface=args.interface,
                base_outdir=args.outdir,
                ports=args.masscan_ports,      # custom Masscan ports if set
                exclusions=exclusions if args.exclusions else None
            )
            for h in hosts
        ]

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
        # Naabu discovery
        naabu_results = [
            run_naabu(
                h,
                interface=args.interface,
                base_outdir=args.outdir,
                ports=args.naabu_ports,        # custom Naabu ports if set
                exclusions=exclusions if args.exclusions else None
            )
            for h in hosts
        ]
        for f in naabu_results:
            if f and os.path.exists(f):
                with open(f, 'r', encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if line and ':' in line:
                            ip_candidate = line.split(':')[0].strip()
                            try:
                                ipaddress.ip_address(ip_candidate)
                                discovered_hosts_naabu.add(ip_candidate)
                            except ValueError:
                                continue
        # optional: show a preview of what was found
        if discovered_hosts_naabu:
            print(f"{Fore.GREEN}[Naabu] Valid hosts discovered: {len(discovered_hosts_naabu)}")
            if len(discovered_hosts_naabu) < 20:
                for ip in sorted(discovered_hosts_naabu):
                    print(f"  {ip}")
        else:
            print(f"{Fore.RED}[Naabu] No valid hosts discovered.")

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

    run_nmap_parallel(nmap_targets, args.processes, base_outdir=args.outdir, scan_type=args.scan_type, ports=args.ports, nmap_options=getattr(args, 'nmap_options', None))
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
