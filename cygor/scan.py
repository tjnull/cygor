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

# Initialize colorama. ``strip=False`` keeps ANSI escape sequences in the
# output even when stdout is a pipe — the cygor task manager always pipes
# scan workers, and the web UI's ansi_up library converts those escapes to
# colored HTML in the live console. Without this, every Fore.GREEN /
# Fore.YELLOW status line we emit shows up as plain gray in the browser.
init(autoreset=True, strip=False)

# Proxy support for jumpbox routing
from cygor.proxy_config import wrap_command_if_needed, is_jumpbox_routing_active

# IP rotation is an enterprise-only feature; provide a no-op shim on dev so the
# call sites below can stay structurally identical between branches.
def get_next_ip(target_ip=None, context=None):
    return None

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


def _check_fingerprint_cache_exists() -> bool:
    """
    Check if fingerprint cache files exist.

    Returns:
        True if the essential cache file (OUI) exists and has data
    """
    try:
        from cygor.fingerprinting import get_cache
        cache = get_cache()

        # Check if OUI file exists (the most important one for basic fingerprinting)
        if not cache.oui_file.exists():
            return False

        # Check if it has content
        if cache.oui_file.stat().st_size < 1000:  # Less than 1KB means empty/invalid
            return False

        return True
    except Exception:
        return False


def _ensure_fingerprint_data_available():
    """
    Ensure fingerprint data is available before scanning.

    If cache files don't exist, automatically sync the databases.
    """
    if _check_fingerprint_cache_exists():
        # Cache exists, check if it's stale
        try:
            from cygor.fingerprinting import get_cache
            cache = get_cache()

            # Only print a message, don't auto-sync if data exists
            stats = cache.get_stats()
            oui_info = stats.get("files", {}).get("oui", {})
            if oui_info.get("exists", True):
                count = oui_info.get("record_count", 0)
                if count > 0:
                    print(f"{Fore.CYAN}[+] Using cached fingerprint data ({count:,} OUI entries){Style.RESET_ALL}")
                    print(f"    Cache location: {cache.cache_dir}")
                    return
        except Exception:
            pass
        return

    # No cache - need to sync
    print(f"{Fore.YELLOW}[!] Fingerprint databases not found. Downloading...{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[i] This is a one-time download. Use --sync-fp to update later.{Style.RESET_ALL}\n")
    _sync_fingerprint_databases()


def _sync_fingerprint_databases():
    """Sync fingerprint databases (OUI, JA3, JA4, p0f) to JSON files.

    Uses JSON file cache - no SQLite required.
    Files are stored in ~/.cache/cygor/fingerprints/
    """
    import asyncio
    import time as time_module

    try:
        from cygor.fingerprinting import JSONSyncEngine, get_cache

        start_time = time_module.time()

        # Run the sync
        sync_engine = JSONSyncEngine()
        results = asyncio.run(sync_engine.sync_all(use_rich=True))

        end_time = time_module.time()
        elapsed = end_time - start_time

        # Get stats from cache
        cache = get_cache()
        stats = cache.get_stats()

        # Try to use rich for summary
        try:
            from rich.console import Console
            console = Console()

            total = sum(r if isinstance(r, int) and r > 0 else 0 for r in results.values())

            console.print(f"\n[green][+][/green] Sync complete: [bold]{total:,}[/bold] fingerprints")
            console.print(f"[cyan][i][/cyan] Time elapsed: [bold]{elapsed:.1f}[/bold] seconds")
            console.print(f"[cyan][i][/cyan] Cache: {cache.cache_dir}")

            # Show cache file sizes
            if cache.cache_dir.exists():
                console.print("\n[dim]Cache Files:[/dim]")
                for cache_file in sorted(cache.cache_dir.glob("*.json")):
                    size_kb = cache_file.stat().st_size / 1024
                    size_str = f"{size_kb/1024:.1f} MB" if size_kb > 1024 else f"{size_kb:.1f} KB"
                    console.print(f"  [yellow]-[/yellow] {cache_file.name:<25} [dim]{size_str:>10}[/dim]")

            console.print()

        except ImportError:
            # Fallback to colorama
            total = sum(r if isinstance(r, int) and r > 0 else 0 for r in results.values())
            print(f"\n{Fore.GREEN}[+] Sync complete: {total:,} fingerprints{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[i] Time elapsed: {elapsed:.1f} seconds{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[i] Cache: {cache.cache_dir}{Style.RESET_ALL}")

            if cache.cache_dir.exists():
                print(f"\n{Fore.WHITE}Cache Files:{Style.RESET_ALL}")
                for cache_file in sorted(cache.cache_dir.glob("*.json")):
                    size_kb = cache_file.stat().st_size / 1024
                    size_str = f"{size_kb/1024:.1f} MB" if size_kb > 1024 else f"{size_kb:.1f} KB"
                    print(f"  {Fore.YELLOW}-{Style.RESET_ALL} {cache_file.name:<25} {size_str:>10}")

            print()

    except ImportError as e:
        print(f"{Fore.YELLOW}[!] Fingerprint sync not available: {e}{Style.RESET_ALL}")
    except Exception as e:
        import traceback
        print(f"{Fore.YELLOW}[!] Fingerprint sync failed: {e}{Style.RESET_ALL}")
        traceback.print_exc()


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


def save_discovery_results(masscan_hosts, naabu_hosts, merged_hosts, base_outdir, tools_used=None):
    """
    Save discovery results into tool-specific directories.

    Only saves files relevant to the tools that were actually used:
    - If only masscan: saves masscan/masscan-discovered.txt
    - If only naabu: saves naabu/naabu-discovered.txt
    - If both tools: saves files in respective directories + all-discovered-hosts.txt in base dir

    All files contain only IP addresses without ports, with duplicates removed.

    Args:
        masscan_hosts: Set of hosts discovered by masscan
        naabu_hosts: Set of hosts discovered by naabu
        merged_hosts: Combined set of all discovered hosts
        base_outdir: Base output directory
        tools_used: List of discovery tools used (e.g., ['masscan'], ['naabu'], or ['masscan', 'naabu'])
    """
    # Determine which tools were used
    if tools_used is None:
        # Fallback: detect based on non-empty host sets
        tools_used = []
        if masscan_hosts:
            tools_used.append('masscan')
        if naabu_hosts:
            tools_used.append('naabu')

    # Ensure merged_hosts is sorted with no duplicates
    unique_merged = sorted(set(merged_hosts))

    # Save masscan results if masscan was used
    if 'masscan' in tools_used:
        masscan_dir = os.path.join(base_outdir, 'masscan')
        ensure_directory_exists(masscan_dir)
        fpath = os.path.join(masscan_dir, 'masscan-discovered.txt')
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(masscan_hosts)))
        print(f"{Fore.GREEN}[+] Saved {len(masscan_hosts)} hosts to {fpath}")

    # Save naabu results if naabu was used
    if 'naabu' in tools_used:
        naabu_dir = os.path.join(base_outdir, 'naabu')
        ensure_directory_exists(naabu_dir)
        fpath = os.path.join(naabu_dir, 'naabu-discovered.txt')
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("\n".join(sorted(naabu_hosts)))
        print(f"{Fore.GREEN}[+] Saved {len(naabu_hosts)} hosts to {fpath}")

    # Save combined file only if BOTH tools were used (save to base directory)
    if 'masscan' in tools_used and 'naabu' in tools_used:
        ensure_directory_exists(base_outdir)
        fpath = os.path.join(base_outdir, 'all-discovered-hosts.txt')
        with open(fpath, "w", encoding="utf-8") as f:
            f.write("\n".join(unique_merged))
        print(f"{Fore.GREEN}[+] Saved {len(unique_merged)} hosts to {fpath}")


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



def run_masscan(host, interface=None, base_outdir=None, ports=None, rate=1000, exclusions=None, source_ip=None):
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
    if source_ip:
        cmd_args.extend(["--adapter-ip", source_ip])
    if ports:
        cmd_args.extend(["-p", ports])
    else:
        cmd_args.extend(["-p", "21,22,23,25,80,88,111,135,139,389,443,445,636,1099,1433,2049,3389,4786,5900,5985,8080,9100"])
    if exclude_file:
        cmd_args.extend(["--excludefile", exclude_file])
    cmd_args.extend(["--rate", str(rate), "--wait", "0", "--open-only", "-oL", output_file])

    # Wrap with proxychains if jumpbox routing is active
    cmd_args = wrap_command_if_needed(cmd_args, 'masscan')
    if is_jumpbox_routing_active():
        print(f"{Fore.CYAN}[i] Routing masscan through jumpbox via proxychains{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}[masscan] {' '.join(cmd_args)}{Style.RESET_ALL}\n")

    process = None
    try:
        # Use Popen to have better control over the process
        process = subprocess.Popen(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )
        
        # Monitor output to detect completion
        scan_complete = False
        last_output_time = time.time()
        timeout_after_complete = 5  # Wait max 5 seconds after seeing 100% done
        
        while True:
            # Check if process has finished
            if process.poll() is not None:
                break
            
            # Read a line of output (non-blocking)
            try:
                line = process.stdout.readline()
                if line:
                    line = line.strip()
                    # Check if scan is 100% done
                    if "100.00% done" in line or "100% done" in line:
                        scan_complete = True
                        last_output_time = time.time()
                    # Print progress (but filter out repetitive rate lines).
                    # No per-line ``[masscan]`` prefix — the command echo right
                    # above and the "[+] Running Masscan discovery..." banner
                    # already establish what tool is producing this output.
                    if not line.startswith("rate:"):
                        print(line)
            except Exception:
                pass
            
            # If we've seen 100% done, wait a bit for file to be written, then terminate
            if scan_complete:
                elapsed = time.time() - last_output_time
                if elapsed >= timeout_after_complete:
                    # Check if output file exists and has content
                    if os.path.exists(output_file):
                        try:
                            with open(output_file, "r", encoding="utf-8") as fh:
                                if any(line.startswith("open") for line in fh):
                                    # File exists and has results, terminate process
                                    process.terminate()
                                    # Give it a moment to exit gracefully
                                    time.sleep(1)
                                    if process.poll() is None:
                                        process.kill()
                                    break
                        except Exception:
                            pass
                    # If file doesn't exist yet, wait a bit more
                    if not os.path.exists(output_file) and elapsed < 10:
                        continue
                    # Otherwise terminate
                    process.terminate()
                    time.sleep(1)
                    if process.poll() is None:
                        process.kill()
                    break
            
            # Safety timeout: if process runs for more than 1 hour, kill it
            if time.time() - last_output_time > 3600:
                print(f"{Fore.YELLOW}[!] Masscan timeout, terminating...{Style.RESET_ALL}")
                process.terminate()
                time.sleep(1)
                if process.poll() is None:
                    process.kill()
                break
            
            time.sleep(0.1)  # Small sleep to avoid busy-waiting
        
        # Wait for process to finish (should be done by now)
        returncode = process.wait()
        
    except KeyboardInterrupt:
        # If interrupted, still try to read output file if it exists
        if process:
            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        print(f"{Fore.YELLOW}[!] Masscan interrupted, checking for partial results...{Style.RESET_ALL}")
    except Exception as e:
        # Any other error
        if process:
            try:
                process.terminate()
                process.wait(timeout=2)
            except Exception:
                try:
                    process.kill()
                except Exception:
                    pass
        print(f"{Fore.YELLOW}[!] Masscan error: {e}, checking for partial results...{Style.RESET_ALL}")
    finally:
        # Cleanup exclude file
        if exclude_file and os.path.exists(exclude_file):
            try:
                os.remove(exclude_file)
            except Exception:
                pass
    
    # Check for output file even if masscan was interrupted or errored
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8") as fh:
                if any(line.startswith("open") for line in fh):
                    print(f"{Fore.GREEN}Masscan completed for {host}. Output: {output_file}\n")
                    return output_file
                else:
                    print(f"{Fore.YELLOW}[!] Masscan found no open ports for {host}{Style.RESET_ALL}")
                    return None
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Error reading masscan output file: {e}{Style.RESET_ALL}")
            return None
    else:
        print(f"{Fore.YELLOW}[!] Masscan did not produce output file for {host}{Style.RESET_ALL}")
        return None

def run_naabu(host, interface=None, base_outdir=None, ports=None, rate=10000, exclusions=None, source_ip=None):
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
    if source_ip:
        cmd_args.extend(["-source-ip", source_ip])
    if ports:
        cmd_args.extend(["-p", ports])
    else:
        cmd_args.extend(["-p", "21,22,23,25,80,88,111,135,139,389,443,445,636,1099,1433,2049,3389,4786,5900,5985,3389,8080,9100"])
    if exclude_file:
        cmd_args.extend(["-exclude-file", exclude_file])
    cmd_args.extend(["-rate", str(rate), "-o", output_file, "-list", tmp_path])

    # Wrap with proxychains if jumpbox routing is active
    cmd_args = wrap_command_if_needed(cmd_args, 'naabu')
    if is_jumpbox_routing_active():
        print(f"{Fore.CYAN}[i] Routing naabu through jumpbox via proxychains{Style.RESET_ALL}")

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


def run_icmp_naabu(hosts, interface=None, base_outdir=None, exclusions=None):
    """
    Run naabu host discovery to find live hosts.

    Uses: -sn (host-discovery only). naabu selects its default probes (ICMP
    echo + TCP SYN when privileged). Note: naabu >= 2.6 rejects explicit
    -pe/-pp probes together with -sn ("discovery probes were provided but host
    discovery is disabled"), so we let -sn pick the probes.

    Args:
        hosts: List of target hosts/CIDRs to probe
        interface: Network interface to use (optional)
        base_outdir: Base output directory
        exclusions: Tuple of (ip_set, net_set, dom_set) for exclusions

    Returns:
        Set of live host IP addresses
    """
    if not shutil.which('naabu'):
        print(f"{Fore.RED}[!] naabu not found in PATH. Cannot run ICMP discovery.{Style.RESET_ALL}")
        return set()

    live_hosts = set()

    # Create output directory
    icmp_dir = os.path.join(base_outdir, 'icmp')
    ensure_directory_exists(icmp_dir)
    ensure_directory_owned(icmp_dir)

    # Create temp file for targets
    fd, tmp_path = tempfile.mkstemp(prefix="naabu_icmp_", suffix=".txt", dir=icmp_dir)
    os.close(fd)

    with open(tmp_path, 'w', encoding='utf-8') as tf:
        for host in hosts:
            tf.write(f"{host}\n")

    output_file = os.path.join(icmp_dir, 'naabu-icmp-raw.txt')

    # Build command: naabu -sn -list <targets>
    # (-sn = host-discovery only; naabu picks default probes when privileged.
    #  In -sn mode naabu prints alive hosts to STDOUT and leaves -o empty, so
    #  we capture stdout rather than passing -o.)
    cmd_args = ['naabu', '-sn']

    if interface:
        cmd_args.extend(['-interface', interface])

    # Handle exclusions
    exclude_file = None
    if exclusions:
        ip_exclude, net_exclude, dom_exclude = exclusions
        if ip_exclude or net_exclude:
            exclude_path = os.path.join(icmp_dir, 'naabu_icmp_exclude.txt')
            with open(exclude_path, 'w', encoding='utf-8') as ef:
                for ip in sorted(ip_exclude):
                    ef.write(f"{ip}\n")
                for net in sorted(net_exclude, key=lambda x: str(x)):
                    ef.write(f"{net}\n")
            exclude_file = exclude_path
            cmd_args.extend(['-exclude-file', exclude_file])

    cmd_args.extend(['-list', tmp_path])

    # Wrap with proxychains if jumpbox routing is active
    cmd_args = wrap_command_if_needed(cmd_args, 'naabu')
    if is_jumpbox_routing_active():
        print(f"{Fore.CYAN}[i] Routing naabu ICMP through jumpbox via proxychains{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}[ICMP-Naabu] Starting ICMP host discovery")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[naabu-icmp] {' '.join(cmd_args)}{Style.RESET_ALL}")

    try:
        # naabu prints alive hosts to STDOUT in -sn mode (the -o file stays
        # empty for host discovery), so capture stdout. stderr is left attached
        # so naabu's live "Found alive host" progress still streams to console.
        result = subprocess.run(cmd_args, check=True, stdout=subprocess.PIPE, text=True)

        for line in (result.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue
            # Handle both IP-only and IP:port formats
            ip_part = line.split(':')[0].strip()
            try:
                ipaddress.ip_address(ip_part)
                live_hosts.add(ip_part)
            except ValueError:
                continue

        # Persist the discovered hosts to the workspace for record-keeping.
        try:
            with open(output_file, 'w', encoding='utf-8') as fh:
                for ip in sorted(live_hosts, key=lambda x: ipaddress.ip_address(x)):
                    fh.write(f"{ip}\n")
        except Exception:
            pass

        print(f"{Fore.GREEN}[naabu-icmp] Discovered {len(live_hosts)} live hosts{Style.RESET_ALL}")

    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[!] naabu ICMP discovery failed: {e}{Style.RESET_ALL}")
    finally:
        # Cleanup temp files
        for f in [tmp_path, exclude_file]:
            if f and os.path.exists(f):
                try:
                    os.remove(f)
                except Exception:
                    pass

    return live_hosts


def run_icmp_fping(hosts, interface=None, base_outdir=None, exclusions=None, source_ip=None):
    """
    Run fping for ICMP host discovery.

    Uses: fping -a -g (for CIDRs) or fping -a -f (for file input)

    Args:
        hosts: List of target hosts/CIDRs to probe
        interface: Network interface to use (optional)
        base_outdir: Base output directory
        exclusions: Tuple of (ip_set, net_set, dom_set) for exclusions

    Returns:
        Set of live host IP addresses
    """
    if not shutil.which('fping'):
        print(f"{Fore.RED}[!] fping not found in PATH. Cannot run ICMP discovery.{Style.RESET_ALL}")
        return set()

    live_hosts = set()

    # Create output directory
    icmp_dir = os.path.join(base_outdir, 'icmp')
    ensure_directory_exists(icmp_dir)
    ensure_directory_owned(icmp_dir)

    # Parse exclusions
    ip_exclude = set()
    net_exclude = set()
    if exclusions:
        ip_exclude, net_exclude, _ = exclusions

    # Separate CIDRs from individual IPs
    cidrs = []
    single_ips = []

    for host in hosts:
        if '/' in host:
            cidrs.append(host)
        else:
            try:
                ipaddress.ip_address(host)
                single_ips.append(host)
            except ValueError:
                # Skip non-IP (domains) for fping - it only works with IPs
                continue

    # Apply exclusions to single IPs
    if exclusions:
        filtered_ips = []
        for ip in single_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if str(ip_obj) in ip_exclude:
                    continue
                if any(ip_obj in net for net in net_exclude):
                    continue
                filtered_ips.append(ip)
            except ValueError:
                continue
        single_ips = filtered_ips

    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}[ICMP-Fping] Starting ICMP host discovery")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    # Process CIDRs with fping -g
    for cidr in cidrs:
        cmd_args = ['fping', '-a', '-g', '-q', '-r', '1', cidr]

        if source_ip:
            cmd_args.extend(['-S', source_ip])
        if interface:
            cmd_args.extend(['-I', interface])

        # Wrap with proxychains if needed
        cmd_args = wrap_command_if_needed(cmd_args, 'fping')

        print(f"{Fore.YELLOW}[fping] {' '.join(cmd_args)}{Style.RESET_ALL}")

        try:
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout per CIDR
            )
            # fping -a outputs alive hosts to stdout
            for line in result.stdout.strip().split('\n'):
                ip = line.strip()
                if ip:
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        # Apply exclusions
                        if str(ip_obj) in ip_exclude:
                            continue
                        if any(ip_obj in net for net in net_exclude):
                            continue
                        live_hosts.add(ip)
                    except ValueError:
                        continue
        except subprocess.TimeoutExpired:
            print(f"{Fore.YELLOW}[!] fping timeout for {cidr}{Style.RESET_ALL}")
        except subprocess.CalledProcessError as e:
            # fping returns non-zero if some hosts are unreachable
            # stdout still contains alive hosts
            if e.stdout:
                for line in e.stdout.strip().split('\n'):
                    ip = line.strip()
                    if ip:
                        try:
                            ip_obj = ipaddress.ip_address(ip)
                            if str(ip_obj) in ip_exclude:
                                continue
                            if any(ip_obj in net for net in net_exclude):
                                continue
                            live_hosts.add(ip)
                        except ValueError:
                            continue

    # Process individual IPs
    if single_ips:
        # Write IPs to temp file
        fd, tmp_path = tempfile.mkstemp(prefix="fping_", suffix=".txt", dir=icmp_dir)
        os.close(fd)

        with open(tmp_path, 'w', encoding='utf-8') as tf:
            for ip in single_ips:
                tf.write(f"{ip}\n")

        cmd_args = ['fping', '-a', '-f', tmp_path, '-q', '-r', '1']

        if source_ip:
            cmd_args.extend(['-S', source_ip])
        if interface:
            cmd_args.extend(['-I', interface])

        cmd_args = wrap_command_if_needed(cmd_args, 'fping')

        print(f"{Fore.YELLOW}[fping] {' '.join(cmd_args)}{Style.RESET_ALL}")

        try:
            result = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=300
            )
            for line in result.stdout.strip().split('\n'):
                ip = line.strip()
                if ip:
                    try:
                        ipaddress.ip_address(ip)
                        live_hosts.add(ip)
                    except ValueError:
                        continue
        except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
            if hasattr(e, 'stdout') and e.stdout:
                for line in e.stdout.strip().split('\n'):
                    ip = line.strip()
                    if ip:
                        try:
                            ipaddress.ip_address(ip)
                            live_hosts.add(ip)
                        except ValueError:
                            continue
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass

    print(f"{Fore.GREEN}[fping] Discovered {len(live_hosts)} live hosts{Style.RESET_ALL}")

    return live_hosts


def save_icmp_results(icmp_hosts, base_outdir):
    """
    Save ICMP discovery results to results/icmp/icmp-discovered.txt

    Args:
        icmp_hosts: Set of live host IP addresses
        base_outdir: Base output directory
    """
    if not icmp_hosts:
        return

    icmp_dir = os.path.join(base_outdir, 'icmp')
    ensure_directory_exists(icmp_dir)
    ensure_directory_owned(icmp_dir)

    fpath = os.path.join(icmp_dir, 'icmp-discovered.txt')
    with open(fpath, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(icmp_hosts)))
    print(f"{Fore.GREEN}[+] Saved {len(icmp_hosts)} live hosts to {fpath}{Style.RESET_ALL}")


def ensure_nmap_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

def run_nmap(ip, base_outdir=None, scan_type='top-ports', ports=None, nmap_options=None, fingerprint=False, interface=None, source_ip=None, max_retries=None):
    """
    Run Nmap on a single host.
    Ensures all output directories are writable and owned by the invoking user (not root),
    even if executed with sudo.

    Returns:
        str: Path to XML output file, or None on failure
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
    if source_ip:
        cmd_args.extend(["-S", source_ip])
    if interface:
        cmd_args.extend(["-e", interface])
        # When ``-e`` is set, nmap's default async (nsock) resolver tries to bind
        # an IPv6 source socket on the interface and HANGS at "Parallel DNS
        # resolution of 1 host" -- the scan stalls indefinitely before any port
        # is scanned (reproduced on an eth0 with IPv6 addresses). ``-n`` disables
        # reverse DNS entirely, sidestepping the broken resolver path (and it's
        # faster). cygor identifies hosts via its own fingerprinting, so PTR
        # hostnames aren't needed here. (This replaces the old ``--system-dns``
        # workaround, which avoided the hang but serialized DNS and was slow.)
        cmd_args.append("-n")
    cmd_args.extend(["-Pn", "-sC", "-sV", "-O", "-T4"])
    # Cap probe retransmits when requested. -T4 defaults to 6 retries; lowering
    # this (e.g. 2) cuts time wasted retransmitting to filtered/dropped ports
    # during the -p- port-scan phase and reduces nmap's congestion throttling.
    if max_retries is not None:
        cmd_args.extend(["--max-retries", str(max_retries)])

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

    # Wrap with proxychains if jumpbox routing is active
    cmd_args = wrap_command_if_needed(cmd_args, 'nmap')
    if is_jumpbox_routing_active():
        print(f"{Fore.CYAN}[i] Routing nmap through jumpbox via proxychains{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}[nmap] {' '.join(cmd_args)}{Style.RESET_ALL}", flush=True)

    xml_path = f"{output_file_prefix}.xml"
    success = False

    # Force line-buffered nmap stdout so per-port discoveries stream live
    # instead of sitting in libc's block buffer until the process exits.
    # Without ``stdbuf -oL`` nmap detects stdout-is-a-pipe (always true under
    # the cygor task manager) and only flushes on exit, so the live console
    # shows nothing until the scan finishes.
    if shutil.which('stdbuf'):
        run_cmd = ['stdbuf', '-oL', '-eL'] + cmd_args
    else:
        run_cmd = cmd_args

    try:
        subprocess.run(run_cmd, check=True)
        print(f"{Fore.GREEN}Nmap completed for {ip}.", flush=True)
        success = True
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}Error running nmap for {ip}: {e}", flush=True)
    finally:
        # Ensure Nmap results and subdirs are owned by invoking user
        try:
            set_owner_recursive(scan_directory)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Warning: could not reset ownership on {scan_directory}: {e}{Style.RESET_ALL}")

    # Run fingerprinting if enabled and Nmap succeeded
    if success and fingerprint and os.path.exists(xml_path):
        try:
            from cygor.fingerprinting import fingerprint_host_sync
            fp_result = fingerprint_host_sync(xml_path)
            if fp_result:
                sources_str = fp_result.get_sources_summary()
                # Show validation status with color coding
                if fp_result.validated:
                    status_icon = "[+]"
                    status_color = Fore.GREEN
                    validation_str = f"VALIDATED ({fp_result.validation_sources} sources)"
                else:
                    status_icon = "[?]"
                    status_color = Fore.YELLOW
                    validation_str = "unvalidated"

                # Build OS string - prefer os_full (detailed), fall back to os_family
                os_display = fp_result.os_full or fp_result.os_name or fp_result.os_family or 'Unknown OS'

                # Add NetBIOS name if available
                hostname_str = ""
                if fp_result.netbios_name:
                    hostname_str = f" ({fp_result.netbios_name})"
                elif fp_result.hostname:
                    hostname_str = f" ({fp_result.hostname})"

                print(f"{status_color}{status_icon} [fingerprint] {ip}{hostname_str}: "
                      f"{fp_result.device_type} | "
                      f"{fp_result.manufacturer or 'Unknown'} | "
                      f"{os_display} "
                      f"(confidence: {fp_result.confidence:.0%}, {validation_str}) "
                      f"[sources: {sources_str}]{Style.RESET_ALL}")
                return (xml_path, fp_result)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Fingerprinting failed for {ip}: {e}{Style.RESET_ALL}")

    return (xml_path, None) if success else (None, None)


def _resolve_nmap_concurrency(requested, n_hosts):
    """Decide how many nmap scans to run in parallel.

    Bounded by (a) the number of live hosts -- more workers than hosts is a
    no-op -- and (b) a CPU-derived ceiling that keeps concurrent heavy nmap runs
    from saturating the host's network stack (the cause of nsock WRITE errors).
    CPU count is used as a universal capacity proxy that scales across VMs,
    containers, cloud instances, and bare metal alike. Honors an explicit
    --processes value and a CYGOR_MAX_PROCESSES override for the ceiling.

    Returns (effective, cpu, ceiling, reason).
    """
    try:
        cpu = len(os.sched_getaffinity(0))   # respects cgroup/cpuset on Linux
    except (AttributeError, OSError):
        cpu = os.cpu_count() or 4

    ceiling = max(4, cpu * 4)
    override = os.environ.get("CYGOR_MAX_PROCESSES", "")
    if override.isdigit() and int(override) > 0:
        ceiling = int(override)

    n_hosts = max(1, n_hosts)
    # requested is None/0 -> auto (let the ceiling/host-count decide)
    req = requested if requested else ceiling
    effective = max(1, min(req, n_hosts, ceiling))

    if effective == n_hosts and n_hosts <= ceiling and (not requested or requested >= n_hosts):
        reason = "one per live host"
    elif requested and effective == requested:
        reason = "requested"
    else:
        reason = f"CPU ceiling ({cpu} CPUx4={ceiling})"
    return effective, cpu, ceiling, reason


def run_nmap_parallel(ips, processes, base_outdir=None, scan_type='top-ports', ports=None, nmap_options=None, fingerprint=False, interface=None, source_ip=None, max_retries=None):
    """
    Run Nmap scans in parallel with optional fingerprinting.

    Returns:
        List of (xml_path, fingerprint_result) tuples if fingerprint=True,
        otherwise None
    """
    import json as _json

    output_dir = os.path.join(base_outdir, 'nmap')
    ensure_nmap_directory_exists(os.path.join(output_dir, scan_type))

    results = []
    fingerprint_results = []

    # Decide concurrency from live-host count + CPU capacity, and tell the user.
    effective, _cpu, _ceiling, _reason = _resolve_nmap_concurrency(processes, len(ips))
    if processes and processes > effective:
        print(f"{Fore.YELLOW}[i] Capping Nmap concurrency: requested {processes} -> {effective} "
              f"({_reason}). Override the ceiling with CYGOR_MAX_PROCESSES.{Style.RESET_ALL}", flush=True)
    print(f"{Fore.CYAN}[i] Nmap concurrency: {effective} parallel scan(s) for {len(ips)} live host(s) "
          f"[{_reason}]{Style.RESET_ALL}", flush=True)
    processes = effective

    with ThreadPoolExecutor(max_workers=processes) as executor:
        futures = {}
        for ip in ips:
            # Per-target IP rotation: each host gets its own rotated source IP
            _rot = get_next_ip(target_ip=ip, context="scan") if source_ip is None else None
            _src_ip = _rot["address"] if _rot else source_ip
            _iface = (_rot.get("interface") or interface) if _rot else interface
            futures[executor.submit(
                run_nmap,
                ip,
                base_outdir=base_outdir,
                scan_type=scan_type,
                ports=ports,
                nmap_options=nmap_options,
                fingerprint=fingerprint,
                interface=_iface,
                source_ip=_src_ip,
                max_retries=max_retries
            )] = ip

        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                result = future.result()
                if result:
                    xml_path, fp_result = result
                    results.append((ip, xml_path))
                    if fp_result:
                        fingerprint_results.append(fp_result)
            except Exception as e:
                print(f"{Fore.RED}[!] Error scanning {ip}: {e}{Style.RESET_ALL}")

    # Save fingerprint results to JSON if any were collected
    if fingerprint and fingerprint_results:
        fp_output_path = os.path.join(base_outdir, 'fingerprints.json')
        try:
            with open(fp_output_path, 'w', encoding='utf-8') as f:
                _json.dump(
                    [fp.to_dict() for fp in fingerprint_results],
                    f,
                    indent=2,
                    default=str
                )
            print(f"{Fore.GREEN}[+] Fingerprint results saved to: {fp_output_path}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to save fingerprint results: {e}{Style.RESET_ALL}")

        # Print summary
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"Device Fingerprinting Summary")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Total hosts fingerprinted: {len(fingerprint_results)}{Style.RESET_ALL}")

        # Group by device type
        device_types = {}
        for fp in fingerprint_results:
            dt = fp.device_type or "Unknown"
            device_types[dt] = device_types.get(dt, 0) + 1

        if device_types:
            print(f"\n{Fore.CYAN}Device Types:{Style.RESET_ALL}")
            for dt, count in sorted(device_types.items(), key=lambda x: -x[1]):
                print(f"  {dt}: {count}")

        # Group by OS (detailed - using os_full or os_name)
        os_details = {}
        for fp in fingerprint_results:
            # Prefer detailed OS, fall back to family
            os_str = fp.os_full or fp.os_name or fp.os_family or "Unknown"
            os_details[os_str] = os_details.get(os_str, 0) + 1

        if os_details:
            print(f"\n{Fore.CYAN}Operating Systems:{Style.RESET_ALL}")
            for os_str, count in sorted(os_details.items(), key=lambda x: -x[1]):
                print(f"  {os_str}: {count}")

        # Group by manufacturer
        manufacturers = {}
        for fp in fingerprint_results:
            mfr = fp.manufacturer or "Unknown"
            manufacturers[mfr] = manufacturers.get(mfr, 0) + 1

        if manufacturers:
            print(f"\n{Fore.CYAN}Manufacturers:{Style.RESET_ALL}")
            for mfr, count in sorted(manufacturers.items(), key=lambda x: -x[1])[:10]:
                print(f"  {mfr}: {count}")

        # Show hosts with detailed OS info
        validated_count = sum(1 for fp in fingerprint_results if fp.validated)
        print(f"\n{Fore.CYAN}Validation Status:{Style.RESET_ALL}")
        print(f"  Validated (2+ sources): {validated_count}")
        print(f"  Unvalidated: {len(fingerprint_results) - validated_count}")

        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")

    return fingerprint_results if fingerprint else None

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

    {Fore.YELLOW}# 4. Discovery only (no Nmap), save hostlists in tool directories{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover masscan naabu --discover-only
    # ➜ Creates: results/masscan/masscan-discovered.txt, results/naabu/naabu-discovered.txt, results/all-discovered-hosts.txt

    {Fore.YELLOW}# 4a. Discovery with single tool (masscan only){Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover masscan --discover-only
    # ➜ Creates: results/masscan/masscan-discovered.txt (only)

    {Fore.YELLOW}# 4b. Discovery with single tool (naabu only){Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover naabu --discover-only
    # ➜ Creates: results/naabu/naabu-discovered.txt (only)

    {Fore.YELLOW}# 5. Reuse discovered hostlist for Nmap scan{Style.RESET_ALL}
    cygor scan --use-discovery results/all-discovered-hosts.txt --scan-type fullscan
    # Or use: results/masscan/masscan-discovered.txt or results/naabu/naabu-discovered.txt

    {Fore.YELLOW}# 6. Run Nmap with custom ports on discovered hosts{Style.RESET_ALL}
    cygor scan --use-discovery results/masscan/masscan-discovered.txt --ports 80,443,8443

    {Fore.YELLOW}# 7. Run with 10 parallel Nmap processes{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover naabu --processes 10 --scan-type fullscan

    {Fore.YELLOW}# 8. Exclude specific subnets or hosts from scan{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --exclusions exclusions.txt --discover masscan

    {Fore.YELLOW}# 9. Use discovery files via glob for Nmap (works with shell expansion or as a pattern){Style.RESET_ALL}
    cygor scan --use-discovery results/discovery/*.txt --scan-type top-ports --processes 50

    {Fore.YELLOW}# 10. Provide a directory of scope files; each file can contain IPs, CIDRs, domains or URLs{Style.RESET_ALL}
    cygor scan -f path/to/scope_dir --discover masscan

    {Fore.YELLOW}# 11. Enable device fingerprinting during scan{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --fingerprint
    # Identifies devices, manufacturers, and OS from scan data
    # Results saved to: results/fingerprints.json

    {Fore.YELLOW}# 12. Sync fingerprint databases before scanning{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --fingerprint --sync-fp
    # Downloads OUI, JA3, JA4, and p0f databases before scanning

    {Fore.YELLOW}# 13. Sync fingerprint databases only (no scanning){Style.RESET_ALL}
    cygor scan --sync-fp-only
    # Downloads OUI, JA3, JA4, and p0f databases without running any scans
    # Shows data sources, URLs, record counts, and cache file locations

    {Fore.YELLOW}# 15. ICMP discovery before port scanning{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover icmp-naabu masscan
    # 1) ICMP sweep finds live hosts -> results/icmp/icmp-discovered.txt
    # 2) Masscan port scan on live hosts only (reduces scan time)

    {Fore.YELLOW}# 16. ICMP discovery only (no port scan){Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover icmp-naabu --discover-only
    # ➜ Creates: results/icmp/icmp-discovered.txt

    {Fore.YELLOW}# 17. Use fping for ICMP discovery{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover icmp-fping naabu
    # Uses fping (async ICMP) instead of naabu for host discovery

    {Fore.YELLOW}# 18. Full pipeline: ICMP -> masscan -> nmap{Style.RESET_ALL}
    cygor scan -i eth0 -f scope.txt --discover icmp-naabu masscan --scan-type fullscan
    # 1) ICMP sweep to find live hosts
    # 2) Masscan port discovery on live hosts only
    # 3) Nmap full port scan on discovered services

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
    scope_group.add_argument("-o", "--outdir",default=None,help="Base output directory (workspace) for all outputs (discovery, masscan, naabu, nmap). Required unless an active workspace is set with 'cygor workspace' or $CYGOR_WORKSPACE.")
    scope_group.add_argument("--exclusions", help="File or CIDR(s) of IPs/ranges to exclude")

    # Discovery
    disc_group = parser.add_argument_group("Discovery")
    disc_group.add_argument(
        "--discover",
        nargs="+",
        choices=["masscan", "naabu", "icmp-naabu", "icmp-fping"],
        default=["masscan"],
        help="Run host discovery with one or more tools. "
             "ICMP tools (icmp-naabu/icmp-fping) run first to find live hosts, "
             "then port scanners (masscan/naabu) scan only live hosts. "
             "(default: masscan)"
    )
    disc_group.add_argument(
    "--masscan-ports",
    help="Custom ports for Masscan discovery phase (e.g., '80,443,8080')."
    )
    disc_group.add_argument(
        "--masscan-rate",
        type=int,
        default=None,
        help="Masscan packet rate (pps) for the discovery phase. Default 1000; "
             "increase on fast/authorized networks."
    )
    disc_group.add_argument(
        "--naabu-ports",
        help="Custom ports for Naabu discovery phase (e.g., '1-1024,8080')."
    )
    disc_group.add_argument(
        "--discover-only",
        action="store_true",
        help="Run discovery only, save results into tool directories (e.g., masscan/masscan-discovered.txt), and skip Nmap."
    )
    disc_group.add_argument(
    "--use-discovery",
    nargs="+",
    help="Reuse one or more discovery results files or glob patterns (e.g., results/masscan/*.txt or results/all-discovered-hosts.txt) "
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
        default=None,
        help="Parallel Nmap scans. Default: auto -- chosen after host discovery "
             "from CPU count and the live-host count, capped so concurrent scans "
             "don't saturate the NIC (a cause of nsock WRITE errors). Pass a "
             "number to request a specific value (still capped to live hosts and "
             "the CPU ceiling); raise the ceiling with CYGOR_MAX_PROCESSES."
    )
    nmap_group.add_argument(
        "--max-retries",
        type=int,
        default=None,
        help="Cap Nmap probe retransmissions (nmap -T4 default is 6). Lower "
             "values (e.g. 2) speed up scans of firewalled/filtered or lossy "
             "hosts by retransmitting less; may slightly raise miss rate on "
             "lossy networks. Default: nmap's -T4 behavior."
    )
    # Fingerprinting
    fp_group = parser.add_argument_group("Device Fingerprinting")
    fp_group.add_argument(
        "--fingerprint",
        action="store_true",
        help="Enable device fingerprinting during Nmap scan. Identifies devices, manufacturers, and OS from scan data."
    )
    fp_group.add_argument(
        "--sync-fp",
        action="store_true",
        help="Sync fingerprint databases before scanning (downloads OUI, JA3, JA4, p0f data)."
    )
    fp_group.add_argument(
        "--sync-fp-only",
        action="store_true",
        help="Only sync fingerprint databases (no scanning). Downloads OUI, JA3, JA4, p0f data and exits."
    )
    fp_group.add_argument(
        "--fp-output",
        metavar="FILE",
        help="Write fingerprint results to JSON file (default: <outdir>/fingerprints.json)."
    )

    # Misc
    misc_group = parser.add_argument_group("Other")
    misc_group.add_argument("-b", "--banner", action="store_true", help="Display the banner")
    misc_group.add_argument("--parse", action="store_true", help="Enable parsing of results after scanning")

    


    args = parser.parse_args()

    # Handle --sync-fp-only: just sync fingerprint databases and exit
    if getattr(args, 'sync_fp_only', False):
        _sync_fingerprint_databases()
        return

    # Check if running with required privileges for scanning tools
    # Only required if doing actual discovery (not when using --use-discovery)
    if not args.use_discovery and args.discover:
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Error: Scanner requires root privileges (masscan/naabu/nmap need raw socket access)")
            print(f"{Fore.YELLOW}[i] Please run with: sudo cygor scan ...{Style.RESET_ALL}")
            sys.exit(1)

    # Resolve the output workspace. There is no implicit ./results default:
    # require an explicit -o, $CYGOR_WORKSPACE, or a configured active workspace.
    from cygor.workspace import require_workspace
    args.outdir = str(require_workspace(args.outdir))

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

        # Sync fingerprint databases if requested, or ensure data exists if fingerprinting
        if getattr(args, 'sync_fp', False):
            _sync_fingerprint_databases()
        elif getattr(args, 'fingerprint', False):
            _ensure_fingerprint_data_available()

        # IP rotation lookup for nmap parallel scan
        rotation_entry = get_next_ip(target_ip=None, context="scan")
        rotation_ip = rotation_entry["address"] if rotation_entry else None
        rotation_iface = (rotation_entry.get("interface") or args.interface) if rotation_entry else args.interface

        # ensure Nmap writes to outdir when using --use-discovery
        run_nmap_parallel(
            nmap_targets,
            args.processes,
            base_outdir=args.outdir,
            scan_type=args.scan_type,
            ports=args.ports,
            nmap_options=getattr(args, 'nmap_options', None),
            fingerprint=getattr(args, 'fingerprint', False),
            interface=rotation_iface,
            source_ip=rotation_ip,
            max_retries=args.max_retries
        )
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
    discovered_hosts_icmp = set()

    # --- Separate ICMP tools from port scanners ---
    icmp_tools = [t for t in args.discover if t in ('icmp-naabu', 'icmp-fping')]
    port_tools = [t for t in args.discover if t in ('masscan', 'naabu')]

    # --- Discovery Phase Start ---
    print(f"\n{Fore.CYAN}[+] Starting discovery phase using: {', '.join(args.discover)}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Output directory: {args.outdir}{Style.RESET_ALL}")

    # --- ICMP Pre-Discovery Phase (runs first if requested) ---
    if icmp_tools:
        icmp_tool = icmp_tools[0]  # Use first ICMP tool specified
        if icmp_tool == 'icmp-naabu':
            discovered_hosts_icmp = run_icmp_naabu(
                hosts,
                interface=args.interface,
                base_outdir=args.outdir,
                exclusions=exclusions if args.exclusions else None
            )
        elif icmp_tool == 'icmp-fping':
            rotation_entry = get_next_ip(target_ip=None, context="scan")
            rotation_ip = rotation_entry["address"] if rotation_entry else None
            rotation_iface = (rotation_entry.get("interface") or args.interface) if rotation_entry else args.interface
            discovered_hosts_icmp = run_icmp_fping(
                hosts,
                interface=rotation_iface,
                base_outdir=args.outdir,
                exclusions=exclusions if args.exclusions else None,
                source_ip=rotation_ip
            )

        # Save ICMP results
        save_icmp_results(discovered_hosts_icmp, args.outdir)

        # If port scanners are also requested, narrow targets to live hosts only
        if port_tools and discovered_hosts_icmp:
            original_count = len(hosts)
            hosts = list(discovered_hosts_icmp)
            print(f"{Fore.GREEN}[+] ICMP narrowed targets: {original_count} -> {len(hosts)} live hosts{Style.RESET_ALL}")
        elif port_tools and not discovered_hosts_icmp:
            print(f"{Fore.YELLOW}[!] ICMP found no live hosts. Proceeding with original target list.{Style.RESET_ALL}")
            # Continue with original hosts - ICMP might be blocked

    if 'masscan' in args.discover:
        print(f"{Fore.CYAN}[+] Running Masscan discovery...{Style.RESET_ALL}")
        _ms_rate = args.masscan_rate if args.masscan_rate else 1000
        # Masscan discovery
        try:
            masscan_results = []
            for h in hosts:
                rotation_entry = get_next_ip(target_ip=h, context="scan")
                rotation_ip = rotation_entry["address"] if rotation_entry else None
                rotation_iface = (rotation_entry.get("interface") or args.interface) if rotation_entry else args.interface
                masscan_results.append(
                    run_masscan(
                        h,
                        interface=rotation_iface,
                        base_outdir=args.outdir,
                        ports=args.masscan_ports,      # custom Masscan ports if set
                        rate=_ms_rate,
                        exclusions=exclusions if args.exclusions else None,
                        source_ip=rotation_ip
                    )
                )
        except KeyboardInterrupt:
            # If interrupted during discovery, still try to process any results we have
            print(f"{Fore.YELLOW}[!] Discovery interrupted, processing partial results...{Style.RESET_ALL}")
            # Try to get results from any existing output files
            masscan_results = []
            for h in hosts:
                safe_host = h.replace('/', '_').replace(':', '_')
                output_file = os.path.join(args.outdir, 'masscan', f"masscan_{safe_host}.txt")
                if os.path.exists(output_file):
                    masscan_results.append(output_file)
                else:
                    masscan_results.append(None)

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
        naabu_results = []
        for h in hosts:
            rotation_entry = get_next_ip(target_ip=h, context="scan")
            rotation_ip = rotation_entry["address"] if rotation_entry else None
            rotation_iface = (rotation_entry.get("interface") or args.interface) if rotation_entry else args.interface
            naabu_results.append(
                run_naabu(
                    h,
                    interface=rotation_iface,
                    base_outdir=args.outdir,
                    ports=args.naabu_ports,        # custom Naabu ports if set
                    exclusions=exclusions if args.exclusions else None,
                    source_ip=rotation_ip
                )
            )
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

    # If ICMP was used but no port scanners, use ICMP results for Nmap
    # If ICMP + port scanners, the merge already contains the port scan results
    # (port scanners only scanned ICMP-discovered hosts, so their results are the final targets)
    if icmp_tools and not port_tools:
        # ICMP-only discovery: use ICMP results directly for Nmap
        discovered_hosts_merge = discovered_hosts_icmp

    # --- stop after discovery if requested ---
    if args.discover_only:
        save_discovery_results(discovered_hosts_masscan, discovered_hosts_naabu, discovered_hosts_merge, args.outdir, args.discover)
        print(f"\n{Fore.YELLOW}{'='*50}")
        print(f"{Fore.YELLOW}Discovery Summary")
        print(f"{Fore.YELLOW}{'='*50}")
        if icmp_tools:
            print(f"{Fore.CYAN}ICMP:    {len(discovered_hosts_icmp)} hosts")
        if 'masscan' in args.discover:
            print(f"{Fore.CYAN}Masscan: {len(discovered_hosts_masscan)} hosts")
        if 'naabu' in args.discover:
            print(f"{Fore.CYAN}Naabu:   {len(discovered_hosts_naabu)} hosts")
        if port_tools:
            print(f"{Fore.CYAN}Merged:  {len(discovered_hosts_merge)} hosts")
        print(f"{Fore.YELLOW}{'='*50}")

        # Show which files were saved
        print(f"{Fore.GREEN}\nResults saved to:{Style.RESET_ALL}")
        if icmp_tools:
            print(f"{Fore.CYAN}  {os.path.join(args.outdir, 'icmp', 'icmp-discovered.txt')}")
        if 'masscan' in args.discover and 'naabu' in args.discover:
            print(f"{Fore.GREEN}  {os.path.join(args.outdir, 'all-discovered-hosts.txt')}")
            print(f"{Fore.CYAN}  {os.path.join(args.outdir, 'masscan', 'masscan-discovered.txt')}")
            print(f"{Fore.CYAN}  {os.path.join(args.outdir, 'naabu', 'naabu-discovered.txt')}")
        elif 'masscan' in args.discover:
            print(f"{Fore.CYAN}  {os.path.join(args.outdir, 'masscan', 'masscan-discovered.txt')}")
        elif 'naabu' in args.discover:
            print(f"{Fore.CYAN}  {os.path.join(args.outdir, 'naabu', 'naabu-discovered.txt')}")

        print(f"{Fore.YELLOW}{'='*50}\n")
        return

    # Save discovery results even when continuing to Nmap phase
    save_discovery_results(discovered_hosts_masscan, discovered_hosts_naabu, discovered_hosts_merge, args.outdir, args.discover)

    # --- Nmap phase ---
    # Determine Nmap targets based on discovery method used
    if icmp_tools and not port_tools:
        # ICMP-only: use ICMP results directly
        nmap_targets = list(discovered_hosts_icmp)
    elif args.nmap_source == 'masscan':
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

    # Sync fingerprint databases if requested, or ensure data exists if fingerprinting
    if getattr(args, 'sync_fp', False):
        _sync_fingerprint_databases()
    elif getattr(args, 'fingerprint', False):
        _ensure_fingerprint_data_available()

    # IP rotation lookup for nmap parallel scan
    rotation_entry = get_next_ip(target_ip=None, context="scan")
    rotation_ip = rotation_entry["address"] if rotation_entry else None
    rotation_iface = (rotation_entry.get("interface") or args.interface) if rotation_entry else args.interface

    run_nmap_parallel(
        nmap_targets,
        args.processes,
        base_outdir=args.outdir,
        scan_type=args.scan_type,
        ports=args.ports,
        nmap_options=getattr(args, 'nmap_options', None),
        fingerprint=getattr(args, 'fingerprint', False),
        interface=rotation_iface,
        source_ip=rotation_ip,
        max_retries=args.max_retries
    )
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
