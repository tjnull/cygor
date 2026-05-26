# cygor/privileges.py
"""
One-time system configuration for scan tool privileges.

Provides two mechanisms so the web UI (and daemon mode) can run
masscan, nmap, naabu, etc. without interactive sudo prompts:

  1. Linux capabilities  – setcap cap_net_raw,cap_net_admin on tool binaries
  2. sudoers NOPASSWD    – /etc/sudoers.d/cygor with NOPASSWD entries

Run as:  sudo cygor setup-privileges
"""

import os
import sys
import shutil
import subprocess
import getpass
from pathlib import Path

# Tools that need raw-socket / elevated privileges for scanning
SCAN_TOOLS = [
    "masscan",
    "nmap",
    "naabu",
]

# Linux capabilities needed for raw-socket scanning
RAW_CAPS = "cap_net_raw,cap_net_admin=eip"

SUDOERS_FILE = Path("/etc/sudoers.d/cygor")
SUDOERS_HEADER = "# Managed by cygor setup-privileges — do not edit manually\n"


# --------------------------------------------------------------------------- #
#  Detection helpers
# --------------------------------------------------------------------------- #

def _find_tools() -> list[dict]:
    """Return info dicts for every discovered scan tool."""
    tools = []
    for name in SCAN_TOOLS:
        path = shutil.which(name)
        info = {"name": name, "path": path, "installed": path is not None}

        if path:
            # Check current capabilities
            info["caps"] = _get_caps(path)
            # Resolve symlinks for capability setting (setcap needs real binary)
            real = os.path.realpath(path)
            info["real_path"] = real
        else:
            info["caps"] = ""
            info["real_path"] = None

        tools.append(info)
    return tools


def _get_caps(binary_path: str) -> str:
    """Return the current capabilities string for a binary (empty if none)."""
    try:
        result = subprocess.run(
            ["getcap", binary_path],
            capture_output=True, text=True, timeout=5,
        )
        # Output looks like:  /usr/bin/nmap cap_net_raw,cap_net_admin=eip
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split("=", 1)
            if len(parts) == 2:
                return parts[0].split()[-1] + "=" + parts[1]
            return result.stdout.strip()
    except Exception:
        pass
    return ""


def _check_sudoers_entry(username: str, tool_path: str) -> bool:
    """Check if a NOPASSWD sudoers entry exists for this user + tool."""
    if not SUDOERS_FILE.exists():
        return False
    try:
        content = SUDOERS_FILE.read_text()
        # Pattern: username ALL=(ALL) NOPASSWD: /path/to/tool
        return f"{username} ALL=(ALL) NOPASSWD: {tool_path}" in content
    except PermissionError:
        return False


def _is_root() -> bool:
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def get_privilege_status() -> dict:
    """
    Get full privilege status for all scan tools.
    Used by both the CLI and the web API.
    """
    tools = _find_tools()
    is_root = _is_root()

    # Determine the effective user (SUDO_USER if running under sudo, else current)
    effective_user = os.environ.get("SUDO_USER") or getpass.getuser()

    result = {
        "is_root": is_root,
        "user": effective_user,
        "tools": [],
        "sudoers_file": str(SUDOERS_FILE),
        "sudoers_exists": SUDOERS_FILE.exists(),
    }

    for tool in tools:
        status = {
            "name": tool["name"],
            "installed": tool["installed"],
            "path": tool["path"],
        }
        if tool["installed"]:
            status["has_caps"] = bool(tool["caps"])
            status["caps"] = tool["caps"]
            status["has_sudoers"] = _check_sudoers_entry(effective_user, tool["path"])
            # Tool is "privileged" if root, has caps, or has sudoers NOPASSWD
            status["privileged"] = is_root or status["has_caps"] or status["has_sudoers"]
        else:
            status["has_caps"] = False
            status["caps"] = ""
            status["has_sudoers"] = False
            status["privileged"] = False
        result["tools"].append(status)

    # Check passwordless sudo generally
    passwordless = False
    if not is_root:
        try:
            r = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5)
            passwordless = r.returncode == 0
        except Exception:
            pass
    result["passwordless_sudo"] = passwordless

    return result


# --------------------------------------------------------------------------- #
#  Setup actions
# --------------------------------------------------------------------------- #

def setup_capabilities(tools: list[dict], verbose: bool = True) -> list[str]:
    """
    Apply Linux capabilities to scan tool binaries.
    Must be run as root.  Returns list of messages.
    """
    messages = []
    setcap = shutil.which("setcap")
    if not setcap:
        messages.append("[!] setcap not found — install libcap2-bin (Debian/Ubuntu) or libcap (RHEL/Fedora)")
        return messages

    for tool in tools:
        if not tool["installed"]:
            if verbose:
                messages.append(f"[-] {tool['name']}: not installed, skipping")
            continue

        real_path = tool["real_path"]
        try:
            result = subprocess.run(
                [setcap, RAW_CAPS, real_path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                messages.append(f"[+] {tool['name']}: capabilities set ({RAW_CAPS}) on {real_path}")
            else:
                err = result.stderr.strip()
                messages.append(f"[!] {tool['name']}: setcap failed — {err}")
        except Exception as e:
            messages.append(f"[!] {tool['name']}: setcap error — {e}")

    return messages


def setup_sudoers(tools: list[dict], username: str, verbose: bool = True) -> list[str]:
    """
    Create /etc/sudoers.d/cygor with NOPASSWD entries for scan tools.
    Must be run as root.  Returns list of messages.
    """
    messages = []

    # Build the sudoers content
    lines = [SUDOERS_HEADER]
    added = 0
    for tool in tools:
        if not tool["installed"]:
            if verbose:
                messages.append(f"[-] {tool['name']}: not installed, skipping sudoers entry")
            continue
        line = f"{username} ALL=(ALL) NOPASSWD: {tool['path']}"
        lines.append(line + "\n")
        added += 1
        messages.append(f"[+] {tool['name']}: NOPASSWD entry for {username} -> {tool['path']}")

    if added == 0:
        messages.append("[!] No installed tools found — nothing to add to sudoers")
        return messages

    content = "".join(lines)

    # Write to a temp file and validate with visudo -cf
    import tempfile
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".cygor", delete=False) as f:
            f.write(content)
            tmp_path = f.name

        # Validate syntax
        check = subprocess.run(
            ["visudo", "-cf", tmp_path],
            capture_output=True, text=True, timeout=10,
        )
        if check.returncode != 0:
            messages.append(f"[!] sudoers syntax check failed: {check.stderr.strip()}")
            os.unlink(tmp_path)
            return messages

        # Install the file
        SUDOERS_FILE.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(tmp_path, str(SUDOERS_FILE))
        os.chmod(str(SUDOERS_FILE), 0o440)
        messages.append(f"[+] Installed {SUDOERS_FILE} ({added} tool(s))")

    except Exception as e:
        messages.append(f"[!] Failed to write sudoers file: {e}")
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

    return messages


def remove_sudoers(verbose: bool = True) -> list[str]:
    """Remove the cygor sudoers file."""
    messages = []
    if SUDOERS_FILE.exists():
        try:
            SUDOERS_FILE.unlink()
            messages.append(f"[+] Removed {SUDOERS_FILE}")
        except Exception as e:
            messages.append(f"[!] Failed to remove {SUDOERS_FILE}: {e}")
    else:
        messages.append(f"[-] {SUDOERS_FILE} does not exist")
    return messages


def remove_capabilities(tools: list[dict], verbose: bool = True) -> list[str]:
    """Remove Linux capabilities from scan tool binaries."""
    messages = []
    setcap = shutil.which("setcap")
    if not setcap:
        messages.append("[!] setcap not found")
        return messages

    for tool in tools:
        if not tool["installed"] or not tool["caps"]:
            continue
        real_path = tool["real_path"]
        try:
            result = subprocess.run(
                [setcap, "-r", real_path],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                messages.append(f"[+] {tool['name']}: capabilities removed from {real_path}")
            else:
                messages.append(f"[!] {tool['name']}: failed to remove capabilities — {result.stderr.strip()}")
        except Exception as e:
            messages.append(f"[!] {tool['name']}: error — {e}")

    return messages


# --------------------------------------------------------------------------- #
#  CLI entry point
# --------------------------------------------------------------------------- #

def cli_main(args: list[str]) -> None:
    """CLI handler for 'cygor setup-privileges'."""
    # Try colorama if available
    try:
        from colorama import Fore, Style, init
        init(autoreset=True, strip=False)
    except ImportError:
        class Fore:
            CYAN = GREEN = YELLOW = RED = MAGENTA = RESET = ""
        class Style:
            RESET_ALL = BRIGHT = ""

    # Parse args
    action = "setup"  # default
    method = None  # auto-detect
    force_user = None

    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-h", "--help"):
            _print_help(Fore, Style)
            return
        elif arg == "status":
            action = "status"
        elif arg == "remove":
            action = "remove"
        elif arg == "--caps-only":
            method = "caps"
        elif arg == "--sudoers-only":
            method = "sudoers"
        elif arg == "--user" and i + 1 < len(args):
            i += 1
            force_user = args[i]
        i += 1

    # ---- STATUS ----
    if action == "status":
        status = get_privilege_status()
        print(f"\n{Fore.CYAN}Cygor Scan Privilege Status{Style.RESET_ALL}")
        print(f"{'='*50}")
        print(f"  Running as root:    {'Yes' if status['is_root'] else 'No'}")
        print(f"  Effective user:     {status['user']}")
        print(f"  Passwordless sudo:  {'Yes' if status['passwordless_sudo'] else 'No'}")
        print(f"  Sudoers file:       {'Exists' if status['sudoers_exists'] else 'Not found'}")
        print()
        print(f"  {'Tool':<12} {'Installed':<12} {'Capabilities':<16} {'Sudoers':<12} {'Status'}")
        print(f"  {'-'*12} {'-'*12} {'-'*16} {'-'*12} {'-'*10}")
        for t in status["tools"]:
            installed = f"{Fore.GREEN}Yes{Style.RESET_ALL}" if t["installed"] else f"{Fore.RED}No{Style.RESET_ALL}"
            caps = f"{Fore.GREEN}Yes{Style.RESET_ALL}" if t.get("has_caps") else f"{Fore.YELLOW}No{Style.RESET_ALL}"
            sudoers = f"{Fore.GREEN}Yes{Style.RESET_ALL}" if t.get("has_sudoers") else f"{Fore.YELLOW}No{Style.RESET_ALL}"
            priv = f"{Fore.GREEN}Ready{Style.RESET_ALL}" if t.get("privileged") else f"{Fore.RED}Not configured{Style.RESET_ALL}"
            if not t["installed"]:
                caps = f"{Fore.YELLOW}N/A{Style.RESET_ALL}"
                sudoers = f"{Fore.YELLOW}N/A{Style.RESET_ALL}"
                priv = f"{Fore.YELLOW}Not installed{Style.RESET_ALL}"
            print(f"  {t['name']:<12} {installed:<22} {caps:<26} {sudoers:<22} {priv}")
        print()
        return

    # ---- SETUP / REMOVE need root ----
    if not _is_root():
        print(f"\n{Fore.RED}[!] This command must be run as root (use sudo).{Style.RESET_ALL}")
        print(f"    Run: {Fore.CYAN}sudo cygor setup-privileges{Style.RESET_ALL}")
        print()
        sys.exit(1)

    tools = _find_tools()
    username = force_user or os.environ.get("SUDO_USER") or getpass.getuser()

    # Check if any tools are installed
    installed_tools = [t for t in tools if t["installed"]]
    if not installed_tools:
        print(f"\n{Fore.YELLOW}[!] No scanning tools found (masscan, nmap, naabu).{Style.RESET_ALL}")
        print("    Install them first, then re-run this command.")
        return

    # ---- REMOVE ----
    if action == "remove":
        print(f"\n{Fore.CYAN}Removing Cygor scan privileges...{Style.RESET_ALL}\n")

        if method != "sudoers":
            for msg in remove_capabilities(tools):
                print(f"  {msg}")
        if method != "caps":
            for msg in remove_sudoers():
                print(f"  {msg}")

        print(f"\n{Fore.GREEN}Done.{Style.RESET_ALL}\n")
        return

    # ---- SETUP ----
    print(f"\n{Fore.CYAN}Setting up Cygor scan privileges...{Style.RESET_ALL}")
    print(f"  User: {username}")
    print(f"  Tools found: {', '.join(t['name'] for t in installed_tools)}")
    print()

    all_ok = True

    # Method 1: Linux capabilities (preferred — no sudo needed at runtime)
    if method != "sudoers":
        print(f"{Fore.CYAN}[1] Setting Linux capabilities (cap_net_raw, cap_net_admin)...{Style.RESET_ALL}")
        for msg in setup_capabilities(tools):
            print(f"    {msg}")
            if "[!]" in msg:
                all_ok = False
        print()

    # Method 2: sudoers NOPASSWD (fallback / additional)
    if method != "caps":
        print(f"{Fore.CYAN}[2] Configuring sudoers NOPASSWD entries...{Style.RESET_ALL}")
        for msg in setup_sudoers(tools, username):
            print(f"    {msg}")
            if "[!]" in msg:
                all_ok = False
        print()

    # Verify
    print(f"{Fore.CYAN}[3] Verifying configuration...{Style.RESET_ALL}")
    status = get_privilege_status()
    for t in status["tools"]:
        if not t["installed"]:
            continue
        if t["privileged"]:
            print(f"    {Fore.GREEN}[+] {t['name']}: ready{Style.RESET_ALL}")
        else:
            print(f"    {Fore.RED}[!] {t['name']}: NOT configured — may need manual setup{Style.RESET_ALL}")
            all_ok = False
    print()

    if all_ok:
        print(f"{Fore.GREEN}All scan tools are configured for non-interactive privilege escalation.{Style.RESET_ALL}")
        print(f"The Cygor web UI and daemon mode can now run scans without sudo prompts.")
    else:
        print(f"{Fore.YELLOW}Some tools may not be fully configured.{Style.RESET_ALL}")
        print(f"Run '{Fore.CYAN}cygor setup-privileges status{Style.RESET_ALL}' to check.")
    print()


def _print_help(Fore, Style):
    print(f"""
{Fore.CYAN}Cygor Setup Privileges{Style.RESET_ALL}

Configure the system so scanning tools (masscan, nmap, naabu) can run
without interactive sudo prompts. Required for web UI and daemon mode.

{Fore.CYAN}Usage:{Style.RESET_ALL}
  sudo cygor setup-privileges              Set up privileges (caps + sudoers)
  sudo cygor setup-privileges --caps-only  Only set Linux capabilities
  sudo cygor setup-privileges --sudoers-only  Only configure sudoers
  sudo cygor setup-privileges --user USER  Specify the user for sudoers entries
  sudo cygor setup-privileges remove       Remove all privilege configurations
  cygor setup-privileges status            Show current privilege status

{Fore.CYAN}Methods:{Style.RESET_ALL}
  Linux capabilities   setcap cap_net_raw,cap_net_admin on tool binaries.
                        Tools can then use raw sockets without any sudo.

  Sudoers NOPASSWD     Creates /etc/sudoers.d/cygor so the web UI can
                        run tools with sudo -n (non-interactive).

{Fore.CYAN}Examples:{Style.RESET_ALL}
  sudo cygor setup-privileges              # Full setup (recommended)
  sudo cygor setup-privileges status       # Check current state
  sudo cygor setup-privileges remove       # Undo all changes
""")
