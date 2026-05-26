# cygor/precheck.py
from __future__ import annotations
import os, shutil, subprocess, sys
from pathlib import Path

SENTINEL = Path.home() / ".config" / "cygor" / "first_run_complete"

REQUIRED = ["nmap", "masscan", "psql", "git"]
NAABU = "naabu"  # handled specially
PY_PKGS = ["playwright"]

def run_once_precheck(force: bool = False) -> None:
    if SENTINEL.exists() and not force:
        return
    print("[*] Cygor: running one-time dependency precheck...")
    SENTINEL.parent.mkdir(parents=True, exist_ok=True)

    mgr, family = detect_pkg_mgr()
    if not mgr:
        print("[!] No supported package manager detected. Install deps manually.")
        finalize()
        return

    # install core CLI deps from repos
    missing = [b for b in REQUIRED if not which(b)]
    if missing:
        pkgs = map_packages(mgr, family, missing)
        install(mgr, pkgs)

    # naabu: repo if present, otherwise Go fallback
    if not which(NAABU):
        naabu_pkgs = map_packages(mgr, family, [NAABU])
        if naabu_pkgs:
            install(mgr, naabu_pkgs)
        if not which(NAABU):
            ensure_go(mgr, family)
            build_naabu_via_go()

    # playwright python pkg
    for mod in PY_PKGS:
        try:
            __import__(mod)
        except Exception:
            pip_install(mod)

    # playwright system deps + chromium
    install_playwright_bundle()

    finalize()
    print("[✓] Cygor precheck complete. Run 'cygor' to start.")

def finalize():
    try:
        SENTINEL.write_text("done\n", encoding="utf-8")
    except Exception:
        pass

def which(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def run(cmd, check=True):
    return subprocess.run(cmd, check=check)

def detect_pkg_mgr():
    for m, fam in (("apt-get","debian"), ("dnf","fedora"), ("yum","fedora"),
                   ("pacman","arch"), ("zypper","suse"), ("apk","alpine")):
        if which(m): return m, fam
    return None, None

def map_packages(mgr: str, family: str, bins: list[str]) -> list[str]:
    # sensible defaults, then family-specific overrides
    base = {
        "nmap": ["nmap"],
        "masscan": ["masscan"],
        "psql": ["postgresql-client"],  # overridden by family
        "git": ["git"],
        "naabu": ["naabu"],             # may be empty -> Go fallback
    }
    if family == "debian":
        base["psql"] = ["postgresql-client"]
        # Kali has naabu; Ubuntu might not. We’ll try; Go fallback will handle misses.
        base["naabu"] = ["naabu"]
    elif family == "fedora":
        base["psql"] = ["postgresql"]
        base["naabu"] = []             # not in main repos reliably
    elif family == "arch":
        base["psql"] = ["postgresql"]
        base["naabu"] = []             # AUR; use Go fallback
    elif family == "suse":
        base["psql"] = ["postgresql-client"]
        base["naabu"] = []
    elif family == "alpine":
        base["psql"] = ["postgresql15-client", "postgresql-client"]
        base["naabu"] = []

    pkgs: list[str] = []
    for b in bins:
        pkgs += base.get(b, [b])
    # dedupe, keep order
    out, seen = [], set()
    for p in pkgs:
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    return out

def sudo_prefix() -> list[str]:
    if os.geteuid() == 0:
        return []
    if which("sudo"):
        try:
            run(["sudo", "-v"], check=True)
            return ["sudo"]
        except subprocess.CalledProcessError:
            print("[!] sudo auth failed; proceeding without escalation.")
    return []

def install(mgr: str, pkgs: list[str]) -> None:
    if not pkgs:
        return
    s = sudo_prefix()
    try:
        if mgr == "apt-get":
            run(s + ["apt-get", "update"])
            run(s + ["apt-get", "install", "-y"] + pkgs, check=False)
        elif mgr in ("dnf","yum"):
            run(s + [mgr, "install", "-y"] + pkgs, check=False)
        elif mgr == "pacman":
            run(s + ["pacman", "-Sy", "--noconfirm"] + pkgs, check=False)
        elif mgr == "zypper":
            run(s + ["zypper", "--non-interactive", "install"] + pkgs, check=False)
        elif mgr == "apk":
            run(s + ["apk", "add"] + pkgs, check=False)
        else:
            print(f"[!] Unsupported package manager '{mgr}'.")
    except Exception as e:
        print(f"[!] Package install error: {e}")

def ensure_go(mgr: str, family: str) -> None:
    if which("go"):
        return
    go_pkg = {"debian":["golang"], "fedora":["golang"], "arch":["go"], "suse":["go"], "alpine":["go"]}.get(family, ["golang"])
    print("[*] Installing Go toolchain for naabu build...")
    install(mgr, go_pkg)

def build_naabu_via_go() -> None:
    try:
        print("[*] Building naabu from source (Go)...")
        # v2 path; installs into GOPATH/bin
        run(["bash","-lc","GO111MODULE=on go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"], check=False)
        if which("naabu"):
            return
        # advise on PATH if needed
        gopath = subprocess.check_output(["bash","-lc","go env GOPATH"], text=True).strip()
        binpath = str(Path(gopath)/"bin")
        if binpath not in os.environ.get("PATH",""):
            print(f"[i] Add {binpath} to PATH to use 'naabu'.")
    except Exception as e:
        print(f"[!] naabu build failed: {e}")

def pip_install(pkg: str) -> None:
    try:
        run([sys.executable, "-m", "pip", "install", "--upgrade", pkg], check=False)
    except Exception as e:
        print(f"[!] pip install failed for {pkg}: {e}")

def install_playwright_bundle() -> None:
    """
    Install Playwright Chromium browser and its dependencies.
    Adds specific Debian/Kali/Ubuntu dependency installs instead of
    the generic Playwright install-deps list.
    """
    try:
        cmd = [sys.executable, "-m", "playwright"]
        s = sudo_prefix()

        distro = "unknown"
        try:
            with open("/etc/os-release", "r", encoding="utf-8") as f:
                data = f.read().lower()
                if "kali" in data:
                    distro = "kali"
                elif "debian" in data:
                    distro = "debian"
                elif "ubuntu" in data:
                    distro = "ubuntu"
                elif "fedora" in data:
                    distro = "fedora"
                elif "arch" in data:
                    distro = "arch"
                elif "suse" in data:
                    distro = "suse"
                elif "alpine" in data:
                    distro = "alpine"
        except Exception:
            pass

        # --- Debian-family specific dependencies ---
        if distro in ("debian", "ubuntu", "kali"):
            print(f"[*] Installing Playwright dependencies for {distro}...")
            pkgs = ["libasound2t64", "fonts-unifont"]
            try:
                run(s + ["apt-get", "update"], check=False)
                run(s + ["apt-get", "install", "-y"] + pkgs, check=False)
            except Exception as e:
                print(f"[!] Could not install {pkgs}: {e}")
        else:
            print(f"[*] Installing Playwright system dependencies for {distro}...")
            run(s + ["bash", "-lc", f"{' '.join(cmd)} install-deps"], check=False)

        print("[*] Installing Playwright Chromium browser...")
        run(["bash", "-lc", f"{' '.join(cmd)} install chromium"], check=False)

    except Exception as e:
        print(f"[!] Playwright setup skipped: {e}")


