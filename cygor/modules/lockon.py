#!/usr/bin/env python3
import csv
import os
import sys
import argparse
import shutil
import asyncio
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from subprocess import run, PIPE, TimeoutExpired
from pathlib import Path
from typing import Iterable, List, Tuple

import json
import re
import requests
from requests.exceptions import RequestException, ConnectionError, HTTPError
import xml.etree.ElementTree as ET
from colorama import init, Fore, Style
from playwright.async_api import async_playwright

# ----------------------------------------------------------------------
# Init
# ----------------------------------------------------------------------
init(autoreset=True)
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

MAX_RETRIES = 3
RETRY_DELAY = 2  # seconds

# ----------------------------------------------------------------------
# Status code color mapping
# ----------------------------------------------------------------------
def _color_for_status(code: int) -> str:
    if code is None or code < 0:
        return Fore.MAGENTA
    if 200 <= code < 300:
        return Fore.GREEN
    elif 300 <= code < 400:
        return Fore.CYAN
    elif 400 <= code < 500:
        return Fore.YELLOW
    elif 500 <= code < 600:
        return Fore.RED
    else:
        return Fore.MAGENTA

# global print lock
_print_lock = threading.Lock()

def _print_status(tag: str, url: str, code: int):
    """Pretty-print status lines aligned across threads, thread-safe."""
    color = _color_for_status(code)
    tag_fmt = f"[{tag}]".ljust(7)        # e.g. "[LIVE]" padded
    url_fmt = url.ljust(65)              # URL column
    code_fmt = f"(status={code})".ljust(14)
    line = f"{tag_fmt} {url_fmt} {code_fmt}"
    with _print_lock:
        print(color + line + Style.RESET_ALL, flush=True)

# ----------------------------------------------------------------------
# Output Formats
# ----------------------------------------------------------------------
def save_as_txt(results, path: Path):
    with open(path, "w", encoding="utf-8") as f:
        for r in results:
            f.write(f"{r['url']} (status={r['status_code']}) -> {r['screenshot_file']}\n")

def save_as_csv(results, path: Path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url","status_code","screenshot_file","screenshot_failed"])
        writer.writeheader()
        writer.writerows(results)

def save_as_xml(results, path: Path):
    root = ET.Element("LockonResults")
    for r in results:
        entry = ET.SubElement(root, "Result")
        ET.SubElement(entry, "URL").text = r["url"]
        ET.SubElement(entry, "StatusCode").text = str(r["status_code"])
        ET.SubElement(entry, "ScreenshotFile").text = r["screenshot_file"]
        ET.SubElement(entry, "ScreenshotFailed").text = str(r["screenshot_failed"])
    ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)

# ----------------------------------------------------------------------
# Playwright readiness / install / uninstall
# ----------------------------------------------------------------------
def _is_debian_like() -> bool:
    try:
        data = Path("/etc/os-release").read_text().lower()
        return any(x in data for x in ("debian", "ubuntu", "kali", "linuxmint"))
    except Exception:
        return False

def _playwright_bin() -> str:
    exe = shutil.which("playwright")
    if exe:
        return exe
    return f"{sys.executable} -m playwright"

async def _try_launch_chromium_quick_async() -> bool:
    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--ignore-certificate-errors"],
            )
            await browser.close()
        return True
    except Exception:
        return False

def _print_kali_debian_instructions():
    pw = _playwright_bin()
    print(Fore.YELLOW + "[!] Playwright Chromium not installed or system deps missing." + Style.RESET_ALL)
    print(Fore.CYAN + "    On Kali/Debian, run once:" + Style.RESET_ALL)
    if os.geteuid() == 0:
        print(f"      {pw} install --with-deps chromium")
    else:
        print(f"      sudo {pw} install --with-deps chromium")

def _attempt_install_browsers(auto_with_deps: bool, timeout_sec: int = 1200) -> bool:
    pw = _playwright_bin()
    if auto_with_deps and _is_debian_like():
        if os.geteuid() == 0:
            cmd = f"{pw} install --with-deps chromium"
        else:
            cmd = f"sudo -n {pw} install --with-deps chromium || {pw} install chromium"
    else:
        cmd = f"{pw} install chromium"

    print(Fore.CYAN + f"[*] Attempting Playwright install: {cmd}" + Style.RESET_ALL)
    try:
        proc = run(cmd, shell=True, stdout=PIPE, stderr=PIPE, text=True, timeout=timeout_sec)
        if proc.returncode == 0:
            print(Fore.GREEN + "[+] Playwright install completed." + Style.RESET_ALL)
            return True
        print(Fore.RED + f"[!] Playwright install failed (rc={proc.returncode})." + Style.RESET_ALL)
        return False
    except TimeoutExpired:
        print(Fore.RED + "[!] Playwright install timed out." + Style.RESET_ALL)
        return False
    except Exception as e:
        print(Fore.RED + f"[!] Error during Playwright install: {e}" + Style.RESET_ALL)
        return False


def _fmt_bytes(n: int) -> str:
    units = ["B","KB","MB","GB","TB"]
    i = 0
    val = float(n)
    while val >= 1024 and i < len(units)-1:
        val /= 1024.0
        i += 1
    return f"{val:.2f} {units[i]}"

def _dir_size(path: Path) -> int:
    total = 0
    try:
        for root, dirs, files in os.walk(path):
            for f in files:
                try:
                    total += (Path(root) / f).stat().st_size
                except Exception:
                    pass
    except Exception:
        pass
    return total

def _collect_playwright_cache_paths() -> List[Path]:
    paths: List[Path] = []
    env_path = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env_path:
        p = Path(env_path).expanduser()
        if str(p).strip():
            paths.append(p)

    home = Path.home()
    # Common locations across platforms
    paths.append(home / ".cache" / "ms-playwright")                 # Linux default
    paths.append(home / "Library" / "Caches" / "ms-playwright")    # macOS default
    localapp = os.environ.get("LOCALAPPDATA")
    if localapp:
        paths.append(Path(localapp) / "ms-playwright")             # Windows default

    # Deduplicate while preserving order
    seen = set()
    out: List[Path] = []
    for p in paths:
        if p and str(p) not in seen:
            seen.add(str(p))
            out.append(p)
    return out

def _attempt_uninstall_browsers(timeout_sec: int = 1200) -> Tuple[bool, int, List[Path]]:
    """
    Try a CLI uninstall first (if supported), then remove cache dirs.
    Returns (success, bytes_freed, removed_paths)
    """
    removed_paths: List[Path] = []
    bytes_before = 0
    bytes_after = 0

    pw = _playwright_bin()
    cli_cmd = f"{pw} uninstall chromium"
    print(Fore.CYAN + f"[*] Attempting Playwright uninstall: {cli_cmd}" + Style.RESET_ALL)
    try:
        proc = run(cli_cmd, shell=True, stdout=PIPE, stderr=PIPE, text=True, timeout=timeout_sec)
        if proc.returncode == 0:
            print(Fore.GREEN + "[+] Playwright CLI uninstall reported success." + Style.RESET_ALL)
        else:
            # Many versions of Playwright don't support 'uninstall'; that's fine.
            print(Fore.YELLOW + "[~] CLI uninstall not supported or failed; falling back to cache removal." + Style.RESET_ALL)
    except Exception:
        print(Fore.YELLOW + "[~] CLI uninstall failed; falling back to cache removal." + Style.RESET_ALL)

    # Remove caches
    cache_paths = _collect_playwright_cache_paths()
    for p in cache_paths:
        if p.exists():
            size = _dir_size(p)
            bytes_before += size
            try:
                shutil.rmtree(p, ignore_errors=True)
                removed_paths.append(p)
            except Exception as e:
                print(Fore.RED + f"[!] Failed to remove {p}: {e}" + Style.RESET_ALL)

    # Recheck remaining size (should be ~0 for removed paths)
    for p in cache_paths:
        if p.exists():
            bytes_after += _dir_size(p)

    freed = max(0, bytes_before - bytes_after)
    success = freed > 0 or len(removed_paths) > 0
    return success, freed, removed_paths

async def ensure_playwright_ready_async(install_browsers: bool = False) -> bool:
    if await _try_launch_chromium_quick_async():
        return True
    auto_env = os.environ.get("CYGOR_PW_AUTO_INSTALL", "").strip().lower() in ("1","true","yes")
    auto_with_deps = os.environ.get("CYGOR_PLAYWRIGHT_WITH_DEPS","").strip().lower() in ("1","true","yes")
    want_auto = install_browsers or auto_env
    if not want_auto:
        _print_kali_debian_instructions()
        print(Fore.YELLOW + "[i] Continuing: HTTP/HTTPS tests run; screenshots skipped if browser unavailable." + Style.RESET_ALL)
        return False
    ok = _attempt_install_browsers(auto_with_deps=auto_with_deps)
    if not ok:
        _print_kali_debian_instructions()
        return await _try_launch_chromium_quick_async()
    return await _try_launch_chromium_quick_async()

# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
from argparse import RawTextHelpFormatter
class ColorHelpFormatter(RawTextHelpFormatter, argparse.ArgumentDefaultsHelpFormatter):
    def start_section(self, heading):
        heading = f"{Fore.CYAN}{heading}{Style.RESET_ALL}"
        super().start_section(heading)
    def _format_action_invocation(self, action):
        parts = super()._format_action_invocation(action)
        return f"{Fore.YELLOW}{parts}{Style.RESET_ALL}"

examples = f"""
   {Fore.MAGENTA}Examples:{Style.RESET_ALL}

    {Fore.YELLOW}# Run lockon against a host list (mixed IPs + URLs){Style.RESET_ALL}
    cygor enum lockon -f scope.txt

    {Fore.YELLOW}# Run lockon with explicit IPs and save to custom output dir{Style.RESET_ALL}
    cygor enum lockon --ips 10.10.10.5:80 10.10.10.6:443 -o results/cygor-enumeration-modules/lockon

    {Fore.YELLOW}# Provide full URLs directly{Style.RESET_ALL}
    cygor enum lockon --url https://example.com http://test.local

    {Fore.YELLOW}# Screenshot only specific status codes{Style.RESET_ALL}
    cygor enum lockon -f scope.txt --status-filter 200 403

    {Fore.YELLOW}# Screenshot all sites regardless of status{Fore.RED} (may be noisy){Style.RESET_ALL}
    cygor enum lockon -f scope.txt --status-filter 0

    {Fore.YELLOW}# Screenshot with custom timeouts; save all output formats{Style.RESET_ALL}
    cygor enum lockon -f scope.txt --workers 16 --http-timeout 10 --nav-timeout 50000 --extra-wait 3000 --status-filter 0 --output-format all

    {Fore.YELLOW}# Install Playwright Chromium (and deps on Debian-like){Style.RESET_ALL}
    cygor enum lockon -f scope.txt --install-browsers

    {Fore.YELLOW}# Uninstall Playwright browser binaries for this user and exit{Style.RESET_ALL}
    cygor enum lockon --uninstall-browsers
"""

def parse_arguments():
    banner = f"""
    {Fore.GREEN}{'='*60}
      CYGOR LOCKON - Web Service Screenshot & Discovery
    {Fore.GREEN}{'='*60}{Style.RESET_ALL}
    """
    p = argparse.ArgumentParser(
        prog="cygor enum lockon",
        usage="cygor enum lockon [options]",
        description=banner + "\nCapture screenshots of HTTP/HTTPS services.\n",
        epilog=examples,
        formatter_class=ColorHelpFormatter,
    )
    io_group = p.add_argument_group("Input/Output")
    io_group.add_argument('-f','--file', help="Path to host list file (mix of host:port and/or full URLs).")
    io_group.add_argument('--ips', nargs='+', help="List of IPs/host:port entries.")
    io_group.add_argument('--url', nargs='+', help="Full URLs or bare host entries.")
    io_group.add_argument('-o','--output', default=None, help="Custom output directory (overrides workspace if set).")
    io_group.add_argument("--output-format", choices=["json","xml","csv","txt","all"], default="json",
                          help="Save results in this format (default: json). Use 'all' to save every format.")
    io_group.add_argument('--scheme', choices=['http','https','both'], default='both',
        help="Scheme(s) for bare hosts (default: both).")

    # concurrency
    default_workers = min(32,(os.cpu_count() or 4)*4)
    conc = p.add_argument_group("Concurrency")
    conc.add_argument('--workers', type=int, default=default_workers)
    conc.add_argument('--scan-workers', type=int)
    conc.add_argument('--shot-workers', type=int)

    # tuning
    tune = p.add_argument_group("Timeouts/Tuning")
    tune.add_argument('--http-timeout', type=float, default=5.0, help="HTTP connect/read timeout (s).")
    tune.add_argument('--nav-timeout', type=int, default=45000,
                      help="Playwright page.goto timeout (ms). Default: 45000 (45s).")
    tune.add_argument('--viewport', default="1366x768", help="Viewport WxH, e.g. 1366x768.")
    tune.add_argument('--extra-wait', type=int, default=2000,
                      help="Extra wait after load before screenshot (ms). Default: 2000ms")

    # filtering
    filt = p.add_argument_group("Filtering")
    filt.add_argument("--status-filter", nargs="+", type=int, default=[200,301,302,307,308],
                      help="List of status codes to capture screenshots for (default: 200,301,302,307,308). "
                           "Use 0 to capture all statuses.")

    # browser setup (explicit flags; mutually exclusive handled below)
    setup = p.add_argument_group("Browser Setup")
    setup.add_argument('--install-browsers', action='store_true',
                       help="Attempt to install Playwright Chromium for screenshots.")
    setup.add_argument('--uninstall-browsers', action='store_true',
                       help="Remove Playwright browser binaries/cache for this user and exit.")

    args = p.parse_args()

    # Require targets unless doing maintenance (install/uninstall)
    if not (args.install_browsers or args.uninstall_browsers) and not (args.file or args.ips or args.url):
        p.error("Specify -f, --ips, or --url. (Or use --install-browsers/--uninstall-browsers for maintenance only.)")


    # Prevent contradictory usage
    if args.install_browsers and args.uninstall_browsers:
        p.error("Cannot use --install-browsers and --uninstall-browsers together.")

    return args

# ----------------------------------------------------------------------
# Input parsing helpers
# ----------------------------------------------------------------------
def _is_full_url(s: str) -> bool:
    return s.lower().startswith("http://") or s.lower().startswith("https://")

def _expand_url_entries(entries: List[str], scheme_setting: str) -> List[str]:
    out=[]
    for e in entries:
        e=e.strip()
        if not e: continue
        if _is_full_url(e):
            out.append(e); continue
        if scheme_setting=="both":
            out.append(f"http://{e}")
            out.append(f"https://{e}")
        else:
            out.append(f"{scheme_setting}://{e}")
    return out

def read_targets(file: str) -> Tuple[List[str], List[str]]:
    print(Fore.YELLOW + f"[*] Reading targets from: {file}\n" + Style.RESET_ALL)
    hosts, urls = [], []
    if not file: return hosts, urls
    path=Path(file)
    if not path.is_file():
        print(Fore.RED+f"File not found: {file}")
        return hosts, urls
    for line in path.read_text().splitlines():
        line=line.strip()
        if not line: continue
        if _is_full_url(line):
            urls.append(line)
        else:
            hosts.append(line)
    print(Fore.BLUE + "[*] Targets analyzed. Initating Lockon sequence for stage 1 reachability\n"  + Style.RESET_ALL)
    return hosts, urls

# ----------------------------------------------------------------------
# Stage 1: reachability
# ----------------------------------------------------------------------
def _test_one_target(target: str, schemes: List[str], timeout: float) -> List[Tuple[str,int]]:
    results=[]
    with requests.Session() as session:
        session.verify=False
        for scheme in schemes:
            url=f"{scheme}://{target}"
            retries=0
            while retries<MAX_RETRIES:
                try:
                    r=session.get(url,timeout=timeout)
                    code = r.status_code
                    _print_status("LIVE", url, code)
                    results.append((url, code))
                    break
                except (RequestException,ConnectionError):
                    retries+=1
                    if retries<MAX_RETRIES: time.sleep(RETRY_DELAY)
                except HTTPError as e:
                    code = getattr(e.response,"status_code",0)
                    _print_status("LIVE", url, code)
                    results.append((url, code))
                    break
                except Exception as e:
                    print(Fore.RED+f"[!] Error {url}: {e}")
                    results.append((url,-1))
                    break
    return results

def stage1_discover_urls(targets: Iterable[str], schemes: List[str], timeout: float, workers: int) -> List[Tuple[str,int]]:
    results=[]
    with ThreadPoolExecutor(max_workers=max(1,workers)) as pool:
        futs={pool.submit(_test_one_target,t,schemes,timeout):t for t in targets}
        for fut in as_completed(futs):
            try: results.extend(fut.result())
            except Exception as e:
                print(Fore.RED+f"[!] worker error on {futs[fut]}: {e}")
    seen=set(); dedup=[]
    for u,code in results:
        if u not in seen:
            seen.add(u)
            dedup.append((u,code))
    return dedup

# ----------------------------------------------------------------------
# Stage 2: screenshots
# ----------------------------------------------------------------------
def _parse_viewport(v:str)->Tuple[int,int]:
    try: w,h=v.lower().split("x"); return int(w),int(h)
    except: return (1366,768)

_SANITIZE_RE=re.compile(r'[^A-Za-z0-9._-]')
def _sanitize_filename(s:str)->str:
    s=s.replace("://","_").replace("/","_").replace(":","_").replace("?","_").replace("&","_")
    return _SANITIZE_RE.sub("_",s)[:200]

async def _shot_one(page,url:str,path:Path,nav_timeout:int,extra_wait:int):
    page.set_default_navigation_timeout(nav_timeout)
    await page.goto(url, wait_until="load")
    if extra_wait > 0:
        await page.wait_for_timeout(extra_wait)
    await page.screenshot(path=str(path), full_page=True)

async def stage2_screenshots(urls:List[str],out_dir:Path,workers:int,
                             nav_timeout:int,viewport:str,browser_ready:bool,
                             extra_wait:int)->Tuple[int,int]:
    shots=out_dir/"screenshots"; shots.mkdir(parents=True,exist_ok=True)
    if not browser_ready:
        for u in urls: print(Fore.YELLOW+f"[~] Skipping screenshot: {u}")
        return (0,len(urls))
    w,h=_parse_viewport(viewport); sem=asyncio.Semaphore(max(1,workers))
    succ,fail=0,0
    async with async_playwright() as p:
        browser=await p.chromium.launch(headless=True,
            args=["--ignore-certificate-errors","--no-sandbox","--disable-setuid-sandbox"])
        ctx=await browser.new_context(viewport={"width":w,"height":h})
        async def worker(u):
            nonlocal succ,fail
            name=_sanitize_filename(u); path=shots/f"{name}.png"
            async with sem:
                pg=await ctx.new_page()
                try:
                    await _shot_one(pg,u,path,nav_timeout,extra_wait)
                    print(Fore.GREEN+f"[+] Screenshot saved for {u:<60} -> {path}")
                    succ+=1
                except Exception as e:
                    print(Fore.RED+f"[!] Screenshot failed for {u:<60}: {e}")
                    fail+=1
                finally: await pg.close()
        await asyncio.gather(*(worker(u) for u in urls))
        await ctx.close(); await browser.close()
    return (succ,fail)

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def _fmt_secs(sec:float)->str:
    if sec<1: return f"{sec*1000:.0f} ms"
    if sec<60: return f"{sec:.2f} s"
    m,s=divmod(sec,60)
    if m<60: return f"{int(m)}m {s:.1f}s"
    h,m=divmod(m,60); return f"{int(h)}h {int(m)}m {s:.0f}s"

async def amain():
    args=parse_arguments()

    # Maintenance mode: uninstall browsers and exit
    if args.uninstall_browsers:
        ok, freed, removed = _attempt_uninstall_browsers()
        if removed:
            print(Fore.CYAN + "\n[+] Removed the following Playwright cache directories:" + Style.RESET_ALL)
            for p in removed:
                print(f"    - {p}")
        if freed:
            print(Fore.GREEN + f"[+] Estimated disk space freed: {_fmt_bytes(freed)}" + Style.RESET_ALL)
        if not ok:
            print(Fore.YELLOW + "[~] Nothing to remove or uninstall failed." + Style.RESET_ALL)
        print(Fore.BLUE + "[i] Note: This does not uninstall the Python package 'playwright'. Use 'pip uninstall playwright' to remove it." + Style.RESET_ALL)
        return

    # Maintenance mode: install browsers and exit
    if args.install_browsers and not (args.file or args.ips or args.url):
        print(Fore.CYAN + "[*] Installing Playwright browsers..." + Style.RESET_ALL)
        _attempt_install_browsers(auto_with_deps=_is_debian_like())
        return


    scan_workers=args.scan_workers if args.scan_workers else args.workers
    shot_workers=args.shot_workers if args.shot_workers else args.workers
    # Resolve output directory:
    # Priority:
    # 1) explicit CLI arg `--output`
    # 2) workspace environment variable CYGOR_RESULTS_DIR
    # 3) default results directory
    env_ws = os.environ.get("CYGOR_RESULTS_DIR")

    if args.output:
        out_dir = Path(args.output)
    elif env_ws:
        # Workspace-aware path (no nested "results/")
        out_dir = Path(env_ws) / "cygor-enumeration-modules" / "lockon"
    else:
        out_dir = Path("results") / "cygor-enumeration-modules" / "lockon"

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "screenshots").mkdir(exist_ok=True)
    print(Fore.CYAN + f"[*] Output directory: {out_dir}" + Style.RESET_ALL)


    out_list=out_dir/"tested-urls.txt"
    schemes=["http","https"] if args.scheme=="both" else [args.scheme]

    # Parse inputs
    file_hosts,file_urls=read_targets(args.file) if args.file else ([],[])
    ip_targets=args.ips or []
    cli_urls=_expand_url_entries(args.url or [],args.scheme)
    targets=file_hosts+ip_targets
    expanded_urls=cli_urls+file_urls

    if not targets and not expanded_urls:
        print(Fore.RED+"No valid targets found."); return

    t0_total=time.perf_counter()
    browser_ready=await ensure_playwright_ready_async(install_browsers=args.install_browsers)

    t0_scan=time.perf_counter()
    discovered=stage1_discover_urls(targets,schemes,args.http_timeout,scan_workers) if targets else []
    t1_scan=time.perf_counter()

    # Combine discovered + expanded
    combined=[(u,code) for u,code in discovered]

    for u in expanded_urls:
        code = None
        try:
            r = requests.get(u, timeout=args.http_timeout, verify=False)
            code = r.status_code
        except Exception:
            code = -1
        _print_status("PROBE", u, code)
        combined.append((u, code))

    # Deduplicate
    seen=set(); final=[]
    for u,code in combined:
        if u not in seen:
            seen.add(u)
            final.append((u,code))

    # Apply status filter
    if args.status_filter != [0]:
        final=[(u,code) for u,code in final if (code in args.status_filter) or (code is None)]

    if not final:
        print(Fore.RED+"No URLs after expansion/discovery and filtering."); return

    out_list.write_text("\n".join([u for u,_ in final])+"\n",encoding="utf-8")

    print(Fore.BLUE+"[+] Stage 1 Complete. Initating Stage 2 Lockon sequence to gather screenshots of active URLs\n")
    t0_shot=time.perf_counter()
    urls_only=[u for u,_ in final]
    succ,fail=await stage2_screenshots(urls_only,out_dir,shot_workers,
                                      args.nav_timeout,args.viewport,
                                      browser_ready,args.extra_wait)
    t1_shot=time.perf_counter(); t1_total=time.perf_counter()

    # Build JSON results
    results = []
    for u, code in final:
        shot_file = f"{_sanitize_filename(u)}.png"
        full_path = out_dir / "screenshots" / shot_file
        results.append({
            "url": u,
            "status_code": code,
            "screenshot_file": shot_file,
            "screenshot_failed": not full_path.exists()
        })

    # Final summary table
    print(Style.BRIGHT+Fore.CYAN+"\n========== URL Summary =========="+Style.RESET_ALL)
    for r in results:
        code = r["status_code"]
        color = _color_for_status(code)
        status = "OK" if not r["screenshot_failed"] else "FAIL"
        print(color + f"{r['url']:50} ({code}) -> {status:4}  {r['screenshot_file']}" + Style.RESET_ALL)
    print(Style.BRIGHT+Fore.CYAN+"=================================\n"+Style.RESET_ALL)

    # Status code breakdown
    codes = [r["status_code"] for r in results if isinstance(r["status_code"], int)]
    count_2xx = sum(1 for c in codes if 200 <= c < 300)
    count_3xx = sum(1 for c in codes if 300 <= c < 400)
    count_4xx = sum(1 for c in codes if 400 <= c < 500)
    count_5xx = sum(1 for c in codes if 500 <= c < 600)
    count_other = sum(1 for c in codes if c < 200 or c >= 600)

    print(Style.BRIGHT+Fore.CYAN+"========== Status Code Summary =========="+Style.RESET_ALL)
    print(Fore.GREEN   + f"2xx Success      : {count_2xx}" + Style.RESET_ALL)
    print(Fore.CYAN    + f"3xx Redirects    : {count_3xx}" + Style.RESET_ALL)
    print(Fore.YELLOW  + f"4xx Client Error : {count_4xx}" + Style.RESET_ALL)
    print(Fore.RED     + f"5xx Server Error : {count_5xx}" + Style.RESET_ALL)
    print(Fore.MAGENTA + f"Other/Unknown    : {count_other}" + Style.RESET_ALL)
    print(Style.BRIGHT+Fore.CYAN+"========================================="+Style.RESET_ALL)

    # Timing summary
    print(Style.BRIGHT+Fore.CYAN+"========== Timing Summary =========="+Style.RESET_ALL)
    print(f"Targets provided       : {len(file_hosts)+len(ip_targets)+(len(args.url or []))}")
    print(f"Live URLs discovered   : {len(final)}")
    print(f"Stage 1 (reachability) : {_fmt_secs(t1_scan-t0_scan)}")
    print(f"Stage 2 (screenshots)  : {_fmt_secs(t1_shot-t0_shot)} | Success: {succ} Fail: {fail}")
    print(f"Total time             : {_fmt_secs(t1_total-t0_total)}")
    print(Style.BRIGHT+Fore.CYAN+"===================================="+Style.RESET_ALL)

    # ------------------------------------------------------------------
    # Save results AFTER summaries
    # ------------------------------------------------------------------
    # Always save tested-urls.txt
    out_list.write_text("\n".join([u for u,_ in final])+"\n", encoding="utf-8")
    print(Fore.CYAN + f"\n[+] URLs saved -> {out_list}" + Style.RESET_ALL)

    # Always save JSON
    json_path = out_dir / "lockon-results.json"
    json_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(Fore.CYAN + f"[+] JSON results saved -> {json_path}" + Style.RESET_ALL)

    # Save optional formats
    if args.output_format in ("txt", "all"):
        save_as_txt(results, out_dir / "lockon-results.txt")
        print(Fore.CYAN + f"[+] TXT results saved -> {out_dir/'lockon-results.txt'}" + Style.RESET_ALL)

    if args.output_format in ("csv", "all"):
        save_as_csv(results, out_dir / "lockon-results.csv")
        print(Fore.CYAN + f"[+] CSV results saved -> {out_dir/'lockon-results.csv'}" + Style.RESET_ALL)

    if args.output_format in ("xml", "all"):
        save_as_xml(results, out_dir / "lockon-results.xml")
        print(Fore.CYAN + f"[+] XML results saved -> {out_dir/'lockon-results.xml'}" + Style.RESET_ALL)

def main():
    try: asyncio.run(amain())
    except KeyboardInterrupt: print("\n[!] Interrupted by user")

if __name__=="__main__":
    main()
