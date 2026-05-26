"""
Shared helper functions for Cygor webapp routes.

Extracted from main.py - service normalization, OS bucketing, nmap parsing utilities.
"""

import gzip
import logging
import os
import re
import xml.etree.ElementTree as ET
from collections import namedtuple
from datetime import datetime, timezone, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

# -------- Service normalization --------
SERVICE_NAME_MAP = {
    "domain": "dns", "kerberos-sec": "kerberos", "ldapssl": "ldaps",
    "microsoft-ds": "smb", "netbios-ssn": "smb", "ms-wbt-server": "rdp",
    "epmap": "dcom", "http-alt": "http", "ssl/http": "https",
    "https-alt": "https", "http-proxy": "proxy", "ajp13": "ajp",
    "ajp12": "ajp", "ms-sql-s": "mssql", "ms-sql-m": "mssql",
    "mysqlx": "mysql", "postgresql": "postgres", "oracle-tns": "oracle",
    "redis": "redis", "smtp-submission": "smtp", "submission": "smtp",
    "pop3s": "pop3", "imaps": "imap", "vnc": "vnc",
    "pcanywheredata": "pcanywhere", "rpcbind": "rpc", "ipp": "cups",
    "upnp": "upnp", "mdns": "mdns", "snmptrap": "snmp", "snmp": "snmp",
}

def normalize_service(name: str | None) -> str:
    if not name:
        return "unknown"
    return SERVICE_NAME_MAP.get(name.lower(), name.lower())

# -------- OS Guess Helpers --------
def _bucket_family(guess) -> str:
    txt = " ".join([
        (guess.name or ""), (guess.family or ""),
        (guess.vendor or ""), (guess.type or "")
    ]).lower()

    if "windows" in txt or "microsoft" in txt: return "Windows"
    if "linux" in txt: return "Linux"
    if "android" in txt: return "Android"
    if "mac os" in txt or "macos" in txt or "apple" in txt or "os x" in txt: return "macOS"
    if any(x in txt for x in ["freebsd","openbsd","netbsd","solaris","unix"]): return "BSD/Unix"
    if any(x in txt for x in ["router","switch","ubiquiti","cisco","juniper","embedded","network device"]): return "Network Device"
    if any(x in txt for x in ["vmware","oracle vm","virtualbox","hyper-v","qemu","xen"]): return "Virtualization/Hypervisor"
    if any(x in txt for x in ["ios","ipad","iphone"]): return "iOS"
    if any(x in txt for x in ["printer","copier","hp","xerox","ricoh"]): return "Printer/Peripheral"
    if any(x in txt for x in ["specialized","appliance","control system","crestron","scada"]): return "Specialized Device"
    return "Other"

def _bucket_family_from_device_info(di) -> str:
    """Classify a DeviceInfo record into one of the 12 OS family buckets."""
    fam = (di.os_family or "").lower()
    if "windows" in fam or "microsoft" in fam: return "Windows"
    if "linux" in fam: return "Linux"
    if "android" in fam: return "Android"
    if "mac" in fam or "apple" in fam or "os x" in fam or "darwin" in fam: return "macOS"
    if any(x in fam for x in ["freebsd","openbsd","netbsd","solaris","unix","bsd"]): return "BSD/Unix"
    if any(x in fam for x in ["ios","ipad","iphone"]): return "iOS"

    dt = (di.device_type or "").lower()
    dc = (di.device_category or "").lower()
    mfr = (di.manufacturer or "").lower()
    combined = f"{dt} {dc} {mfr} {fam}"

    if any(x in combined for x in ["router","switch","firewall","access point","network device","cisco","juniper","ubiquiti","fortinet","paloalto"]): return "Network Device"
    if any(x in combined for x in ["vmware","virtualbox","hyper-v","qemu","xen","hypervisor","virtual"]): return "Virtualization/Hypervisor"
    if any(x in combined for x in ["printer","copier","xerox","ricoh","peripheral","mfp"]): return "Printer/Peripheral"
    if any(x in combined for x in ["specialized","appliance","scada","crestron","iot","plc","control system"]): return "Specialized Device"

    os_text = f"{di.os_full or ''} {di.inferred_os or ''} {di.nmap_os_raw or ''} {di.os_name or ''}".lower()
    if "windows" in os_text or "microsoft" in os_text: return "Windows"
    if "linux" in os_text: return "Linux"
    if "android" in os_text: return "Android"
    if any(x in os_text for x in ["mac os","macos","apple","os x","darwin"]): return "macOS"
    if any(x in os_text for x in ["freebsd","openbsd","netbsd","solaris","unix"]): return "BSD/Unix"

    if fam or os_text.strip(): return "Other"
    return ""

def _top_guess(host):
    if not host.os_guesses: return None
    return sorted(host.os_guesses, key=lambda g: (-int(g.accuracy or 0), len(g.name or "")))[0]

TopItem = namedtuple("TopItem", ["host", "guess"])

def _count_hosts_in_nmap_xml(path: Path) -> int:
    """Return number of <host> elements in an nmap XML file. Returns 0 on failure."""
    try:
        tree = ET.parse(path)
        root = tree.getroot()
        hosts = list(root.iter('host'))
        if hosts:
            return len(hosts)
        hosts = [el for el in root.iter() if isinstance(el.tag, str) and el.tag.endswith('host')]
        return len(hosts)
    except Exception:
        return 0

def _count_hosts_in_nmap_text(path: Path) -> int:
    """Try to extract host summary from an nmap textual file (best-effort)."""
    try:
        txt = path.read_text(errors="ignore")
        m2 = re.search(r"\((\d+)\s+hosts?\s+up\)", txt)
        if m2:
            return int(m2.group(1))
        m = re.search(r"Nmap done: .*?(\d+)\s+IP addresses", txt)
        if m:
            return int(m.group(1))
        count_hosts = len(re.findall(r"(?m)^Host:\s", txt))
        if count_hosts:
            return count_hosts
    except Exception:
        pass
    return 0

def _parse_nmap_xml_times(path: Path):
    """
    Read an Nmap XML file and return (start_iso, end_iso, host_count).
    """
    start_iso = None
    end_iso = None
    host_count = 1

    try:
        raw_text = ""
        try:
            if path.suffix.lower().endswith(".gz"):
                with gzip.open(path, "rt", errors="ignore") as fh:
                    raw_text = fh.read()
            else:
                raw_text = path.read_text(errors="ignore")
        except Exception:
            try:
                raw_text = path.read_bytes().decode("utf-8", errors="ignore")
            except Exception:
                raw_text = ""

        tree = None
        try:
            tree = ET.parse(path)
        except Exception:
            try:
                tree = ET.ElementTree(ET.fromstring(raw_text))
            except Exception:
                tree = None

        root = tree.getroot() if tree is not None else None

        def _find_tag_suffix(root_el, suffix):
            if root_el is None:
                return None
            if isinstance(root_el.tag, str) and root_el.tag.endswith(suffix):
                return root_el
            for el in root_el.iter():
                if isinstance(el.tag, str) and el.tag.endswith(suffix):
                    return el
            return None

        nmaprun_el = root if root is not None and root.tag.endswith("nmaprun") else _find_tag_suffix(root, "nmaprun")
        finished_el = _find_tag_suffix(root, "finished")
        hosts_el = _find_tag_suffix(root, "hosts")

        if nmaprun_el is not None:
            start_attr = nmaprun_el.attrib.get("start")
            startstr_attr = nmaprun_el.attrib.get("startstr")

            if start_attr:
                try:
                    start_dt = datetime.fromtimestamp(int(start_attr), tz=timezone.utc)
                    start_iso = start_dt.isoformat()
                except Exception:
                    start_iso = None

            if start_iso is None and startstr_attr:
                try:
                    start_dt = datetime.strptime(startstr_attr.strip(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                    start_iso = start_dt.isoformat()
                except Exception:
                    try:
                        start_dt = datetime.fromisoformat(startstr_attr)
                        if start_dt.tzinfo is None:
                            start_dt = start_dt.replace(tzinfo=timezone.utc)
                        start_iso = start_dt.isoformat()
                    except Exception:
                        start_iso = None

        if finished_el is not None:
            finished_time = finished_el.attrib.get("time")
            finished_timestr = finished_el.attrib.get("timestr")

            if finished_time:
                try:
                    if str(finished_time).isdigit():
                        end_dt = datetime.fromtimestamp(int(finished_time), tz=timezone.utc)
                    else:
                        end_dt = datetime.fromisoformat(finished_time)
                        if end_dt.tzinfo is None:
                            end_dt = end_dt.replace(tzinfo=timezone.utc)
                    end_iso = end_dt.isoformat()
                except Exception:
                    end_iso = None

            if end_iso is None and finished_timestr:
                try:
                    end_dt = datetime.strptime(finished_timestr.strip(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                    end_iso = end_dt.isoformat()
                except Exception:
                    try:
                        end_dt = datetime.fromisoformat(finished_timestr)
                        if end_dt.tzinfo is None:
                            end_dt = end_dt.replace(tzinfo=timezone.utc)
                        end_iso = end_dt.isoformat()
                    except Exception:
                        end_iso = None

        if hosts_el is not None:
            up = hosts_el.attrib.get("up")
            if up:
                try:
                    host_count = max(1, int(up))
                except Exception:
                    pass
        if host_count == 1 and root is not None:
            try:
                hosts = [el for el in root.iter() if isinstance(el.tag, str) and el.tag.endswith("host")]
                if hosts:
                    host_count = len(hosts)
            except Exception:
                pass

        if start_iso is None and raw_text:
            m = re.search(
                r"scan initiated\s+([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+as:",
                raw_text,
                re.I,
            )
            if m:
                ts = m.group(1).strip()
                try:
                    dt = datetime.strptime(ts, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                    start_iso = dt.isoformat()
                except Exception:
                    try:
                        dt = datetime.fromisoformat(ts)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        start_iso = dt.isoformat()
                    except Exception:
                        pass

        if start_iso is None and end_iso is not None:
            dt_end = datetime.fromisoformat(end_iso)
            start_iso = (dt_end - timedelta(seconds=60)).isoformat()

        if end_iso is None and start_iso is not None:
            dt_start = datetime.fromisoformat(start_iso)
            end_iso = (dt_start + timedelta(seconds=60)).isoformat()

        return start_iso, end_iso, host_count

    except Exception:
        return None, None, 1

def extract_host_key(label_or_path: str) -> str | None:
    """Extract an IP or base name from a scan label/path."""
    if not label_or_path:
        return None
    m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', label_or_path)
    if m:
        return m.group(1)
    base = os.path.basename(label_or_path)
    base = re.sub(r'\.(xml|nmap|gnmap|txt|gz)$', '', base, flags=re.I)
    return base or None

def gather_scan_times(results_dir: str):
    """
    Walk RESULTS_DIR/nmap and collect scan start/end times.
    Returns a list of dicts sorted by parsed start time (earliest first).
    """
    scans = []
    base = Path(results_dir) / "nmap"
    if not base.exists():
        logger.debug(f"[gather_scan_times] nmap directory does not exist: {base}")
        return scans

    logger.debug(f"[gather_scan_times] Scanning directory: {base}")

    for f in sorted(base.rglob("*")):
        if not f.is_file():
            continue

        parsed_start = None
        parsed_end = None
        host_count = 1

        try:
            if f.suffix.lower() == ".xml" or f.suffix.lower().endswith(".gz"):
                parsed_start, parsed_end, host_count = _parse_nmap_xml_times(f)
            else:
                txt = None
                try:
                    txt = f.read_text(errors="ignore")
                except Exception:
                    try:
                        txt = f.open('rb').read().decode('utf-8', errors='ignore')
                    except Exception:
                        txt = ''
                if txt:
                    m = re.search(r"^#?\s*Nmap scan initiated\s*:\s*(.+)$", txt, re.M | re.I)
                    if not m:
                        m = re.search(r"^#?\s*Nmap .* scan initiated\s*(.+)$", txt, re.M | re.I)
                    if m:
                        ts = m.group(1).strip()
                        try:
                            dt = datetime.fromisoformat(ts)
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            parsed_start = dt.isoformat()
                        except Exception:
                            try:
                                dt = datetime.strptime(ts, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                                parsed_start = dt.isoformat()
                            except Exception:
                                parsed_start = None

                    m2 = re.search(r"Nmap done at (.+); .* scanned in", txt)
                    if m2:
                        ts2 = m2.group(1).strip()
                        try:
                            dt2 = datetime.fromisoformat(ts2)
                            if dt2.tzinfo is None:
                                dt2 = dt2.replace(tzinfo=timezone.utc)
                            parsed_end = dt2.isoformat()
                        except Exception:
                            try:
                                dt2 = datetime.strptime(ts2, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                                parsed_end = dt2.isoformat()
                            except Exception:
                                parsed_end = None

                    m3 = re.search(r"\((\d+)\s+hosts?\s+up\)", txt)
                    if m3:
                        try:
                            host_count = int(m3.group(1))
                        except Exception:
                            pass

        except Exception:
            pass

        if parsed_start is None:
            parsed_start = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat()

        scans.append({
            "label": f.name,
            "path": str(f.relative_to(base.parent)),
            "start": parsed_start,
            "end": parsed_end,
            "host_count": host_count,
        })

    scans.sort(key=lambda s: _parse_iso_to_dt(s.get("start")))
    logger.debug(f"[gather_scan_times] Found {len(scans)} CLI scan files")
    return scans

def gather_ondemand_scan_times(results_dir: str):
    """
    Walk RESULTS_DIR/ondemand-scans and collect scan start/end times.
    """
    scans = []
    base = Path(results_dir) / "ondemand-scans"
    if not base.exists():
        return scans

    for scan_dir in sorted(base.iterdir()):
        if not scan_dir.is_dir():
            continue

        nmap_dir = scan_dir / "nmap"
        if not nmap_dir.exists():
            continue

        for f in sorted(nmap_dir.rglob("*")):
            if not f.is_file():
                continue

            parsed_start = None
            parsed_end = None
            host_count = 1

            try:
                if f.suffix.lower() == ".xml" or f.suffix.lower().endswith(".gz"):
                    parsed_start, parsed_end, host_count = _parse_nmap_xml_times(f)
                else:
                    txt = None
                    try:
                        txt = f.read_text(errors="ignore")
                    except Exception:
                        try:
                            txt = f.open('rb').read().decode('utf-8', errors='ignore')
                        except Exception:
                            txt = ''
                    if txt:
                        m = re.search(r"^#?\s*Nmap scan initiated\s*:\s*(.+)$", txt, re.M | re.I)
                        if not m:
                            m = re.search(r"^#?\s*Nmap .* scan initiated\s*(.+)$", txt, re.M | re.I)
                        if m:
                            ts = m.group(1).strip()
                            try:
                                dt = datetime.fromisoformat(ts)
                                if dt.tzinfo is None:
                                    dt = dt.replace(tzinfo=timezone.utc)
                                parsed_start = dt.isoformat()
                            except Exception:
                                try:
                                    dt = datetime.strptime(ts, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                                    parsed_start = dt.isoformat()
                                except Exception:
                                    parsed_start = None

                        m2 = re.search(r"Nmap done at (.+); .* scanned in", txt)
                        if m2:
                            ts2 = m2.group(1).strip()
                            try:
                                dt2 = datetime.fromisoformat(ts2)
                                if dt2.tzinfo is None:
                                    dt2 = dt2.replace(tzinfo=timezone.utc)
                                parsed_end = dt2.isoformat()
                            except Exception:
                                try:
                                    dt2 = datetime.strptime(ts2, "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                                    parsed_end = dt2.isoformat()
                                except Exception:
                                    parsed_end = None

                        m3 = re.search(r"\((\d+)\s+hosts?\s+up\)", txt)
                        if m3:
                            try:
                                host_count = int(m3.group(1))
                            except Exception:
                                pass

            except Exception:
                pass

            if parsed_start is None:
                parsed_start = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat()

            scans.append({
                "label": f"{scan_dir.name} - {f.name}",
                "path": str(f.relative_to(base.parent)),
                "start": parsed_start,
                "end": parsed_end,
                "host_count": host_count,
                "scan_dir": scan_dir.name,
            })

    scans.sort(key=lambda s: _parse_iso_to_dt(s.get("start")))
    return scans


def _parse_iso_to_dt(iso_str):
    """Safely parse an ISO datetime string to a timezone-aware datetime."""
    if not iso_str:
        return datetime.fromtimestamp(0, tz=timezone.utc)
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        try:
            s = iso_str.replace('Z', '')
            s = re.sub(r'(\.\d{3})\d+', r'\1', s)
            dt = datetime.fromisoformat(s)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return datetime.fromtimestamp(0, tz=timezone.utc)
