# modules/ftpexplorer.py
"""
FTP Explorer — Enumerate FTP services discovered across scans.

Drop this file into `cygor/modules/` and restart Cygor Web.
A new page will appear automatically at: /modules/ftpexplorer

This module aggregates FTP service information from:
  - results/cygor-enumeration-modules/ftpexplorer/*.json
  - results/nmap/*.xml (parses port 21 entries and ftp-anon scripts)
  - results/naabu/*.txt (fallback detection of port 21)

Output is normalized into table rows:
  IP | Port | Service | Banner | Anonymous | Source
"""

module_info = {
    "name": "FTP Explorer",
    "slug": "ftpexplorer",
    "description": "Enumerates FTP services discovered across Nmap, Naabu, or module outputs.",
    "author": "tjnull",
    "version": "1.0",
    "view": "table",
    "table": {
        "columns": [
            {"key": "ip", "label": "IP"},
            {"key": "port", "label": "Port"},
            {"key": "service", "label": "Service"},
            {"key": "banner", "label": "Banner / Product"},
            {"key": "anonymous", "label": "Anonymous OK"},
            {"key": "source", "label": "Source"},
        ]
    },
}

from pathlib import Path
import json
import xml.etree.ElementTree as ET
import re


def _resolve_results_dir():
    """Prefer Cygor’s settings.RESULTS_DIR if available, else ./results."""
    try:
        from cygor.config import settings  # type: ignore
        return Path(settings.RESULTS_DIR)
    except Exception:
        return Path.cwd() / "results"


def _parse_json_dir(path: Path):
    """Load any JSON results for FTP enumeration."""
    rows = []
    if not path.exists():
        return rows

    for file in sorted(path.glob("*.json")):
        try:
            data = json.loads(file.read_text())
        except Exception:
            continue

        if isinstance(data, dict):
            data = [data]

        for entry in data:
            ip = entry.get("ip") or entry.get("host") or ""
            port = entry.get("port", 21)
            service = entry.get("service", "ftp")
            banner = entry.get("banner") or entry.get("product") or ""
            anon = entry.get("anonymous")
            if anon is None:
                anon = bool(re.search(r"anonymous|anon", banner, re.I))
            rows.append({
                "ip": ip,
                "port": int(port) if str(port).isdigit() else port,
                "service": service,
                "banner": banner,
                "anonymous": anon,
                "source": file.name,
            })
    return rows


def _parse_nmap_xml(path: Path):
    """Extract FTP information from Nmap XML scans."""
    rows = []
    try:
        root = ET.parse(str(path)).getroot()
    except Exception:
        return rows

    for host in root.findall("host"):
        ip = ""
        addr = host.find("address")
        if addr is not None:
            ip = addr.get("addr", "")

        for port in host.findall(".//port"):
            portid = port.get("portid")
            state = port.find("state")
            if not (state is not None and state.get("state") == "open"):
                continue

            service = port.find("service")
            svc_name = service.get("name", "") if service is not None else ""
            if "ftp" not in svc_name.lower() and portid != "21":
                continue

            banner_parts = []
            anon_ok = False
            for script in port.findall("script"):
                sid = script.get("id", "")
                out = script.get("output", "")
                if sid and out:
                    banner_parts.append(f"[{sid}] {out}")
                if "ftp-anon" in sid and "Anonymous login allowed" in out:
                    anon_ok = True

            banner = " ".join(banner_parts) or (service.get("product", "") if service is not None else "")
            rows.append({
                "ip": ip,
                "port": int(portid),
                "service": svc_name or "ftp",
                "banner": banner.strip(),
                "anonymous": anon_ok,
                "source": path.name,
            })
    return rows


def _parse_naabu_txt(path: Path):
    """Parse Naabu output text for FTP ports."""
    rows = []
    text = path.read_text(errors="ignore")
    for match in re.finditer(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})", text):
        ip, port = match.groups()
        if port == "21":
            rows.append({
                "ip": ip,
                "port": int(port),
                "service": "ftp",
                "banner": "",
                "anonymous": False,
                "source": path.name,
            })
    return rows


def get_context(request=None, session=None):
    """Gather results from all sources and return them to the Web UI."""
    base = _resolve_results_dir()
    rows = []

    # 1. Module-specific JSON output
    rows += _parse_json_dir(base / "cygor-enumeration-modules" / "ftpexplorer")

    # 2. Nmap XML parsing
    nmap_dir = base / "nmap"
    if nmap_dir.exists():
        for xml in nmap_dir.glob("*.xml"):
            rows += _parse_nmap_xml(xml)

    # 3. Naabu fallback
    naabu_dir = base / "naabu"
    if naabu_dir.exists():
        for txt in naabu_dir.glob("*.txt"):
            rows += _parse_naabu_txt(txt)

    # 4. Deduplicate by (ip, port)
    seen, deduped = set(), []
    for r in rows:
        key = (r.get("ip"), r.get("port"))
        if key not in seen:
            deduped.append(r)
            seen.add(key)

    return {"rows": deduped}
