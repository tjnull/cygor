# cygor/parse_ext.py
import sys, argparse, pathlib, ipaddress, json, csv, re, os
from typing import Dict, List, Any, Tuple, Set
from libnmap.parser import NmapParser

# Default output into results/parsed-hostlists unless overridden by -o/--out-dir
DEFAULT_OUT_DIR = pathlib.Path("results")

DEFAULT_SERVICE_PORTS: Dict[str, List[int]] = {
    "http":   [80, 8080, 8000, 8888, 81],
    "https":  [443, 8443, 9443],
    "smb":    [139, 445],
    "rdp":    [3389],
    "nfs":    [2049],
    "ldap":   [389, 636],
    "ssh":    [22],
    "ftp":    [21],
    "mysql":  [3306],
    "postgres":[5432],
    "mssql":  [1433],
    "redis":  [6379],
    "rpc":    [111],
    "winrm":  [5985, 5986],
    "vnc":    [5900, 5901, 5902],
    "dns":    [53],
    "snmp":   [161],
    "smtp":   [25, 587, 465],
    "imap":   [143, 993],
    "pop3":   [110, 995],
    "rdp-gw": [3391],
}

_SSL_SUBJECT_RE = re.compile(r"Subject:\s*(.+)")
_SSL_ISSUER_RE  = re.compile(r"Issuer:\s*(.+)")
_SSL_CN_RE      = re.compile(r"commonName=([^,;]+)", re.IGNORECASE)
_SSL_NOTBEFORE  = re.compile(r"notBefore=(.+)")
_SSL_NOTAFTER   = re.compile(r"notAfter=(.+)")

def _ensure_dir(p: pathlib.Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def _append_lines_unique(path: pathlib.Path, lines: List[str]) -> None:
    seen: Set[str] = set()
    if path.exists():
        with path.open("r", encoding="utf-8", errors="ignore") as fh:
            seen.update(x.strip() for x in fh if x.strip())
    with path.open("a", encoding="utf-8") as fh:
        for line in lines:
            s = line.strip()
            if s and s not in seen:
                fh.write(s + "\n")
                seen.add(s)

def _normalize_ip(host: str) -> str:
    try:
        return str(ipaddress.ip_address(host))
    except Exception:
        return host

def _extract_script(obj, script_id: str) -> List[str]:
    outs = []
    try:
        for entry in getattr(obj, "scripts_results", []) or []:
            if isinstance(entry, dict) and entry.get("id") == script_id:
                out = entry.get("output", "")
                if out:
                    outs.append(out)
    except Exception:
        pass
    return outs

def _parse_ssl_cert_text(txt: str) -> Dict[str, Any]:
    d: Dict[str, Any] = {"raw": txt}
    subj = _SSL_SUBJECT_RE.search(txt)
    iss  = _SSL_ISSUER_RE.search(txt)
    nbf  = _SSL_NOTBEFORE.search(txt)
    naf  = _SSL_NOTAFTER.search(txt)
    if subj:
        d["subject"] = subj.group(1).strip()
        m = _SSL_CN_RE.search(d["subject"])
        if m: d["subject_cn"] = m.group(1).strip()
    if iss:
        d["issuer"] = iss.group(1).strip()
        m = _SSL_CN_RE.search(d.get("issuer", ""))
        if m: d["issuer_cn"] = m.group(1).strip()
    if nbf: d["not_before"] = nbf.group(1).strip()
    if naf: d["not_after"]  = naf.group(1).strip()
    return d

def _emit_web_urls(outdir: pathlib.Path, records: List[Tuple[str,int]]) -> None:
    http_file  = outdir / "http"  / "urls.txt"
    https_file = outdir / "https" / "urls.txt"
    _ensure_dir(http_file.parent); _ensure_dir(https_file.parent)
    http, https = [], []
    for host, port in records:
        if port in DEFAULT_SERVICE_PORTS["https"]:
            https.append(f"https://{host}:{port}")
        elif port in DEFAULT_SERVICE_PORTS["http"]:
            http.append(f"http://{host}:{port}")
    _append_lines_unique(http_file, http)
    _append_lines_unique(https_file, https)

def _emit_index_json(outdir: pathlib.Path, rows: List[Dict[str, Any]]) -> None:
    idx = outdir / "index.json"
    with idx.open("w", encoding="utf-8") as fh:
        json.dump({"rows": rows}, fh, indent=2, sort_keys=True)

def _emit_index_csv(outdir: pathlib.Path, rows: List[Dict[str, Any]]) -> None:
    if not rows: return
    fields = sorted(rows[0].keys())
    c = outdir / "index.csv"
    with c.open("w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields); w.writeheader(); w.writerows(rows)

def _service_for_port(port: int, mapping: Dict[str, List[int]]) -> List[str]:
    hits = []
    for svc, ports in mapping.items():
        if port in ports:
            hits.append(svc)
    return hits

def _collect_xml_in_dir(d: pathlib.Path) -> List[str]:
    return [str(p) for p in sorted(d.rglob("*.xml"))]

def _resolve_nmap_inputs(args) -> List[str]:
    """
    Resolution priority:
    1) If --inputs given: use those files/dirs (recursively gather .xml)
    2) Else if --nmap-dir given: use that directory (recursively gather .xml)
    3) Else: auto-detect ./results/nmap/
       - If results/nmap/top-ports and results/nmap/fullscan both exist:
           - If interactive TTY: prompt to select
           - Else: prefer fullscan/, else top-ports/, else results/nmap/
       - If only one exists: use it
       - If neither exists: use results/nmap/ if it exists, else error
    """
    files: List[str] = []

    # 1) explicit inputs
    if args.inputs:
        for p in args.inputs:
            P = pathlib.Path(p)
            if P.is_dir():
                files.extend(_collect_xml_in_dir(P))
            else:
                files.append(str(P))
        return files

    # 2) explicit nmap-dir
    if args.nmap_dir:
        N = pathlib.Path(args.nmap_dir)
        if not N.exists():
            print(f"[-] nmap dir not found: {N}")
            return []
        files.extend(_collect_xml_in_dir(N))
        return files

    # 3) auto-detect results/nmap
    base = pathlib.Path("results") / "nmap"
    if not base.exists():
        print("[-] No directory supplied and default results/nmap/ not found.")
        return []

    tp = base / "top-ports"
    fs = base / "fullscan"

    selected = None
    options = [("fullscan", fs), ("top-ports", tp)]
    existing = [(name, path) for name, path in options if path.exists()]

    if len(existing) == 0:
        selected = base
        print(f"[*] Using {selected} (no top-ports/ or fullscan/).")
    elif len(existing) == 1:
        selected = existing[0][1]
        print(f"[*] Using {selected} (only {existing[0][0]} present).")
    else:
        # both exist
        if sys.stdin.isatty():
            print("[*] Found both profiles under results/nmap/:")
            for i, (name, path) in enumerate(existing, 1):
                print(f"  [{i}] {name}: {path}")
            print("  [0] cancel")
            try:
                choice = int(input("Select profile to parse [1-2]: ").strip() or "0")
            except Exception:
                choice = 0
            if choice not in (1,2):
                print("[-] Cancelled.")
                return []
            selected = existing[choice-1][1]
        else:
            # non-interactive: prefer fullscan then top-ports
            selected = fs if fs.exists() else tp
            print(f"[*] Non-interactive: selected {selected}")

    files.extend(_collect_xml_in_dir(selected))
    return files

def add_arguments(parser: argparse.ArgumentParser):
    parser.add_argument("--inputs", nargs="+", help="One or more Nmap XML files or directories")
    parser.add_argument("--nmap-dir", help="Directory containing Nmap XML (e.g., results/nmap/fullscan)")
    parser.add_argument("-o", "--out-dir", default=str(DEFAULT_OUT_DIR), help="Output root (default: results/)")
    parser.add_argument("--emit-json", action="store_true", help="Also emit index.json")
    parser.add_argument("--emit-csv", action="store_true", help="Also emit index.csv")

def exec_argv(argv: List[str]):
    sys.argv = ["cygor-parsex"] + list(argv)
    parser = argparse.ArgumentParser(
        prog="cygor parse",
        description="Cygor Parser (auto-detect results/nmap; enriched outputs; non-breaking)"
    )
    add_arguments(parser)
    args = parser.parse_args()

    outdir = pathlib.Path(args.out_dir)
    _ensure_dir(outdir)

    inputs = _resolve_nmap_inputs(args)
    if not inputs:
        print("[-] No input XML files resolved. Use --inputs or --nmap-dir.")
        return

    index_rows: List[Dict[str, Any]] = []
    all_http_https: List[Tuple[str,int]] = []

    # Parse each input XML and enrich
    for xml in inputs:
        try:
            rpt = NmapParser.parse_fromfile(xml)
        except Exception as e:
            print(f"[!] Failed to parse {xml}: {e}")
            continue

        for host in rpt.hosts:
            if not getattr(host, "is_up", lambda: False)():
                continue
            h = _normalize_ip(host.address)
            for s in host.services:
                try:
                    port = int(s.port)
                except Exception:
                    continue
                if getattr(s, "state", "") != "open":
                    continue

                services = _service_for_port(port, DEFAULT_SERVICE_PORTS)
                if not services and getattr(s, "service", None):
                    services = [s.service]

                row = {
                    "host": h,
                    "port": port,
                    "proto": getattr(s, "protocol", "tcp"),
                    "service": ",".join(services) if services else getattr(s, "service", "") or "",
                    "product": getattr(s, "serviceproduct", "") or "",
                    "version": getattr(s, "serviceversion", "") or "",
                    "extrainfo": getattr(s, "serviceextrainfo", "") or "",
                }

                titles = _extract_script(s, "http-title") or _extract_script(host, "http-title")
                certs  = _extract_script(s, "ssl-cert")   or _extract_script(host, "ssl-cert")
                smbos  = _extract_script(s, "smb-os-discovery") or _extract_script(host, "smb-os-discovery")

                if titles:
                    title = titles[0].splitlines()[0].strip()
                    if title:
                        row["http_title"] = title

                if certs:
                    parsed = _parse_ssl_cert_text(certs[0])
                    row.update({
                        "tls_subject_cn": parsed.get("subject_cn", ""),
                        "tls_issuer_cn": parsed.get("issuer_cn", ""),
                        "tls_not_before": parsed.get("not_before", ""),
                        "tls_not_after": parsed.get("not_after", ""),
                    })

                if smbos:
                    txt = smbos[0]
                    for line in txt.splitlines():
                        if line.startswith("OS:"):
                            row["smb_os"] = line.split(":",1)[1].strip()
                        elif line.lower().startswith("computer name:"):
                            row["smb_computer"] = line.split(":",1)[1].strip()
                        elif line.lower().startswith("domain name:") or line.lower().startswith("workgroup:"):
                            row["smb_domain"] = line.split(":",1)[1].strip()

                index_rows.append(row)

                # per-service host:port files
                for svc in (services or ["unknown"]):
                    svc_dir = outdir / svc
                    _ensure_dir(svc_dir)
                    _append_lines_unique(svc_dir / "targets.txt", [f"{h}:{port}"])
                if port in DEFAULT_SERVICE_PORTS["http"] or port in DEFAULT_SERVICE_PORTS["https"]:
                    all_http_https.append((h, port))

    # Emit helper artifacts
    _emit_web_urls(outdir, all_http_https)
    if args.emit_json: _emit_index_json(outdir, index_rows)
    if args.emit_csv:  _emit_index_csv(outdir, index_rows)

    print(f"[+] Parsed {len(inputs)} file(s). Rows: {len(index_rows)}. Output -> {outdir}")
