"""
Next-Steps engine
==================

Turn observed scan + enumeration facts into prioritized, evidence-backed
recommendations -- "what should I do next?"

Every recommendation is derived from something cygor actually observed: an open
port, or a concrete field in an enumeration module's result row. Each carries the
evidence that justified it. Nothing is emitted on speculation or version-banner
guesswork, so the guidance stays accurate -- if cygor didn't observe it, it isn't
suggested.

Two kinds of recommendation:
  * ``finding`` -- something notable was observed (unauthenticated Redis,
    anonymous SMB share, DNS AXFR, ...). These are persisted as Finding rows and
    feed the cross-host triage view.
  * ``action``  -- a service is open and has a cygor module, but hasn't been
    enumerated for this host yet ("run smbexplorer"). Guidance only; not
    persisted.

Pure logic -- no DB, no I/O -- so it is trivially testable and is the single
source of truth shared by the per-host panel and the Finding ingestion.
"""
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Service bucket -> cygor enumeration module(s). Mirrors enumcli.SERVICE_MODULES;
# used to suggest "enumerate this service" actions for open ports.
SERVICE_TO_MODULE = {
    "smb": ["smbexplorer", "rpcexplorer"],
    "nfs": ["nfsexplorer"],
    "snmp": ["snmpexplorer"],
    "http": ["lockon", "webenum"],
    "https": ["lockon", "webenum"],
    "ftp": ["ftpexplorer"],
    "smtp": ["smtpexplorer"],
    "ldap": ["ldapexplorer"],
    "dns": ["dnsexplorer"],
    "redis": ["dbprobe"],
    "mysql": ["dbprobe"],
    "postgres": ["dbprobe"],
    "mongodb": ["dbprobe"],
    "elasticsearch": ["dbprobe"],
    "couchdb": ["dbprobe"],
}


def _host_of(row: Dict[str, Any]) -> str:
    for k in ("ip", "host", "target", "address"):
        v = row.get(k)
        if v:
            v = str(v)
            # webenum rows carry a URL (e.g. https://10.0.0.5:443); reduce to the
            # bare host so findings link to the Host row.
            if "://" in v:
                return urlparse(v).hostname or v
            return v
    return ""


def _finding(finding_type: str, severity: str, title: str, evidence: str,
             command: str = "", service: str = "", port: Any = "",
             module: str = "") -> Dict[str, Any]:
    return {
        "kind": "finding",
        "finding_type": finding_type,
        "severity": severity,
        "title": title,
        "evidence": evidence,
        "command": command,
        "service": service,
        "port": str(port) if port else "",
        "module": module,
    }


# ----------------------------------------------------------------------
# Per-module extractors: (host, row) -> list of findings.
# Each keys only on concrete observed fields, so a schema mismatch simply
# yields nothing (never a false positive).
# ----------------------------------------------------------------------
_DB_CMD = {
    "redis": "redis-cli -h {h} -p {p} INFO",
    "postgres": "psql -h {h} -p {p} -U postgres",
    "mongodb": "mongosh mongodb://{h}:{p}/ --eval 'db.adminCommand({{listDatabases:1}})'",
    "elasticsearch": "curl -s http://{h}:{p}/_cat/indices?v",
    "couchdb": "curl -s http://{h}:{p}/_all_dbs",
    "mysql": "mysql -h {h} -P {p} -u root",
}


def _x_dbprobe(h: str, row: Dict[str, Any]) -> List[Dict[str, Any]]:
    if row.get("auth_required") != "no":
        return []
    svc = row.get("service", "")
    port = row.get("port", "")
    ver = row.get("version", "")
    cmd = _DB_CMD.get(svc, "").format(h=h, p=port or "")
    evidence = "auth_required=no" + (f"; version={ver}" if ver else "")
    return [_finding("unauth_database", "high", f"Unauthenticated {svc}",
                     evidence, cmd, svc, port)]


def _x_smb(h: str, row: Dict[str, Any]) -> List[Dict[str, Any]]:
    share = row.get("share") or ""
    perm = (row.get("permissions") or row.get("perm") or "")
    pu = perm.upper()
    if not share:
        return []
    if "WRITE" in pu:
        return [_finding("smb_writable_share", "high", f"Writable SMB share '{share}'",
                         f"permissions={perm}", f"smbclient //{h}/{share} -N", "smb", 445)]
    if "READ" in pu:
        return [_finding("smb_readable_share", "medium", f"Readable SMB share '{share}'",
                         f"permissions={perm}", f"smbclient //{h}/{share} -N", "smb", 445)]
    return []


def _x_ldap(h: str, row: Dict[str, Any]) -> List[Dict[str, Any]]:
    if row.get("anon_search") == "yes":
        return [_finding("ldap_anon_search", "high",
                         "Anonymous LDAP search (directory readable)",
                         f"anon_search=yes; domain={row.get('domain','')}",
                         f'ldapsearch -x -H ldap://{h} -b "" -s sub "(objectClass=*)"',
                         "ldap", 389)]
    if row.get("anon_bind") == "yes":
        return [_finding("ldap_anon_bind", "medium", "Anonymous LDAP bind",
                         f"anon_bind=yes; domain={row.get('domain','')}",
                         f"ldapsearch -x -H ldap://{h} -s base -b '' namingContexts",
                         "ldap", 389)]
    return []


def _x_ftp(h: str, row: Dict[str, Any]) -> List[Dict[str, Any]]:
    port = row.get("port", "21")
    if row.get("writable") == "yes":
        return [_finding("ftp_anon_write", "critical", "Anonymous FTP write access",
                         "anon_login=yes; writable=yes",
                         f"lftp -u anonymous,anonymous {h} -p {port}", "ftp", port)]
    if row.get("anon_login") == "yes":
        return [_finding("ftp_anon", "high", "Anonymous FTP login",
                         f"anon_login=yes; entries={row.get('listing','')}",
                         f"ftp {h} {port}   # user: anonymous", "ftp", port)]
    return []


def _x_smtp(h: str, row: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    port = row.get("port", "25")
    if row.get("open_relay") == "OPEN":
        out.append(_finding("smtp_open_relay", "high", "SMTP open relay",
                            "open_relay=OPEN",
                            f"swaks --server {h}:{port} --to test@example.com --from x@{h}",
                            "smtp", port))
    if row.get("vrfy") == "yes":
        out.append(_finding("smtp_vrfy", "low", "SMTP VRFY user enumeration enabled",
                            "vrfy=yes",
                            f"smtp-user-enum -M VRFY -U users.txt -t {h}", "smtp", port))
    return out


def _x_dns(h: str, row: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    if row.get("axfr") == "SUCCESS":
        out.append(_finding("dns_axfr", "high", "DNS zone transfer (AXFR) allowed",
                            f"axfr=SUCCESS; records={row.get('records','')}",
                            f"dig @{h} <zone> AXFR", "dns", 53))
    if row.get("recursion") == "open":
        out.append(_finding("dns_open_resolver", "medium", "Open DNS resolver (recursion)",
                            "recursion=open", f"dig @{h} example.com", "dns", 53))
    return out


def _x_snmp(h: str, row: Dict[str, Any]) -> List[Dict[str, Any]]:
    community = row.get("community", "")
    if not community:
        return []
    descr = (row.get("sysDescr") or "")[:40]
    evidence = f"community={community}" + (f"; sysDescr={descr}" if descr else "")
    # Surface what the walk exposed -- accounts/processes/software are the
    # high-value leak that makes an open community worth acting on.
    loot = []
    for key, label in (("user_count", "users"), ("process_count", "processes"),
                       ("software_count", "software")):
        v = row.get(key)
        if v and str(v) not in ("0", ""):
            loot.append(f"{v} {label}")
    if row.get("tcp_ports"):
        loot.append(f"{len(str(row['tcp_ports']).split(','))} TCP ports")
    if loot:
        evidence += "; exposed " + ", ".join(loot)
    return [_finding("snmp_community", "high", f"SNMP community '{community}' valid",
                     evidence, f"snmpwalk -v2c -c {community} {h}", "snmp", 161)]


def _x_rpc(h: str, row: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    if row.get("null_session") == "yes":
        out.append(_finding("rpc_null_session", "high", "RPC null session allowed",
                            f"domain={row.get('domain','')}; users={row.get('users','')}",
                            f'rpcclient -U "" -N {h} -c "enumdomusers"', "smb", 445))
    # Weak password policy -- only fires when the policy was actually read.
    lockout = str(row.get("pw_lockout", "")).strip().lower()
    if lockout in ("none", "0", "disabled", "not set", "no"):
        out.append(_finding("weak_pw_policy", "high", "No account lockout policy",
                            f"lockout={row.get('pw_lockout')} -- password spraying isn't rate-limited",
                            f"nxc smb {h} -u users.txt -p passwords.txt --no-bruteforce",
                            "smb", 445))
    if str(row.get("pw_complexity", "")).strip().lower() == "no":
        out.append(_finding("weak_pw_policy", "medium", "Password complexity not enforced",
                            f"complexity=no; min_length={row.get('pw_min_length', '?')}",
                            "", "smb", 445))
    ml = str(row.get("pw_min_length", "")).strip()
    if ml.isdigit() and 0 < int(ml) < 8:
        out.append(_finding("weak_pw_policy", "low", f"Weak minimum password length ({ml})",
                            f"min_password_length={ml}", "", "smb", 445))
    return out


def _x_nfs(h: str, row: Dict[str, Any]) -> List[Dict[str, Any]]:
    export = row.get("export") or row.get("path") or ""
    if not export:
        return []
    perm = (row.get("perm") or row.get("permissions") or "").lower()
    sev = "high" if ("write" in perm or "rw" in perm) else "medium"
    return [_finding("nfs_export", sev, f"NFS export {export} accessible",
                     f"perm={row.get('perm') or row.get('permissions') or ''}",
                     f"showmount -e {h} ; mount -t nfs {h}:{export} /mnt", "nfs", 2049)]


# webenum: classify a discovered path into a finding category. Ordered by
# severity so the first match wins (secrets before generic admin, etc.).
_WEBENUM_CATEGORIES = [
    ("exposed_secret", "Exposed secret/VCS", "critical", re.compile(
        r"(?i)(/\.git|/\.svn|/\.hg|/\.env|\.htpasswd|id_rsa|\.pem$|\.ppk$|\.kdbx$"
        r"|/credentials?\b|/secrets?\b|/passwd\b|\.key$)")),
    ("exposed_backup", "Exposed backup/source", "high", re.compile(
        r"(?i)(\.bak$|\.old$|\.save$|\.orig$|\.swp$|\.backup$|\.sql$|\.db$|/dump\b"
        r"|\.tar(\.gz)?$|\.tgz$|\.zip$|\.rar$|\.7z$)")),
    ("exposed_config", "Exposed config/diagnostic", "high", re.compile(
        r"(?i)(wp-config|web\.config|\.htaccess|phpinfo|/server-status|/server-info"
        r"|/actuator|/metrics\b)")),
    ("admin_interface", "Management/admin interface", "medium", re.compile(
        r"(?i)(phpmyadmin|/adminer|wp-admin|wp-login|/jenkins|/gitlab|/console\b"
        r"|/manager/html|/solr\b)")),
    ("api_surface", "API documentation/spec", "low", re.compile(
        r"(?i)(swagger|openapi|/graphql\b|api-docs|/\.well-known)")),
]

_SEV_DOWN = {"critical": "high", "high": "medium", "medium": "low",
             "low": "info", "info": "info"}


def _x_webenum(h: str, row: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Turn a high-signal discovered web path into a finding.

    Only present/accessible resources (200/401/403) qualify; 401/403 mean the
    resource exists but is access-controlled, so its severity is dropped a notch
    and labelled '(protected)'."""
    raw = row.get("status", "")
    code = int(raw) if str(raw).isdigit() else 0
    if code not in (200, 401, 403):
        return []
    path = row.get("path", "") or ""
    cat = next((c for c in _WEBENUM_CATEGORIES if c[3].search(path)), None)
    if not cat:
        return []
    ftype, label, sev, _ = cat

    url = row.get("url", "") or ""
    pr = urlparse(url)
    svc = "https" if pr.scheme == "https" else "http"
    port = pr.port or (443 if svc == "https" else 80)

    if code in (401, 403):
        sev = _SEV_DOWN.get(sev, sev)
        label += " (protected)"

    title = (row.get("title") or "").strip()
    found_by = row.get("found_by") or ""
    evidence = f"HTTP {code} at {path}"
    if title:
        evidence += f' — "{title}"'
    if found_by:
        evidence += f"  [{found_by}]"
    return [_finding(ftype, sev, f"{label}: {path}", evidence,
                     f"curl -sk {url}", svc, port, "webenum")]


_EXTRACTORS = {
    "dbprobe": _x_dbprobe,
    "smbexplorer": _x_smb,
    "ldapexplorer": _x_ldap,
    "ftpexplorer": _x_ftp,
    "smtpexplorer": _x_smtp,
    "dnsexplorer": _x_dns,
    "snmpexplorer": _x_snmp,
    "rpcexplorer": _x_rpc,
    "nfsexplorer": _x_nfs,
    "webenum": _x_webenum,
}


def module_findings(module_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract observed findings from a list of per-module result blocks.

    ``module_results`` items have the shape produced by the host page /
    ingestion: ``{"module": {"slug": ...}, "results": [row, ...]}``. Works for a
    single host (rows already filtered) or many hosts (host taken per row).
    """
    findings: List[Dict[str, Any]] = []
    for mr in module_results or []:
        slug = (mr.get("module") or {}).get("slug", "")
        fn = _EXTRACTORS.get(slug)
        if not fn:
            continue
        for row in mr.get("results") or []:
            if not isinstance(row, dict):
                continue
            host = _host_of(row)
            for fnd in fn(host, row):
                fnd["host"] = host
                fnd["module"] = fnd.get("module") or slug
                findings.append(fnd)
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    return findings


def next_actions(host: str, ports: List[Dict[str, Any]],
                 present_slugs: set) -> List[Dict[str, Any]]:
    """Suggest enumeration to run: open services that map to a cygor module but
    haven't been enumerated for this host yet."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for p in ports or []:
        if (p.get("state") or "open") != "open":
            continue
        svc = (p.get("service") or "").lower()
        port = p.get("port")
        for module in SERVICE_TO_MODULE.get(svc, []):
            if module in present_slugs:
                continue
            key = (svc, module)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "kind": "action", "finding_type": "enumerate", "severity": "info",
                "title": f"Enumerate {svc} with {module}",
                "evidence": f"port {port}/{svc} open, not yet enumerated",
                "command": f"cygor enum {module} -t {host}",
                "service": svc, "port": str(port or ""), "module": module, "host": host,
            })
    return out


def build_host_panel(host: str, module_results: List[Dict[str, Any]],
                     ports: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
    """Full, severity-sorted next-steps list for one host's detail page:
    observed findings + 'enumerate this' actions."""
    present = {(mr.get("module") or {}).get("slug", "")
              for mr in (module_results or []) if mr.get("results")}
    items = module_findings(module_results)
    items += next_actions(host, ports or [], present)
    items.sort(key=lambda x: SEVERITY_ORDER.get(x.get("severity", "info"), 9))
    return items
