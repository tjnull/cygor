"""Tests for the Next-Steps engine (cygor/nextsteps.py).

Each recommendation must be driven by an observed fact -- so the core assertions
are: the right finding fires for the right field value, and nothing fires
otherwise (no false positives)."""
from cygor import nextsteps as ns


def _mr(slug, rows):
    return [{"module": {"slug": slug}, "results": rows}]


def test_unauth_database_fires_only_when_no_auth():
    rows = [{"ip": "h", "service": "redis", "port": "6379", "auth_required": "no", "version": "7"},
            {"ip": "h", "service": "postgres", "port": "5432", "auth_required": "yes"}]
    fnds = ns.module_findings(_mr("dbprobe", rows))
    assert len(fnds) == 1
    f = fnds[0]
    assert f["finding_type"] == "unauth_database" and f["service"] == "redis"
    assert f["severity"] == "high" and "redis-cli" in f["command"]


def test_smb_write_outranks_read():
    w = ns.module_findings(_mr("smbexplorer", [{"ip": "h", "share": "data", "permissions": "READ, WRITE"}]))
    r = ns.module_findings(_mr("smbexplorer", [{"ip": "h", "share": "pub", "permissions": "READ"}]))
    assert w[0]["finding_type"] == "smb_writable_share" and w[0]["severity"] == "high"
    assert r[0]["finding_type"] == "smb_readable_share" and r[0]["severity"] == "medium"
    # No share / no perms -> nothing
    assert ns.module_findings(_mr("smbexplorer", [{"ip": "h", "share": "x", "permissions": ""}])) == []


def test_ldap_anon_search_beats_bind():
    s = ns.module_findings(_mr("ldapexplorer", [{"ip": "h", "anon_search": "yes", "anon_bind": "yes"}]))
    b = ns.module_findings(_mr("ldapexplorer", [{"ip": "h", "anon_search": "no", "anon_bind": "yes"}]))
    assert s[0]["finding_type"] == "ldap_anon_search"
    assert b[0]["finding_type"] == "ldap_anon_bind"
    assert ns.module_findings(_mr("ldapexplorer", [{"ip": "h", "anon_bind": "no", "anon_search": "no"}])) == []


def test_ftp_anon_and_write():
    a = ns.module_findings(_mr("ftpexplorer", [{"ip": "h", "port": "21", "anon_login": "yes", "writable": "no"}]))
    w = ns.module_findings(_mr("ftpexplorer", [{"ip": "h", "port": "21", "anon_login": "yes", "writable": "yes"}]))
    assert a[0]["finding_type"] == "ftp_anon" and a[0]["severity"] == "high"
    assert w[0]["finding_type"] == "ftp_anon_write" and w[0]["severity"] == "critical"


def test_dns_axfr_and_resolver():
    fnds = ns.module_findings(_mr("dnsexplorer", [{"ip": "h", "axfr": "SUCCESS", "recursion": "open", "records": "42"}]))
    types = {f["finding_type"] for f in fnds}
    assert types == {"dns_axfr", "dns_open_resolver"}


def test_snmp_and_rpc():
    snmp = ns.module_findings(_mr("snmpexplorer", [{"ip": "h", "community": "public", "sysDescr": "Linux"}]))
    rpc = ns.module_findings(_mr("rpcexplorer", [{"ip": "h", "null_session": "yes", "domain": "CORP", "users": "30"}]))
    assert snmp[0]["finding_type"] == "snmp_community" and "public" in snmp[0]["command"]
    assert rpc[0]["finding_type"] == "rpc_null_session"
    assert ns.module_findings(_mr("rpcexplorer", [{"ip": "h", "null_session": "no"}])) == []


def test_next_actions_suggests_unenumerated_services():
    ports = [{"port": 445, "service": "smb", "state": "open"},
             {"port": 53, "service": "dns", "state": "open"},
             {"port": 9999, "service": "unknown", "state": "open"}]
    # smbexplorer already ran for this host -> only the OTHER smb module + dns suggested
    actions = ns.next_actions("h", ports, present_slugs={"smbexplorer"})
    mods = {a["module"] for a in actions}
    assert "rpcexplorer" in mods       # smb still has an un-run module
    assert "dnsexplorer" in mods
    assert "smbexplorer" not in mods   # already enumerated
    assert all(a["kind"] == "action" and a["severity"] == "info" for a in actions)


def test_build_host_panel_sorts_by_severity():
    # Combine module results of two different severities (high + critical) so
    # we can verify the panel ordering puts the higher-severity item first.
    mr = (
        _mr("dbprobe", [{"ip": "h", "service": "redis", "port": "6379", "auth_required": "no"}])
        + _mr("ftpexplorer", [{"ip": "h", "port": "21", "anon_login": "yes", "writable": "yes"}])
    )
    ports = [{"port": 6379, "service": "redis", "state": "open"},
             {"port": 21, "service": "ftp", "state": "open"}]
    panel = ns.build_host_panel("h", mr, ports)
    sevs = [ns.SEVERITY_ORDER[p["severity"]] for p in panel]
    assert sevs == sorted(sevs)                # severity-ordered
    assert panel[0]["severity"] == "critical"  # critical first


def _we(path, status, **extra):
    """Build a webenum result row."""
    base = "https://10.0.0.5:443"
    row = {"target": base, "url": f"{base}{path}", "path": path, "status": str(status)}
    row.update(extra)
    return row


def test_webenum_exposed_secret_is_critical():
    f = ns.module_findings(_mr("webenum", [_we("/.git/config", 200, found_by="ffuf, feroxbuster")]))
    assert len(f) == 1
    assert f[0]["finding_type"] == "exposed_secret" and f[0]["severity"] == "critical"
    # host parsed out of the URL target, web port carried through
    assert f[0]["host"] == "10.0.0.5" and f[0]["port"] == "443"
    assert "feroxbuster" in f[0]["evidence"]


def test_webenum_category_severity_order():
    rows = [_we("/.env", 200), _we("/backup.sql", 200),
            _we("/openapi.json", 200), _we("/phpmyadmin", 200)]
    f = ns.module_findings(_mr("webenum", rows))
    sev = {x["finding_type"]: x["severity"] for x in f}
    assert sev["exposed_secret"] == "critical"
    assert sev["exposed_backup"] == "high"
    assert sev["admin_interface"] == "medium"
    assert sev["api_surface"] == "low"


def test_webenum_protected_downgrades_severity():
    # 403 = present but access-controlled -> one notch down + '(protected)' label
    f = ns.module_findings(_mr("webenum", [_we("/phpmyadmin", 403, title="Forbidden")]))
    assert f[0]["severity"] == "low"           # medium -> low
    assert "(protected)" in f[0]["title"]


def test_webenum_ignores_redirects_uncategorized_and_404():
    rows = [
        _we("/images", 301),        # redirect -> not a finding
        _we("/docs", 200),          # not a categorized notable path
        _we("/.git/config", 404),   # not accessible
    ]
    assert ns.module_findings(_mr("webenum", rows)) == []


def test_webenum_in_service_to_module():
    assert "webenum" in ns.SERVICE_TO_MODULE["http"]
    assert "webenum" in ns.SERVICE_TO_MODULE["https"]
    actions = ns.next_actions("h", [{"port": 443, "service": "https", "state": "open"}], set())
    assert any(a["module"] == "webenum" for a in actions)


def test_snmp_finding_includes_walk_loot():
    """The SNMP finding's evidence now reflects what the MIB walk exposed."""
    rows = [{"ip": "h", "community": "public", "sysDescr": "Linux box",
             "user_count": "5", "process_count": "40", "software_count": "12",
             "tcp_ports": "22, 80, 443"}]
    f = ns.module_findings(_mr("snmpexplorer", rows))
    assert len(f) == 1 and f[0]["severity"] == "high"
    ev = f[0]["evidence"]
    assert "5 users" in ev and "40 processes" in ev and "12 software" in ev
    assert "3 TCP ports" in ev
