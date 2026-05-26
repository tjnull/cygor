"""Tests for ldapexplorer: LDIF parsing, DN->domain conversion, functional-level
mapping, and rootDSE/anonymous-search row assembly (ldapsearch is mocked)."""
from cygor.modules import ldapexplorer as ldap


def test_ldif_parse():
    text = ("dn: \n"
            "namingContexts: DC=corp,DC=local\n"
            "dnsHostName: dc01.corp.local\n"
            "# a comment\n")
    d = ldap._ldif_parse(text)
    assert d["namingContexts"] == ["DC=corp,DC=local"]
    assert d["dnsHostName"] == ["dc01.corp.local"]
    assert "# a comment" not in d


def test_dn_to_domain():
    assert ldap._dn_to_domain("DC=corp,DC=local") == "corp.local"
    assert ldap._dn_to_domain("CN=x,DC=ad,DC=example,DC=com") == "ad.example.com"


def test_func_levels_map():
    assert ldap.FUNC_LEVELS["7"] == "2016+"
    assert ldap.FUNC_LEVELS["3"] == "2008"


def test_run_rootdse_and_anon_search(monkeypatch, tmp_path):
    rootdse = ("defaultNamingContext: DC=corp,DC=local\n"
               "dnsHostName: dc01.corp.local\n"
               "domainControllerFunctionality: 7\n")

    def fake_ldapsearch(server, base, scope, timeout, filt="(objectClass=*)",
                        attrs=None, sizelimit=None):
        if scope == "base":
            return 0, rootdse
        return 0, "dn: CN=Administrator,CN=Users,DC=corp,DC=local\n"

    monkeypatch.setattr(ldap.shutil, "which", lambda x: "/usr/bin/ldapsearch")
    monkeypatch.setattr(ldap, "_ldapsearch", fake_ldapsearch)

    m = ldap.LDAPExplorer(output_dir=str(tmp_path / "o"))
    m.run(["10.0.0.1"], timeout=2)
    r = m.results[0]
    assert r["domain"] == "corp.local"
    assert r["dc_hostname"] == "dc01.corp.local"
    assert r["func_level"] == "2016+"
    assert r["anon_bind"] == "yes"
    assert r["anon_search"] == "yes"


def test_run_no_anonymous(monkeypatch, tmp_path):
    monkeypatch.setattr(ldap.shutil, "which", lambda x: "/usr/bin/ldapsearch")
    monkeypatch.setattr(ldap, "_ldapsearch", lambda *a, **k: (1, ""))
    m = ldap.LDAPExplorer(output_dir=str(tmp_path / "o"))
    m.run(["10.0.0.1"], timeout=2)
    r = m.results[0]
    assert r["anon_bind"] == "no"
    assert r["anon_search"] == "no"
    assert r["info"] == "no anonymous rootDSE"
