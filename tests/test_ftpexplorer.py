"""Tests for ftpexplorer: anonymous-login detection, listing count, and FEAT
parsing (ftplib.FTP is faked, no network)."""
from ftplib import error_perm

from cygor.modules import ftpexplorer as ftp


class _FakeFTP:
    welcome = "220 ProFTPD 1.3.6 Server ready"

    def connect(self, host, port, timeout=0):
        return self.welcome

    def getwelcome(self):
        return self.welcome

    def login(self, user, passwd):
        return "230 Anonymous access granted"

    def nlst(self):
        return ["pub", "upload", "readme.txt"]

    def mkd(self, d):
        return d

    def rmd(self, d):
        pass

    def sendcmd(self, cmd):
        return "211-Features:\n UTF8\n MDTM\n211 End"

    def quit(self):
        pass

    def close(self):
        pass


def test_ftp_probe_anonymous(monkeypatch):
    monkeypatch.setattr(ftp, "FTP", _FakeFTP)
    row = ftp._ftp_probe("h", 21, 3, False)
    assert row is not None
    assert row["anon_login"] == "yes"
    assert row["listing"] == "3"
    assert "ProFTPD" in row["banner"]
    assert "UTF8" in row["info"]


def test_ftp_probe_anon_denied(monkeypatch):
    class NoAnon(_FakeFTP):
        def login(self, user, passwd):
            raise error_perm("530 Login incorrect")
    monkeypatch.setattr(ftp, "FTP", NoAnon)
    row = ftp._ftp_probe("h", 21, 3, False)
    assert row["anon_login"] == "no"
    assert row["listing"] == ""  # not attempted without anon access


def test_ftp_probe_unreachable(monkeypatch):
    class Fail(_FakeFTP):
        def connect(self, host, port, timeout=0):
            raise OSError("connection refused")
    monkeypatch.setattr(ftp, "FTP", Fail)
    assert ftp._ftp_probe("h", 21, 3, False) is None
