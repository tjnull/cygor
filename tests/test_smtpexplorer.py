"""Tests for smtpexplorer: EHLO capability / VRFY parsing and non-SMTP rejection
(socket responses are faked, no network)."""
from cygor.modules import smtpexplorer as smtp


class _FakeSMTP:
    """Context-manager socket that replays canned responses, one per recv."""
    def __init__(self, responses):
        self._responses = list(responses)
        self.sent = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def settimeout(self, *a):
        pass

    def sendall(self, b):
        self.sent.append(b)

    def recv(self, n):
        return self._responses.pop(0) if self._responses else b""


def test_smtp_probe_parses_caps(monkeypatch):
    responses = [
        b"220 mail.test ESMTP Postfix\r\n",
        b"250-mail.test\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n250 SIZE 10240000\r\n",
        b"252 2.0.0 cannot VRFY user\r\n",
        b"221 Bye\r\n",
    ]
    monkeypatch.setattr(smtp.socket, "create_connection", lambda *a, **k: _FakeSMTP(responses))
    row = smtp._smtp_probe("h", 25, 3, False)
    assert row is not None
    assert "Postfix" in row["banner"]
    assert row["starttls"] == "yes"
    assert "PLAIN" in row["auth"]
    assert row["vrfy"] == "yes"
    assert row["open_relay"] == "not-tested"


def test_smtp_probe_rejects_non_smtp(monkeypatch):
    monkeypatch.setattr(smtp.socket, "create_connection",
                        lambda *a, **k: _FakeSMTP([b"SSH-2.0-OpenSSH_9.6\r\n"]))
    assert smtp._smtp_probe("h", 25, 3, False) is None


def test_smtp_open_relay_flagged(monkeypatch):
    responses = [
        b"220 relay.test ESMTP\r\n",
        b"250 relay.test\r\n",
        b"252 ok\r\n",            # VRFY
        b"250 2.1.0 Ok\r\n",      # MAIL FROM
        b"250 2.1.5 Ok\r\n",      # RCPT TO (external accepted -> open relay)
        b"250 Reset\r\n",         # RSET
        b"221 Bye\r\n",
    ]
    monkeypatch.setattr(smtp.socket, "create_connection", lambda *a, **k: _FakeSMTP(responses))
    row = smtp._smtp_probe("h", 25, 3, True)
    assert row["open_relay"] == "OPEN"
