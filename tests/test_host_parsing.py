"""Tests for cygor.modules.base.parse_host_token.

The previous per-module idiom -- ``raw.strip().split()[0].split(":")[0]`` --
mangled IPv6 because every IPv6 address contains colons. parse_host_token
needs to round-trip IPv4, IPv6 (bracketed + bare), and host:port shapes
without losing the host.
"""
import pytest

from cygor.modules.base import parse_host_token


@pytest.mark.parametrize("raw,expected", [
    # IPv4
    ("192.168.1.1", "192.168.1.1"),
    ("192.168.1.1:445", "192.168.1.1"),
    ("  192.168.1.1  ", "192.168.1.1"),
    ("192.168.1.1 # comment", "192.168.1.1"),

    # IPv6 bracketed
    ("[2001:db8::1]", "2001:db8::1"),
    ("[2001:db8::1]:445", "2001:db8::1"),
    ("[::1]:80", "::1"),

    # IPv6 bare (no brackets, no port)
    ("2001:db8::1", "2001:db8::1"),
    ("::1", "::1"),
    ("fe80::1234:5678:9abc:def0", "fe80::1234:5678:9abc:def0"),

    # Hostnames
    ("host.example.com", "host.example.com"),
    ("host.example.com:8080", "host.example.com"),

    # Empty / whitespace
    ("", ""),
    ("   ", ""),
    ("\t\n", ""),
])
def test_parse_host_token(raw, expected):
    assert parse_host_token(raw) == expected


def test_parse_host_token_does_not_mangle_bare_ipv6():
    """The original regression: '2001:db8::1'.split(':')[0] == '2001'.
    parse_host_token must not do that."""
    assert parse_host_token("2001:db8::1") == "2001:db8::1"


def test_parse_host_token_takes_first_whitespace_token():
    """Hostlists sometimes carry comments or extra fields after the host."""
    assert parse_host_token("10.0.0.1 some-tag") == "10.0.0.1"
    assert parse_host_token("[2001:db8::1] some-tag") == "2001:db8::1"
