"""Tests for `cygor.parse.parse_nmap_text` covering the .nmap + .gnmap
formats and the IPv4 + IPv6 host shapes.

Real bugs the previous text parser had:
  - gnmap puts every open port on the same "Host:" line, but the regex
    captured only the first port/open match -- subsequent ports on the
    same host were silently dropped.
  - The IP regex was hard-coded to dotted-quad IPv4, so every IPv6 host
    in gnmap or .nmap text files was missed entirely.
"""
import textwrap

import pytest

from cygor import parse as P


def _write(tmp_path, name: str, content: str):
    p = tmp_path / name
    p.write_text(textwrap.dedent(content).lstrip())
    return str(p)


# ---------------------------------------------------------------------------
# gnmap
# ---------------------------------------------------------------------------
def test_gnmap_extracts_every_open_port_on_a_host_line(tmp_path):
    """The single biggest gnmap bug: multi-port host lines used to lose all
    but the first open port."""
    f = _write(tmp_path, "scan.gnmap", """
        # Nmap 7.94 scan initiated ...
        Host: 10.0.0.1 (gateway.lab) Status: Up
        Host: 10.0.0.1 (gateway.lab)\tPorts: 22/open/tcp//ssh//OpenSSH 9.6//, 80/open/tcp//http//lighttpd//, 443/open/tcp//ssl/http//lighttpd//\tIgnored State: closed
    """)
    h = P.parse_nmap_text(f)
    assert "10.0.0.1:22" in h["ssh"]
    assert "10.0.0.1:80" in h["http"]
    assert "10.0.0.1:443" in h["https"]


def test_gnmap_skips_closed_filtered_ports(tmp_path):
    f = _write(tmp_path, "scan.gnmap", """
        Host: 10.0.0.2 ()\tPorts: 22/open/tcp//ssh//, 23/closed/tcp//telnet//, 80/filtered/tcp//http//\tIgnored State: closed
    """)
    h = P.parse_nmap_text(f)
    assert "10.0.0.2:22" in h["ssh"]
    # closed + filtered must not leak in
    assert all(not entry.startswith("10.0.0.2:23") for entries in h.values() for entry in entries)
    assert "10.0.0.2:80" not in h["http"]


def test_gnmap_ipv6_host(tmp_path):
    """IPv6 hosts in gnmap used to be dropped because the regex was IPv4-only."""
    f = _write(tmp_path, "scan.gnmap", """
        Host: 2001:db8::1 ()\tPorts: 22/open/tcp//ssh//, 80/open/tcp//http//\tIgnored State: closed
    """)
    h = P.parse_nmap_text(f)
    # IPv6 host:port renders as [ip]:port so URLs / shell quoting stay sane.
    assert "[2001:db8::1]:22" in h["ssh"]
    assert "[2001:db8::1]:80" in h["http"]


# ---------------------------------------------------------------------------
# .nmap text (block-oriented)
# ---------------------------------------------------------------------------
def test_nmap_text_tracks_host_across_lines(tmp_path):
    f = _write(tmp_path, "scan.nmap", """
        Nmap scan report for 10.0.0.5
        Host is up.
        PORT     STATE SERVICE
        22/tcp   open  ssh
        80/tcp   open  http
        443/tcp  open  https
        445/tcp  open  microsoft-ds
    """)
    h = P.parse_nmap_text(f)
    assert "10.0.0.5:22" in h["ssh"]
    assert "10.0.0.5:80" in h["http"]
    assert "10.0.0.5:443" in h["https"]
    # smb hostlist is IP-only by convention (see SERVICES dispatch).
    assert "10.0.0.5" in h["smb"]


def test_nmap_text_hostname_with_ip(tmp_path):
    """nmap renders `Nmap scan report for host.example.com (10.0.0.6)` --
    the (parenthesised) IP is what we want to record, not the hostname."""
    f = _write(tmp_path, "scan.nmap", """
        Nmap scan report for host.example.com (10.0.0.6)
        22/tcp open ssh
    """)
    h = P.parse_nmap_text(f)
    assert "10.0.0.6:22" in h["ssh"]


def test_nmap_text_ipv6(tmp_path):
    f = _write(tmp_path, "scan.nmap", """
        Nmap scan report for 2001:db8::42
        22/tcp open ssh
        53/tcp open domain
    """)
    h = P.parse_nmap_text(f)
    assert "[2001:db8::42]:22" in h["ssh"]
    assert "[2001:db8::42]:53" in h["dns"]


def test_nmap_text_two_hosts_no_cross_contamination(tmp_path):
    """Verify port lines from host B never leak onto host A's record."""
    f = _write(tmp_path, "scan.nmap", """
        Nmap scan report for 10.0.0.10
        22/tcp open ssh
        Nmap scan report for 10.0.0.20
        443/tcp open https
    """)
    h = P.parse_nmap_text(f)
    assert "10.0.0.10:22" in h["ssh"]
    assert "10.0.0.20:443" in h["https"]
    # not the cross product
    assert "10.0.0.10:443" not in h["https"]
    assert "10.0.0.20:22" not in h["ssh"]


def test_nmap_text_closed_ports_skipped(tmp_path):
    f = _write(tmp_path, "scan.nmap", """
        Nmap scan report for 10.0.0.30
        22/tcp   closed ssh
        80/tcp   filtered http
        443/tcp  open    https
    """)
    h = P.parse_nmap_text(f)
    assert "10.0.0.30:443" in h["https"]
    assert "10.0.0.30:22" not in h["ssh"]
    assert "10.0.0.30:80" not in h["http"]


def test_empty_file_returns_empty_hostlists(tmp_path):
    f = _write(tmp_path, "scan.nmap", "")
    h = P.parse_nmap_text(f)
    for entries in h.values():
        assert entries == set()
