"""
Tests for Phase E: hypervisor / VM / container / specific-OS-version detection.

Covers:
- CPE parsing of every common shape (Windows Server, Ubuntu, ESXi, Linux kernel)
- VM MAC OUI detection for VMware, VirtualBox, Xen, Hyper-V
- Hypervisor port-set heuristics (ESXi, Proxmox, vCenter)
- Kubernetes / etcd / Docker Swarm port-set heuristics
- VMware NSE script extractors
"""
from __future__ import annotations

import asyncio

import pytest

from cygor.fingerprinting.cpe_extractor import (
    cpe_to_match_payload,
    parse_cpe,
)
from cygor.fingerprinting.fingerprint import (
    _detect_virtualization_by_ports,
    _extract_virt_scripts,
)
from cygor.fingerprinting.lookup import FingerprintLookup


# ---------------------------------------------------------------------------
# CPE parsing
# ---------------------------------------------------------------------------


class TestCPEParsing:
    def test_windows_server_2019(self):
        p = parse_cpe("cpe:/o:microsoft:windows_server_2019:standard")
        assert p.is_os
        assert p.vendor == "microsoft"
        assert p.product == "windows_server_2019"
        payload = cpe_to_match_payload(p)
        assert payload["os_family"] == "Windows Server"
        assert payload["os_vendor"] == "Microsoft"

    def test_ubuntu_with_version(self):
        p = parse_cpe("cpe:/o:canonical:ubuntu_linux:22.04")
        payload = cpe_to_match_payload(p)
        assert payload["os_family"] == "Linux"
        assert payload["os_vendor"] == "Canonical"
        assert payload["os_version"] == "22.04"

    def test_vmware_esxi(self):
        p = parse_cpe("cpe:/o:vmware:esxi:6.7.0")
        payload = cpe_to_match_payload(p)
        assert payload["os_family"] == "VMkernel"
        assert payload["os_vendor"] == "VMware"
        assert payload["os_version"] == "6.7.0"

    def test_linux_kernel_versionless(self):
        p = parse_cpe("cpe:/o:linux:linux_kernel")
        payload = cpe_to_match_payload(p)
        assert payload["os_family"] == "Linux"
        # No vendor display for "linux" — it's generic.
        assert payload["os_vendor"] is None

    def test_application_cpe_skipped_for_os_fields(self):
        p = parse_cpe("cpe:/a:apache:http_server:2.4.41")
        payload = cpe_to_match_payload(p)
        # Application CPE should not surface os_family
        assert payload.get("os_family") is None

    def test_hardware_cpe_emits_manufacturer(self):
        p = parse_cpe("cpe:/h:cisco:catalyst_2960")
        payload = cpe_to_match_payload(p)
        assert payload["manufacturer"] == "Cisco"
        assert "Catalyst 2960" in (payload.get("model") or "")

    def test_malformed_cpe_returns_none(self):
        assert parse_cpe("not a cpe") is None
        assert parse_cpe("") is None
        assert parse_cpe(None) is None


# ---------------------------------------------------------------------------
# Hypervisor / Container port heuristics
# ---------------------------------------------------------------------------


class TestVirtPortHeuristics:
    def test_esxi_signature(self):
        # ESXi: SDK 902 + WBEM 5989 + HTTPS 443
        matches = _detect_virtualization_by_ports({902, 5989, 443}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        assert "esxi-port-set" in sigs
        esxi = next(m for m in matches if m.raw_data["signature"] == "esxi-port-set")
        assert esxi.device_type == "hypervisor"
        assert esxi.manufacturer == "VMware"
        assert esxi.os_family == "VMkernel"

    def test_proxmox_signature(self):
        # Proxmox VE web UI on 8006 + ssh
        matches = _detect_virtualization_by_ports({8006, 22}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        assert "proxmox-port-set" in sigs

    def test_kubernetes_master_signature(self):
        # K8s API server + kubelet + etcd
        matches = _detect_virtualization_by_ports({6443, 10250, 2379, 2380}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        # Should fire both master + worker + etcd
        assert "k8s-master-port-set" in sigs
        master = next(m for m in matches if m.raw_data["signature"] == "k8s-master-port-set")
        assert master.device_type == "kubernetes_master"
        assert master.os_family == "Linux"

    def test_etcd_alone(self):
        matches = _detect_virtualization_by_ports({2379, 2380}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        assert "etcd-port-set" in sigs

    def test_docker_swarm_manager(self):
        matches = _detect_virtualization_by_ports({2377, 7946}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        assert "swarm-port-set" in sigs

    def test_no_match_for_typical_web_server(self):
        # A normal web server shouldn't fire any virt signature.
        matches = _detect_virtualization_by_ports({22, 80, 443}, host=None)
        # 80+443 alone should not trigger xen-port-set without 27000/5900/5989
        sigs = {m.raw_data["signature"] for m in matches}
        assert "esxi-port-set" not in sigs
        assert "proxmox-port-set" not in sigs

    def test_empty_ports_returns_empty(self):
        assert _detect_virtualization_by_ports(set(), host=None) == []


# ---------------------------------------------------------------------------
# VM MAC OUI detection (verifies E.4 wiring)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mac,expected_type,expected_mfg_substr", [
    ("00:0C:29:11:22:33", "virtual_machine", "VMware"),
    ("00:50:56:11:22:33", "hypervisor",      "VMware ESXi"),
    ("08:00:27:11:22:33", "virtual_machine", "VirtualBox"),
    ("00:16:3E:11:22:33", "virtual_machine", "Xen"),
    ("00:15:5D:11:22:33", "virtual_machine", "Hyper-V"),
])
@pytest.mark.asyncio
async def test_vm_mac_detection(mac, expected_type, expected_mfg_substr):
    lookup = FingerprintLookup()
    match = await lookup.lookup_mac(mac)
    assert match is not None, f"No match for {mac}"
    assert match.device_type == expected_type, (
        f"{mac}: device_type was {match.device_type!r}, expected {expected_type!r}"
    )
    assert expected_mfg_substr in (match.manufacturer or ""), (
        f"{mac}: manufacturer {match.manufacturer!r} missing {expected_mfg_substr!r}"
    )


# ---------------------------------------------------------------------------
# VMware NSE script extractors
# ---------------------------------------------------------------------------


class _FakeService:
    def __init__(self, port, scripts):
        self.port = port
        self.scripts_results = scripts


class _FakeHost:
    def __init__(self, services, host_scripts=None):
        self.services = services
        self.scripts_results = host_scripts or []


def test_vmware_version_script_extractor():
    services = [
        _FakeService(443, [
            {"id": "vmware-version", "output": "VMware ESXi version: 6.7.0"},
        ])
    ]
    matches = _extract_virt_scripts(_FakeHost(services))
    assert any(m.match_type == "vmware-version" for m in matches)
    vmw = next(m for m in matches if m.match_type == "vmware-version")
    assert vmw.manufacturer == "VMware"
    assert vmw.os_family == "VMkernel"
    assert vmw.os_version == "6.7.0"


def test_vsphere_version_script_extractor():
    services = [
        _FakeService(443, [
            {"id": "vsphere-version", "output": "vSphere 7.0 Update 3"},
        ])
    ]
    matches = _extract_virt_scripts(_FakeHost(services))
    assert any(m.match_type == "vsphere-version" for m in matches)


def test_no_vmware_scripts_returns_empty():
    services = [
        _FakeService(80, [{"id": "http-headers", "output": "Server: nginx"}]),
    ]
    matches = _extract_virt_scripts(_FakeHost(services))
    assert matches == []


# ---------------------------------------------------------------------------
# Source weights — new sources must be in the table
# ---------------------------------------------------------------------------


def test_new_phase_e_sources_have_weights():
    from cygor.fingerprinting.lookup import FingerprintMatch, aggregate_evidence
    # Each new source should win against ttl (weight 0.55) when carrying
    # the same field with confidence=1.0. ttl baseline test:
    for source in ("cpe", "virt_ports", "nmap_script"):
        evidence = [
            FingerprintMatch(source=source, confidence=1.0, match_type="t",
                             os_family="TestOS"),
            FingerprintMatch(source="ttl", confidence=1.0, match_type="t",
                             os_family="OtherOS"),
        ]
        agg = aggregate_evidence(evidence)
        assert agg["os_family"] == "TestOS", (
            f"Source {source!r} should outweigh ttl but didn't — "
            f"check SOURCE_WEIGHTS table"
        )
