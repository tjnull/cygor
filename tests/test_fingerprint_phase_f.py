"""
Tests for Phase F:
  F.1 — Cloud VM MAC detection (AWS LAA, GCP, Azure, OpenStack)
  F.2 — Container/Docker/Kubernetes port heuristics
  F.3 — Windows build number resolution
  F.4 — OUI auto-discovery: 200+ vendor dicts wired automatically
"""
from __future__ import annotations

import pytest

from cygor.fingerprinting.fingerprint import (
    _detect_virtualization_by_ports,
    _extract_windows_build_evidence,
    _harvest_windows_builds,
)
from cygor.fingerprinting.lookup import _VENDOR_MAC_LOOKUP, FingerprintLookup


# ---------------------------------------------------------------------------
# F.1 — Cloud VM MAC detection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mac,expected_label", [
    # GCP — internal-IP-encoded MACs
    ("42:01:0A:80:00:01", "GCP Compute Engine VM"),
    ("42:01:AC:10:00:05", "GCP Compute Engine VM"),
    ("42:01:C0:A8:01:01", "GCP Compute Engine VM"),
    # Azure
    ("00:0D:3A:11:22:33", "Azure VM"),
    ("00:22:48:11:22:33", "Azure VM"),
    # OpenStack (covers OVH Public Cloud and any OpenStack)
    ("FA:16:3E:11:22:33", "OpenStack VM"),
])
@pytest.mark.asyncio
async def test_cloud_vm_mac_detection(mac, expected_label):
    lookup = FingerprintLookup()
    match = await lookup.lookup_mac(mac)
    assert match is not None, f"No match for cloud MAC {mac}"
    assert match.device_type == "virtual_machine"
    assert expected_label in (match.manufacturer or "")


# ---------------------------------------------------------------------------
# F.2 — Container / Docker / Kubernetes port heuristics
# ---------------------------------------------------------------------------


class TestContainerPorts:
    def test_docker_daemon_unencrypted_flagged(self):
        """Port 2375 is the unencrypted Docker socket — full host RCE if reachable."""
        matches = _detect_virtualization_by_ports({2375}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        assert "docker-daemon-tcp" in sigs
        d = next(m for m in matches if m.raw_data["signature"] == "docker-daemon-tcp")
        assert "UNENCRYPTED" in (d.raw_data.get("platform_label") or "")
        assert d.manufacturer == "Docker"

    def test_docker_daemon_tls(self):
        matches = _detect_virtualization_by_ports({2376}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        assert "docker-daemon-tls" in sigs

    def test_k3s_pattern(self):
        # K3s runs API + kubelet, often without separate etcd
        matches = _detect_virtualization_by_ports({6443, 10250}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        # k3s, k8s-master-port-set, and k8s-kube-proxy-port-set may all fire —
        # the broad k8s-master signature should still match.
        assert "k8s-master-port-set" in sigs or "k3s-port-set" in sigs

    def test_docker_swarm_manager(self):
        matches = _detect_virtualization_by_ports({2377, 7946}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        assert "swarm-port-set" in sigs

    def test_portainer(self):
        # Portainer with Docker daemon exposed
        matches = _detect_virtualization_by_ports({9000, 2375}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        assert "portainer-port-set" in sigs

    def test_harbor_registry(self):
        matches = _detect_virtualization_by_ports({443, 4443, 5000}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        assert "harbor-port-set" in sigs

    def test_kubelet_only_node(self):
        matches = _detect_virtualization_by_ports({10250, 30000}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        assert "k8s-worker-port-set" in sigs

    def test_etcd_alone(self):
        matches = _detect_virtualization_by_ports({2379, 2380}, host=None)
        sigs = {m.raw_data["signature"] for m in matches}
        assert "etcd-port-set" in sigs


# ---------------------------------------------------------------------------
# F.3 — Windows build resolution
# ---------------------------------------------------------------------------


class TestWindowsBuildExtraction:
    @pytest.mark.parametrize("text,expected_builds", [
        ("Windows Server 2019 Standard 10.0 Build 17763", ["17763"]),
        ("10.0.22621.123",                                 ["22621"]),
        ("IIS/10.0 (Windows Server 2022 build 20348)",     ["20348"]),
        ("Server: Microsoft-IIS/10.0",                     []),
        ("",                                               []),
        # Known false-positive guards: the harvester rejects sub-2600 builds.
        ("Apache 2.4.41",                                  []),
    ])
    def test_harvest_finds_real_builds(self, text, expected_builds):
        builds = _harvest_windows_builds(text)
        assert builds == expected_builds

    def test_smb_with_build_resolves(self):
        matches = _extract_windows_build_evidence(
            smb_info={"os": "Windows Server 2019 Standard", "lanman": "Build 17763"},
            nmap_os_matches=[],
            services=[],
        )
        assert len(matches) == 1
        m = matches[0]
        assert m.os_family == "Windows Server"
        assert m.os_version == "17763"
        assert "Server 2019" in m.raw_data["resolved_name"]

    def test_no_build_returns_empty(self):
        matches = _extract_windows_build_evidence(
            smb_info={"os": "Linux 5.4.0"},
            nmap_os_matches=[],
            services=[],
        )
        assert matches == []

    def test_windows_11_22h2_build(self):
        matches = _extract_windows_build_evidence(
            smb_info={"os": "Windows 10.0.22621"},
            nmap_os_matches=[],
            services=[],
        )
        assert len(matches) == 1
        assert matches[0].raw_data["resolved_name"] == "Windows 11 (22H2)"


# ---------------------------------------------------------------------------
# F.4 — OUI auto-discovery
# ---------------------------------------------------------------------------


class TestOUIAutoDiscovery:
    def test_lookup_table_grew_dramatically(self):
        """Pre-fix: ~36 dicts manually imported. Post-fix: auto-discovery
        should yield well over 1,000 entries from the 200+ vendor dicts."""
        assert len(_VENDOR_MAC_LOOKUP) > 1000, (
            f"Expected >1000 OUI entries, got {len(_VENDOR_MAC_LOOKUP)} — "
            "auto-discovery may not be wired"
        )

    @pytest.mark.parametrize("mac,expected_substr", [
        # Smart home / IoT — previously unimported
        ("64:16:66:11:22:33", "Nest"),
        ("2C:AA:8E:11:22:33", "Wyze"),
        # Streaming
        ("B0:A7:37:11:22:33", "Roku"),
        # Vehicles
        ("98:ED:5C:11:22:33", "Tesla"),
        # Mesh wifi
        ("8C:85:80:11:22:33", "Eero"),
    ])
    @pytest.mark.asyncio
    async def test_previously_unwired_categories_now_match(self, mac, expected_substr):
        """Categories the audit identified as 'defined but never imported'
        should now produce matches via auto-discovery."""
        lookup = FingerprintLookup()
        match = await lookup.lookup_mac(mac)
        assert match is not None, f"No match for {mac}"
        assert expected_substr in (match.manufacturer or ""), (
            f"{mac}: manufacturer {match.manufacturer!r} missing {expected_substr!r}"
        )

    def test_overrides_win_for_shared_oui_blocks(self):
        """The override dicts (cloud, hyper-v, mesh) are applied LAST so
        they win for shared OUI blocks. 00:15:5D is a Microsoft OUI but
        the Hyper-V override should set device_type=virtual_machine."""
        entry = _VENDOR_MAC_LOOKUP.get("00:15:5D")
        assert entry is not None
        device_type, category, label = entry
        assert device_type == "virtual_machine"
        assert "Hyper-V" in label
