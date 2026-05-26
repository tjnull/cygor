"""
Tests for Phase G — cloud provider attribution from outside-the-VM signals.

Covers:
  - PTR reverse-DNS pattern matching for AWS/GCP/Azure/DO/Linode/Vultr/OVH/Oracle/Alibaba
  - TLS SAN cloud-host extraction
  - IP-range membership lookup (with mock-cached prefixes)
  - Source-weight presence for cloud_iprange / cloud_ptr / cloud_tls_san
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cygor.fingerprinting.cloud_detector import (
    detect_from_hostname,
    detect_from_hostnames,
    detect_from_tls_sans,
)
from cygor.fingerprinting.cloud_ipranges import (
    _LOADED,
    _PROVIDER_FILES,
    clear_loaded_cache,
    lookup_ip,
    save_provider_ranges,
)


# ---------------------------------------------------------------------------
# G.1 — PTR / reverse DNS
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("hostname,expected_provider,expected_service", [
    # AWS
    ("ec2-1-2-3-4.compute-1.amazonaws.com",     "AWS",       "compute"),
    ("ec2-54-200-1-1.us-west-2.compute.amazonaws.com", "AWS", "compute"),
    ("ip-10-0-1-50.us-east-2.compute.internal", "AWS",       "compute_internal"),
    ("foo.elb.amazonaws.com",                   "AWS",       "elb"),
    ("mybucket.s3.amazonaws.com",               "AWS",       "s3"),
    ("d12345.cloudfront.net",                   "AWS",       "cloudfront"),
    ("my-api.execute-api.us-east-1.amazonaws.com", "AWS",    "apigateway"),
    ("db.abc123.us-east-1.rds.amazonaws.com",   "AWS",       "rds"),
    # GCP
    ("5.180.in-addr.bc.googleusercontent.com",  "GCP",       "compute"),
    ("foo.googleapis.com",                      "GCP",       "googleapis"),
    # Azure
    ("vm-prod.westeurope.cloudapp.azure.com",   "Azure",     "compute"),
    ("legacy.cloudapp.net",                     "Azure",     "compute_legacy"),
    ("webapp.azurewebsites.net",                "Azure",     "appservice"),
    ("mydb.database.windows.net",               "Azure",     "sqldb"),
    ("acct.blob.core.windows.net",              "Azure",     "storage"),
    ("foo.azurefd.net",                         "Azure",     "frontdoor"),
    # DO / Linode / Vultr / OVH / Oracle / Alibaba / Hetzner
    ("ip-1-2-3-4.do-internal.com",              "DigitalOcean", "droplet"),
    ("li-host-5-6-7-8.linode.com",              "Linode",    "compute"),
    ("vps-1-2-3-4.vultr.com",                   "Vultr",     "compute"),
    ("ns123.ovh.net",                           "OVH",       "compute"),
    ("server.oraclecloud.com",                  "Oracle Cloud", "compute"),
    ("foo.aliyuncs.com",                        "Alibaba Cloud", "compute"),
    # Hetzner uses .your-server.de — but OVH also uses it. Either label is fine.
])
def test_ptr_detection(hostname, expected_provider, expected_service):
    result = detect_from_hostname(hostname)
    assert result is not None, f"No match for {hostname!r}"
    assert result.provider == expected_provider
    assert result.service == expected_service


def test_ptr_detection_no_match():
    assert detect_from_hostname("a.example.com") is None
    assert detect_from_hostname("internal.lan") is None
    assert detect_from_hostname("") is None
    assert detect_from_hostname(None) is None


def test_detect_from_hostnames_picks_first_match():
    # First non-cloud, then a cloud match — should still resolve.
    result = detect_from_hostnames(["foo.example.com", "ec2-1-1-1-1.compute-1.amazonaws.com"])
    assert result is not None
    assert result.provider == "AWS"


# ---------------------------------------------------------------------------
# G.2 — IP range lookup
# ---------------------------------------------------------------------------


@pytest.fixture
def aws_cache_with_known_prefix(tmp_path, monkeypatch):
    """Inject a synthetic AWS cache with one known prefix so the lookup
    function has something to match against without fetching from AWS.

    NOTE: cloud_ipranges imports ``get_cache_dir`` at module load, so we
    must monkey-patch the symbol on the cloud_ipranges module — patching
    ``cache.get_cache_dir`` doesn't propagate to the already-bound name.
    """
    from cygor.fingerprinting import cloud_ipranges as cir
    monkeypatch.setattr(cir, "get_cache_dir", lambda: tmp_path)
    clear_loaded_cache()

    save_provider_ranges("AWS", [
        {"cidr": "3.5.0.0/16",   "service": "EC2", "region": "us-east-1"},
        {"cidr": "52.94.0.0/22", "service": "S3",  "region": "us-east-1"},
        {"cidr": "2600:1f18::/32", "service": "EC2", "region": "us-west-2"},
    ])
    yield
    # Clean up so subsequent tests don't see stale data.
    clear_loaded_cache()


class TestIPRangeLookup:
    def test_v4_match(self, aws_cache_with_known_prefix):
        m = lookup_ip("3.5.0.5")
        assert m is not None
        assert m.provider == "AWS"
        assert m.service == "EC2"
        assert m.region == "us-east-1"
        assert m.cidr == "3.5.0.0/16"

    def test_v4_outside_known_range(self, aws_cache_with_known_prefix):
        assert lookup_ip("8.8.8.8") is None

    def test_most_specific_prefix_wins(self, tmp_path, monkeypatch):
        """When two CIDRs from the same provider both contain the IP, the
        more-specific one should win."""
        from cygor.fingerprinting import cloud_ipranges as cir
        monkeypatch.setattr(cir, "get_cache_dir", lambda: tmp_path)
        clear_loaded_cache()
        save_provider_ranges("AWS", [
            {"cidr": "3.0.0.0/8",  "service": "EC2",   "region": "us-east-1"},
            {"cidr": "3.5.0.0/16", "service": "S3",    "region": "us-east-1"},
        ])
        m = lookup_ip("3.5.0.5")
        # Most-specific match is /16 (S3), not /8 (EC2)
        assert m is not None
        assert m.cidr == "3.5.0.0/16"
        assert m.service == "S3"

    def test_invalid_ip_returns_none(self, aws_cache_with_known_prefix):
        assert lookup_ip("not-an-ip") is None
        assert lookup_ip("") is None
        assert lookup_ip(None) is None

    def test_no_cache_returns_none(self, tmp_path, monkeypatch):
        """When a provider's cache file doesn't exist, lookup gracefully
        returns None instead of raising."""
        from cygor.fingerprinting import cloud_ipranges as cir
        monkeypatch.setattr(cir, "get_cache_dir", lambda: tmp_path)
        clear_loaded_cache()
        # No save_provider_ranges call — cache is empty.
        assert lookup_ip("3.5.0.5") is None


# ---------------------------------------------------------------------------
# G.3 — TLS SAN extraction
# ---------------------------------------------------------------------------


class TestTLSSanExtraction:
    def test_aws_elb_san(self):
        results = detect_from_tls_sans(["*.elb.amazonaws.com", "myapp.example.com"])
        assert len(results) == 1
        assert results[0].provider == "AWS"
        assert results[0].service == "elb"
        assert results[0].source == "tls_san"

    def test_multiple_cloud_sans(self):
        results = detect_from_tls_sans([
            "*.elb.amazonaws.com",
            "webapp.azurewebsites.net",
            "*.googleapis.com",
            "private.lan",
        ])
        providers = {r.provider for r in results}
        assert providers == {"AWS", "Azure", "GCP"}

    def test_no_match_returns_empty(self):
        results = detect_from_tls_sans(["foo.example.com", "lan.local"])
        assert results == []

    def test_dedupe_same_san(self):
        # Same SAN listed twice shouldn't produce duplicate findings.
        results = detect_from_tls_sans(["*.elb.amazonaws.com", "*.elb.amazonaws.com"])
        assert len(results) == 1


# ---------------------------------------------------------------------------
# G.4 — source weights present for cloud sources
# ---------------------------------------------------------------------------


def test_cloud_sources_in_weight_table():
    """Each cloud-attribution source must outvote ``ttl`` (weight 0.55)
    when carrying the same field. Catches accidental drops from the
    SOURCE_WEIGHTS table."""
    from cygor.fingerprinting.lookup import FingerprintMatch, aggregate_evidence
    for source in ("cloud_iprange", "cloud_ptr", "cloud_tls_san"):
        evidence = [
            FingerprintMatch(source=source, confidence=1.0, match_type="t",
                             manufacturer="TestCloud"),
            FingerprintMatch(source="ttl", confidence=1.0, match_type="t",
                             manufacturer="OtherCloud"),
        ]
        agg = aggregate_evidence(evidence)
        assert agg["manufacturer"] == "TestCloud", (
            f"Source {source!r} should outweigh ttl — check SOURCE_WEIGHTS"
        )
