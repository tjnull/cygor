"""
Integration tests for the fingerprinting pipeline after Phase A+B fixes.

These exercise the realistic end-to-end flow:
- Huginn cache lookups (via the on-disk cache when present, mocked otherwise)
- Cross-source aggregation
- Realistic hostnames yielding correct device_type / manufacturer / os_family
- The unused-source-now-used wiring (huginn_mac_vendor, cross-source search,
  banner-seeded nmap_os)

These are intentionally cache-aware: when the user has the real Huginn
cache on disk, the tests assert against actual production data. When the
cache isn't present (CI environments), the relevant tests are skipped
with a clear reason.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from cygor.fingerprinting.cache import get_cache, _tokenize_for_match
from cygor.fingerprinting.lookup import (
    FingerprintLookup,
    FingerprintMatch,
    aggregate_evidence,
)
from cygor.fingerprinting.huginn_normalize import normalize_huginn_record


def _have_cache(name: str) -> bool:
    return (Path.home() / ".cache" / "cygor" / "fingerprints" / f"{name}.json").exists()


needs_huginn = pytest.mark.skipif(
    not _have_cache("huginn_devices"),
    reason="Huginn devices cache not present locally",
)
needs_huginn_mac = pytest.mark.skipif(
    not _have_cache("huginn_mac_vendors"),
    reason="Huginn mac_vendors cache not present locally",
)


# ---------------------------------------------------------------------------
# Aggregation: device_type buckets are correct after the fix
# ---------------------------------------------------------------------------


class TestAggregationBuckets:
    """The aggregator's DEVICE_CATEGORIES dict expects normalized type strings."""

    def test_iphone_evidence_aggregates_to_mobile(self):
        evidence = [
            FingerprintMatch(
                source="oui", match_type="exact", confidence=0.85,
                manufacturer="Apple, Inc.",
            ),
            FingerprintMatch(
                source="huginn_device", match_type="fuzzy_hostname", confidence=0.70,
                manufacturer="Apple", device_type="smartphone",
                os_family="iOS", os_vendor="Apple", model="Apple iPhone",
            ),
        ]
        agg = aggregate_evidence(evidence)
        assert agg["device_type"] == "smartphone"
        assert agg["device_category"] == "Mobile"
        assert agg["os_family"] == "iOS"
        assert agg["manufacturer"] in ("Apple", "Apple, Inc.")

    def test_router_evidence_aggregates_to_network_device(self):
        evidence = [
            FingerprintMatch(
                source="huginn_device", match_type="fuzzy_hostname", confidence=0.70,
                manufacturer="Cisco", device_type="router",
            ),
        ]
        agg = aggregate_evidence(evidence)
        assert agg["device_type"] == "router"
        assert agg["device_category"] == "Network Device"

    def test_printer_evidence_aggregates_to_peripheral(self):
        evidence = [
            FingerprintMatch(
                source="huginn_device", match_type="fuzzy_hostname", confidence=0.70,
                manufacturer="HP", device_type="printer",
            ),
        ]
        agg = aggregate_evidence(evidence)
        assert agg["device_type"] == "printer"
        assert agg["device_category"] == "Peripheral"

    def test_evidence_with_huginn_does_not_emit_apple_iphone_as_type(self):
        """Regression guard: pre-fix bug placed 'Apple iPhone' into device_type."""
        evidence = [
            FingerprintMatch(
                source="huginn_device", match_type="fuzzy_hostname", confidence=0.7,
                manufacturer="Apple", device_type="smartphone", model="Apple iPhone",
            ),
        ]
        agg = aggregate_evidence(evidence)
        # The model string must not appear in the device_type slot.
        assert agg["device_type"] != "Apple iPhone"
        assert agg["device_type"] in ("smartphone", "tablet")


# ---------------------------------------------------------------------------
# Weight-balance regression: Huginn no longer poisons OUI-based manufacturer
# ---------------------------------------------------------------------------


class TestWeightBalance:
    """Pre-fix, huginn_device dominated votes with a model-name device_type
    string ('Apple iPhone'), which displaced the clean OUI manufacturer
    name. With the normalizer, both sources agree on Apple."""

    def test_oui_and_huginn_converge_on_same_vendor(self):
        evidence = [
            FingerprintMatch(
                source="oui", match_type="exact", confidence=0.85,
                manufacturer="Apple, Inc.",
            ),
            FingerprintMatch(
                source="huginn_device", match_type="exact", confidence=0.90,
                manufacturer="Apple", device_type="smartphone", os_family="iOS",
            ),
        ]
        agg = aggregate_evidence(evidence)
        # Both sources point at Apple — the aggregator picks one.
        # (We accept either since both are correct after the fix.)
        assert agg["manufacturer"] in ("Apple", "Apple, Inc.")

    def test_conflicting_vendor_oui_still_wins_when_huginn_is_silent(self):
        evidence = [
            FingerprintMatch(
                source="oui", match_type="exact", confidence=0.85,
                manufacturer="Ubiquiti Networks",
            ),
            # nmap_os says Linux 3.18 — used to displace OUI vendor pre-fix
            FingerprintMatch(
                source="nmap_os", match_type="fingerprint", confidence=0.92,
                os_family="Linux", os_version="3.18",
            ),
        ]
        agg = aggregate_evidence(evidence)
        # OUI manufacturer is authoritative for vendor identity.
        assert agg["manufacturer"] == "Ubiquiti Networks"
        assert agg["os_family"] == "Linux"


# ---------------------------------------------------------------------------
# Hostname fuzzy matching against the live Huginn cache (if present)
# ---------------------------------------------------------------------------


@needs_huginn
class TestHostnameFuzzyMatching:
    """Real-world hostnames must surface the right Huginn record."""

    @pytest.mark.parametrize("hostname,expected_vendor,expected_type", [
        ("iphone-bob",       "Apple", "smartphone"),
        ("apple-iphone-12",  "Apple", "smartphone"),
        ("galaxy-s22-jdoe",  "Samsung", "smartphone"),
        ("cisco-catalyst-2960",  "Cisco", "switch"),
        ("hp-laserjet-floor3",   "HP", "printer"),
    ])
    def test_hostname_yields_expected_match(self, hostname, expected_vendor, expected_type):
        lookup = FingerprintLookup()
        match = lookup.lookup_huginn_device(hostname=hostname)
        assert match is not None, f"No match for {hostname!r}"
        assert match.manufacturer == expected_vendor, (
            f"{hostname}: got {match.manufacturer!r} want {expected_vendor!r}"
        )
        assert match.device_type == expected_type, (
            f"{hostname}: got {match.device_type!r} want {expected_type!r}"
        )

    def test_garbage_hostname_returns_none(self):
        lookup = FingerprintLookup()
        match = lookup.lookup_huginn_device(hostname="asdf-xyz-totally-random")
        assert match is None

    def test_iphone_specific_match_includes_ios_inference(self):
        lookup = FingerprintLookup()
        match = lookup.lookup_huginn_device(hostname="iphone-bob")
        assert match.os_family == "iOS"
        assert match.os_vendor == "Apple"


# ---------------------------------------------------------------------------
# Huginn MAC vendor wiring (Phase B.1)
# ---------------------------------------------------------------------------


@needs_huginn_mac
class TestHuginnMacVendorWired:
    """Verify the MAC lookup now consults the 10.1M Huginn entries."""

    @pytest.mark.asyncio
    async def test_apple_mac_returns_huginn_match(self):
        lookup = FingerprintLookup()
        # Apple-prefix MAC (00:1E:C2:xx) is in both OUI and Huginn.
        match = await lookup.lookup_mac("00:1E:C2:11:22:33")
        assert match is not None
        # Should prefer huginn_mac_vendor (it's checked before plain OUI now)
        # OR a higher-priority vendor-specific match — both are acceptable
        # post-fix; the regression to guard against is None.
        assert "Apple" in (match.manufacturer or "")

    @pytest.mark.asyncio
    async def test_ubiquiti_mac_returns_match(self):
        lookup = FingerprintLookup()
        match = await lookup.lookup_mac("E0:63:DA:11:22:33")
        assert match is not None
        # Either "Ubiquiti" (Huginn/OUI generic) or "UniFi AP" (vendor-prefix
        # specific) is acceptable — both mean we identified the device.
        assert any(s in (match.manufacturer or "") for s in ("Ubiquiti", "UniFi"))


# ---------------------------------------------------------------------------
# Cross-source enrichment helper (Phase B.2)
# ---------------------------------------------------------------------------


class TestCrossSourceSummarizer:
    """The _summarize_partial helper feeds search_huginn_devices."""

    def test_picks_highest_confidence_per_field(self):
        from cygor.fingerprinting.fingerprint import _summarize_partial
        evidence = [
            FingerprintMatch(source="ttl", match_type="heuristic", confidence=0.4,
                             os_family="Linux"),
            FingerprintMatch(source="oui", match_type="exact", confidence=0.85,
                             manufacturer="Cisco"),
            FingerprintMatch(source="banner", match_type="pattern", confidence=0.80,
                             os_family="IOS XE", manufacturer="Cisco Systems"),
        ]
        out = _summarize_partial(evidence)
        # banner os_family beats ttl on confidence
        assert out["os_family"] == "IOS XE"
        # oui manufacturer beats banner on confidence
        assert out["manufacturer"] == "Cisco"

    def test_empty_evidence_returns_all_none(self):
        from cygor.fingerprinting.fingerprint import _summarize_partial
        assert _summarize_partial([]) == {
            "manufacturer": None, "os_family": None, "device_type": None,
        }


# ---------------------------------------------------------------------------
# Tokenizer (used by both normalizer and cache fuzzy matcher)
# ---------------------------------------------------------------------------


class TestTokenizer:
    def test_split_on_separators(self):
        assert _tokenize_for_match("iphone-bob") == ["iphone", "bob"]
        assert _tokenize_for_match("DESKTOP-H1JK345") == ["desktop", "h1jk345"]

    def test_empty_input(self):
        assert _tokenize_for_match("") == []
        assert _tokenize_for_match(None) == []
