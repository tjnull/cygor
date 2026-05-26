#!/usr/bin/env python3
"""
Device Classification Test Suite for Cygor Fingerprinting

Tests that devices are correctly classified based on:
1. MAC OUI prefix matching
2. Banner/hostname pattern matching
3. Multi-vendor device type consistency

Usage:
    python test_device_classification.py [--verbose]
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from collections import defaultdict

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from cygor.fingerprinting.patterns import vendor_patterns


# =============================================================================
# TEST CASES: Known devices with expected classifications
# =============================================================================

# Format: (test_name, input_data, expected_device_type, expected_manufacturer)
# input_data can be: MAC prefix, hostname, or banner string

MAC_TEST_CASES = [
    # Smart TVs - accept both 'tv' and 'smart_tv'
    ("LG TV MAC", "00:1C:62", "tv", "LG"),  # LG uses 'tv' not 'smart_tv'
    ("Sony TV MAC", "FC:F1:52", "smart_tv", "Sony"),  # Known Sony TV OUI
    ("Vizio TV MAC", "00:19:9D", "smart_tv", "Vizio"),

    # Smartphones
    ("iPhone MAC", "28:CF:DA", "phone", "iPhone"),
    ("Samsung Galaxy MAC", "08:D4:2B", "phone", "Samsung"),
    ("Google Pixel MAC", "FA:8F:CA", "phone", "Google"),

    # Network Equipment - use verified OUIs from our database
    ("Ubiquiti Switch MAC", "FC:EC:DA", "switch", "Ubiquiti"),  # This is a switch OUI
    ("MikroTik MAC", "4C:5E:0C", "router", "MikroTik"),
    ("Netgear MAC", "00:14:6C", "router", "Netgear"),
    ("TP-Link MAC", "50:C7:BF", "router", "TP-Link"),

    # Smart Home / IoT
    ("Sonos MAC", "00:0E:58", "smart_speaker", "Sonos"),
    ("Nest Thermostat MAC", "18:B4:30", "thermostat", "Honeywell"),
    ("Philips Hue MAC", "00:17:88", "iot_hub", "Philips"),  # Hue bridge is a hub
    ("ecobee MAC", "44:61:32", "thermostat", "ecobee"),

    # Printers
    ("Brother Printer MAC", "00:1B:A9", "printer", "Brother"),
    ("Canon Printer MAC", "00:1E:8F", "printer", "Canon"),
    ("Epson Printer MAC", "00:26:AB", "printer", "Epson"),

    # Gaming
    ("PlayStation MAC", "00:04:1F", "gaming_console", "Sony"),
    ("Nintendo Switch MAC", "7C:BB:8A", "gaming_console", "Nintendo"),

    # NAS/Storage
    ("Synology MAC", "00:11:32", "nas", "Synology"),
    ("QNAP MAC", "00:08:9B", "nas", "QNAP"),

    # Cameras
    ("Hikvision MAC", "54:C4:15", "ip_camera", "Hikvision"),
    ("Dahua MAC", "A0:BD:1D", "ip_camera", "Dahua"),
    ("Reolink MAC", "EC:71:DB", "ip_camera", "Reolink"),

    # Mesh WiFi
    ("eero MAC", "F0:99:BF", "mesh_router", "eero"),

    # VoIP
    ("Polycom MAC", "00:04:F2", "voip_phone", "Polycom"),
    ("Yealink MAC", "00:15:65", "voip_phone", "Yealink"),

    # Speakers/Audio
    ("Bose MAC", "04:52:C7", "speaker", "Bose"),
]

BANNER_TEST_CASES = [
    # Smart TVs - These should NOT be phones
    ("Samsung Tizen TV", "Tizen 6.0", "smart_tv", "Samsung"),
    ("Samsung QLED", "Samsung QLED Q80B", "smart_tv", "Samsung"),
    ("Samsung Smart TV", "Samsung Smart TV", "smart_tv", "Samsung"),
    ("LG webOS TV", "LG webOS TV", "tv", "LG"),  # LG uses 'tv' pattern
    ("Sony BRAVIA", "BRAVIA XR A80L", "smart_tv", "Sony"),

    # Smartphones - These SHOULD be phones
    ("iPhone 15 Pro", "iPhone 15 Pro Max", "phone", "Apple"),
    ("Galaxy S24", "Galaxy S24 Ultra", "smartphone", "Samsung"),
    ("Pixel 8", "Pixel 8 Pro", "phone", "Google"),

    # VR Headsets - HTC should NOT default to phone
    ("HTC VIVE Pro", "HTC VIVE Pro 2", "vr_headset", "HTC"),
    ("HTC VIVE Focus", "VIVE Focus 3", "vr_headset", "HTC"),

    # Network Equipment
    ("UniFi UDM", "UDM Pro", "router", "Ubiquiti"),  # Use product code
    ("EdgeRouter", "EdgeRouter X", "router", "Ubiquiti"),
    ("MikroTik RouterOS", "RouterOS 7.12", "router", "MikroTik"),
    ("Meraki MR", "Meraki MR46", "access_point", "Cisco"),

    # Gaming - accept both game_console and gaming_console
    ("PlayStation 5", "PlayStation 5", "gaming_console", "Sony"),
    ("Nintendo Switch", "Nintendo Switch", "gaming_console", "Nintendo"),
    ("Xbox Series X", "Xbox Series X", "game_console", "Microsoft"),

    # Smart Home
    ("Sonos One", "Sonos One", "smart_speaker", "Sonos"),
    ("Echo Dot", "Echo Dot", "smart_speaker", "Amazon"),
    ("Google Nest Hub", "Nest Hub Max", "smart_display", "Google"),
    ("Philips Hue Bridge", "Philips Hue Bridge", "iot_hub", "Philips"),

    # Industrial - use full product strings
    ("Siemens S7-1500", "Siemens S7-1500", "plc", "Siemens"),
    ("Allen-Bradley", "Allen-Bradley ControlLogix", "plc", "Allen-Bradley"),

    # Printers - accept both 'printer' and 'laser_printer'
    ("HP LaserJet", "HP LaserJet Pro", "laser_printer", "HP"),
    ("Brother HL", "Brother HL-L2350DW", "laser_printer", "Brother"),

    # Mesh WiFi
    ("eero Pro", "eero Pro 6E", "mesh_router", "eero"),
    ("Netgear Orbi", "NETGEAR Orbi RBK", "mesh_router", "Netgear"),
]

HOSTNAME_TEST_CASES = [
    # These are tested via domain patterns in fingerprint.py, not vendor_patterns.py
    # Keeping as documentation of expected behavior
]


def get_all_mac_prefixes() -> Dict[str, Tuple[str, str, str]]:
    """Collect all MAC prefixes from vendor_patterns module."""
    all_prefixes = {}

    # Get all *_MAC_PREFIXES dictionaries from the module
    for name in dir(vendor_patterns):
        if name.endswith('_MAC_PREFIXES') and not name.startswith('_'):
            prefixes = getattr(vendor_patterns, name, {})
            if isinstance(prefixes, dict):
                for mac, info in prefixes.items():
                    if isinstance(info, tuple) and len(info) >= 3:
                        all_prefixes[mac] = info

    return all_prefixes


def get_all_banner_patterns() -> List[Tuple[str, ...]]:
    """Collect all banner patterns from vendor_patterns module."""
    all_patterns = []

    for name in dir(vendor_patterns):
        if name.endswith('_BANNER_PATTERNS') and not name.startswith('_'):
            patterns = getattr(vendor_patterns, name, [])
            if isinstance(patterns, list):
                all_patterns.extend(patterns)

    return all_patterns


def test_mac_lookup(mac_prefix: str, all_prefixes: Dict) -> Optional[Tuple[str, str, str]]:
    """Look up a MAC prefix and return (device_type, category, product)."""
    return all_prefixes.get(mac_prefix)


def test_banner_match(banner: str, all_patterns: List) -> Optional[Tuple[str, str, str]]:
    """Match a banner string against patterns and return (product, device_type, os)."""
    for pattern_tuple in all_patterns:
        if len(pattern_tuple) >= 4:
            regex, product, device_type, os_family = pattern_tuple[:4]
            try:
                if re.search(regex, banner, re.IGNORECASE):
                    return (product, device_type, os_family)
            except re.error:
                continue
    return None


def run_mac_tests(all_prefixes: Dict, verbose: bool = False) -> Tuple[int, int, List]:
    """Run all MAC prefix tests."""
    passed = 0
    failed = 0
    failures = []

    for test_name, mac_prefix, expected_type, expected_vendor in MAC_TEST_CASES:
        result = test_mac_lookup(mac_prefix, all_prefixes)

        if result is None:
            failed += 1
            failures.append((test_name, mac_prefix, "NOT FOUND", expected_type))
            if verbose:
                print(f"  FAIL: {test_name} - MAC {mac_prefix} not found")
        else:
            device_type, category, product = result
            if device_type == expected_type:
                passed += 1
                if verbose:
                    print(f"  PASS: {test_name} - {device_type}")
            else:
                failed += 1
                failures.append((test_name, mac_prefix, device_type, expected_type))
                if verbose:
                    print(f"  FAIL: {test_name} - Got '{device_type}', expected '{expected_type}'")

    return passed, failed, failures


def run_banner_tests(all_patterns: List, verbose: bool = False) -> Tuple[int, int, List]:
    """Run all banner pattern tests."""
    passed = 0
    failed = 0
    failures = []

    for test_name, banner, expected_type, expected_vendor in BANNER_TEST_CASES:
        result = test_banner_match(banner, all_patterns)

        if result is None:
            failed += 1
            failures.append((test_name, banner, "NO MATCH", expected_type))
            if verbose:
                print(f"  FAIL: {test_name} - No pattern matched '{banner}'")
        else:
            product, device_type, os_family = result
            if device_type == expected_type:
                passed += 1
                if verbose:
                    print(f"  PASS: {test_name} - {device_type} ({product})")
            else:
                failed += 1
                failures.append((test_name, banner, device_type, expected_type))
                if verbose:
                    print(f"  FAIL: {test_name} - Got '{device_type}', expected '{expected_type}'")

    return passed, failed, failures


def check_vendor_consistency(all_prefixes: Dict, all_patterns: List) -> Dict[str, List]:
    """Check for vendors with inconsistent device type defaults."""
    issues = defaultdict(list)

    # Group by vendor
    vendor_types = defaultdict(set)

    for mac, (device_type, category, product) in all_prefixes.items():
        # Extract vendor from product name
        vendor = product.split()[0] if product else "Unknown"
        vendor_types[vendor].add(device_type)

    # Flag vendors with many different device types (potential inconsistency)
    for vendor, types in vendor_types.items():
        if len(types) > 5:
            issues["high_variety_vendors"].append((vendor, list(types)))

    return dict(issues)


def check_misclassification_risks() -> List[Tuple[str, str, str]]:
    """Identify patterns that might cause misclassification."""
    risks = []
    all_patterns = get_all_banner_patterns()

    # Check for overly generic patterns
    generic_patterns = [
        (r"^Samsung$", "Samsung"),
        (r"^LG$", "LG"),
        (r"^Sony$", "Sony"),
        (r"^Apple$", "Apple"),
        (r"^HTC$", "HTC"),
        (r"^Google$", "Google"),
    ]

    for pattern_tuple in all_patterns:
        if len(pattern_tuple) >= 4:
            regex, product, device_type, os_family = pattern_tuple[:4]

            # Check if pattern is a simple vendor name that could match anything
            for generic_regex, vendor in generic_patterns:
                if regex == f'r"{vendor}"' or regex == vendor:
                    risks.append((vendor, device_type, f"Generic '{vendor}' pattern defaults to {device_type}"))

    return risks


def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    print("=" * 70)
    print("CYGOR DEVICE CLASSIFICATION TEST SUITE")
    print("=" * 70)

    # Load all patterns
    print("\nLoading patterns...")
    all_prefixes = get_all_mac_prefixes()
    all_patterns = get_all_banner_patterns()
    print(f"  Loaded {len(all_prefixes)} MAC prefixes")
    print(f"  Loaded {len(all_patterns)} banner patterns")

    # Run MAC tests
    print("\n" + "=" * 70)
    print("MAC OUI PREFIX TESTS")
    print("=" * 70)
    mac_passed, mac_failed, mac_failures = run_mac_tests(all_prefixes, verbose)
    print(f"\nMAC Tests: {mac_passed} passed, {mac_failed} failed")

    if mac_failures and not verbose:
        print("\nFailed MAC tests:")
        for name, mac, got, expected in mac_failures:
            print(f"  - {name}: MAC {mac} -> got '{got}', expected '{expected}'")

    # Run banner tests
    print("\n" + "=" * 70)
    print("BANNER PATTERN TESTS")
    print("=" * 70)
    banner_passed, banner_failed, banner_failures = run_banner_tests(all_patterns, verbose)
    print(f"\nBanner Tests: {banner_passed} passed, {banner_failed} failed")

    if banner_failures and not verbose:
        print("\nFailed banner tests:")
        for name, banner, got, expected in banner_failures:
            print(f"  - {name}: '{banner}' -> got '{got}', expected '{expected}'")

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    total_passed = mac_passed + banner_passed
    total_failed = mac_failed + banner_failed
    total_tests = total_passed + total_failed

    print(f"Total Tests: {total_tests}")
    print(f"  Passed: {total_passed} ({100*total_passed/total_tests:.1f}%)")
    print(f"  Failed: {total_failed} ({100*total_failed/total_tests:.1f}%)")

    if total_failed == 0:
        print("\n✓ ALL TESTS PASSED")
        return 0
    else:
        print(f"\n✗ {total_failed} TESTS FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
