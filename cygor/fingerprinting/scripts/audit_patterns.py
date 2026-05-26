#!/usr/bin/env python3
"""
Comprehensive Pattern Audit for Cygor Fingerprinting

Checks for:
1. Overly generic patterns that could cause false matches
2. Patterns without vendor context that might match unrelated devices
3. Device type inconsistencies
4. Potential cross-vendor conflicts
5. Patterns that are too short (< 3 chars)

Usage:
    python audit_patterns.py
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Set
from collections import defaultdict

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from cygor.fingerprinting.patterns import vendor_patterns


# Common words that shouldn't be standalone patterns (too generic)
GENERIC_WORDS = {
    'pro', 'max', 'plus', 'mini', 'lite', 'ultra', 'air', 'one', 'two', 'go',
    'home', 'hub', 'link', 'smart', 'cloud', 'net', 'wifi', 'wireless',
    'device', 'system', 'server', 'client', 'host', 'node', 'gateway',
    'router', 'switch', 'bridge', 'controller', 'manager', 'monitor',
    'camera', 'sensor', 'light', 'plug', 'speaker', 'display', 'tv',
    'phone', 'tablet', 'watch', 'band', 'ring', 'dot', 'show', 'echo',
    'nest', 'home', 'fire', 'stick', 'box', 'cast', 'play', 'view',
    'essential', 'basic', 'standard', 'advanced', 'enterprise',
    'indoor', 'outdoor', 'wired', 'wireless', 'portable', 'mobile',
    'series', 'generation', 'version', 'model', 'type', 'class',
}

# Short patterns (1-2 chars) that are likely too generic
SHORT_PATTERN_EXCEPTIONS = {
    'TV', 'AP', 'NAS', 'PLC', 'UPS', 'PC', 'VM', 'VR', 'AR', 'AI',
    'IoT', 'IP', 'PoE', 'AV', 'AC', 'DC', 'RF', 'IR', 'HD', '4K', '8K',
}


def get_all_banner_patterns() -> Dict[str, List[Tuple]]:
    """Collect all banner patterns grouped by vendor."""
    patterns_by_vendor = {}

    for name in dir(vendor_patterns):
        if name.endswith('_BANNER_PATTERNS') and not name.startswith('_'):
            patterns = getattr(vendor_patterns, name, [])
            if isinstance(patterns, list):
                vendor = name.replace('_BANNER_PATTERNS', '')
                patterns_by_vendor[vendor] = patterns

    return patterns_by_vendor


def extract_pattern_core(regex: str) -> str:
    """Extract the core matching text from a regex pattern."""
    # Remove common regex syntax
    core = regex
    core = re.sub(r'\\s\*', ' ', core)  # \s* -> space
    core = re.sub(r'\\s\+', ' ', core)  # \s+ -> space
    core = re.sub(r'\\d\+', '#', core)  # \d+ -> #
    core = re.sub(r'\\d\*', '', core)   # \d* -> empty
    core = re.sub(r'\\d', '#', core)    # \d -> #
    core = re.sub(r'\[\^"\]\*', '', core)  # [^"]* -> empty
    core = re.sub(r'\.\*', '', core)    # .* -> empty
    core = re.sub(r'\.\+', '', core)    # .+ -> empty
    core = re.sub(r'[()?\[\]^$|\\]', '', core)  # Remove special chars
    core = re.sub(r'\{[\d,]+\}', '', core)  # Remove quantifiers
    return core.strip()


def check_generic_patterns(patterns_by_vendor: Dict) -> List[Tuple[str, str, str, str]]:
    """Find patterns that are too generic and could match unrelated devices."""
    issues = []

    for vendor, patterns in patterns_by_vendor.items():
        for pattern_tuple in patterns:
            if len(pattern_tuple) < 4:
                continue

            regex, product, device_type, os_family = pattern_tuple[:4]
            core = extract_pattern_core(regex)

            # Check if pattern is just a generic word
            if core.lower() in GENERIC_WORDS:
                issues.append((
                    vendor, regex, device_type,
                    f"Generic word '{core}' - could match unrelated devices"
                ))

            # Check for very short patterns (excluding known abbreviations)
            if len(core) <= 2 and core.upper() not in SHORT_PATTERN_EXCEPTIONS:
                issues.append((
                    vendor, regex, device_type,
                    f"Very short pattern '{core}' - likely too generic"
                ))

            # Check for single letter + digit patterns like S\d+, M\d+
            if re.match(r'^[A-Za-z]#*$', core) and len(core) <= 3:
                issues.append((
                    vendor, regex, device_type,
                    f"Single letter pattern '{regex}' - could match many things"
                ))

    return issues


def check_cross_vendor_conflicts(patterns_by_vendor: Dict) -> List[Tuple[str, str, List[str]]]:
    """Find patterns that match across multiple vendors."""
    # Build index of pattern -> vendors
    pattern_vendors = defaultdict(list)

    for vendor, patterns in patterns_by_vendor.items():
        for pattern_tuple in patterns:
            if len(pattern_tuple) < 4:
                continue
            regex = pattern_tuple[0]
            core = extract_pattern_core(regex).lower()
            if core and len(core) >= 3:
                pattern_vendors[core].append((vendor, regex, pattern_tuple[2]))

    # Find conflicts
    conflicts = []
    for core, vendors in pattern_vendors.items():
        if len(vendors) > 1:
            # Check if they have different device types
            device_types = set(v[2] for v in vendors)
            if len(device_types) > 1:
                conflicts.append((
                    core,
                    f"Pattern matches with different device types",
                    [(v[0], v[1], v[2]) for v in vendors]
                ))

    return conflicts


def check_missing_vendor_context(patterns_by_vendor: Dict) -> List[Tuple[str, str, str, str]]:
    """Find patterns that should include vendor name but don't."""
    issues = []

    # Vendors that should have their name in patterns
    context_required_vendors = {
        'SAMSUNG', 'LG', 'SONY', 'APPLE', 'GOOGLE', 'AMAZON', 'MICROSOFT',
        'HUAWEI', 'XIAOMI', 'ARLO', 'RING', 'NEST', 'PHILIPS', 'HONEYWELL',
        'SIEMENS', 'SCHNEIDER', 'ABB', 'MOBOTIX', 'HIKVISION', 'DAHUA',
    }

    for vendor, patterns in patterns_by_vendor.items():
        if vendor not in context_required_vendors:
            continue

        for pattern_tuple in patterns:
            if len(pattern_tuple) < 4:
                continue

            regex, product, device_type, os_family = pattern_tuple[:4]

            # Skip if pattern already includes vendor name
            if vendor.lower() in regex.lower():
                continue

            # Skip generic fallback patterns (they're intentional)
            if regex.lower() == vendor.lower():
                continue

            core = extract_pattern_core(regex)

            # Flag patterns that are model numbers without vendor context
            # e.g., "S\d+" should be "Samsung S\d+" or "MOBOTIX S\d+"
            if re.match(r'^[A-Z]\d', core) or re.match(r'^[A-Z]{1,2}#', core):
                issues.append((
                    vendor, regex, device_type,
                    f"Model pattern '{regex}' lacks vendor context - could match other brands"
                ))

    return issues


def check_device_type_consistency(patterns_by_vendor: Dict) -> List[Tuple[str, str, str, str]]:
    """Find inconsistent device type usage."""
    issues = []

    # Expected device types for certain product keywords
    expected_types = {
        'tv': {'tv', 'smart_tv'},
        'television': {'tv', 'smart_tv'},
        'phone': {'phone', 'smartphone', 'mobile'},
        'smartphone': {'phone', 'smartphone', 'mobile'},
        'tablet': {'tablet'},
        'laptop': {'laptop', 'computer'},
        'router': {'router', 'mesh_router', 'gateway'},
        'switch': {'switch'},
        'camera': {'ip_camera', 'camera', 'ptz_camera', 'thermal_camera', 'doorbell_camera'},
        'printer': {'printer', 'laser_printer', 'inkjet_printer', 'mfp'},
        'speaker': {'speaker', 'smart_speaker', 'soundbar'},
        'watch': {'smartwatch', 'wearable'},
        'thermostat': {'thermostat'},
        'doorbell': {'doorbell', 'doorbell_camera'},
    }

    for vendor, patterns in patterns_by_vendor.items():
        for pattern_tuple in patterns:
            if len(pattern_tuple) < 4:
                continue

            regex, product, device_type, os_family = pattern_tuple[:4]
            product_lower = product.lower()

            for keyword, expected in expected_types.items():
                if keyword in product_lower:
                    if device_type not in expected:
                        issues.append((
                            vendor, regex, device_type,
                            f"Product '{product}' contains '{keyword}' but device_type is '{device_type}' (expected: {expected})"
                        ))
                    break

    return issues


def check_regex_syntax(patterns_by_vendor: Dict) -> List[Tuple[str, str, str]]:
    """Find patterns with regex syntax errors."""
    issues = []

    for vendor, patterns in patterns_by_vendor.items():
        for pattern_tuple in patterns:
            if len(pattern_tuple) < 1:
                continue

            regex = pattern_tuple[0]
            try:
                re.compile(regex)
            except re.error as e:
                issues.append((vendor, regex, str(e)))

    return issues


def main():
    print("=" * 70)
    print("CYGOR PATTERN AUDIT REPORT")
    print("=" * 70)

    patterns_by_vendor = get_all_banner_patterns()
    total_patterns = sum(len(p) for p in patterns_by_vendor.values())
    print(f"\nAnalyzing {total_patterns} patterns across {len(patterns_by_vendor)} vendors...\n")

    all_issues = []

    # Check regex syntax first
    print("=" * 70)
    print("1. REGEX SYNTAX ERRORS")
    print("=" * 70)
    syntax_errors = check_regex_syntax(patterns_by_vendor)
    if syntax_errors:
        for vendor, regex, error in syntax_errors:
            print(f"  {vendor}: {regex}")
            print(f"    Error: {error}")
        all_issues.extend(syntax_errors)
    else:
        print("  No syntax errors found")

    # Check generic patterns
    print("\n" + "=" * 70)
    print("2. OVERLY GENERIC PATTERNS (potential false matches)")
    print("=" * 70)
    generic_issues = check_generic_patterns(patterns_by_vendor)
    if generic_issues:
        for vendor, regex, device_type, reason in generic_issues[:30]:
            print(f"  {vendor}: r\"{regex}\" -> {device_type}")
            print(f"    Issue: {reason}")
        if len(generic_issues) > 30:
            print(f"  ... and {len(generic_issues) - 30} more")
        all_issues.extend(generic_issues)
    else:
        print("  No overly generic patterns found")

    # Check missing vendor context
    print("\n" + "=" * 70)
    print("3. PATTERNS MISSING VENDOR CONTEXT")
    print("=" * 70)
    context_issues = check_missing_vendor_context(patterns_by_vendor)
    if context_issues:
        for vendor, regex, device_type, reason in context_issues[:30]:
            print(f"  {vendor}: r\"{regex}\" -> {device_type}")
            print(f"    Issue: {reason}")
        if len(context_issues) > 30:
            print(f"  ... and {len(context_issues) - 30} more")
        all_issues.extend(context_issues)
    else:
        print("  No missing context issues found")

    # Check device type consistency
    print("\n" + "=" * 70)
    print("4. DEVICE TYPE INCONSISTENCIES")
    print("=" * 70)
    type_issues = check_device_type_consistency(patterns_by_vendor)
    if type_issues:
        for vendor, regex, device_type, reason in type_issues[:30]:
            print(f"  {vendor}: r\"{regex}\" -> {device_type}")
            print(f"    Issue: {reason}")
        if len(type_issues) > 30:
            print(f"  ... and {len(type_issues) - 30} more")
        all_issues.extend(type_issues)
    else:
        print("  No device type inconsistencies found")

    # Check cross-vendor conflicts
    print("\n" + "=" * 70)
    print("5. CROSS-VENDOR PATTERN CONFLICTS")
    print("=" * 70)
    conflicts = check_cross_vendor_conflicts(patterns_by_vendor)
    if conflicts:
        for core, reason, vendors in conflicts[:20]:
            print(f"  Pattern core: '{core}'")
            print(f"    {reason}:")
            for v, r, d in vendors:
                print(f"      - {v}: r\"{r}\" -> {d}")
        if len(conflicts) > 20:
            print(f"  ... and {len(conflicts) - 20} more")
    else:
        print("  No cross-vendor conflicts found")

    # Summary
    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total patterns analyzed: {total_patterns}")
    print(f"Syntax errors: {len(syntax_errors)}")
    print(f"Generic patterns: {len(generic_issues)}")
    print(f"Missing vendor context: {len(context_issues)}")
    print(f"Device type issues: {len(type_issues)}")
    print(f"Cross-vendor conflicts: {len(conflicts)}")

    total_issues = len(syntax_errors) + len(generic_issues) + len(context_issues) + len(type_issues) + len(conflicts)

    if total_issues == 0:
        print("\n✓ NO ISSUES FOUND")
        return 0
    else:
        print(f"\n⚠ {total_issues} POTENTIAL ISSUES FOUND")
        print("Review the above and fix high-priority items")
        return 1


if __name__ == "__main__":
    sys.exit(main())
