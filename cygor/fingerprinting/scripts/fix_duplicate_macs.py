#!/usr/bin/env python3
"""
Fix duplicate MAC OUI prefixes in vendor_patterns.py

Uses the OUI database to determine correct vendor assignments and
removes duplicate entries that conflict with IEEE assignments.

Usage:
    python fix_duplicate_macs.py --dry-run  # Show what would change
    python fix_duplicate_macs.py --fix      # Actually fix the file
"""

import re
import sys
import json
import argparse
from collections import defaultdict
from pathlib import Path

# Paths
SCRIPT_DIR = Path(__file__).parent
VENDOR_PATTERNS = SCRIPT_DIR.parent / "patterns" / "vendor_patterns.py"
OUI_CACHE = SCRIPT_DIR.parent.parent.parent / "data" / "fingerprints" / "oui.json"

# Known company relationships (normalize to canonical name)
COMPANY_ALIASES = {
    'CISCO MERAKI': 'CISCO',
    'CISCO SYSTEMS': 'CISCO',
    'CISCO-LINKSYS': 'LINKSYS',
    'SONY INTERACTIVE': 'SONY',
    'SONY CORPORATION': 'SONY',
    'HEWLETT PACKARD': 'HPE',
    'HP INC': 'HPE',
    'D-LINK INTERNATIONAL': 'DLINK',
    'D-LINK CORPORATION': 'DLINK',
    'SAMSUNG ELECTRONICS': 'SAMSUNG',
    'LG ELECTRONICS': 'LG',
    'ASUS': 'ASUS',
    'ASUSTEK': 'ASUS',
    'APPLE': 'APPLE',
    'ARUBA': 'ARUBA',
    'HUAWEI': 'HUAWEI',
    'ZYXEL': 'ZYXEL',
    'NINTENDO': 'NINTENDO',
    'MICROSOFT': 'MICROSOFT',
    'GOOGLE': 'GOOGLE',
    'AMAZON': 'AMAZON',
    'UBIQUITI': 'UBIQUITI',
    'MIKROTIK': 'MIKROTIK',
    'NETGEAR': 'NETGEAR',
    'TP-LINK': 'TPLINK',
    'FORTINET': 'FORTINET',
    'PALO ALTO': 'PALOALTO',
    'JUNIPER': 'JUNIPER',
    'DELL': 'DELL',
    'LENOVO': 'LENOVO',
    'SYNOLOGY': 'SYNOLOGY',
    'QNAP': 'QNAP',
    'HIKVISION': 'HIKVISION',
    'DAHUA': 'DAHUA',
}


def load_oui_database() -> dict:
    """Load OUI database from cache."""
    if not OUI_CACHE.exists():
        print(f"Warning: OUI cache not found at {OUI_CACHE}")
        return {}

    with open(OUI_CACHE) as f:
        data = json.load(f)

    # Convert to prefix -> vendor mapping
    oui_map = {}
    for prefix, info in data.get('prefixes', {}).items():
        vendor = info.get('vendor', info.get('manufacturer', ''))
        oui_map[prefix.upper()] = vendor.upper()

    return oui_map


def normalize_vendor(vendor: str) -> str:
    """Normalize vendor name to canonical form."""
    vendor_upper = vendor.upper()
    for alias, canonical in COMPANY_ALIASES.items():
        if alias in vendor_upper:
            return canonical
    return vendor_upper.split()[0] if vendor_upper else ''


def find_duplicates(content: str) -> dict:
    """Find all duplicate MAC prefixes with line info."""
    mac_entries = defaultdict(list)
    current_vendor = None

    lines = content.split('\n')
    for i, line in enumerate(lines, 1):
        vendor_match = re.search(r'^([A-Z0-9_]+)_MAC_PREFIXES:', line)
        if vendor_match:
            current_vendor = vendor_match.group(1)

        mac_match = re.search(r'"([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})":', line)
        if mac_match and current_vendor:
            mac = mac_match.group(1)
            mac_entries[mac].append({
                'line_num': i,
                'line_idx': i - 1,
                'vendor': current_vendor,
                'line': line
            })

    return {mac: entries for mac, entries in mac_entries.items() if len(entries) > 1}


def determine_correct_vendor(mac: str, entries: list, oui_db: dict) -> str:
    """Determine which vendor should keep this MAC prefix."""
    # Check OUI database
    ieee_vendor = oui_db.get(mac, '')
    if ieee_vendor:
        ieee_normalized = normalize_vendor(ieee_vendor)

        # Find best match among entries
        for entry in entries:
            if ieee_normalized in entry['vendor'].upper():
                return entry['vendor']
            if entry['vendor'].upper() in ieee_normalized:
                return entry['vendor']

    # Fallback: keep first occurrence
    return entries[0]['vendor']


def fix_duplicates(dry_run: bool = True):
    """Fix duplicate MAC prefixes."""
    if not VENDOR_PATTERNS.exists():
        print(f"Error: {VENDOR_PATTERNS} not found")
        return 1

    content = VENDOR_PATTERNS.read_text()
    lines = content.split('\n')

    oui_db = load_oui_database()
    print(f"Loaded {len(oui_db)} OUI entries from database")

    duplicates = find_duplicates(content)
    print(f"Found {len(duplicates)} MAC prefixes with duplicates")

    lines_to_comment = []

    for mac, entries in duplicates.items():
        if len(set(e['vendor'] for e in entries)) == 1:
            # Same vendor - skip (Python dict handles this)
            continue

        correct_vendor = determine_correct_vendor(mac, entries, oui_db)
        ieee_vendor = oui_db.get(mac, 'Unknown')

        for entry in entries:
            if entry['vendor'] != correct_vendor:
                lines_to_comment.append({
                    'line_idx': entry['line_idx'],
                    'mac': mac,
                    'wrong_vendor': entry['vendor'],
                    'correct_vendor': correct_vendor,
                    'ieee_vendor': ieee_vendor,
                })

    print(f"\nWill comment out {len(lines_to_comment)} incorrect entries")

    if dry_run:
        print("\n=== DRY RUN - Changes that would be made ===")
        for change in lines_to_comment[:30]:
            print(f"  Line {change['line_idx']+1}: {change['mac']} - "
                  f"remove from {change['wrong_vendor']} "
                  f"(IEEE: {change['ieee_vendor']}, keep in: {change['correct_vendor']})")
        if len(lines_to_comment) > 30:
            print(f"  ... and {len(lines_to_comment) - 30} more")
        return 0

    # Actually fix the file
    for change in sorted(lines_to_comment, key=lambda x: x['line_idx'], reverse=True):
        idx = change['line_idx']
        old_line = lines[idx]
        # Comment out the line with explanation
        lines[idx] = f"    # REMOVED: {change['mac']} - IEEE assigns to {change['ieee_vendor']}, not {change['wrong_vendor']}"

    # Write back
    VENDOR_PATTERNS.write_text('\n'.join(lines))
    print(f"\nFixed {len(lines_to_comment)} duplicate entries")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Fix duplicate MAC OUI prefixes")
    parser.add_argument('--dry-run', action='store_true',
                        help="Show what would change without making changes")
    parser.add_argument('--fix', action='store_true',
                        help="Actually fix the file")
    args = parser.parse_args()

    if not args.dry_run and not args.fix:
        print("Please specify --dry-run or --fix")
        return 1

    return fix_duplicates(dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
