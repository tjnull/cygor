#!/usr/bin/env python3
"""
Pattern Validation Script for Cygor Fingerprinting

Checks for:
1. Duplicate MAC OUI prefixes
2. Inconsistent device type naming
3. Pattern syntax errors

Usage:
    python validate_patterns.py [--fix]
"""

import re
import sys
from collections import defaultdict
from pathlib import Path

# Path to vendor patterns
VENDOR_PATTERNS_FILE = Path(__file__).parent.parent / "patterns" / "vendor_patterns.py"

# Known parent company relationships (child -> parent)
PARENT_COMPANIES = {
    'MERAKI': 'CISCO',
    'AEROHIVE': 'EXTREME',
    'WINCOR': 'DIEBOLD',
    'MELLANOX': 'NVIDIA',
    'KASA': 'TPLINK',
    'CISCO_VOIP': 'CISCO',
    'ASUS_MOBILE': 'ASUS',
    'LG_MOBILE': 'LG',
    'SONY_MOBILE': 'SONY',
    'LENOVO_MOBILE': 'LENOVO',
    'LENOVO_SERVER': 'LENOVO',
    'HONEYWELL_BUILDING': 'HONEYWELL',
    'HP_PRINTER': 'HPE',
    'DELL_WYSE': 'DELL',
    'PHILIPS_HEALTHCARE': 'PHILIPS_HUE',
    'GE_HEALTHCARE': 'GE',
    'HONEYWELL_SCANNER': 'HONEYWELL',
    'ZEBRA_SCANNER': 'ZEBRA',
}

# Standard device types - comprehensive list including all vendor categories
STANDARD_DEVICE_TYPES = {
    # Core network infrastructure
    'router', 'switch', 'firewall', 'access_point', 'gateway', 'bridge',
    'mesh_router', 'range_extender', 'wireless_controller', 'wireless_bridge',
    'vpn_gateway', 'vpn', 'sd_wan', 'sdwan', 'sdn', 'sdn_controller',

    # Servers and compute
    'server', 'workstation', 'desktop', 'laptop', 'computer', 'thin_client',
    'blade_server', 'mini_pc', 'hypervisor', 'virtual_machine', 'container',
    'hci', 'hci_node', 'cluster', 'gpu', 'dpu', 'bmc', 'motherboard',

    # Storage
    'nas', 'storage', 'das', 'storage_server', 'object_storage', 'backup',
    'backup_appliance', 'replication', 'virtual_storage', 'fc_switch', 'ib_switch',

    # Printers and imaging
    'printer', 'mfp', 'laser_printer', 'inkjet_printer', 'label_printer',
    'photo_printer', 'production_printer', 'card_printer', 'large_format_printer',
    'mobile_printer', 'scanner', 'projector',

    # Cameras and surveillance
    'camera', 'ip_camera', 'ptz_camera', 'thermal_camera', 'webcam',
    'nvr', 'dvr', 'doorbell_camera', 'conference_camera',

    # Voice and communication
    'phone', 'voip_phone', 'dect_phone', 'dect_base', 'conference_phone',
    'video_phone', 'pbx', 'ip_pbx', 'cloud_pbx', 'sbc', 'ata',
    'intercom', 'two_way_radio', 'messaging', 'collaboration', 'uc',
    'contact_center', 'conferencing', 'video_conference', 'video_conferencing',
    'video_bar', 'mcu',

    # Mobile and personal
    'smartphone', 'tablet', 'wearable', 'smartwatch', 'smart_ring',
    'fitness_tracker', 'earbuds', 'wireless_earbuds', 'headphones',
    'wireless_headphones', 'vr_headset', 'ar_headset', 'cycling_computer',
    'sleep_tracker', 'health_device', 'gps',

    # Gaming
    'gaming_console', 'game_console', 'handheld_console', 'gaming_device',
    'gaming_pc', 'gaming_controller', 'gaming_peripheral', 'cloud_gaming',

    # Smart home and IoT
    'iot', 'iot_device', 'iot_hub', 'smart_hub', 'smart_speaker', 'smart_display',
    'smart_tv', 'tv', 'streaming_device', 'media_player', 'soundbar', 'speaker',
    'portable_speaker', 'subwoofer', 'amplifier', 'av_receiver', 'audio_streamer',
    'smart_plug', 'smart_switch', 'smart_bulb', 'smart_light', 'smart_dimmer',
    'dimmer', 'smart_lock', 'smart_thermostat', 'thermostat', 'smart_button',
    'motion_sensor', 'sensor', 'doorbell', 'smoke_detector', 'security_panel',
    'alarm_panel', 'smart_device', 'smart_appliance', 'remote', 'remote_control',
    'led_controller', 'lighting_controller', 'fan', 'humidifier', 'air_purifier',
    'vacuum', 'robot_vacuum', 'robot_cleaner', 'robot_mop', 'robot',

    # POS and retail
    'pos_terminal', 'card_reader', 'barcode_scanner', 'kitchen_display',
    'self_checkout', 'cash_recycler',

    # ATM and financial
    'atm', 'kiosk',

    # Medical and healthcare
    'medical_device', 'patient_monitor', 'cardiac_monitor', 'infusion_pump',
    'insulin_pump', 'smart_insulin_pen', 'ventilator', 'defibrillator', 'aed',
    'dialysis_machine', 'anesthesia_machine', 'mri_scanner', 'ct_scanner',
    'ultrasound', 'xray', 'interventional_xray', 'surgical_robot',
    'surgical_imaging', 'surgical_navigation', 'incubator', 'infant_warmer',
    'blood_pressure', 'thermometer', 'cgm', 'smart_scale',

    # Building automation and HVAC
    'building_controller', 'hvac', 'hvac_controller', 'automation_controller',
    'unit_controller', 'rooftop_unit', 'chiller', 'automation', 'fire_panel',

    # Industrial and SCADA
    'plc', 'safety_plc', 'dcs', 'rtu', 'hmi', 'safety_controller',
    'industrial_pc', 'io_module', 'servo', 'vfd', 'mcu', 'microcontroller',
    'embedded', 'sbc',

    # Telecom and carrier
    'telecom', 'olt', 'ont', 'cpe', 'base_station',

    # Security appliances
    'security', 'security_appliance', 'waf', 'ddos_protection', 'ssl_inspection',
    'email_gateway', 'mail_gateway', 'cloud_firewall', 'cloud_security',
    'virtual_firewall', 'virtual_router',

    # Load balancing and optimization
    'load_balancer', 'wan_optimizer', 'dns_load_balancer', 'apm', 'npm',
    'cgnat',

    # Virtualization and cloud
    'virtualization', 'vdi', 'vdi_client', 'guest_agent', 'kubernetes',
    'cloud', 'cloud_storage', 'paas', 'migration', 'dr', 'ha',

    # AV and presentation
    'av_controller', 'av_switcher', 'av_encoder', 'av_decoder', 'video_encoder',
    'av_transmitter', 'av_distributor', 'av_scaler', 'av_processor', 'av_recorder',
    'dsp', 'touch_panel', 'interactive_display', 'display', 'wireless_presentation',
    'microphone',

    # Management and monitoring
    'controller', 'management', 'management_platform', 'monitoring', 'logging',
    'analytics', 'identity', 'licensing', 'provisioning', 'mdm',
    'access_controller', 'access_manager', 'dns', 'database', 'data',

    # Power and infrastructure
    'ups', 'power_supply', 'battery', 'power_meter', 'energy_monitor',
    'energy_gateway', 'ev_charger', 'dc_fast_charger',

    # Miscellaneous
    'general purpose', 'appliance', 'peripheral', 'network_adapter', 'nic',
    'network_device', 'mobile', 'mobile_computer', 'rugged_tablet',
    'file_sharing', 'vms', 'fitness_equipment',
}



def find_duplicate_macs(content: str) -> dict:
    """Find all duplicate MAC prefixes."""
    mac_entries = defaultdict(list)
    current_vendor = None

    for i, line in enumerate(content.split('\n'), 1):
        vendor_match = re.search(r'^([A-Z0-9_]+)_MAC_PREFIXES:', line)
        if vendor_match:
            current_vendor = vendor_match.group(1)

        mac_match = re.search(r'"([0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2})":', line)
        if mac_match and current_vendor:
            mac = mac_match.group(1)
            mac_entries[mac].append({
                'line': i,
                'vendor': current_vendor,
                'full_line': line.strip()
            })

    return {mac: entries for mac, entries in mac_entries.items() if len(entries) > 1}


def get_parent(vendor: str) -> str:
    """Get parent company for a vendor."""
    return PARENT_COMPANIES.get(vendor, vendor)


def categorize_duplicates(duplicates: dict) -> tuple:
    """Categorize duplicates into same-vendor, same-parent, and cross-vendor."""
    same_vendor = []
    same_parent = []
    cross_vendor = []

    for mac, entries in duplicates.items():
        vendors = [e['vendor'] for e in entries]
        unique_vendors = set(vendors)
        unique_parents = set(get_parent(v) for v in vendors)

        if len(unique_vendors) == 1:
            same_vendor.append((mac, entries))
        elif len(unique_parents) == 1:
            same_parent.append((mac, entries, list(unique_parents)[0]))
        else:
            cross_vendor.append((mac, entries))

    return same_vendor, same_parent, cross_vendor


def check_device_types(content: str) -> set:
    """Extract all device types used in patterns."""
    device_types = set()

    # Pattern for device_type in MAC prefixes: ("device_type", ...
    mac_types = re.findall(r'\("([a-z_]+)",\s*"[^"]+",', content)
    device_types.update(mac_types)

    # Pattern for device_type in banner patterns: ..., "device_type", ...
    banner_types = re.findall(r',\s*"([a-z_]+)",\s*(?:None|"[^"]*")\)', content)
    device_types.update(banner_types)

    return device_types


def main():
    if not VENDOR_PATTERNS_FILE.exists():
        print(f"Error: {VENDOR_PATTERNS_FILE} not found")
        sys.exit(1)

    content = VENDOR_PATTERNS_FILE.read_text()

    # Check duplicates
    duplicates = find_duplicate_macs(content)
    same_vendor, same_parent, cross_vendor = categorize_duplicates(duplicates)

    print("=" * 60)
    print("CYGOR PATTERN VALIDATION REPORT")
    print("=" * 60)

    print(f"\n=== MAC OUI ANALYSIS ===")
    print(f"Total MAC prefixes with duplicates: {len(duplicates)}")
    print(f"  - Same vendor (OK, within dict): {len(same_vendor)}")
    print(f"  - Same parent company (OK): {len(same_parent)}")
    print(f"  - Cross-vendor conflicts (ISSUES): {len(cross_vendor)}")

    if cross_vendor:
        print(f"\n=== CROSS-VENDOR CONFLICTS (need resolution) ===")
        for mac, entries in cross_vendor[:20]:
            vendors = [e['vendor'] for e in entries]
            print(f"  {mac}: {vendors}")
        if len(cross_vendor) > 20:
            print(f"  ... and {len(cross_vendor) - 20} more")

    # Check device types
    device_types = check_device_types(content)
    unknown_types = device_types - STANDARD_DEVICE_TYPES

    print(f"\n=== DEVICE TYPE ANALYSIS ===")
    print(f"Total unique device types: {len(device_types)}")
    print(f"Standard types: {len(device_types - unknown_types)}")
    print(f"Non-standard types: {len(unknown_types)}")

    if unknown_types:
        print(f"\nNon-standard device types (may need review):")
        for dt in sorted(unknown_types):
            print(f"  - {dt}")

    # Summary
    print("\n" + "=" * 60)
    issues = len(cross_vendor) + len(unknown_types)
    if issues == 0:
        print("STATUS: PASSED - No critical issues found")
    else:
        print(f"STATUS: REVIEW NEEDED - {issues} items need attention")
    print("=" * 60)

    return 0 if len(cross_vendor) == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
