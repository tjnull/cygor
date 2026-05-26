"""
Cygor Fingerprinting Module.

Device fingerprinting using JSON-based databases.
No SQLite/SQLAlchemy required - all data stored in ~/.cache/cygor/fingerprints/

Databases:
- IEEE OUI: MAC address to manufacturer lookup
- JA3: TLS client fingerprints (SSLBL malicious + Trisul community)
- JA4+: JA4 TLS fingerprints from ja4db.com
- p0f: TCP/IP stack fingerprints for OS detection
- Banners: Service banner patterns

Usage:
    from cygor.fingerprinting import FingerprintLookup, sync_fingerprints

    # Sync databases
    import asyncio
    asyncio.run(sync_fingerprints())

    # Lookup
    lookup = FingerprintLookup()
    match = await lookup.lookup_mac("00:11:22:33:44:55")
"""

from .cache import FingerprintCache, get_cache, get_cache_dir
from .lookup import FingerprintLookup, FingerprintMatch, aggregate_evidence
from .sync import JSONSyncEngine, sync_fingerprints
from .fingerprint import (
    DeviceFingerprint,
    fingerprint_host,
    fingerprint_from_host,
    fingerprint_host_sync,
    fingerprint_nmap_results,
)

__all__ = [
    # Cache
    "FingerprintCache",
    "get_cache",
    "get_cache_dir",
    # Lookup
    "FingerprintLookup",
    "FingerprintMatch",
    "aggregate_evidence",
    # Sync
    "JSONSyncEngine",
    "sync_fingerprints",
    # Device fingerprinting
    "DeviceFingerprint",
    "fingerprint_host",
    "fingerprint_from_host",
    "fingerprint_host_sync",
    "fingerprint_nmap_results",
]
