"""
File-based cache for fingerprint databases.

Provides local file storage for fingerprint data that works without a database.
Cache files are stored in ~/.cache/cygor/fingerprints/

Cache Files:
- oui.json         - MAC OUI manufacturer lookup
- tcpip.json       - TCP/IP stack fingerprints (p0f)
- banners.json     - Service banner patterns
- sync_status.json - Sync status for all sources
"""

import os
import json
import logging
import re
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, List, Any


def _atomic_write_json(path: Path, data: Any) -> None:
    """Write ``data`` to ``path`` as JSON without leaving a partial file behind.

    A KeyboardInterrupt or kill during a 100MB+ fingerprint cache write
    used to leave a truncated JSON; next startup's ``json.load`` raised
    and the in-memory cache silently reset to empty. Atomic temp+rename
    means the destination either has the previous contents or the new
    contents -- never half of either.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # mkstemp on the same directory so os.replace() is atomic (no
    # cross-device fallback). The 'tmp' prefix + random suffix avoids
    # collisions with concurrent saves of the same cache file.
    fd, tmp_path = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            try:
                os.fsync(f.fileno())  # durability: survive a panic/kill
            except OSError:
                pass  # not supported on every fs; the rename below is the
                      # real atomicity guarantee
        os.replace(tmp_path, path)
    except Exception:
        # Clean up the temp on failure so we don't leave .tmp turds behind.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

logger = logging.getLogger(__name__)


_TOKEN_SPLIT_RE = re.compile(r"[^a-zA-Z0-9]+")


def _tokenize_for_match(text: str) -> List[str]:
    """Lowercase + split on non-alphanumeric characters; filter blanks."""
    if not text:
        return []
    return [t for t in _TOKEN_SPLIT_RE.split(text.lower()) if t]


def get_cache_dir() -> Path:
    """
    Get the fingerprint cache directory.

    When running with sudo, uses the original user's home directory
    to avoid re-downloading databases that already exist.

    Returns:
        Path to ~/.cache/cygor/fingerprints/
    """
    # Check for custom cache dir in environment
    custom_dir = os.environ.get("CYGOR_FINGERPRINT_CACHE")
    if custom_dir:
        cache_dir = Path(custom_dir)
    else:
        # When running with sudo, use the original user's home directory
        # SUDO_USER is set when running via sudo
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            # Get original user's home directory
            import pwd
            try:
                user_home = Path(pwd.getpwnam(sudo_user).pw_dir)
                cache_dir = user_home / ".cache" / "cygor" / "fingerprints"
            except KeyError:
                # Fallback if user lookup fails
                cache_dir = Path.home() / ".cache" / "cygor" / "fingerprints"
        else:
            cache_dir = Path.home() / ".cache" / "cygor" / "fingerprints"

    # Create directory if it doesn't exist
    cache_dir.mkdir(parents=True, exist_ok=True)

    return cache_dir


def get_cache_file(name: str) -> Path:
    """
    Get path to a specific cache file.

    Args:
        name: Cache file name (e.g., 'oui', 'ja3')

    Returns:
        Full path to the cache file
    """
    return get_cache_dir() / f"{name}.json"


class FingerprintCache:
    """
    File-based cache for fingerprint data.

    Provides a fallback when database is not available,
    and serves as a persistent local copy of fingerprint databases.
    """

    # Cache file names
    CACHE_FILES = {
        "oui": "oui.json",
        "tcpip": "tcpip.json",
        "banners": "banners.json",
        "sync_status": "sync_status.json",
        # Huginn-Muninn databases (device fingerprinting)
        "huginn_devices": "huginn_devices.json",
        "huginn_dhcp": "huginn_dhcp.json",
        "huginn_dhcp_vendor": "huginn_dhcp_vendor.json",
        "huginn_dhcpv6": "huginn_dhcpv6.json",
        "huginn_dhcpv6_enterprise": "huginn_dhcpv6_enterprise.json",
        "huginn_mac_vendors": "huginn_mac_vendors.json",
        # Satori fingerprint databases
        "satori_ssh": "satori_ssh.json",
        "satori_smb": "satori_smb.json",
        "satori_http": "satori_http.json",
        "satori_useragent": "satori_useragent.json",
        "satori_dhcp": "satori_dhcp.json",
        "satori_sip": "satori_sip.json",
        # Huginn-Muninn DHCP Combinations
        "huginn_combinations": "huginn_combinations.json",
        # OS Fingerprints
        "nmap_os_db": "nmap_os_db.json",
    }

    def __init__(self, cache_dir: Path = None):
        """
        Initialize fingerprint cache.

        Args:
            cache_dir: Optional custom cache directory
        """
        self.cache_dir = cache_dir or get_cache_dir()
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # In-memory caches (lazy loaded)
        self._oui_cache: Optional[Dict[str, Dict]] = None
        self._tcpip_cache: Optional[List[Dict]] = None
        self._banners_cache: Optional[List[Dict]] = None
        # Huginn-Muninn caches (device fingerprinting)
        self._huginn_devices_cache: Optional[Dict[str, Dict]] = None
        self._huginn_dhcp_cache: Optional[Dict[str, Dict]] = None
        self._huginn_dhcp_vendor_cache: Optional[Dict[str, Dict]] = None
        self._huginn_dhcpv6_cache: Optional[Dict[str, Dict]] = None
        self._huginn_dhcpv6_enterprise_cache: Optional[Dict[str, Dict]] = None
        self._huginn_mac_vendors_cache: Optional[Dict[str, Dict]] = None
        # Lookup indexes for fast matching
        self._huginn_dhcp_hash_index: Optional[Dict[str, str]] = None  # hash -> fp_id
        self._huginn_device_name_index: Optional[Dict[str, str]] = None  # lowercase name -> device_id
        # Token index: significant token (len >= 4) -> set of device_ids that
        # contain it. Used by hostname-based fuzzy matching.
        self._huginn_device_token_index: Optional[Dict[str, set]] = None
        # Satori fingerprint caches
        self._satori_ssh_cache: Optional[List[Dict]] = None
        self._satori_smb_cache: Optional[List[Dict]] = None
        self._satori_http_cache: Optional[List[Dict]] = None
        self._satori_useragent_cache: Optional[List[Dict]] = None
        self._satori_dhcp_cache: Optional[List[Dict]] = None
        self._satori_sip_cache: Optional[List[Dict]] = None
        self._huginn_combinations_cache: Optional[Dict[str, Dict]] = None
        # OS Fingerprint caches
        self._nmap_os_db_cache: Optional[List[Dict]] = None

    def clear_memory_cache(self):
        """Clear in-memory caches to force reload from files."""
        self._oui_cache = None
        self._tcpip_cache = None
        self._banners_cache = None
        self._huginn_devices_cache = None
        self._huginn_dhcp_cache = None
        self._huginn_dhcp_vendor_cache = None
        self._huginn_dhcpv6_cache = None
        self._huginn_dhcpv6_enterprise_cache = None
        self._huginn_mac_vendors_cache = None
        self._huginn_dhcp_hash_index = None
        self._huginn_device_name_index = None
        self._huginn_device_token_index = None
        # Satori fingerprints
        self._satori_ssh_cache = None
        self._satori_smb_cache = None
        self._satori_http_cache = None
        self._satori_useragent_cache = None
        self._satori_dhcp_cache = None
        self._satori_sip_cache = None
        self._huginn_combinations_cache = None
        # OS Fingerprints
        self._nmap_os_db_cache = None

    @property
    def oui_file(self) -> Path:
        return self.cache_dir / self.CACHE_FILES["oui"]

    @property
    def tcpip_file(self) -> Path:
        return self.cache_dir / self.CACHE_FILES["tcpip"]

    @property
    def banners_file(self) -> Path:
        return self.cache_dir / self.CACHE_FILES["banners"]

    @property
    def status_file(self) -> Path:
        return self.cache_dir / self.CACHE_FILES["sync_status"]

    # =========================================================================
    # OUI Cache (MAC -> Manufacturer)
    # =========================================================================

    def load_oui(self) -> Dict[str, Dict]:
        """
        Load OUI cache from file.

        Returns:
            Dict mapping OUI (e.g., "00:00:0C") to vendor info
        """
        if self._oui_cache is not None:
            return self._oui_cache

        if self.oui_file.exists():
            try:
                with open(self.oui_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._oui_cache = data.get("entries", {})
                    logger.debug(f"Loaded {len(self._oui_cache)} OUI entries from cache")
                    return self._oui_cache
            except Exception as e:
                logger.warning(f"Failed to load OUI cache: {e}")

        self._oui_cache = {}
        return self._oui_cache

    def save_oui(self, entries: Dict[str, Dict], metadata: Dict = None) -> bool:
        """
        Save OUI data to cache file.

        Args:
            entries: Dict mapping OUI to vendor info (vendor, vendor_short, device_type, etc.)
            metadata: Optional metadata (source, timestamp, etc.)

        Returns:
            True if saved successfully
        """
        try:
            # Determine source from metadata or default
            source = metadata.get("source", "ieee_oui") if metadata else "ieee_oui"

            # Set URL based on source
            if source == "oui_master":
                url = "https://raw.githubusercontent.com/Ringmast4r/OUI-Master-Database/master/LISTS/master_oui.csv"
            else:
                url = "https://standards-oui.ieee.org/oui/oui.txt"

            # Count entries with device_type for stats
            entries_with_device_type = sum(1 for e in entries.values() if e.get("device_type"))

            data = {
                "source": source,
                "url": url,
                "synced_at": datetime.utcnow().isoformat(),
                "count": len(entries),
                "entries_with_device_type": entries_with_device_type,
                "entries": entries,
            }
            if metadata:
                data.update(metadata)

            _atomic_write_json(self.oui_file, data)

            self._oui_cache = entries
            logger.info(f"Saved {len(entries)} OUI entries ({entries_with_device_type} with device_type) to {self.oui_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save OUI cache: {e}")
            return False

    def lookup_oui(self, mac: str) -> Optional[Dict]:
        """
        Look up manufacturer by MAC address using longest-prefix matching.

        Tries the full MAC first (MA-L/MA-M/MA-S prefixes of decreasing length),
        then falls back to the standard 3-byte OUI prefix.

        Args:
            mac: MAC address in any format

        Returns:
            Vendor info dict or None
        """
        cache = self.load_oui()
        if not cache:
            return None

        # Normalize MAC to colon-separated uppercase hex
        mac_clean = mac.upper().replace("-", ":").replace(".", ":")
        parts = mac_clean.split(":")

        if len(parts) == 6:
            # Standard format XX:XX:XX:XX:XX:XX
            hex_parts = parts
        elif len(parts) == 3 and len(parts[0]) == 4:
            # Cisco format: XXXX.XXXX.XXXX
            flat = mac_clean.replace(":", "")
            hex_parts = [flat[i:i+2] for i in range(0, 12, 2)]
        else:
            # Fallback: try to extract 3-byte OUI
            oui = mac_clean[:8].replace("-", ":")
            return cache.get(oui)

        # Longest-prefix matching: try 5-byte, 4-byte, 3-byte OUI prefixes
        # This supports MA-S (36-bit/5-byte), MA-M (28-bit/4-byte), and
        # MA-L (24-bit/3-byte) assignments
        for prefix_len in (5, 4, 3):
            prefix = ":".join(hex_parts[:prefix_len])
            result = cache.get(prefix)
            if result:
                return result

        return None

    # =========================================================================
    # TCP/IP Fingerprint Cache (p0f)
    # =========================================================================

    def load_tcpip(self) -> List[Dict]:
        """Load TCP/IP fingerprint cache from file."""
        if self._tcpip_cache is not None:
            return self._tcpip_cache

        if self.tcpip_file.exists():
            try:
                with open(self.tcpip_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._tcpip_cache = data.get("entries", [])
                    return self._tcpip_cache
            except Exception as e:
                logger.warning(f"Failed to load TCP/IP cache: {e}")

        self._tcpip_cache = []
        return self._tcpip_cache

    def save_tcpip(self, entries: List[Dict], metadata: Dict = None) -> bool:
        """Save TCP/IP fingerprint data to cache file."""
        try:
            data = {
                "source": "p0f",
                "synced_at": datetime.utcnow().isoformat(),
                "count": len(entries),
                "entries": entries,
            }
            if metadata:
                data.update(metadata)

            _atomic_write_json(self.tcpip_file, data)

            self._tcpip_cache = entries
            logger.info(f"Saved {len(entries)} TCP/IP entries to {self.tcpip_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save TCP/IP cache: {e}")
            return False

    # =========================================================================
    # Banner Pattern Cache
    # =========================================================================

    def load_banners(self) -> List[Dict]:
        """Load banner pattern cache from file."""
        if self._banners_cache is not None:
            return self._banners_cache

        if self.banners_file.exists():
            try:
                with open(self.banners_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._banners_cache = data.get("entries", [])
                    return self._banners_cache
            except Exception as e:
                logger.warning(f"Failed to load banners cache: {e}")

        self._banners_cache = []
        return self._banners_cache

    def save_banners(self, entries: List[Dict], metadata: Dict = None) -> bool:
        """Save banner pattern data to cache file."""
        try:
            data = {
                "source": "cygor_patterns",
                "synced_at": datetime.utcnow().isoformat(),
                "count": len(entries),
                "entries": entries,
            }
            if metadata:
                data.update(metadata)

            _atomic_write_json(self.banners_file, data)

            self._banners_cache = entries
            logger.info(f"Saved {len(entries)} banner patterns to {self.banners_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save banners cache: {e}")
            return False

    # =========================================================================
    # Sync Status
    # =========================================================================

    def load_sync_status(self) -> Dict[str, Dict]:
        """
        Load sync status for all sources.

        Returns:
            Dict mapping source name to status info
        """
        if self.status_file.exists():
            try:
                with open(self.status_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load sync status: {e}")

        return {}

    def save_sync_status(self, source: str, status: str,
                         record_count: int = 0, duration: float = 0.0,
                         error_message: str = None) -> bool:
        """
        Update sync status for a source.

        Args:
            source: Source name (e.g., 'ieee_oui', 'ja3_sslbl')
            status: Status string ('success', 'failed', 'in_progress')
            record_count: Number of records synced
            duration: Sync duration in seconds
            error_message: Error message if failed

        Returns:
            True if saved successfully
        """
        try:
            all_status = self.load_sync_status()

            all_status[source] = {
                "status": status,
                "last_sync": datetime.utcnow().isoformat() if status == "success" else None,
                "record_count": record_count,
                "duration_seconds": duration,
                "error_message": error_message,
            }

            _atomic_write_json(self.status_file, all_status)

            return True
        except Exception as e:
            logger.error(f"Failed to save sync status: {e}")
            return False

    def get_source_status(self, source: str) -> Optional[Dict]:
        """Get sync status for a specific source."""
        all_status = self.load_sync_status()
        return all_status.get(source)

    def needs_sync(self, source: str, max_age_days: int = 7) -> bool:
        """
        Check if a source needs syncing.

        Args:
            source: Source name
            max_age_days: Maximum age before considered stale

        Returns:
            True if needs sync
        """
        status = self.get_source_status(source)

        if not status:
            return True

        if status.get("status") != "success":
            return True

        last_sync = status.get("last_sync")
        if not last_sync:
            return True

        try:
            last_sync_dt = datetime.fromisoformat(last_sync)
            age_days = (datetime.utcnow() - last_sync_dt).days
            return age_days >= max_age_days
        except Exception:
            return True

    # =========================================================================
    # Utility Methods
    # =========================================================================

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dict with cache file info
        """
        stats = {
            "cache_dir": str(self.cache_dir),
            "files": {},
        }

        for name, filename in self.CACHE_FILES.items():
            filepath = self.cache_dir / filename
            if filepath.exists():
                stat = filepath.stat()
                stats["files"][name] = {
                    "path": str(filepath),
                    "size_bytes": stat.st_size,
                    "size_human": self._format_size(stat.st_size),
                    "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                }
            else:
                stats["files"][name] = {
                    "path": str(filepath),
                    "exists": False,
                }

        # Add record counts from status
        sync_status = self.load_sync_status()
        for source, info in sync_status.items():
            if source in stats["files"]:
                stats["files"][source]["record_count"] = info.get("record_count", 0)
                stats["files"][source]["last_sync"] = info.get("last_sync")

        return stats

    def _format_size(self, size_bytes: int) -> str:
        """Format size in bytes to human readable."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"

    def clear(self, source: str = None) -> bool:
        """
        Clear cache files.

        Args:
            source: Specific source to clear, or None for all

        Returns:
            True if cleared successfully
        """
        try:
            if source:
                if source in self.CACHE_FILES:
                    filepath = self.cache_dir / self.CACHE_FILES[source]
                    if filepath.exists():
                        filepath.unlink()
                        logger.info(f"Cleared cache file: {filepath}")
            else:
                for name, filename in self.CACHE_FILES.items():
                    filepath = self.cache_dir / filename
                    if filepath.exists():
                        filepath.unlink()
                logger.info(f"Cleared all cache files in {self.cache_dir}")

            # Clear all in-memory caches
            self.clear_memory_cache()

            return True
        except Exception as e:
            logger.error(f"Failed to clear cache: {e}")
            return False

    # =========================================================================
    # Huginn-Muninn Device Profiles Cache
    # =========================================================================

    @property
    def huginn_devices_file(self) -> Path:
        return self.cache_dir / self.CACHE_FILES["huginn_devices"]

    @property
    def huginn_dhcp_file(self) -> Path:
        return self.cache_dir / self.CACHE_FILES["huginn_dhcp"]

    @property
    def huginn_dhcp_vendor_file(self) -> Path:
        return self.cache_dir / self.CACHE_FILES["huginn_dhcp_vendor"]

    def load_huginn_devices(self) -> Dict[str, Dict]:
        """Load Huginn-Muninn device profiles from cache."""
        if self._huginn_devices_cache is not None:
            return self._huginn_devices_cache

        if self.huginn_devices_file.exists():
            try:
                with open(self.huginn_devices_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._huginn_devices_cache = data.get("entries", {})
                    # Build name index for fast lookup
                    self._build_device_name_index()
                    logger.debug(f"Loaded {len(self._huginn_devices_cache)} Huginn-Muninn device profiles")
                    return self._huginn_devices_cache
            except Exception as e:
                logger.warning(f"Failed to load Huginn-Muninn devices cache: {e}")

        self._huginn_devices_cache = {}
        return self._huginn_devices_cache

    def _build_device_name_index(self):
        """Build index for device name lookup."""
        if self._huginn_devices_cache is None:
            return
        self._huginn_device_name_index = {}
        for device_id, info in self._huginn_devices_cache.items():
            name = info.get("name", "").lower()
            if name:
                self._huginn_device_name_index[name] = device_id

    def _build_device_token_index(self):
        """Build a token → device_ids index for fuzzy hostname matching."""
        if self._huginn_devices_cache is None:
            return
        self._huginn_device_token_index = {}
        for device_id, info in self._huginn_devices_cache.items():
            for source_field in (info.get("name"), info.get("simplified_name")):
                for tok in _tokenize_for_match(source_field or ""):
                    if len(tok) >= 4:
                        self._huginn_device_token_index.setdefault(tok, set()).add(device_id)

    def save_huginn_devices(self, entries: Dict[str, Dict], metadata: Dict = None) -> bool:
        """Save Huginn-Muninn device profiles to cache."""
        try:
            data = {
                "source": "huginn_devices",
                "url": "https://github.com/Ringmast4r/Huginn-Muninn",
                "synced_at": datetime.utcnow().isoformat(),
                "count": len(entries),
                "entries": entries,
            }
            if metadata:
                data.update(metadata)

            _atomic_write_json(self.huginn_devices_file, data)

            self._huginn_devices_cache = entries
            self._build_device_name_index()
            logger.info(f"Saved {len(entries)} Huginn-Muninn device profiles to {self.huginn_devices_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save Huginn-Muninn devices cache: {e}")
            return False

    def lookup_huginn_device(self, device_id: str) -> Optional[Dict]:
        """Look up device info by Huginn-Muninn device ID."""
        cache = self.load_huginn_devices()
        return cache.get(device_id)

    def lookup_huginn_device_by_name(self, name: str) -> Optional[Dict]:
        """Look up device info by name (case-insensitive, exact match)."""
        self.load_huginn_devices()
        if self._huginn_device_name_index is None:
            return None
        device_id = self._huginn_device_name_index.get(name.lower())
        if device_id:
            return self._huginn_devices_cache.get(device_id)
        return None

    def lookup_huginn_device_by_hostname(self, hostname: str) -> Optional[Dict]:
        """
        Find the best Huginn device record for a real-world hostname.

        Real hostnames (``iphone-bob``, ``mac-book-pro-jdoe``,
        ``printer-floor3``) almost never equal Huginn's normalized device
        names (``Apple iPhone``, ``MacBook Pro``, ``HP LaserJet``). Exact
        matching renders the 116K database unreachable from real scan data.

        This method tokenizes both the hostname and each candidate name,
        ranks by overlap, and returns the best record (or None when no
        meaningful overlap exists). The token index is built lazily on
        first call and cached for the process lifetime.
        """
        self.load_huginn_devices()
        if not self._huginn_devices_cache:
            return None
        if self._huginn_device_token_index is None:
            self._build_device_token_index()

        host_tokens = _tokenize_for_match(hostname)
        if not host_tokens:
            return None

        # Score candidates by how many of the hostname's tokens appear in
        # the candidate's token set. Tokens shorter than 4 chars are noisy
        # ("ip", "tv", "hp") and only contribute when paired with another
        # discriminating token.
        candidate_scores: Dict[str, int] = {}
        for tok in host_tokens:
            if len(tok) < 4 and len(host_tokens) == 1:
                # Lone short token like "tv" alone is too noisy.
                continue
            for did in self._huginn_device_token_index.get(tok, ()):
                candidate_scores[did] = candidate_scores.get(did, 0) + len(tok)

        if not candidate_scores:
            return None

        # The token index stores device IDs in sets, so iterating it (above)
        # inserts them into candidate_scores in hash-seed-dependent order; a
        # plain ``max(..., key=.get)`` then breaks score ties by that order,
        # which made fuzzy-match results vary per process (flaky tests, and
        # worse, non-reproducible classifications in the field).
        top_score = max(candidate_scores.values())
        top_ids = [did for did, sc in candidate_scores.items() if sc == top_score]
        if len(top_ids) == 1:
            return self._huginn_devices_cache.get(top_ids[0])

        # Many candidates tie on token overlap (e.g. the bare token "galaxy"
        # matches 1200+ records). A single discriminating token shouldn't let a
        # lone obscure brand ("Hurricane Galaxy") outvote the family the token
        # overwhelmingly denotes. Resolve toward the most common manufacturer
        # among the tied set -- "galaxy" -> Samsung, "iphone" -> Apple --
        # deterministically. Final tiebreaks: the more canonical (fewest-token)
        # name, then device_id, so the result never depends on iteration order.
        from collections import Counter
        from .huginn_normalize import normalize_huginn_record
        norm_by_id = {}
        mfr_counts = Counter()
        for did in top_ids:
            norm = normalize_huginn_record(self._huginn_devices_cache.get(did) or {})
            norm_by_id[did] = norm
            if norm.get("manufacturer"):
                mfr_counts[norm["manufacturer"]] += 1
        dominant_mfr = mfr_counts.most_common(1)[0][0] if mfr_counts else None

        def _candidate_rank(did):
            info = self._huginn_devices_cache.get(did) or {}
            name = info.get("name") or info.get("simplified_name") or ""
            in_dominant = 1 if norm_by_id[did].get("manufacturer") == dominant_mfr else 0
            return (in_dominant, -len(_tokenize_for_match(name)), str(did))

        best_id = max(top_ids, key=_candidate_rank)
        return self._huginn_devices_cache.get(best_id)

    def search_huginn_devices(
        self,
        os_family: str = None,
        manufacturer: str = None,
        device_type: str = None,
        limit: int = 5
    ) -> List[Dict]:
        """
        Search Huginn-Muninn devices by OS family, manufacturer, or device type.

        This is useful for enriching fingerprint results when we have partial info
        from other sources (Nmap, banners, etc.).

        Args:
            os_family: OS family to search for (e.g., "Linux", "Windows", "Android")
            manufacturer: Manufacturer/vendor name to search for
            device_type: Device type hint (e.g., "router", "phone", "camera")
            limit: Maximum number of results to return

        Returns:
            List of matching device info dicts with device_id included
        """
        cache = self.load_huginn_devices()
        if not cache:
            return []

        results = []
        search_terms = []

        # Build search terms (lowercase)
        if os_family:
            search_terms.append(os_family.lower())
        if manufacturer:
            search_terms.append(manufacturer.lower())
        if device_type:
            search_terms.append(device_type.lower())

        if not search_terms:
            return []

        for device_id, info in cache.items():
            name = info.get("name", "").lower()
            hierarchy = info.get("hierarchy", [])
            hierarchy_str = " ".join(h.lower() for h in hierarchy) if hierarchy else ""

            # Check if any search term matches name or hierarchy
            score = 0
            for term in search_terms:
                if term in name:
                    score += 2  # Direct name match is worth more
                if term in hierarchy_str:
                    score += 1

            if score > 0:
                result = {
                    "device_id": device_id,
                    "name": info.get("name"),
                    "hierarchy": hierarchy,
                    "hierarchy_str": " > ".join(hierarchy) if hierarchy else None,
                    "parent_id": info.get("parent_id"),
                    "score": score,
                }
                results.append(result)

        # Sort by score (highest first) and return top results
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:limit]

    def get_huginn_device_category(self, os_family: str = None, nmap_type: str = None) -> Optional[str]:
        """
        Get a more specific device category from Huginn-Muninn based on OS family and Nmap type.

        This maps generic classifications like "general purpose" to more specific
        Huginn-Muninn device categories when possible.

        Args:
            os_family: OS family (e.g., "Linux", "Windows", "iOS")
            nmap_type: Nmap device type (e.g., "general purpose", "router", "phone")

        Returns:
            More specific device category string, or None if no enrichment possible
        """
        if not os_family and not nmap_type:
            return None

        # If Nmap already has a specific type, use that
        if nmap_type and nmap_type.lower() not in ("general purpose", "unknown"):
            return nmap_type

        # Map OS families to device categories for "general purpose" devices
        os_family_lower = os_family.lower() if os_family else ""

        # Server/Desktop operating systems -> Computer
        if os_family_lower in ("linux", "windows", "freebsd", "openbsd", "netbsd", "solaris", "unix"):
            return "Computer"

        # Mobile operating systems -> specific types
        if os_family_lower in ("ios", "iphone os"):
            return "Smartphone"
        if os_family_lower == "android":
            return "Smartphone/Tablet"
        if os_family_lower == "ipados":
            return "Tablet"

        # Embedded/IoT
        if os_family_lower in ("embedded", "rtos", "vxworks"):
            return "Embedded Device"

        # Network OS
        if os_family_lower in ("ios", "ios-xe", "nx-os", "junos") and "cisco" in (nmap_type or "").lower():
            return "Network Device"

        return None

    # =========================================================================
    # Huginn-Muninn DHCP Fingerprints Cache
    # =========================================================================

    def load_huginn_dhcp(self) -> Dict[str, Dict]:
        """Load Huginn-Muninn DHCP fingerprints from cache."""
        if self._huginn_dhcp_cache is not None:
            return self._huginn_dhcp_cache

        if self.huginn_dhcp_file.exists():
            try:
                with open(self.huginn_dhcp_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._huginn_dhcp_cache = data.get("entries", {})
                    # Build hash index for fast lookup
                    self._build_dhcp_hash_index()
                    logger.debug(f"Loaded {len(self._huginn_dhcp_cache)} Huginn-Muninn DHCP fingerprints")
                    return self._huginn_dhcp_cache
            except Exception as e:
                logger.warning(f"Failed to load Huginn-Muninn DHCP cache: {e}")

        self._huginn_dhcp_cache = {}
        return self._huginn_dhcp_cache

    def _build_dhcp_hash_index(self):
        """Build index for DHCP options hash lookup."""
        if self._huginn_dhcp_cache is None:
            return
        self._huginn_dhcp_hash_index = {}
        for fp_id, info in self._huginn_dhcp_cache.items():
            options_hash = info.get("options_hash")
            if options_hash:
                self._huginn_dhcp_hash_index[options_hash] = fp_id

    def save_huginn_dhcp(self, entries: Dict[str, Dict], metadata: Dict = None) -> bool:
        """Save Huginn-Muninn DHCP fingerprints to cache."""
        try:
            data = {
                "source": "huginn_dhcp",
                "url": "https://github.com/Ringmast4r/Huginn-Muninn",
                "synced_at": datetime.utcnow().isoformat(),
                "count": len(entries),
                "entries": entries,
            }
            if metadata:
                data.update(metadata)

            _atomic_write_json(self.huginn_dhcp_file, data)

            self._huginn_dhcp_cache = entries
            self._build_dhcp_hash_index()
            logger.info(f"Saved {len(entries)} Huginn-Muninn DHCP fingerprints to {self.huginn_dhcp_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save Huginn-Muninn DHCP cache: {e}")
            return False

    def lookup_huginn_dhcp_by_hash(self, options_hash: str) -> Optional[Dict]:
        """Look up DHCP fingerprint by options hash."""
        self.load_huginn_dhcp()
        if self._huginn_dhcp_hash_index is None:
            return None
        fp_id = self._huginn_dhcp_hash_index.get(options_hash)
        if fp_id:
            return self._huginn_dhcp_cache.get(fp_id)
        return None

    def lookup_huginn_dhcp_by_options(self, dhcp_options: str) -> Optional[Dict]:
        """
        Look up DHCP fingerprint by option string.

        Args:
            dhcp_options: Comma-separated DHCP option numbers (e.g., "1,3,6,12,15")

        Returns:
            Fingerprint info dict or None
        """
        import hashlib
        # Normalize and hash
        normalized = ",".join(sorted(opt.strip() for opt in dhcp_options.split(",") if opt.strip()))
        options_hash = hashlib.md5(normalized.encode()).hexdigest()
        return self.lookup_huginn_dhcp_by_hash(options_hash)

    # =========================================================================
    # Huginn-Muninn DHCP Vendor Cache
    # =========================================================================

    def load_huginn_dhcp_vendor(self) -> Dict[str, Dict]:
        """Load Huginn-Muninn DHCP vendor classes from cache."""
        if self._huginn_dhcp_vendor_cache is not None:
            return self._huginn_dhcp_vendor_cache

        if self.huginn_dhcp_vendor_file.exists():
            try:
                with open(self.huginn_dhcp_vendor_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._huginn_dhcp_vendor_cache = data.get("entries", {})
                    logger.debug(f"Loaded {len(self._huginn_dhcp_vendor_cache)} Huginn-Muninn DHCP vendor entries")
                    return self._huginn_dhcp_vendor_cache
            except Exception as e:
                logger.warning(f"Failed to load Huginn-Muninn DHCP vendor cache: {e}")

        self._huginn_dhcp_vendor_cache = {}
        return self._huginn_dhcp_vendor_cache

    def save_huginn_dhcp_vendor(self, entries: Dict[str, Dict], metadata: Dict = None) -> bool:
        """Save Huginn-Muninn DHCP vendor classes to cache."""
        try:
            data = {
                "source": "huginn_dhcp_vendor",
                "url": "https://github.com/Ringmast4r/Huginn-Muninn",
                "synced_at": datetime.utcnow().isoformat(),
                "count": len(entries),
                "entries": entries,
            }
            if metadata:
                data.update(metadata)

            _atomic_write_json(self.huginn_dhcp_vendor_file, data)

            self._huginn_dhcp_vendor_cache = entries
            logger.info(f"Saved {len(entries)} Huginn-Muninn DHCP vendor entries to {self.huginn_dhcp_vendor_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save Huginn-Muninn DHCP vendor cache: {e}")
            return False

    def lookup_huginn_dhcp_vendor(self, vendor_class: str) -> Optional[Dict]:
        """
        Look up device by DHCP vendor class string (Option 60).

        Does partial matching to find the best match.
        """
        cache = self.load_huginn_dhcp_vendor()
        if not cache:
            return None

        vendor_class_lower = vendor_class.lower()

        # Try exact match first
        for vendor_id, info in cache.items():
            if info.get("value", "").lower() == vendor_class_lower:
                return info

        # Try partial match (vendor class contains or is contained in entry)
        best_match = None
        best_match_len = 0
        for vendor_id, info in cache.items():
            entry_value = info.get("value", "").lower()
            if entry_value in vendor_class_lower or vendor_class_lower in entry_value:
                match_len = len(entry_value)
                if match_len > best_match_len:
                    best_match = info
                    best_match_len = match_len

        return best_match

    # =========================================================================
    # Huginn-Muninn DHCPv6 Cache (IPv6 device fingerprinting)
    # =========================================================================

    @property
    def huginn_dhcpv6_file(self) -> Path:
        return self.cache_dir / self.CACHE_FILES["huginn_dhcpv6"]

    @property
    def huginn_dhcpv6_enterprise_file(self) -> Path:
        return self.cache_dir / self.CACHE_FILES["huginn_dhcpv6_enterprise"]

    def load_huginn_dhcpv6(self) -> Dict[str, Dict]:
        """Load Huginn-Muninn DHCPv6 signatures from cache."""
        if self._huginn_dhcpv6_cache is not None:
            return self._huginn_dhcpv6_cache

        if self.huginn_dhcpv6_file.exists():
            try:
                with open(self.huginn_dhcpv6_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._huginn_dhcpv6_cache = data.get("entries", {})
                    logger.debug(f"Loaded {len(self._huginn_dhcpv6_cache)} Huginn-Muninn DHCPv6 signatures")
                    return self._huginn_dhcpv6_cache
            except Exception as e:
                logger.warning(f"Failed to load Huginn-Muninn DHCPv6 cache: {e}")

        self._huginn_dhcpv6_cache = {}
        return self._huginn_dhcpv6_cache

    def save_huginn_dhcpv6(self, entries: Dict[str, Dict], metadata: Dict = None) -> bool:
        """Save Huginn-Muninn DHCPv6 signatures to cache."""
        try:
            data = {
                "source": "huginn_dhcpv6",
                "url": "https://github.com/Ringmast4r/Huginn-Muninn",
                "synced_at": datetime.utcnow().isoformat(),
                "count": len(entries),
                "entries": entries,
            }
            if metadata:
                data.update(metadata)

            _atomic_write_json(self.huginn_dhcpv6_file, data)

            self._huginn_dhcpv6_cache = entries
            logger.info(f"Saved {len(entries)} Huginn-Muninn DHCPv6 signatures to {self.huginn_dhcpv6_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save Huginn-Muninn DHCPv6 cache: {e}")
            return False

    def load_huginn_dhcpv6_enterprise(self) -> Dict[str, Dict]:
        """Load Huginn-Muninn DHCPv6 enterprise IDs from cache."""
        if self._huginn_dhcpv6_enterprise_cache is not None:
            return self._huginn_dhcpv6_enterprise_cache

        if self.huginn_dhcpv6_enterprise_file.exists():
            try:
                with open(self.huginn_dhcpv6_enterprise_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._huginn_dhcpv6_enterprise_cache = data.get("entries", {})
                    logger.debug(f"Loaded {len(self._huginn_dhcpv6_enterprise_cache)} Huginn-Muninn DHCPv6 enterprise IDs")
                    return self._huginn_dhcpv6_enterprise_cache
            except Exception as e:
                logger.warning(f"Failed to load Huginn-Muninn DHCPv6 enterprise cache: {e}")

        self._huginn_dhcpv6_enterprise_cache = {}
        return self._huginn_dhcpv6_enterprise_cache

    def save_huginn_dhcpv6_enterprise(self, entries: Dict[str, Dict], metadata: Dict = None) -> bool:
        """Save Huginn-Muninn DHCPv6 enterprise IDs to cache."""
        try:
            data = {
                "source": "huginn_dhcpv6_enterprise",
                "url": "https://github.com/Ringmast4r/Huginn-Muninn",
                "synced_at": datetime.utcnow().isoformat(),
                "count": len(entries),
                "entries": entries,
            }
            if metadata:
                data.update(metadata)

            _atomic_write_json(self.huginn_dhcpv6_enterprise_file, data)

            self._huginn_dhcpv6_enterprise_cache = entries
            logger.info(f"Saved {len(entries)} Huginn-Muninn DHCPv6 enterprise IDs to {self.huginn_dhcpv6_enterprise_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save Huginn-Muninn DHCPv6 enterprise cache: {e}")
            return False

    # =========================================================================
    # Huginn-Muninn MAC Vendors Cache (10.1M MAC address vendor mappings)
    # =========================================================================

    @property
    def huginn_mac_vendors_file(self) -> Path:
        return self.cache_dir / self.CACHE_FILES["huginn_mac_vendors"]

    def load_huginn_mac_vendors(self) -> Dict[str, Dict]:
        """Load Huginn-Muninn MAC vendors from cache."""
        if self._huginn_mac_vendors_cache is not None:
            return self._huginn_mac_vendors_cache

        if self.huginn_mac_vendors_file.exists():
            try:
                with open(self.huginn_mac_vendors_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._huginn_mac_vendors_cache = data.get("entries", {})
                    logger.debug(f"Loaded {len(self._huginn_mac_vendors_cache)} Huginn-Muninn MAC vendors")
                    return self._huginn_mac_vendors_cache
            except Exception as e:
                logger.warning(f"Failed to load Huginn-Muninn MAC vendors cache: {e}")

        self._huginn_mac_vendors_cache = {}
        return self._huginn_mac_vendors_cache

    def save_huginn_mac_vendors(self, entries: Dict[str, Dict], metadata: Dict = None) -> bool:
        """Save Huginn-Muninn MAC vendors to cache."""
        try:
            data = {
                "source": "huginn_mac_vendors",
                "url": "https://github.com/Ringmast4r/Huginn-Muninn",
                "synced_at": datetime.utcnow().isoformat(),
                "count": len(entries),
                "entries": entries,
            }
            if metadata:
                data.update(metadata)

            _atomic_write_json(self.huginn_mac_vendors_file, data)

            self._huginn_mac_vendors_cache = entries
            logger.info(f"Saved {len(entries)} Huginn-Muninn MAC vendors to {self.huginn_mac_vendors_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save Huginn-Muninn MAC vendors cache: {e}")
            return False

    def lookup_huginn_mac_vendor(self, mac: str) -> Optional[Dict]:
        """
        Look up vendor by MAC address prefix using Huginn-Muninn database.

        Args:
            mac: MAC address (any format, will be normalized)

        Returns:
            Dict with vendor info if found, None otherwise
        """
        cache = self.load_huginn_mac_vendors()
        if not cache:
            return None

        # Normalize MAC to 6-char lowercase hex (first 3 octets)
        mac_clean = mac.lower().replace(":", "").replace("-", "").replace(".", "")[:6]

        return cache.get(mac_clean)

    def get_device_info_from_huginn(self, device_id: str) -> Optional[Dict]:
        """
        Get full device information from Huginn-Muninn including hierarchy.

        Args:
            device_id: Huginn-Muninn device ID

        Returns:
            Dict with device info including hierarchy_str, mobile, tablet flags
        """
        device = self.lookup_huginn_device(device_id)
        if not device:
            return None

        return {
            "name": device.get("name"),
            "hierarchy": device.get("hierarchy_str"),
            "mobile": device.get("mobile", False),
            "tablet": device.get("tablet", False),
            "device_id": device_id,
        }

    # =========================================================================
    # Satori Fingerprint Databases
    # =========================================================================

    def load_satori_ssh(self) -> List[Dict]:
        """Load Satori SSH fingerprints from cache."""
        if self._satori_ssh_cache is not None:
            return self._satori_ssh_cache
        filepath = self.cache_dir / self.CACHE_FILES["satori_ssh"]
        if filepath.exists():
            try:
                data = json.loads(filepath.read_text())
                self._satori_ssh_cache = data if isinstance(data, list) else []
            except Exception:
                self._satori_ssh_cache = []
        else:
            self._satori_ssh_cache = []
        return self._satori_ssh_cache

    def lookup_satori_ssh(self, banner: str) -> Optional[Dict]:
        """Look up SSH banner against Satori SSH fingerprints."""
        if not banner:
            return None
        entries = self.load_satori_ssh()
        banner_lower = banner.lower()
        for entry in entries:
            pattern = entry.get("pattern", entry.get("name", "")).lower()
            if pattern and pattern in banner_lower:
                return entry
        return None

    def load_satori_smb(self) -> List[Dict]:
        """Load Satori SMB fingerprints from cache."""
        if self._satori_smb_cache is not None:
            return self._satori_smb_cache
        filepath = self.cache_dir / self.CACHE_FILES["satori_smb"]
        if filepath.exists():
            try:
                data = json.loads(filepath.read_text())
                self._satori_smb_cache = data if isinstance(data, list) else []
            except Exception:
                self._satori_smb_cache = []
        else:
            self._satori_smb_cache = []
        return self._satori_smb_cache

    def lookup_satori_smb(self, os_string: str) -> Optional[Dict]:
        """Look up SMB OS string against Satori SMB fingerprints."""
        if not os_string:
            return None
        entries = self.load_satori_smb()
        os_lower = os_string.lower()
        for entry in entries:
            pattern = entry.get("os", entry.get("native_os", "")).lower()
            if pattern and pattern in os_lower:
                return entry
        return None

    def load_satori_http(self) -> List[Dict]:
        """Load Satori HTTP server fingerprints from cache."""
        if self._satori_http_cache is not None:
            return self._satori_http_cache
        filepath = self.cache_dir / self.CACHE_FILES["satori_http"]
        if filepath.exists():
            try:
                data = json.loads(filepath.read_text())
                self._satori_http_cache = data if isinstance(data, list) else []
            except Exception:
                self._satori_http_cache = []
        else:
            self._satori_http_cache = []
        return self._satori_http_cache

    def lookup_satori_http(self, server_header: str) -> Optional[Dict]:
        """Look up HTTP Server header against Satori HTTP fingerprints."""
        if not server_header:
            return None
        entries = self.load_satori_http()
        header_lower = server_header.lower()
        for entry in entries:
            pattern = entry.get("pattern", entry.get("name", "")).lower()
            if pattern and pattern in header_lower:
                return entry
        return None

    def load_satori_useragent(self) -> List[Dict]:
        """Load Satori User-Agent fingerprints from cache."""
        if self._satori_useragent_cache is not None:
            return self._satori_useragent_cache
        filepath = self.cache_dir / self.CACHE_FILES["satori_useragent"]
        if filepath.exists():
            try:
                data = json.loads(filepath.read_text())
                self._satori_useragent_cache = data if isinstance(data, list) else []
            except Exception:
                self._satori_useragent_cache = []
        else:
            self._satori_useragent_cache = []
        return self._satori_useragent_cache

    def lookup_satori_useragent(self, useragent: str) -> Optional[Dict]:
        """Look up User-Agent string against Satori User-Agent fingerprints."""
        if not useragent:
            return None
        entries = self.load_satori_useragent()
        ua_lower = useragent.lower()
        for entry in entries:
            pattern = entry.get("pattern", entry.get("name", "")).lower()
            if pattern and pattern in ua_lower:
                return entry
        return None

    def load_satori_dhcp(self) -> List[Dict]:
        """Load Satori DHCP fingerprints from cache."""
        if self._satori_dhcp_cache is not None:
            return self._satori_dhcp_cache
        filepath = self.cache_dir / self.CACHE_FILES["satori_dhcp"]
        if filepath.exists():
            try:
                data = json.loads(filepath.read_text())
                self._satori_dhcp_cache = data if isinstance(data, list) else []
            except Exception:
                self._satori_dhcp_cache = []
        else:
            self._satori_dhcp_cache = []
        return self._satori_dhcp_cache

    def lookup_satori_dhcp(self, dhcp_options: str) -> Optional[Dict]:
        """Look up DHCP options against Satori DHCP fingerprints."""
        if not dhcp_options:
            return None
        entries = self.load_satori_dhcp()
        options_lower = dhcp_options.lower()
        for entry in entries:
            pattern = entry.get("pattern", entry.get("name", "")).lower()
            if pattern and pattern in options_lower:
                return entry
        return None

    def lookup_huginn_combination_by_dhcp_options(self, opt55: str) -> Optional[Dict]:
        """
        Find a Huginn-Muninn combination record by exact DHCP option55 string.

        opt55 is the comma-separated parameter request list, e.g.
        ``"1,2,3,6,15,88,42,44,46,47"``. Combinations carry a device_vendor /
        satori_name / device_type that's authoritative when the option55
        matches exactly. Wraps the existing ``load_huginn_combinations``
        loader, which returns a dict-of-records.
        """
        if not opt55:
            return None
        normalized = opt55.replace(" ", "")
        cache = self.load_huginn_combinations()
        # cache is {str_index: record_dict}; iterate values.
        for entry in cache.values() if isinstance(cache, dict) else cache:
            if not isinstance(entry, dict):
                continue
            entry_opt = (entry.get("dhcp_option55") or "").replace(" ", "")
            if entry_opt and entry_opt == normalized:
                return entry
        return None

    def load_satori_sip(self) -> List[Dict]:
        """Load Satori SIP fingerprints from cache."""
        if self._satori_sip_cache is not None:
            return self._satori_sip_cache
        filepath = self.cache_dir / self.CACHE_FILES["satori_sip"]
        if filepath.exists():
            try:
                data = json.loads(filepath.read_text())
                self._satori_sip_cache = data if isinstance(data, list) else []
            except Exception:
                self._satori_sip_cache = []
        else:
            self._satori_sip_cache = []
        return self._satori_sip_cache

    def lookup_satori_sip(self, sip_useragent: str) -> Optional[Dict]:
        """Look up SIP User-Agent against Satori SIP fingerprints."""
        if not sip_useragent:
            return None
        entries = self.load_satori_sip()
        ua_lower = sip_useragent.lower()
        for entry in entries:
            pattern = entry.get("pattern", entry.get("name", "")).lower()
            if pattern and pattern in ua_lower:
                return entry
        return None

    # =========================================================================
    # Huginn-Muninn DHCP Combinations Cache
    # =========================================================================

    def load_huginn_combinations(self) -> Dict[str, Dict]:
        """Load Huginn-Muninn DHCP combinations from cache."""
        if self._huginn_combinations_cache is not None:
            return self._huginn_combinations_cache
        filepath = self.cache_dir / self.CACHE_FILES["huginn_combinations"]
        if filepath.exists():
            try:
                data = json.loads(filepath.read_text())
                if isinstance(data, dict):
                    self._huginn_combinations_cache = data
                elif isinstance(data, list):
                    # Convert list to dict keyed by index for consistency
                    self._huginn_combinations_cache = {str(i): v for i, v in enumerate(data)}
                else:
                    self._huginn_combinations_cache = {}
            except Exception:
                self._huginn_combinations_cache = {}
        else:
            self._huginn_combinations_cache = {}
        return self._huginn_combinations_cache

    def lookup_huginn_combination(self, dhcp_fingerprint: str, dhcp_vendor: str = None) -> Optional[Dict]:
        """
        Look up DHCP combination by fingerprint and optional vendor.

        Args:
            dhcp_fingerprint: DHCP option 55 fingerprint string
            dhcp_vendor: Optional DHCP option 60 vendor class

        Returns:
            Matching combination entry or None
        """
        cache = self.load_huginn_combinations()
        if not cache:
            return None

        fp_lower = dhcp_fingerprint.lower() if dhcp_fingerprint else ""
        vendor_lower = dhcp_vendor.lower() if dhcp_vendor else ""

        for key, entry in cache.items():
            entry_fp = str(entry.get("dhcp_fingerprint", "")).lower()
            entry_vendor = str(entry.get("dhcp_vendor", "")).lower()

            if entry_fp and entry_fp == fp_lower:
                if not vendor_lower or entry_vendor == vendor_lower:
                    return entry

        return None

    # =========================================================================
    # Nmap OS Database Cache
    # =========================================================================

    @property
    def nmap_os_db_file(self) -> Path:
        return self.cache_dir / self.CACHE_FILES["nmap_os_db"]

    def load_nmap_os_db(self) -> List[Dict]:
        """Load Nmap OS fingerprints from cache."""
        if self._nmap_os_db_cache is not None:
            return self._nmap_os_db_cache

        if self.nmap_os_db_file.exists():
            try:
                with open(self.nmap_os_db_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._nmap_os_db_cache = data.get("entries", [])
                    logger.debug(f"Loaded {len(self._nmap_os_db_cache)} Nmap OS fingerprints")
                    return self._nmap_os_db_cache
            except Exception as e:
                logger.warning(f"Failed to load Nmap OS DB cache: {e}")

        self._nmap_os_db_cache = []
        return self._nmap_os_db_cache

    def save_nmap_os_db(self, entries: List[Dict], metadata: Dict = None) -> bool:
        """Save Nmap OS fingerprints to cache."""
        try:
            data = {
                "source": "nmap_os_db",
                "url": "https://github.com/Ringmast4r/Fingerbanged",
                "synced_at": datetime.utcnow().isoformat(),
                "count": len(entries),
                "entries": entries,
            }
            if metadata:
                data.update(metadata)

            _atomic_write_json(self.nmap_os_db_file, data)

            self._nmap_os_db_cache = entries
            logger.info(f"Saved {len(entries)} Nmap OS fingerprints to {self.nmap_os_db_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save Nmap OS DB cache: {e}")
            return False

    def lookup_nmap_os_by_name(self, name: str) -> List[Dict]:
        """
        Search Nmap OS fingerprints by device/OS name.

        Args:
            name: Partial name to search for (case-insensitive)

        Returns:
            List of matching fingerprint entries
        """
        cache = self.load_nmap_os_db()
        if not cache:
            return []

        name_lower = name.lower()
        return [
            entry for entry in cache
            if name_lower in entry.get("name", "").lower()
        ]

    def lookup_nmap_os_by_vendor(self, vendor: str) -> List[Dict]:
        """
        Search Nmap OS fingerprints by vendor.

        Args:
            vendor: Vendor name to search for (case-insensitive)

        Returns:
            List of matching fingerprint entries
        """
        cache = self.load_nmap_os_db()
        if not cache:
            return []

        vendor_lower = vendor.lower()
        return [
            entry for entry in cache
            if vendor_lower in (entry.get("vendor") or "").lower()
        ]

    def get_all_os_fingerprint_counts(self) -> Dict[str, int]:
        """
        Get record counts for all OS fingerprint sources.

        Returns:
            Dict mapping source name to record count
        """
        counts = {}

        # Nmap OS DB
        nmap = self.load_nmap_os_db()
        counts["nmap_os_db"] = len(nmap)

        return counts


# Global cache instance
_cache: Optional[FingerprintCache] = None


def get_cache() -> FingerprintCache:
    """Get the global fingerprint cache instance."""
    global _cache
    if _cache is None:
        _cache = FingerprintCache()
    return _cache
