"""
Credential Cache
================

Caches fetched credentials locally for offline use and performance.
"""

import os
import json
import yaml
import logging
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

from ..credentials.schema import Credential, CredentialSource

logger = logging.getLogger("credrecon.sources.cache")


@dataclass
class CacheConfig:
    """Configuration for the credential cache."""
    cache_dir: Path = None
    default_ttl_hours: int = 24
    max_cache_size_mb: int = 100

    def __post_init__(self):
        if self.cache_dir is None:
            self.cache_dir = Path.home() / ".cache" / "cygor" / "credentials"


@dataclass
class CacheEntry:
    """A cached credential set."""
    source_name: str
    credentials: List[Dict[str, Any]]
    fetched_at: str
    expires_at: str
    metadata: Dict[str, Any]

    def is_expired(self) -> bool:
        """Check if this cache entry is expired."""
        try:
            expires = datetime.fromisoformat(self.expires_at)
            return datetime.now() > expires
        except Exception:
            return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "source_name": self.source_name,
            "credentials": self.credentials,
            "fetched_at": self.fetched_at,
            "expires_at": self.expires_at,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CacheEntry":
        """Create from dictionary."""
        return cls(
            source_name=data.get("source_name", "unknown"),
            credentials=data.get("credentials", []),
            fetched_at=data.get("fetched_at", ""),
            expires_at=data.get("expires_at", ""),
            metadata=data.get("metadata", {}),
        )


class CredentialCache:
    """
    Manages cached credentials from external sources.

    Provides:
    - Persistent storage of fetched credentials
    - TTL-based expiration
    - Cache invalidation
    """

    def __init__(self, config: CacheConfig = None):
        """
        Initialize the cache.

        Args:
            config: Cache configuration (uses defaults if not provided)
        """
        self.config = config or CacheConfig()
        self._ensure_cache_dir()

    def _ensure_cache_dir(self) -> None:
        """Create cache directory if it doesn't exist."""
        self.config.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_cache_path(self, source_name: str) -> Path:
        """Get the cache file path for a source."""
        safe_name = "".join(c if c.isalnum() else "_" for c in source_name)
        return self.config.cache_dir / f"{safe_name}.yaml"

    def get(self, source_name: str) -> Optional[CacheEntry]:
        """
        Get cached credentials for a source.

        Args:
            source_name: Name of the credential source

        Returns:
            CacheEntry if valid cache exists, None otherwise
        """
        cache_path = self._get_cache_path(source_name)

        if not cache_path.exists():
            return None

        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data:
                return None

            entry = CacheEntry.from_dict(data)

            # Check if expired
            if entry.is_expired():
                logger.debug(f"Cache for {source_name} is expired")
                return None

            return entry

        except Exception as e:
            logger.warning(f"Failed to read cache for {source_name}: {e}")
            return None

    def put(
        self,
        source_name: str,
        credentials: List[Credential],
        ttl_hours: int = None,
        metadata: Dict[str, Any] = None,
    ) -> None:
        """
        Store credentials in the cache.

        Args:
            source_name: Name of the credential source
            credentials: List of credentials to cache
            ttl_hours: Time-to-live in hours (uses default if not provided)
            metadata: Additional metadata to store
        """
        ttl_hours = ttl_hours or self.config.default_ttl_hours
        now = datetime.now()
        expires = now + timedelta(hours=ttl_hours)

        entry = CacheEntry(
            source_name=source_name,
            credentials=[c.to_dict() for c in credentials],
            fetched_at=now.isoformat(),
            expires_at=expires.isoformat(),
            metadata=metadata or {},
        )

        cache_path = self._get_cache_path(source_name)

        try:
            with open(cache_path, 'w', encoding='utf-8') as f:
                yaml.dump(entry.to_dict(), f, default_flow_style=False)
            logger.info(f"Cached {len(credentials)} credentials from {source_name}")

        except Exception as e:
            logger.error(f"Failed to write cache for {source_name}: {e}")

    def invalidate(self, source_name: str = None) -> int:
        """
        Invalidate cached credentials.

        Args:
            source_name: Source to invalidate (all sources if None)

        Returns:
            Number of cache entries invalidated
        """
        count = 0

        if source_name:
            cache_path = self._get_cache_path(source_name)
            if cache_path.exists():
                cache_path.unlink()
                count = 1
        else:
            # Invalidate all
            for cache_file in self.config.cache_dir.glob("*.yaml"):
                cache_file.unlink()
                count += 1

        logger.info(f"Invalidated {count} cache entries")
        return count

    def get_all_cached(self) -> Dict[str, CacheEntry]:
        """
        Get all valid cached credentials.

        Returns:
            Dictionary mapping source names to cache entries
        """
        result = {}

        for cache_file in self.config.cache_dir.glob("*.yaml"):
            source_name = cache_file.stem
            entry = self.get(source_name)
            if entry:
                result[source_name] = entry

        return result

    def get_cached_credentials(self) -> List[Credential]:
        """
        Get all cached credentials as Credential objects.

        Returns:
            List of all cached credentials (not expired)
        """
        credentials = []

        for source_name, entry in self.get_all_cached().items():
            for cred_data in entry.credentials:
                try:
                    cred = Credential.from_dict(cred_data)
                    credentials.append(cred)
                except Exception as e:
                    logger.debug(f"Failed to parse cached credential: {e}")

        return credentials

    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        entries = self.get_all_cached()
        total_creds = sum(len(e.credentials) for e in entries.values())

        # Get cache size
        total_size = 0
        for cache_file in self.config.cache_dir.glob("*.yaml"):
            total_size += cache_file.stat().st_size

        return {
            "cache_dir": str(self.config.cache_dir),
            "num_sources": len(entries),
            "total_credentials": total_creds,
            "cache_size_bytes": total_size,
            "cache_size_mb": round(total_size / (1024 * 1024), 2),
            "sources": list(entries.keys()),
        }


def get_cache() -> CredentialCache:
    """Get the default credential cache instance."""
    return CredentialCache()
